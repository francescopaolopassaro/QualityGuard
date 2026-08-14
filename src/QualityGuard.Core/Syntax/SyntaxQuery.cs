using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax;

/// <summary>Query helpers shared by every AST-based rule.</summary>
public static class SyntaxQuery
{
    /// <summary>Full dotted name of a reference, e.g. <c>con.prepareStatement</c>.</summary>
    public static string DottedName(SyntaxNode? node)
    {
        if (node == null)
            return string.Empty;
        return node.Kind switch
        {
            NodeKind.Identifier => node.Text,
            NodeKind.MemberSelect => Join(DottedName(node.ChildAt(0)), node.ChildAt(1)?.Text),
            NodeKind.Invocation or NodeKind.Index => DottedName(node.ChildAt(0)),
            NodeKind.Parenthesized => DottedName(node.ChildAt(0)),
            NodeKind.ObjectCreation => node.Text,
            _ => string.Empty
        };
    }

    private static string Join(string left, string? right)
        => string.IsNullOrEmpty(right) ? left : string.IsNullOrEmpty(left) ? right : $"{left}.{right}";

    /// <summary>Last segment of a dotted name, e.g. <c>prepareStatement</c>.</summary>
    public static string SimpleName(SyntaxNode? node)
    {
        var dotted = DottedName(node);
        var dot = dotted.LastIndexOf('.');
        return dot < 0 ? dotted : dotted[(dot + 1)..];
    }

    public static string InvokedName(SyntaxNode invocation) => SimpleName(invocation.ChildAt(0));

    public static string InvokedDottedName(SyntaxNode invocation) => DottedName(invocation.ChildAt(0));

    /// <summary>Receiver of a method call: <c>con</c> in <c>con.prepareStatement(...)</c>.</summary>
    public static string Receiver(SyntaxNode invocation)
    {
        var callee = invocation.ChildAt(0);
        return callee is { Kind: NodeKind.MemberSelect } ? DottedName(callee.ChildAt(0)) : string.Empty;
    }

    public static IReadOnlyList<SyntaxNode> Arguments(SyntaxNode invocation)
        => invocation.FirstChild(NodeKind.ArgumentList)?.Children ?? [];

    public static SyntaxNode? ArgumentAt(SyntaxNode invocation, int index)
    {
        var args = Arguments(invocation);
        return index >= 0 && index < args.Count ? args[index] : null;
    }

    public static IEnumerable<SyntaxNode> Invocations(SyntaxNode root)
        => root.OfKind(NodeKind.Invocation);

    /// <summary>All calls whose simple name matches one of <paramref name="names"/>.</summary>
    public static IEnumerable<SyntaxNode> InvocationsNamed(SyntaxNode root, params string[] names)
        => Invocations(root).Where(i => names.Contains(InvokedName(i), StringComparer.Ordinal));

    public static IEnumerable<SyntaxNode> InvocationsNamedIgnoreCase(SyntaxNode root, params string[] names)
        => Invocations(root).Where(i => names.Contains(InvokedName(i), StringComparer.OrdinalIgnoreCase));

    /// <summary>Calls matching a dotted suffix such as <c>Cipher.getInstance</c>.</summary>
    public static IEnumerable<SyntaxNode> InvocationsOf(SyntaxNode root, params string[] dottedSuffixes)
        => Invocations(root).Where(i =>
        {
            var dotted = InvokedDottedName(i);
            return dottedSuffixes.Any(s => dotted.Equals(s, StringComparison.Ordinal)
                                        || dotted.EndsWith("." + s, StringComparison.Ordinal));
        });

    public static bool IsStringLiteral(SyntaxNode? node) => node is { Kind: NodeKind.StringLiteral };

    public static bool IsLiteral(SyntaxNode? node)
        => node is { Kind: NodeKind.StringLiteral or NodeKind.NumberLiteral or NodeKind.BooleanLiteral or NodeKind.NullLiteral };

    /// <summary>True when the expression is built at run time (concatenation, interpolation, formatting).</summary>
    public static bool IsDynamicallyBuilt(SyntaxNode? node)
    {
        if (node == null)
            return false;
        switch (node.Kind)
        {
            case NodeKind.Binary when node.Text is "+" or "%" or "&" or "." or "+=":
                return node.Children.Any(c => !IsLiteral(c)) || node.Children.Any(IsDynamicallyBuilt);
            case NodeKind.Invocation:
                var name = InvokedName(node);
                if (name is "format" or "Format" or "sprintf" or "printf" or "Sprintf" or "concat" or "join"
                    or "fmt" or "vsprintf" or "String" or "Join" or "Concat" or "StringBuilder")
                    return true;
                break;
            case NodeKind.StringLiteral:
                return HasInterpolationHole(node.Text) && node.Tokens.Count > 0 && IsInterpolated(node.Tokens[0]);
        }
        return node.Children.Any(IsDynamicallyBuilt);
    }

    private static bool IsInterpolated(Token token) => true;

    private static bool HasInterpolationHole(string text)
    {
        for (var i = 0; i < text.Length - 1; i++)
        {
            if (text[i] == '{' && text[i + 1] != '{' && text.IndexOf('}', i) > i)
                return true;
            if (text[i] == '$' && text[i + 1] == '{')
                return true;
            if (text[i] == '#' && text[i + 1] == '{')
                return true;
        }
        return false;
    }

    /// <summary>Concatenated string value when every part is a literal, otherwise null.</summary>
    public static string? ConstantString(SyntaxNode? node)
    {
        if (node == null)
            return null;
        switch (node.Kind)
        {
            case NodeKind.StringLiteral:
                return node.Text;
            case NodeKind.Parenthesized:
                return ConstantString(node.ChildAt(0));
            case NodeKind.Binary when node.Text is "+" or ".":
                var left = ConstantString(node.ChildAt(0));
                var right = ConstantString(node.ChildAt(1));
                return left != null && right != null ? left + right : null;
            case NodeKind.Identifier when node.Symbol?.SafeStringValue() is { } value:
                return value;
            default:
                return null;
        }
    }

    /// <summary>Enclosing function of a node, or null at file scope.</summary>
    public static SyntaxNode? EnclosingFunction(SyntaxNode node)
        => node.Ancestor(NodeKind.FunctionDeclaration);

    public static SyntaxNode? EnclosingType(SyntaxNode node)
        => node.Ancestor(NodeKind.ClassDeclaration);

    public static IEnumerable<SyntaxNode> Functions(SyntaxNode root)
        => root.OfKind(NodeKind.FunctionDeclaration);

    public static IEnumerable<SyntaxNode> Parameters(SyntaxNode function)
        => function.FirstChild(NodeKind.ParameterList)?.ChildrenOf(NodeKind.Parameter) ?? [];

    public static SyntaxNode? Body(SyntaxNode declaration) => declaration.FirstChild(NodeKind.Block);

    /// <summary>Identifiers referenced anywhere inside the node.</summary>
    public static IEnumerable<SyntaxNode> Identifiers(SyntaxNode node)
        => node.DescendantsAndSelf().Where(n => n.Kind == NodeKind.Identifier);

    public static bool MentionsIdentifier(SyntaxNode node, string name)
        => Identifiers(node).Any(i => i.Text == name);

    /// <summary>Nesting depth of statements inside the closest function.</summary>
    public static int NestingDepth(SyntaxNode node)
    {
        var depth = 0;
        foreach (var ancestor in node.Ancestors())
        {
            if (ancestor.Kind is NodeKind.If or NodeKind.Loop or NodeKind.Match or NodeKind.Try or NodeKind.Catch)
                depth++;
            if (ancestor.Kind == NodeKind.FunctionDeclaration)
                break;
        }
        return depth;
    }
}
