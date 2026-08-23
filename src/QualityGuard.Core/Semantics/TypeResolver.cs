using QualityGuard.Core.Analysis;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Semantics;

/// <summary>
/// Best-effort type of an expression. It combines what the file knows (declarations, literals, object
/// creations) with what the project index knows (member and return types of the types declared in the
/// scanned code). Unknown stays unknown: rules must treat <c>null</c> as "cannot tell" and stay silent
/// rather than guess.
/// </summary>
public sealed class TypeResolver
{
    private readonly SemanticModel _semantics;
    private readonly ProjectIndex _project;

    public TypeResolver(SemanticModel semantics, ProjectIndex project)
    {
        _semantics = semantics;
        _project = project;
    }

    /// <summary>How far the resolver follows one expression into another before giving up.</summary>
    private const int MaxDepth = 8;

    public string? TypeOf(SyntaxNode? expression, int depth = 0)
    {
        if (expression == null || depth > MaxDepth)
            return null;

        switch (expression.Kind)
        {
            // a literal of one character is a char in the languages that have the type and a string
            // in the ones that do not, and the tree does not record which quote wrote it. Answering
            // "string" made every 'c == 'Z'' a comparison between unrelated types.
            case NodeKind.StringLiteral:
                return expression.Text.Length == 1 ? null : "string";
            case NodeKind.InterpolatedString:
                return "string";
            case NodeKind.NumberLiteral:
                return expression.Text.Contains('.') ? "double" : "int";
            case NodeKind.BooleanLiteral:
                return "bool";
            case NodeKind.NullLiteral:
                return null;
            case NodeKind.ListLiteral:
                return "collection";
            case NodeKind.Tuple:
                return "tuple";
            case NodeKind.Lambda:
                return "lambda";
            case NodeKind.ObjectCreation:
            case NodeKind.ArrayCreation:
                return Normalize(expression.Text);
            case NodeKind.Cast:
                return Normalize(expression.Text);
            case NodeKind.Parenthesized:
                return TypeOf(expression.ChildAt(0), depth + 1);
            case NodeKind.Identifier:
                return TypeOfIdentifier(expression, depth);
            case NodeKind.MemberSelect:
                return TypeOfMember(expression, depth);
            case NodeKind.Invocation:
                return TypeOfInvocation(expression, depth);
            case NodeKind.Binary when expression.Text is "+":
                return TypeOf(expression.ChildAt(0), depth + 1) ?? TypeOf(expression.ChildAt(1), depth + 1);
            case NodeKind.Binary when expression.Text is "+" or "-" or "*" or "/" or "%":
                {
                    // arithmetic on two known numeric types produces the wider of the two
                    var leftType = TypeOf(expression.ChildAt(0), depth + 1);
                    var rightType = TypeOf(expression.ChildAt(1), depth + 1);
                    if (leftType != null && rightType != null)
                        return Wider(leftType, rightType) ?? leftType;
                    return leftType ?? rightType;
                }
            case NodeKind.Binary:
                return expression.Text is "==" or "!=" or "<" or ">" or "<=" or ">=" or "&&" or "||"
                    ? "bool"
                    : TypeOf(expression.ChildAt(0), depth + 1);
            default:
                return null;
        }
    }

    private string? TypeOfIdentifier(SyntaxNode identifier, int depth = 0)
    {
        var symbol = _semantics.Resolve(identifier);
        if (symbol?.DeclaredType is { Length: > 0 } declared)
            return Normalize(declared);
        // `var` keeps no type of its own: take it from the expression the variable was assigned,
        // but only when that assignment is the single one, so the answer cannot depend on the path
        if (symbol?.SafeValue() is { } value && depth < MaxDepth)
            return TypeOf(value, depth + 1);
        // a bare name may also be a type used statically
        return _project.FindType(identifier.Text) != null ? Normalize(identifier.Text) : null;
    }

    private string? TypeOfMember(SyntaxNode member, int depth)
    {
        var owner = TypeOf(member.ChildAt(0), depth + 1);
        var name = member.ChildAt(1)?.Text;
        if (owner == null || string.IsNullOrEmpty(name))
            return null;
        return _project.MemberType(owner, name) is { Length: > 0 } type ? Normalize(type) : null;
    }

    private string? TypeOfInvocation(SyntaxNode invocation, int depth)
    {
        var callee = invocation.ChildAt(0);
        if (callee is { Kind: NodeKind.MemberSelect })
        {
            var owner = TypeOf(callee.ChildAt(0), depth + 1);
            var name = callee.ChildAt(1)?.Text;
            if (owner != null && !string.IsNullOrEmpty(name)
                && _project.MemberType(owner, name) is { Length: > 0 } type)
                return Normalize(type);
        }

        var simple = SyntaxQuery.InvokedName(invocation);
        return _project.ReturnType(simple) is { Length: > 0 } returned ? Normalize(returned) : null;
    }

    /// <summary>Strips the decorations that do not change which type is being talked about.</summary>
    public static string Normalize(string type)
    {
        var text = type.Trim();
        var generic = text.IndexOf('<');
        if (generic > 0)
            text = text[..generic];
        text = text.TrimEnd('?', '*', '[', ']', ' ');
        var dot = text.LastIndexOf('.');
        return dot >= 0 && dot < text.Length - 1 ? text[(dot + 1)..] : text;
    }

    private static readonly string[] Width =
        ["sbyte", "byte", "short", "ushort", "int", "uint", "long", "ulong", "float", "double", "decimal"];

    /// <summary>The wider of two numeric types, or null when either is not numeric.</summary>
    private static string? Wider(string a, string b)
    {
        var ia = Array.IndexOf(Width, Normalize(a));
        var ib = Array.IndexOf(Width, Normalize(b));
        if (ia < 0 || ib < 0) return null;
        return Width[Math.Max(ia, ib)];
    }

    private static readonly string[] Primitives =
    [
        "int", "long", "short", "byte", "sbyte", "uint", "ulong", "ushort", "float", "double", "decimal",
        "bool", "char", "string", "str", "object", "number", "boolean", "String", "Integer", "Boolean",
        "Double", "Float", "Long", "Short", "Byte", "Character", "BigDecimal", "BigInteger"
    ];

    /// <summary>
    /// True when the name really is a type: a primitive, or a type declared in the scanned code.
    /// Rules that compare two types must ask this first — a name that came out of an expression the
    /// resolver could not follow is a guess, and acting on a guess is how a checker earns its
    /// reputation for crying wolf.
    /// </summary>
    public bool IsKnownType(string? type)
        => type is { Length: > 0 }
           && (Primitives.Contains(type, StringComparer.Ordinal) || _project.FindType(type) != null);

    /// <summary>True when the type, or one of its ancestors in the scanned code, has that name.</summary>
    public bool IsOrDerivesFrom(string? type, params string[] names)
    {
        if (type == null)
            return false;
        if (names.Contains(type, StringComparer.Ordinal))
            return true;
        var info = _project.FindType(type);
        var guard = 0;
        while (info != null && guard++ < 10)
        {
            if (info.BaseNames.Any(b => names.Contains(Normalize(b), StringComparer.Ordinal)))
                return true;
            info = info.BaseNames.Select(b => _project.FindType(Normalize(b))).FirstOrDefault(t => t != null);
        }
        return false;
    }
}
