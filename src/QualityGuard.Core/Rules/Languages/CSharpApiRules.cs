using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// C# rules about the shape of a type and the contract it offers: what a class exposes, what a
/// property is allowed to do, and the handful of expressions that compile cleanly and mean something
/// other than what they read as.
/// </summary>
public static class CSharpApiRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CSharpPublicFieldRule(),
        new CSharpUtilityClassConstructorRule(),
        new CSharpObsoleteWithoutReasonRule(),
        new CSharpRedundantToStringRule(),
        new CSharpTrivialPropertyRule(),
        // QG-CS-SML-0470 was "a public constant should be static readonly". It was measured on
        // this repository and reported 55 constants that are identifiers — metric keys, option
        // names — which will never change and for which const is the right choice. The premise did
        // not survive real code, so the rule is gone and its number stays retired.
        new CSharpWriteOnlyPropertyRule(),
        new CSharpRedundantConstructorRule(),
        new CSharpMethodReturningConstantRule(),
        new CSharpEmptyFinalizerRule(),
        new CSharpTypeOutsideNamespaceRule(),
        new CSharpNegatedComparisonRule(),
        new CSharpModulusEqualityRule(),
        new CSharpIndexOfPositiveRule(),
        new CSharpThrowFromGetterRule(),
        new CSharpProtectedInSealedRule(),
        new CSharpEmptyGuidRule(),
        new CSharpThrowFromUnexpectedMemberRule(),
        new CSharpParameterNamedLikeMethodRule()
    ];
}

public abstract class CSharpApiRuleBase : RuleBase
{
    public override string[] Languages => ["cs"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static HashSet<string> Modifiers(SyntaxNode declaration)
        => declaration.ChildrenOf(NodeKind.Modifier)
            .Select(m => m.Text.ToLowerInvariant())
            .ToHashSet(StringComparer.Ordinal);

    protected static bool IsPublic(SyntaxNode declaration)
    {
        var modifiers = Modifiers(declaration);
        return modifiers.Contains("public") || modifiers.Contains("protected");
    }

    protected static IEnumerable<SyntaxNode> Members(SyntaxNode type, NodeKind kind)
        => type.FirstChild(NodeKind.Block)?.ChildrenOf(kind) ?? [];

    protected static IEnumerable<SyntaxNode> AllMembers(SyntaxNode type)
        => type.FirstChild(NodeKind.Block)?.Children ?? [];

    /// <summary>The attributes written on a declaration, by simple name.</summary>
    protected static IEnumerable<SyntaxNode> Attributes(SyntaxNode declaration)
        => declaration.ChildrenOf(NodeKind.AttributeList).SelectMany(l => l.ChildrenOf(NodeKind.Attribute))
            .Concat(declaration.ChildrenOf(NodeKind.Attribute));
}

public sealed class CSharpPublicFieldRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-SML-0464";
    public override string Name => "A field should not be part of the public surface";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            foreach (var field in Members(type, NodeKind.FieldDeclaration))
            {
                var modifiers = Modifiers(field);
                if (!modifiers.Contains("public") && !modifiers.Contains("protected"))
                    continue;
                if (modifiers.Contains("const") || modifiers.Contains("readonly") || modifiers.Contains("static"))
                    continue;

                context.Report($"'{field.Text}' is written to and read from anywhere, with nothing in "
                               + "between: no validation, no notification, no way to make it computed "
                               + "later without breaking every caller. A property costs one line and "
                               + "keeps all three options open.", field.Range.StartLine);
            }
        }
    }
}

public sealed class CSharpUtilityClassConstructorRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-SML-0465";
    public override string Name => "A class of static members should not be instantiable";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var modifiers = Modifiers(type);
            if (modifiers.Contains("static") || modifiers.Contains("abstract"))
                continue;

            var members = AllMembers(type)
                .Where(m => m.Kind is NodeKind.FunctionDeclaration or NodeKind.FieldDeclaration
                    or NodeKind.PropertyDeclaration)
                .ToList();
            if (members.Count == 0 || members.Any(m => !Modifiers(m).Contains("static")))
                continue;

            var constructors = Members(type, NodeKind.ConstructorDeclaration).ToList();
            if (constructors.Count == 0)
            {
                context.Report($"Every member of '{type.Text}' is static, but the class still has the "
                               + "implicit public constructor, so nothing stops someone from creating "
                               + "an instance that can do nothing. Mark the class static.",
                    type.Range.StartLine);
                continue;
            }

            foreach (var constructor in constructors.Where(IsPublic))
            {
                context.Report($"Every member of '{type.Text}' is static, so an instance of it can do "
                               + "nothing at all — and this constructor invites one. Mark the class "
                               + "static, or make the constructor private.", constructor.Range.StartLine);
            }
        }
    }
}

public sealed class CSharpObsoleteWithoutReasonRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-SML-0467";
    public override string Name => "An obsolete member should say what to use instead";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var declaration in context.Root.OfKind(NodeKind.ClassDeclaration,
                     NodeKind.FunctionDeclaration, NodeKind.PropertyDeclaration, NodeKind.FieldDeclaration))
        {
            foreach (var attribute in Attributes(declaration))
            {
                var name = attribute.Text;
                if (name is not ("Obsolete" or "ObsoleteAttribute"))
                    continue;
                if (attribute.OfKind(NodeKind.StringLiteral).Any())
                    continue;

                context.Report("This member is marked obsolete without a word about what replaced it, so "
                               + "the warning tells a caller to stop and nothing more. Pass the message "
                               + "that names the alternative.", attribute.Range.StartLine);
            }
        }
    }
}

public sealed class CSharpRedundantToStringRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-SML-0468";
    public override string Name => "ToString should not be called on a string";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "ToString"))
        {
            if (SyntaxQuery.Arguments(call).Count > 0)
                continue; // ToString(format) is a different method
            var receiver = call.ChildAt(0)?.ChildAt(0);
            if (receiver is not { Kind: NodeKind.StringLiteral or NodeKind.InterpolatedString })
                continue;

            context.Report("The value is already a string, so the call returns the same object and only "
                           + "makes the reader look for a conversion that is not there.",
                call.Range.StartLine);
        }
    }
}

public sealed class CSharpTrivialPropertyRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-SML-0469";
    public override string Name => "A property that only wraps a field should be auto-implemented";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var property in context.Root.OfKind(NodeKind.PropertyDeclaration))
        {
            var accessors = property.OfKind(NodeKind.Accessor).ToList();
            if (accessors.Count != 2)
                continue;

            string? backing = null;
            var trivial = true;
            foreach (var accessor in accessors)
            {
                var field = BackingField(accessor);
                if (field == null || (backing != null && field != backing))
                {
                    trivial = false;
                    break;
                }
                backing = field;
            }
            if (!trivial || backing == null)
                continue;
            // The accessors have to reach a field of this type. 'get { return other.Value; }' with a
            // matching setter is a property that forwards to another object — there is no backing
            // field to remove, and on a real code base that was almost every report this rule made.
            var owner = property.Ancestor(NodeKind.ClassDeclaration);
            var declared = owner?.OfKind(NodeKind.FieldDeclaration)
                .Any(f => string.Equals(f.Text, backing, StringComparison.Ordinal)) ?? false;
            if (!declared)
                continue;

            context.Report($"Both accessors do nothing but reach '{backing}'. An auto-implemented "
                           + "property says the same thing in one line and removes the field that only "
                           + "exists to be wrapped.", property.Range.StartLine);
        }
    }

    /// <summary>The single field an accessor reads or writes, when that is all it does.</summary>
    private static string? BackingField(SyntaxNode accessor)
    {
        var body = accessor.FirstChild(NodeKind.Block);
        if (body is not { Children.Count: 1 })
            return null;
        var statement = body.Children[0];

        if (accessor.Text is "get" && statement is { Kind: NodeKind.Jump, Text: "return" })
            return PlainField(statement.ChildAt(0));

        if (accessor.Text is not "set")
            return null;
        var assignment = statement.Kind == NodeKind.ExpressionStatement ? statement.ChildAt(0) : statement;
        if (assignment is not { Kind: NodeKind.Assignment } || assignment.Text != "=")
            return null;
        if (SyntaxQuery.SimpleName(assignment.ChildAt(1)) != "value")
            return null;
        return PlainField(assignment.ChildAt(0));
    }

    /// <summary>
    /// The name when it is a field of this object — 'value' or 'this.value' — and nothing when it
    /// reaches through something else, because then the accessor is forwarding rather than wrapping.
    /// </summary>
    private static string? PlainField(SyntaxNode? node)
    {
        if (node == null)
            return null;
        if (node.Kind == NodeKind.Identifier)
            return node.Text.Length > 0 ? node.Text : null;
        if (node.Kind != NodeKind.MemberSelect
            || node.ChildAt(0) is not { Kind: NodeKind.Identifier, Text: "this" })
            return null;
        return SyntaxQuery.SimpleName(node) is { Length: > 0 } name ? name : null;
    }
}

public sealed class CSharpWriteOnlyPropertyRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-SML-0471";
    public override string Name => "A property should not be write-only";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var property in context.Root.OfKind(NodeKind.PropertyDeclaration))
        {
            var accessors = property.OfKind(NodeKind.Accessor).ToList();
            if (accessors.Count == 0 || accessors.Any(a => a.Text is "get"))
                continue;
            if (!accessors.Any(a => a.Text is "set" or "init"))
                continue;

            context.Report($"'{property.Text}' can be set and never read, so the caller has no way to "
                           + "check what it did or to restore it later. A method named for the effect "
                           + "says what is happening; a property that only goes one way does not.",
                property.Range.StartLine);
        }
    }
}

public sealed class CSharpRedundantConstructorRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-SML-0472";
    public override string Name => "An empty public constructor should be removed";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var constructors = Members(type, NodeKind.ConstructorDeclaration).ToList();
            if (constructors.Count != 1)
                continue; // with an overload, the parameterless one is a real choice

            var constructor = constructors[0];
            if (!Modifiers(constructor).Contains("public"))
                continue;
            if (SyntaxQuery.Parameters(constructor).Any())
                continue;
            if (constructor.FirstChild(NodeKind.Block) is not { Children.Count: 0 })
                continue;
            // a base or this call makes the constructor do something even with an empty body
            if (constructor.Children.Any(c => c.Kind == NodeKind.Invocation))
                continue;

            context.Report($"'{type.Text}' declares the constructor the compiler would have generated "
                           + "anyway. It adds a line to read and a place for someone to add behaviour "
                           + "nobody expects to find.", constructor.Range.StartLine);
        }
    }
}

public sealed class CSharpMethodReturningConstantRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-SML-0473";
    public override string Name => "A method that always returns the same value should be a constant";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var modifiers = Modifiers(method);
            if (modifiers.Contains("virtual") || modifiers.Contains("override") || modifiers.Contains("abstract"))
                continue;
            if (SyntaxQuery.Parameters(method).Any())
                continue;
            var body = SyntaxQuery.Body(method);
            if (body is not { Children.Count: 1 })
                continue;

            var statement = body.Children[0];
            if (statement is not { Kind: NodeKind.Jump, Text: "return" } || statement.Children.Count != 1)
                continue;
            var value = statement.Children[0];
            if (value.Kind is not (NodeKind.NumberLiteral or NodeKind.StringLiteral or NodeKind.BooleanLiteral))
                continue;

            context.Report($"'{method.Text}' takes nothing and always answers '{value.Text}'. A constant "
                           + "says that plainly; a method suggests the answer depends on something.",
                method.Range.StartLine);
        }
    }
}

public sealed class CSharpEmptyFinalizerRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-SML-0474";
    public override string Name => "An empty finalizer should be removed";
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            foreach (var member in AllMembers(type))
            {
                if (member.Kind is not (NodeKind.ConstructorDeclaration or NodeKind.FunctionDeclaration)
                    || member.Text != "~" + type.Text)
                    continue;
                if (member.FirstChild(NodeKind.Block) is not { Children.Count: 0 })
                    continue;

                context.Report("An empty finalizer does nothing except put every instance of this class "
                               + "on the finalization queue: each one survives an extra collection and "
                               + "is then processed by a separate thread, for no result at all.",
                    member.Range.StartLine);
            }
        }
    }
}

public sealed class CSharpTypeOutsideNamespaceRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-SML-0475";
    public override string Name => "A type should live in a namespace";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        if (context.Root.OfKind(NodeKind.PackageDeclaration).Any())
            return;
        // a file of top-level statements has no namespace and needs none
        if (context.Root.ChildrenOf(NodeKind.ExpressionStatement).Any())
            return;

        foreach (var type in context.Root.ChildrenOf(NodeKind.ClassDeclaration))
        {
            context.Report($"'{type.Text}' sits in the global namespace, where its name has to be unique "
                           + "across every assembly the project ever references — and where nothing "
                           + "says which part of the system it belongs to.", type.Range.StartLine);
        }
    }
}

public sealed class CSharpNegatedComparisonRule : CSharpApiRuleBase
{
    private static readonly Dictionary<string, string> Opposite = new(StringComparer.Ordinal)
    {
        ["=="] = "!=",
        ["!="] = "==",
        ["<"] = ">=",
        [">"] = "<=",
        ["<="] = ">",
        [">="] = "<"
    };

    public override string Key => "QG-CS-SML-0476";
    public override string Name => "A comparison should not be negated";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var negation in context.Root.OfKind(NodeKind.Unary))
        {
            if (negation.Text != "!")
                continue;
            var operand = negation.ChildAt(0);
            if (operand is { Kind: NodeKind.Parenthesized })
                operand = operand.ChildAt(0);
            if (operand is not { Kind: NodeKind.Binary })
                continue;
            if (!Opposite.TryGetValue(operand.Text, out var opposite))
                continue;

            context.Report($"Negating '{operand.Text}' says the same thing as '{opposite}' with one more "
                           + "step for the reader to undo.", negation.Range.StartLine);
        }
    }
}

public sealed class CSharpModulusEqualityRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-BUG-0141";
    public override string Name => "A remainder should not be compared to a positive value";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!="))
                continue;
            var remainder = comparison.Children.FirstOrDefault(c => c is { Kind: NodeKind.Binary, Text: "%" });
            var literal = comparison.Children.FirstOrDefault(c => c.Kind == NodeKind.NumberLiteral);
            if (remainder == null || literal == null)
                continue;
            if (literal.Text is "0" || literal.Text.StartsWith('-'))
                continue;

            context.Report($"A remainder keeps the sign of the left operand, so this is false for every "
                           + $"negative value — '-3 % 2' is -1, not {literal.Text}. Compare against zero, "
                           + "or take the absolute value first.", comparison.Range.StartLine);
        }
    }
}

public sealed class CSharpIndexOfPositiveRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-BUG-0142";
    public override string Name => "A search result should be tested against zero";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not (">" or "<="))
                continue;
            var call = comparison.ChildAt(0);
            if (call is not { Kind: NodeKind.Invocation })
                continue;
            var name = SyntaxQuery.InvokedName(call);
            if (name is not ("IndexOf" or "LastIndexOf" or "IndexOfAny" or "FindIndex" or "FindLastIndex"))
                continue;
            var literal = comparison.ChildAt(1);
            if (literal is not { Kind: NodeKind.NumberLiteral } || literal.Text != "0")
                continue;

            var replacement = comparison.Text == ">" ? ">= 0" : "< 0";
            context.Report($"'{name}' answers 0 when the match is at the very beginning, and this "
                           + $"comparison treats that as 'not found'. Use {replacement}.",
                comparison.Range.StartLine);
        }
    }
}

public sealed class CSharpThrowFromGetterRule : CSharpApiRuleBase
{
    private static readonly string[] Acceptable =
        ["InvalidOperationException", "NotSupportedException", "ObjectDisposedException",
         "PlatformNotSupportedException", "NotImplementedException", "KeyNotFoundException"];

    public override string Key => "QG-CS-BUG-0143";
    public override string Name => "A property getter should not throw";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var property in context.Root.OfKind(NodeKind.PropertyDeclaration))
        {
            foreach (var accessor in property.OfKind(NodeKind.Accessor))
            {
                if (accessor.Text != "get")
                    continue;
                var body = accessor.FirstChild(NodeKind.Block);
                if (body == null)
                    continue;

                foreach (var jump in body.OfKind(NodeKind.Jump))
                {
                    if (jump.Text != "throw" || jump.Children.Count == 0)
                        continue;
                    var thrown = SyntaxQuery.SimpleName(jump.Children[0].ChildAt(0));
                    if (thrown.Length == 0)
                        thrown = jump.Children[0].Text;
                    if (Acceptable.Contains(thrown))
                        continue;

                    context.Report($"Reading '{property.Text}' looks like reading a value, so nobody "
                                   + "wraps it in a try — not the debugger that shows it, not the "
                                   + $"serializer that walks the object. Throwing '{thrown}' from here "
                                   + "breaks all of them. Return a value, or make this a method.",
                        jump.Range.StartLine);
                }
            }
        }
    }
}

public sealed class CSharpProtectedInSealedRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-BUG-0144";
    public override string Name => "A sealed class should not declare protected members";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!Modifiers(type).Contains("sealed"))
                continue;

            foreach (var member in AllMembers(type))
            {
                var modifiers = Modifiers(member);
                if (!modifiers.Contains("protected") || modifiers.Contains("override"))
                    continue;

                context.Report($"Nothing can inherit from '{type.Text}', so protected means private "
                               + "here — with a keyword that promises an extension point that cannot "
                               + "exist. Say private.", member.Range.StartLine);
            }
        }
    }
}

public sealed class CSharpEmptyGuidRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-BUG-0145";
    public override string Name => "A new Guid is always the empty one";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            var type = SyntaxQuery.SimpleName(creation.ChildAt(0)) is { Length: > 0 } named
                ? named
                : creation.Text;
            if (type is not ("Guid" or "System.Guid"))
                continue;
            if (creation.OfKind(NodeKind.ArgumentList).FirstOrDefault()?.Children.Count > 0)
                continue;

            context.Report("'new Guid()' does not generate anything: it produces the all-zero value, "
                           + "the same one every time. Use Guid.NewGuid() to create an identifier, or "
                           + "Guid.Empty when the empty value is what you mean.", creation.Range.StartLine);
        }
    }
}

public sealed class CSharpThrowFromUnexpectedMemberRule : CSharpApiRuleBase
{
    private static readonly string[] MustNotThrow =
        ["ToString", "Equals", "GetHashCode", "Dispose", "DisposeAsync"];

    public override string Key => "QG-CS-BUG-0146";
    public override string Name => "Some members should never throw";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!MustNotThrow.Contains(method.Text))
                continue;
            var body = SyntaxQuery.Body(method);
            if (body == null)
                continue;

            foreach (var jump in body.OfKind(NodeKind.Jump))
            {
                if (jump.Text != "throw" || jump.Children.Count == 0)
                    continue;
                var thrown = SyntaxQuery.SimpleName(jump.Children[0].ChildAt(0));
                if (thrown.Length == 0)
                    thrown = jump.Children[0].Text;
                if (thrown is "NotImplementedException" or "NotSupportedException")
                    continue; // a member that is deliberately not available says so this way
                if (SyntaxQuery.EnclosingFunction(jump) != method)
                    continue;

                context.Report($"'{method.Text}' is called by the runtime and by every tool that "
                               + "inspects an object — a debugger window, a log line, a collection "
                               + "lookup, the end of a using block. None of them expects an exception, "
                               + "and Dispose throwing during unwinding replaces the original failure "
                               + "with this one.", jump.Range.StartLine);
            }
        }
    }
}

public sealed class CSharpParameterNamedLikeMethodRule : CSharpApiRuleBase
{
    public override string Key => "QG-CS-CNV-0009";
    public override string Name => "A parameter should not repeat the name of its method";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (method.Text.Length == 0)
                continue;

            foreach (var parameter in SyntaxQuery.Parameters(method))
            {
                var name = ParameterName(parameter);
                if (!string.Equals(name, method.Text, StringComparison.OrdinalIgnoreCase))
                    continue;

                context.Report($"The parameter and the method are both called '{method.Text}', so a "
                               + "reader inside the body cannot tell which one a mention refers to "
                               + "without checking the signature. Name the parameter for the value it "
                               + "carries.", method.Range.StartLine);
            }
        }
    }

    private static string ParameterName(SyntaxNode parameter)
    {
        var identifier = parameter.OfKind(NodeKind.Identifier).LastOrDefault();
        return identifier?.Text ?? parameter.Text;
    }
}
