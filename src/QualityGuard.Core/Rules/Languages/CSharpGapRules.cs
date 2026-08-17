using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// C# rules written to close a measured gap: each one was found by running the reference analyzer and
/// this engine over the same production projects and reading what only the other one reported.
/// </summary>
public static class CSharpGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CsTypeNameCasingRule(),
        new CsDefaultGuidRule(),
        new CsPrivateTypeSealedRule(),
        new CsEmptyDerivedTypeRule(),
        new CsIndexInsteadOfFirstRule(),
        new CsOverloadsTogetherRule()
    ];
}

public abstract class CSharpGapRuleBase : RuleBase
{
    public override string[] Languages => ["cs"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;
}

public sealed class CsTypeNameCasingRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-CNV-0010";
    public override string Name => "A type name should be written in Pascal case";
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var name = type.Text;
            if (name.Length < 2 || !char.IsAsciiLetter(name[0]))
                continue;

            var offender = Offence(name);
            if (offender == null)
                continue;

            context.Report(type, $"'{name}' {offender}. A reader picks type names apart by their "
                                 + "capitals, and a run of them reads as one word.");
        }
    }

    /// <summary>
    /// What is wrong with the name, or null when nothing is. Two capitals in a row are allowed at
    /// the end of a two-letter acronym — 'IO', 'Id' — but a longer run hides where a word begins.
    /// </summary>
    private static string? Offence(string name)
    {
        if (char.IsLower(name[0]))
            return "starts with a lower-case letter";
        if (name.Contains('_'))
            return "separates its words with underscores";

        var run = 0;
        foreach (var c in name)
        {
            if (char.IsUpper(c))
            {
                if (++run > 2)
                    return "runs three capitals together";
            }
            else
            {
                run = 0;
            }
        }
        return null;
    }
}

public sealed class CsDefaultGuidRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0478";
    public override string Name => "The empty identifier should be named";
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            var type = SyntaxQuery.SimpleName(creation.ChildAt(0));
            if (type.Length == 0)
                type = creation.Text;
            if (type != "Guid")
                continue;

            var arguments = SyntaxQuery.Arguments(creation);
            var empty = arguments.Count == 0
                        || (arguments.Count == 1 && arguments[0] is { Kind: NodeKind.StringLiteral } literal
                            && literal.Text.All(c => c is '0' or '-'));
            if (!empty)
                continue;

            context.Report(creation, "This builds the identifier that means 'none', spelled out. "
                                     + "'Guid.Empty' says it in a word, and a reader does not have to "
                                     + "count the zeroes to be sure.");
        }
    }
}

public sealed class CsPrivateTypeSealedRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0479";
    public override string Name => "A type nobody can inherit should say so";
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var modifiers = type.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (!modifiers.Contains("private"))
                continue;
            if (modifiers.Contains("sealed") || modifiers.Contains("abstract")
                || modifiers.Contains("static") || modifiers.Contains("record"))
                continue;
            // only a class can be sealed, and a nested private one is reachable from its owner alone
            if (type.Ancestor(NodeKind.ClassDeclaration) == null)
                continue;

            context.Report(type, $"'{type.Text}' is private, so nothing outside this type can derive "
                                 + "from it. Sealing it says that, and lets the runtime call its "
                                 + "methods without looking them up.");
        }
    }
}

public sealed class CsEmptyDerivedTypeRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0480";
    public override string Name => "A type that adds nothing should not exist";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body is not { Children.Count: 0 })
                continue;
            // a type with no base declares something new by existing; one that derives adds nothing
            if (!DerivesFromSomething(type, context))
                continue;
            if (type.ChildrenOf(NodeKind.Attribute).Any())
                continue; // an attribute can be the whole point of the type

            context.Report(type, $"'{type.Text}' inherits everything and adds nothing, so every use "
                                 + "of it could name the base instead. Either give it the difference "
                                 + "it was created for, or remove it.");
        }
    }

    private static bool DerivesFromSomething(SyntaxNode type, IRuleContext context)
    {
        var info = context.Project.FindTypes(type.Text).FirstOrDefault(t => t.Node == type);
        return info is { BaseNames.Count: > 0 };
    }
}

public sealed class CsIndexInsteadOfFirstRule : CSharpGapRuleBase
{
    private static readonly string[] Indexable = ["List", "IList", "Array", "Collection", "IReadOnlyList"];

    public override string Key => "QG-CS-SML-0481";
    public override string Name => "An indexed collection should be read by index";
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "First", "Last"))
        {
            if (SyntaxQuery.Arguments(call).Count != 0)
                continue;

            var receiver = call.ChildAt(0);
            var target = receiver is { Kind: NodeKind.MemberSelect } ? receiver.ChildAt(0) : receiver;
            var type = context.Types.TypeOf(target);
            if (type is not { Length: > 0 })
                continue;
            var bare = type.Split('<')[0].Split('.').Last().TrimEnd('[', ']');
            if (!Indexable.Contains(bare, StringComparer.Ordinal))
                continue;

            var name = SyntaxQuery.InvokedName(call);
            context.Report(call, $"'{bare}' is indexed, so '{name}()' sets up an enumerator to reach "
                                 + $"something the collection can hand over directly. Use "
                                 + (name == "First" ? "'[0]'." : "'[^1]'."));
        }
    }
}

public sealed class CsOverloadsTogetherRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0482";
    public override string Name => "Overloads of one method should be written together";
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            var methods = body.ChildrenOf(NodeKind.FunctionDeclaration)
                .Where(m => m.Text.Length > 0)
                .ToList();
            // an interface declares its overloads the same way, and the same reading cost applies
            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            for (var i = 0; i < methods.Count; i++)
            {
                var name = methods[i].Text;
                if (!seen.TryGetValue(name, out var previous))
                {
                    seen[name] = i;
                    continue;
                }
                if (previous == i - 1)
                {
                    seen[name] = i;
                    continue;
                }

                context.Report(methods[i], $"'{name}' has another overload {i - previous} members "
                                           + "further up. A reader comparing them has to scroll "
                                           + "between the two, and a change to one is easy to miss "
                                           + "on the other. Put them next to each other.");
                seen[name] = i;
            }
        }
    }
}
