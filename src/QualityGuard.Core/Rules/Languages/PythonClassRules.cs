using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// What a class declaration says about itself, and where it contradicts itself. Each of these
/// reports a statement that the language accepts and then quietly discards, so the file reads as
/// though something is there that is not.
/// </summary>
public static class PythonClassRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PythonDuplicateBaseRule(),
        new PythonFieldDefinedTwiceRule(),
        new PythonStaticDictionaryKeyRule()
    ];
}

public abstract class PythonClassRuleBase : RuleBase
{
    public override string[] Languages => ["py"];
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "5min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;
}

public sealed class PythonDuplicateBaseRule : PythonClassRuleBase
{
    public override string Key => "QG-PY-BUG-0251";
    public override string Name => "A class should not list the same base twice";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var name in Bases(type))
            {
                if (seen.Add(name))
                    continue;
                context.Report(type, $"'{name}' is named twice in the base list. Python resolves the "
                                     + "order once and keeps the first, so the second says nothing — "
                                     + "and the name that was meant to be there is missing.");
            }
        }
    }

    /// <summary>The names between the parentheses of the declaration, in order.</summary>
    private static IEnumerable<string> Bases(SyntaxNode type)
    {
        var open = false;
        foreach (var token in type.Tokens)
        {
            if (token.Text == "(")
            {
                open = true;
                continue;
            }
            if (token.Text is ")" or ":")
                yield break;
            if (open && token.Kind == Tokenization.TokenKind.Identifier)
                yield return token.Text;
        }
    }
}

public sealed class PythonFieldDefinedTwiceRule : PythonClassRuleBase
{
    public override string Key => "QG-PY-BUG-0252";
    public override string Name => "A class should not define the same field twice";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var field in body.ChildrenOf(NodeKind.VariableDeclaration))
            {
                var name = field.Text;
                if (name.Length == 0)
                    continue;
                // only a plain assignment defines the field; an augmented one updates what is there
                if (field.FirstChild(NodeKind.Assignment) is not { Text: "=" })
                    continue;
                if (seen.TryGetValue(name, out var first))
                {
                    context.Report(field, $"'{name}' is given a value here and on line {first}. The "
                                          + "class keeps the last one, so the first is dead — and if "
                                          + "the two were meant to be different fields, one is now "
                                          + "missing.");
                    continue;
                }
                seen[name] = field.Line;
            }
        }
    }
}

public sealed class PythonStaticDictionaryKeyRule : PythonClassRuleBase
{
    public override string Key => "QG-PY-SML-0414";
    public override string Name => "A dictionary comprehension should vary its key";
    public override IssueKind Kind => IssueKind.CodeSmell;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        // A comprehension that never changes the key writes every entry over the last one, so the
        // whole loop leaves a dictionary with one item in it. The reader sees a loop and expects
        // many.
        foreach (var literal in context.Root.OfKind(NodeKind.ObjectInitializer, NodeKind.ListLiteral))
        {
            var tokens = literal.Tokens;
            if (tokens.Count < 5 || tokens[0].Text != "{")
                continue;
            // '{"k": v for v in items}' — the key sits between the brace and the first colon, and
            // 'for' further along is what makes it a comprehension rather than a literal
            if (tokens[2].Text != ":" || !tokens.Any(t => t.Text == "for"))
                continue;
            if (tokens[1].Kind is not (Tokenization.TokenKind.String or Tokenization.TokenKind.Number))
                continue;

            context.Report(literal, $"The key is always {tokens[1].Text}, so every turn of the loop "
                                    + "replaces the entry the last one made and the result holds a "
                                    + "single item. Derive the key from what is being iterated.");
        }
    }
}
