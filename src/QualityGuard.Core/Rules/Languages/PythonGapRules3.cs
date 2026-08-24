using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Third tranche of Python default-profile checks. These read format strings, loop variable
/// scoping and implicit concatenation on tokens and literals.
/// </summary>
public static class PythonGapRuleSet3
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PyImplicitStringConcatenationRule(),
        new PyLoopVariableCaptureRule(),
        new PyAssertInExceptLastRule(),
    ];
}

internal static class PyGap3Helper
{
    internal static int CountFormatSpecs(string s)
    {
        var count = 0;
        for (var i = 0; i < s.Length - 1; i++)
        {
            if (s[i] == '{' && s[i + 1] != '{')
            {
                count++;
                var close = s.IndexOf('}', i);
                if (close > i) i = close;
                else i++;
            }
        }
        return count;
    }
}



public sealed class PyImplicitStringConcatenationRule : RuleBase
{
    public override string Key => "QG-PY-SML-0087";
    public override string Name => "Implicitly concatenated string literals on separate lines";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        // implicit concatenation lives INSIDE one expression: two string-literal siblings with no
        // other element between them, written on different lines. Two strings on adjacent lines of
        // different expressions - separate calls, dictionary entries, asserts - are ordinary code,
        // and reading the file as a token stream reported hundreds of those.
        foreach (var node in context.Root.OfKind(
                     NodeKind.Parenthesized, NodeKind.ListLiteral, NodeKind.ObjectInitializer,
                     NodeKind.Assignment))
        {
            var children = node.Children;
            for (var i = 0; i + 1 < children.Count; i++)
            {
                if (children[i].Kind != NodeKind.StringLiteral
                    || children[i + 1].Kind != NodeKind.StringLiteral)
                    continue;
                if (children[i + 1].Line == children[i].Line)
                    continue;
                // a comma, colon or operator between the siblings means separate elements -
                // dictionary entries, list items - and only bare adjacency glues the strings
                var separators = TokensBetween(node, children[i], children[i + 1]);
                if (separators.Any(t => t.Text is "," or ":" or "+" or ")" or "]" or "}"))
                    continue;
                context.Report(children[i + 1],
                    "These two literals sit side by side inside one expression on different "
                    + "lines, so Python glues them into a single string silently. If that is the "
                    + "intent it reads better on one line or joined with +; if it is not, a "
                    + "missing comma just merged two values.");
            }
        }
    }

    /// <summary>
    /// The punctuation that lives between two sibling nodes - separators are tokens of the parent,
    /// not nodes, so the tree alone cannot tell a glued pair from two list items.
    /// </summary>
    private static IReadOnlyList<Token> TokensBetween(SyntaxNode parent, SyntaxNode first, SyntaxNode second)
    {
        var start = first.Tokens.Count > 0 ? first.Tokens[^1] : null;
        var end = second.Tokens.Count > 0 ? second.Tokens[0] : null;
        if (start == null || end == null)
            return [];
        return parent.Tokens
            .SkipWhile(t => !ReferenceEquals(t, start))
            .Skip(1)
            .TakeWhile(t => !ReferenceEquals(t, end))
            .Where(t => t.Kind != TokenKind.Comment)
            .ToList();
    }
}

public sealed class PyLoopVariableCaptureRule : RuleBase
{
    public override string Key => "QG-PY-SML-0041";
    public override string Name => "Lambdas should not capture the loop variable directly";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            // extract the loop variable name from the header tokens between 'for' and 'in'
            var headerTokens = loop.Tokens.TakeWhile(t => t.Text != "in").ToList();
            var forIdx = headerTokens.FindIndex(t => t.Text == "for");
            if (forIdx < 0 || forIdx + 1 >= headerTokens.Count) continue;
            var varName = headerTokens[forIdx + 1].Text;
            if (varName.Length == 0 || !char.IsLetter(varName[0])) continue;

            // find lambdas inside the loop body that reference this variable
            foreach (var lambda in loop.OfKind(NodeKind.Lambda))
            {
                var captures = lambda.OfKind(NodeKind.Identifier)
                    .Any(id => id.Text == varName && id.Line >= lambda.Range.StartLine);
                if (!captures) continue;
                context.Report(lambda, $"The lambda captures '{varName}', which changes on every "
                                              + "iteration: all closures will see the final value. Bind "
                                              + $"it with a default parameter ({varName}={varName}).");
                break;
            }
        }
    }
}

public sealed class PyAssertInExceptLastRule : RuleBase
{
    public override string Key => "QG-PY-BUG-0099";
    public override string Name => "An assert as last statement of an except hides the error";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var catchClause in context.Root.OfKind(NodeKind.Catch))
        {
            var body = catchClause.Children.Where(c =>
                c.Kind is NodeKind.ExpressionStatement or NodeKind.Jump).ToList();
            if (body.Count == 0) continue;
            var last = body[^1];
            if (last.ChildAt(0)?.Text == "assert")
                context.Report(last, "The handler ends on an assert: under python -O the whole block "
                                            + "becomes a no-op and the error vanishes silently. Raise "
                                            + "instead.");
        }
    }
}
