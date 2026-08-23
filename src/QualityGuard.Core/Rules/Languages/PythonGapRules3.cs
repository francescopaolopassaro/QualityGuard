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
        var strings = context.Tokens.Where(t =>
            t.Kind == TokenKind.String && t.Text.Length > 1).ToList();
        for (var i = 0; i + 1 < strings.Count; i++)
        {
            if (strings[i + 1].Line == strings[i].Line) continue;
            if (strings[i + 1].Line - strings[i].Line > 1) continue;
            // two string literals on adjacent lines with no code between them = implicit concat
            var between = context.Tokens.Where(t =>
                t.Line > strings[i].Line && t.Line < strings[i + 1].Line).ToList();
            if (between.Count > 0) continue;
            context.Report("These two string literals are implicitly concatenated because they sit "
                                  + "on adjacent lines with nothing between them. If the join was not "
                                  + "intentional, add an explicit operator or a comma.",
                strings[i + 1].Line);
        }
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
