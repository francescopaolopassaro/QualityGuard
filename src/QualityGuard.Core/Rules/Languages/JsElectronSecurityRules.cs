using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Electron and desktop-shell rules: the switches that trade the browser sandbox for convenience,
/// written once in a config object and forgotten until the first hostile page loads.
/// </summary>
public static class JsElectronSecurityRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JsWebSecurityDisabledRule(),
    ];
}

public sealed class JsWebSecurityDisabledRule : RuleBase
{
    public override string Key => "QG-JS-SEC-0118";
    public override string Name => "webSecurity should stay enabled";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;
        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            var target = assignment.ChildAt(0);
            var value = assignment.ChildAt(1);
            var isFalseLiteral = value is { Kind: NodeKind.BooleanLiteral, Text: "false" };
            var name = target?.Kind == NodeKind.Identifier ? target.Text : null;
            if (name != "webSecurity" && (target?.Kind != NodeKind.MemberSelect
                    || target.ChildAt(1)?.Text != "webSecurity"))
                continue;
            if (!isFalseLiteral)
                continue;
            context.Report(assignment,
                "webSecurity: false switches off same-origin policy and sandbox protections for "
                + "everything this window renders. One remote page - one ad, one iframe, one "
                + "dependency gone wrong - then reads local files and calls shell APIs. Keep it "
                + "enabled and solve the actual cross-origin need with an explicit bridge or a "
                + "proxy you control.");
        }
    }
}
