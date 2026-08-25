using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// JavaScript and TypeScript rules on the APIs the language has outgrown: index arithmetic that
/// .at() spells directly, findIndex doing indexOf's job, Date objects built only to be read once,
/// and a reduce that throws on the empty array nobody tested.
/// </summary>
public static class JsModernApiRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JsReduceWithoutInitialValueRule(),
        new JsFindIndexAsIndexOfRule(),
        new JsIndexArithmeticToAtRule(),
        new JsDateObjectForTimestampRule(),
        new JsRemoveChildToRemoveRule(),
    ];
}

public abstract class JsModernApiRule : RuleBase
{
    public override string[] Languages => ["js", "ts"];

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static string Called(SyntaxNode call) => SyntaxQuery.InvokedName(call);

    protected static IReadOnlyList<SyntaxNode> Args(SyntaxNode call) => SyntaxQuery.Arguments(call);
}

/// <summary>reduce with no seed throws TypeError on the first empty collection it meets.</summary>
public sealed class JsReduceWithoutInitialValueRule : JsModernApiRule
{
    public override string Key => "QG-JS-BUG-0084";
    public override string Name => "Array.reduce should include an initial value";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Called(call).IsOneOf("reduce", "reduceRight") || Args(call).Count != 1)
                continue;
            context.Report(call,
                "This reduce carries no initial value, so on an empty array it throws TypeError - "
                + "the one input nobody tested. Pass the identity element explicitly (`0` for sums, "
                + "`[]` for accumulations) and empty becomes just another case.");
        }
    }
}

/// <summary>A lambda comparing for equality is indexOf spelled the slow way.</summary>
public sealed class JsFindIndexAsIndexOfRule : JsModernApiRule
{
    public override string Key => "QG-JS-SML-0293";
    public override string Name => "indexOf and lastIndexOf should replace equality findIndex";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = Called(call);
            if (!name.IsOneOf("findIndex", "findLastIndex"))
                continue;
            var lambda = Args(call).FirstOrDefault(a => a.Kind == NodeKind.Lambda);
            var parameters = lambda?.FirstChild(NodeKind.ParameterList)?.Children;
            if (lambda == null || parameters == null || parameters.Count != 1)
                continue;
            var parameter = parameters[0].Text;
            // the body may sit bare or inside a single-expression block; either way the shape we
            // are after is one comparison between the parameter and something else
            var body = lambda.ChildAt(1);
            var comparison = body?.Kind == NodeKind.Block
                ? body.Children.FirstOrDefault()?.ChildAt(0)
                : body;
            if (comparison is not { Kind: NodeKind.Binary, Text: "===" or "==" })
                continue;
            var mentionsParameter = comparison.DescendantsAndSelf()
                .Any(n => n.Kind == NodeKind.Identifier && n.Text == parameter);
            if (!mentionsParameter)
                continue;
            context.Report(call,
                $"The callback only compares elements for identity, which is what {name.Replace("Index", "")}() "
                + "does natively: shorter, faster, and without a lambda to read. Replace it with "
                + $"{name.Replace("Index", "")}(value) unless the predicate really needs more than "
                + "equality.");
        }
    }
}

/// <summary>length-minus-N indexing is what Array.at reads from the end.</summary>
public sealed class JsIndexArithmeticToAtRule : JsModernApiRule
{
    public override string Key => "QG-JS-SML-0295";
    public override string Name => "Complex index access patterns should use .at()";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var access in context.Root.OfKind(NodeKind.Index))
        {
            if (access.ChildAt(0)?.Kind != NodeKind.Identifier
                || access.ChildAt(1)?.Kind != NodeKind.Binary
                || access.ChildAt(1).Text != "-")
                continue;
            var length = access.ChildAt(1).ChildAt(0);
            var offset = access.ChildAt(1).ChildAt(1);
            if (length?.Kind != NodeKind.MemberSelect
                || length.ChildAt(1)?.Text != "length"
                || length.ChildAt(0)?.Text != access.ChildAt(0).Text
                || offset?.Kind != NodeKind.NumberLiteral)
                continue;
            context.Report(access,
                $"`{access.ChildAt(0).Text}[{access.ChildAt(0).Text}.length - {offset.Text}]` "
                + "counts characters to say \"N from the end\". `.at(-" + offset.Text + ")` says "
                + "it directly, works on strings too, and survives a rename of the receiver in one "
                + "place instead of three.");
        }
    }
}

/// <summary>A Date object built and immediately drained is Date.now spelled expensively.</summary>
public sealed class JsDateObjectForTimestampRule : JsModernApiRule
{
    public override string Key => "QG-JS-SML-0299";
    public override string Name => "Use Date.now() instead of building a Date object";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Called(call).IsOneOf("getTime", "valueOf", "Symbol.toPrimitive"))
                continue;
            var receiver = call.ChildAt(0)?.Kind == NodeKind.MemberSelect
                ? call.ChildAt(0).ChildAt(0)
                : null;
            // JavaScript reads `new Date()` as a unary 'new' over a plain invocation
            if (receiver?.Kind == NodeKind.Unary && receiver.Text == "new")
                receiver = receiver.ChildAt(0);
            var isFreshDate = receiver?.Kind == NodeKind.Invocation && Called(receiver) == "Date"
                              && Args(receiver).Count == 0
                || receiver is { Kind: NodeKind.ObjectCreation, Text: "Date" };
            if (!isFreshDate)
                continue;
            context.Report(call,
                "This builds a full Date object only to read the millisecond timestamp off it. "
                + "`Date.now()` returns the same number without the allocation, and reads as what "
                + "it is: now, in milliseconds.");
        }
    }
}

/// <summary>parentNode.removeChild(node) repeats itself; node.remove() does not.</summary>
public sealed class JsRemoveChildToRemoveRule : JsModernApiRule
{
    public override string Key => "QG-JS-SML-0302";
    public override string Name => "DOM nodes should be removed using remove()";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (Called(call) != "removeChild"
                || call.ChildAt(0)?.Kind != NodeKind.MemberSelect)
                continue;
            // the receiver must itself be a `<node>.parentNode` select, and the argument must be
            // that same node: `parent.removeChild(other)` is ordinary and stays silent
            var parentNode = call.ChildAt(0).ChildAt(0);
            if (parentNode?.Kind != NodeKind.MemberSelect
                || parentNode.ChildAt(1)?.Text != "parentNode")
                continue;
            if (Args(call).Count != 1
                || Args(call)[0]?.SourceText() != parentNode.ChildAt(0)?.SourceText())
                continue;
            context.Report(call,
                "`node.parentNode.removeChild(node)` walks up to the parent only to come back down "
                + "to the node you already hold. `node.remove()` does the same thing, says it once, "
                + "and cannot desynchronise if the two spellings drift apart.");
        }
    }
}
