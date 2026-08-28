using QualityGuard.Core.Models;
using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Defects that only show up once the tree is understood: a loop that cannot loop, a comparison whose
/// answer is fixed, a result that is computed and dropped. Each rule here reports a construct that is
/// wrong on its own terms, without needing to know what the surrounding program is for — which is what
/// keeps them usable on every language the parser handles.
/// </summary>
public static class CorrectnessRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new LoopWithAtMostOneIterationRuleCs(),
        new LoopWithAtMostOneIterationRuleJava(),
        new LoopWithAtMostOneIterationRuleKotlin(),
        new LoopWithAtMostOneIterationRuleJs(),
        new LoopWithAtMostOneIterationRulePython(),
        new LoopWithAtMostOneIterationRulePhp(),
        new LoopWithAtMostOneIterationRuleGo(),
        new LoopWithAtMostOneIterationRuleDart(),
        new LoopWithAtMostOneIterationRuleRuby(),
        new LoopWithAtMostOneIterationRuleSwift(),
        new LoopWithAtMostOneIterationRuleCss(),
        new LoopWithAtMostOneIterationRuleHtml(),
        new LoopWithAtMostOneIterationRuleXml(),
        new LoopWithAtMostOneIterationRuleTerraform(),
        new LoopWithAtMostOneIterationRuleDockerfile(),
        new LoopWithAtMostOneIterationRuleKubernetes(),
        new LoopWithAtMostOneIterationRuleCloudFormation(),
        new LoopWithAtMostOneIterationRuleJson(),
        new NonsensicalSizeComparisonRuleCs(),
        new NonsensicalSizeComparisonRuleJava(),
        new NonsensicalSizeComparisonRuleKotlin(),
        new NonsensicalSizeComparisonRuleJs(),
        new NonsensicalSizeComparisonRulePython(),
        new NonsensicalSizeComparisonRulePhp(),
        new NonsensicalSizeComparisonRuleGo(),
        new NonsensicalSizeComparisonRuleDart(),
        new NonsensicalSizeComparisonRuleRuby(),
        new NonsensicalSizeComparisonRuleSwift(),
        new NonsensicalSizeComparisonRuleCss(),
        new NonsensicalSizeComparisonRuleHtml(),
        new NonsensicalSizeComparisonRuleXml(),
        new NonsensicalSizeComparisonRuleTerraform(),
        new NonsensicalSizeComparisonRuleDockerfile(),
        new NonsensicalSizeComparisonRuleKubernetes(),
        new NonsensicalSizeComparisonRuleCloudFormation(),
        new NonsensicalSizeComparisonRuleJson(),
        new CollectionPassedToItsOwnMethodRuleCs(),
        new CollectionPassedToItsOwnMethodRuleJava(),
        new CollectionPassedToItsOwnMethodRuleKotlin(),
        new CollectionPassedToItsOwnMethodRuleJs(),
        new CollectionPassedToItsOwnMethodRulePython(),
        new CollectionPassedToItsOwnMethodRulePhp(),
        new CollectionPassedToItsOwnMethodRuleGo(),
        new CollectionPassedToItsOwnMethodRuleDart(),
        new CollectionPassedToItsOwnMethodRuleRuby(),
        new CollectionPassedToItsOwnMethodRuleSwift(),
        new CollectionPassedToItsOwnMethodRuleCss(),
        new CollectionPassedToItsOwnMethodRuleHtml(),
        new CollectionPassedToItsOwnMethodRuleXml(),
        new CollectionPassedToItsOwnMethodRuleTerraform(),
        new CollectionPassedToItsOwnMethodRuleDockerfile(),
        new CollectionPassedToItsOwnMethodRuleKubernetes(),
        new CollectionPassedToItsOwnMethodRuleCloudFormation(),
        new CollectionPassedToItsOwnMethodRuleJson(),
        new DiscardedPureResultRuleCs(),
        new DiscardedPureResultRuleJava(),
        new DiscardedPureResultRuleKotlin(),
        new DiscardedPureResultRuleJs(),
        new DiscardedPureResultRulePython(),
        new DiscardedPureResultRulePhp(),
        new DiscardedPureResultRuleGo(),
        new DiscardedPureResultRuleDart(),
        new DiscardedPureResultRuleRuby(),
        new DiscardedPureResultRuleSwift(),
        new DiscardedPureResultRuleCss(),
        new DiscardedPureResultRuleHtml(),
        new DiscardedPureResultRuleXml(),
        new DiscardedPureResultRuleTerraform(),
        new DiscardedPureResultRuleDockerfile(),
        new DiscardedPureResultRuleKubernetes(),
        new DiscardedPureResultRuleCloudFormation(),
        new DiscardedPureResultRuleJson(),
        new RepeatedUnaryOperatorRuleCs(),
        new RepeatedUnaryOperatorRuleJava(),
        new RepeatedUnaryOperatorRuleKotlin(),
        new RepeatedUnaryOperatorRuleJs(),
        new RepeatedUnaryOperatorRulePython(),
        new RepeatedUnaryOperatorRulePhp(),
        new RepeatedUnaryOperatorRuleGo(),
        new RepeatedUnaryOperatorRuleDart(),
        new RepeatedUnaryOperatorRuleRuby(),
        new RepeatedUnaryOperatorRuleSwift(),
        new RepeatedUnaryOperatorRuleCss(),
        new RepeatedUnaryOperatorRuleHtml(),
        new RepeatedUnaryOperatorRuleXml(),
        new RepeatedUnaryOperatorRuleTerraform(),
        new RepeatedUnaryOperatorRuleDockerfile(),
        new RepeatedUnaryOperatorRuleKubernetes(),
        new RepeatedUnaryOperatorRuleCloudFormation(),
        new RepeatedUnaryOperatorRuleJson(),
        new PointlessShiftRuleCs(),
        new PointlessShiftRuleJava(),
        new PointlessShiftRuleKotlin(),
        new PointlessShiftRuleJs(),
        new PointlessShiftRulePython(),
        new PointlessShiftRulePhp(),
        new PointlessShiftRuleGo(),
        new PointlessShiftRuleDart(),
        new PointlessShiftRuleRuby(),
        new PointlessShiftRuleSwift(),
        new PointlessShiftRuleCss(),
        new PointlessShiftRuleHtml(),
        new PointlessShiftRuleXml(),
        new PointlessShiftRuleTerraform(),
        new PointlessShiftRuleDockerfile(),
        new PointlessShiftRuleKubernetes(),
        new PointlessShiftRuleCloudFormation(),
        new PointlessShiftRuleJson(),
        new LoopCounterMovesAwayFromBoundRuleCs(),
        new LoopCounterMovesAwayFromBoundRuleJava(),
        new LoopCounterMovesAwayFromBoundRuleKotlin(),
        new LoopCounterMovesAwayFromBoundRuleJs(),
        new LoopCounterMovesAwayFromBoundRulePython(),
        new LoopCounterMovesAwayFromBoundRulePhp(),
        new LoopCounterMovesAwayFromBoundRuleGo(),
        new LoopCounterMovesAwayFromBoundRuleDart(),
        new LoopCounterMovesAwayFromBoundRuleRuby(),
        new LoopCounterMovesAwayFromBoundRuleSwift(),
        new LoopCounterMovesAwayFromBoundRuleCss(),
        new LoopCounterMovesAwayFromBoundRuleHtml(),
        new LoopCounterMovesAwayFromBoundRuleXml(),
        new LoopCounterMovesAwayFromBoundRuleTerraform(),
        new LoopCounterMovesAwayFromBoundRuleDockerfile(),
        new LoopCounterMovesAwayFromBoundRuleKubernetes(),
        new LoopCounterMovesAwayFromBoundRuleCloudFormation(),
        new LoopCounterMovesAwayFromBoundRuleJson(),
        new LoopWithoutExitRuleCs(),
        new LoopWithoutExitRuleJava(),
        new LoopWithoutExitRuleKotlin(),
        new LoopWithoutExitRuleJs(),
        new LoopWithoutExitRulePython(),
        new LoopWithoutExitRulePhp(),
        new LoopWithoutExitRuleGo(),
        new LoopWithoutExitRuleDart(),
        new LoopWithoutExitRuleRuby(),
        new LoopWithoutExitRuleSwift(),
        new LoopWithoutExitRuleCss(),
        new LoopWithoutExitRuleHtml(),
        new LoopWithoutExitRuleXml(),
        new LoopWithoutExitRuleTerraform(),
        new LoopWithoutExitRuleDockerfile(),
        new LoopWithoutExitRuleKubernetes(),
        new LoopWithoutExitRuleCloudFormation(),
        new LoopWithoutExitRuleJson(),
        new UselessIncrementRuleCs(),
        new UselessIncrementRuleRuby(),
        new UselessIncrementRuleSwift(),
        new UselessIncrementRuleCss(),
        new UselessIncrementRuleHtml(),
        new UselessIncrementRuleXml(),
        new UselessIncrementRuleTerraform(),
        new UselessIncrementRuleDockerfile(),
        new UselessIncrementRuleKubernetes(),
        new UselessIncrementRuleCloudFormation(),
        new UselessIncrementRuleJson(),
        new UselessIncrementRuleJava(),
        new UselessIncrementRuleKotlin(),
        new UselessIncrementRuleJs(),
        new UselessIncrementRulePython(),
        new UselessIncrementRulePhp(),
        new UselessIncrementRuleGo(),
        new UselessIncrementRuleDart()
    ];
}

/// <summary>Shared helpers: the tree has to be exact before any of this reasoning is worth reporting.</summary>
public abstract class CorrectnessRuleBase : RuleBase
{
    public override string[] Languages => [];

    protected static bool HasPreciseTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>The statements a loop or branch body runs, whether or not it is wrapped in a block.</summary>
    protected static IReadOnlyList<SyntaxNode> BodyStatements(SyntaxNode owner)
    {
        var block = owner.FirstChild(NodeKind.Block);
        if (block != null)
            return block.Children;
        var statement = owner.Children.LastOrDefault(c => c.Kind is not (NodeKind.ParameterList or NodeKind.Binary
            or NodeKind.Identifier or NodeKind.Assignment or NodeKind.VariableDeclaration));
        return statement == null ? [] : [statement];
    }

    protected static bool IsUnconditional(SyntaxNode statement, SyntaxNode body)
    {
        for (var node = statement.Parent; node != null && node != body; node = node.Parent)
        {
            if (node.Kind is NodeKind.If or NodeKind.Else or NodeKind.Match or NodeKind.MatchCase
                or NodeKind.SwitchSection or NodeKind.Try or NodeKind.Catch or NodeKind.Conditional
                or NodeKind.Lambda or NodeKind.FunctionDeclaration or NodeKind.LocalFunction)
                return false;
        }
        return true;
    }
}

public abstract class LoopWithAtMostOneIterationRule : CorrectnessRuleBase
{
    public override string Name => "Loops should be able to run more than once";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            var body = loop.FirstChild(NodeKind.Block);
            if (body == null || body.Children.Count == 0)
                continue;

            var exit = body.Children.FirstOrDefault(IsExit);
            if (exit == null)
                continue;
            // "guard, then act once" is a deliberate idiom: the statements before the jump decide
            // whether this pass is the one that acts, so the loop really can run several times
            if (body.Children.TakeWhile(child => child != exit).Any(HasJump))
                continue;
            // a jump that is the whole point of the loop body still ends it on the first pass
            context.Report(loop, $"This loop always leaves on its first pass: '{exit.Text}' on line "
                                 + $"{exit.Line} runs unconditionally. Drop the loop, or move the jump "
                                 + "under the condition that is supposed to end the iteration.");
        }
    }

    private static bool IsExit(SyntaxNode statement)
        => statement.Kind == NodeKind.Jump
           && (statement.Text.StartsWith("break", StringComparison.Ordinal)
               || statement.Text.StartsWith("return", StringComparison.Ordinal));

    private static bool HasJump(SyntaxNode statement)
        => statement.DescendantsAndSelf().Any(n => n.Kind == NodeKind.Jump
                                                   || n.Text.StartsWith("throw", StringComparison.Ordinal));
}

public sealed class LoopWithAtMostOneIterationRuleCs : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-CS-BUG-0165";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class LoopWithAtMostOneIterationRuleJava : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-JV-BUG-0219";
    public override string[] Languages => ["java"];
}

public sealed class LoopWithAtMostOneIterationRuleKotlin : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-KT-BUG-0046";
    public override string[] Languages => ["kt"];
}

public sealed class LoopWithAtMostOneIterationRuleJs : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-JS-BUG-0163";
    public override string[] Languages => ["js", "ts"];
}

public sealed class LoopWithAtMostOneIterationRulePython : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-PY-BUG-0169";
    public override string[] Languages => ["py"];
}

public sealed class LoopWithAtMostOneIterationRulePhp : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-PP-BUG-0066";
    public override string[] Languages => ["php"];
}

public sealed class LoopWithAtMostOneIterationRuleGo : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-GO-BUG-0022";
    public override string[] Languages => ["go"];
}

public sealed class LoopWithAtMostOneIterationRuleDart : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-DART-BUG-0020";
    public override string[] Languages => ["dart"];
}

public sealed class LoopWithAtMostOneIterationRuleRuby : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-RB-BUG-0006";
    public override string[] Languages => ["rb"];
}

public sealed class LoopWithAtMostOneIterationRuleSwift : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-SW-BUG-0010";
    public override string[] Languages => ["swift"];
}

public sealed class LoopWithAtMostOneIterationRuleCss : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-CSS-BUG-0035";
    public override string[] Languages => ["css"];
}

public sealed class LoopWithAtMostOneIterationRuleHtml : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-HTML-BUG-0035";
    public override string[] Languages => ["html"];
}

public sealed class LoopWithAtMostOneIterationRuleXml : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-XML-BUG-0010";
    public override string[] Languages => ["xml"];
}

public sealed class LoopWithAtMostOneIterationRuleTerraform : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-TF-BUG-0005";
    public override string[] Languages => ["tf"];
}

public sealed class LoopWithAtMostOneIterationRuleDockerfile : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-DK-BUG-0012";
    public override string[] Languages => ["dk"];
}

public sealed class LoopWithAtMostOneIterationRuleKubernetes : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-K8-BUG-0005";
    public override string[] Languages => ["k8"];
}

public sealed class LoopWithAtMostOneIterationRuleCloudFormation : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-CF-BUG-0005";
    public override string[] Languages => ["cf"];
}

public sealed class LoopWithAtMostOneIterationRuleJson : LoopWithAtMostOneIterationRule
{
    public override string Key => "QG-JSON-BUG-0006";
    public override string[] Languages => ["json"];
}

public abstract class NonsensicalSizeComparisonRule : CorrectnessRuleBase
{
    private static readonly string[] SizeNames =
        ["Count", "Length", "size", "length", "count", "len", "Size", "__len__"];
    public override string Name => "Size comparisons should be able to fail";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not (">=" or "<" or "==" or "<="))
                continue;
            var left = comparison.ChildAt(0);
            var right = comparison.ChildAt(1);
            if (left == null || right == null || !IsSize(left) || NumberText(right) is not { } bound)
                continue;

            var verdict = (comparison.Text, bound) switch
            {
                (">=", "0") => "is always true",
                ("<", "0") => "is always false",
                ("==", "-1") => "is always false",
                ("<=", "-1") => "is always false",
                _ => null
            };
            if (verdict == null)
                continue;
            context.Report(comparison, $"A size is never negative, so this test {verdict}. Compare against "
                                       + "the bound you actually mean — usually emptiness (== 0) or a "
                                       + "minimum number of elements.");
        }
    }

    /// <summary>A numeric literal, with the sign the parser keeps as a separate unary node.</summary>
    private static string? NumberText(SyntaxNode node)
    {
        if (node.Kind == NodeKind.NumberLiteral)
            return node.Text;
        if (node.Kind == NodeKind.Unary && node.Text is "-" && node.ChildAt(0) is { Kind: NodeKind.NumberLiteral } n)
            return "-" + n.Text;
        return null;
    }

    private static bool IsSize(SyntaxNode node)
    {
        var name = node.Kind switch
        {
            NodeKind.Invocation => SyntaxQuery.InvokedName(node),
            NodeKind.MemberSelect => SyntaxQuery.SimpleName(node),
            _ => null
        };
        return name != null && SizeNames.Contains(name, StringComparer.Ordinal);
    }
}

public sealed class NonsensicalSizeComparisonRuleCs : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-CS-BUG-0166";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class NonsensicalSizeComparisonRuleJava : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-JV-BUG-0220";
    public override string[] Languages => ["java"];
}

public sealed class NonsensicalSizeComparisonRuleKotlin : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-KT-BUG-0047";
    public override string[] Languages => ["kt"];
}

public sealed class NonsensicalSizeComparisonRuleJs : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-JS-BUG-0164";
    public override string[] Languages => ["js", "ts"];
}

public sealed class NonsensicalSizeComparisonRulePython : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-PY-BUG-0170";
    public override string[] Languages => ["py"];
}

public sealed class NonsensicalSizeComparisonRulePhp : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-PP-BUG-0067";
    public override string[] Languages => ["php"];
}

public sealed class NonsensicalSizeComparisonRuleGo : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-GO-BUG-0023";
    public override string[] Languages => ["go"];
}

public sealed class NonsensicalSizeComparisonRuleDart : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-DART-BUG-0021";
    public override string[] Languages => ["dart"];
}

public sealed class NonsensicalSizeComparisonRuleRuby : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-RB-BUG-0007";
    public override string[] Languages => ["rb"];
}

public sealed class NonsensicalSizeComparisonRuleSwift : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-SW-BUG-0011";
    public override string[] Languages => ["swift"];
}

public sealed class NonsensicalSizeComparisonRuleCss : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-CSS-BUG-0036";
    public override string[] Languages => ["css"];
}

public sealed class NonsensicalSizeComparisonRuleHtml : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-HTML-BUG-0036";
    public override string[] Languages => ["html"];
}

public sealed class NonsensicalSizeComparisonRuleXml : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-XML-BUG-0011";
    public override string[] Languages => ["xml"];
}

public sealed class NonsensicalSizeComparisonRuleTerraform : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-TF-BUG-0006";
    public override string[] Languages => ["tf"];
}

public sealed class NonsensicalSizeComparisonRuleDockerfile : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-DK-BUG-0013";
    public override string[] Languages => ["dk"];
}

public sealed class NonsensicalSizeComparisonRuleKubernetes : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-K8-BUG-0006";
    public override string[] Languages => ["k8"];
}

public sealed class NonsensicalSizeComparisonRuleCloudFormation : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-CF-BUG-0006";
    public override string[] Languages => ["cf"];
}

public sealed class NonsensicalSizeComparisonRuleJson : NonsensicalSizeComparisonRule
{
    public override string Key => "QG-JSON-BUG-0007";
    public override string[] Languages => ["json"];
}

public abstract class CollectionPassedToItsOwnMethodRule : CorrectnessRuleBase
{
    private static readonly string[] Suspicious =
    [
        "addAll", "AddRange", "removeAll", "RemoveAll", "retainAll", "containsAll", "contains", "Contains",
        "add", "Add", "remove", "Remove", "push", "extend", "update", "concat", "Union", "Intersect",
        "Except", "SequenceEqual", "copyOf", "CopyTo", "putAll", "merge"
    ];
    public override string Name => "A collection should not be passed to its own method";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!Suspicious.Contains(name, StringComparer.Ordinal))
                continue;
            var receiver = SyntaxQuery.Receiver(call);
            if (receiver.Length == 0)
                continue;
            var arguments = SyntaxQuery.Arguments(call);
            if (arguments.Count != 1)
                continue;
            if (SyntaxQuery.DottedName(arguments[0]) != receiver)
                continue;

            context.Report(call, $"'{receiver}' is passed to its own '{name}'. The call either does nothing "
                                 + "or never ends; one of the two operands is the wrong one.");
        }
    }
}

public sealed class CollectionPassedToItsOwnMethodRuleCs : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-CS-BUG-0167";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class CollectionPassedToItsOwnMethodRuleJava : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-JV-BUG-0221";
    public override string[] Languages => ["java"];
}

public sealed class CollectionPassedToItsOwnMethodRuleKotlin : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-KT-BUG-0048";
    public override string[] Languages => ["kt"];
}

public sealed class CollectionPassedToItsOwnMethodRuleJs : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-JS-BUG-0165";
    public override string[] Languages => ["js", "ts"];
}

public sealed class CollectionPassedToItsOwnMethodRulePython : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-PY-BUG-0171";
    public override string[] Languages => ["py"];
}

public sealed class CollectionPassedToItsOwnMethodRulePhp : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-PP-BUG-0068";
    public override string[] Languages => ["php"];
}

public sealed class CollectionPassedToItsOwnMethodRuleGo : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-GO-BUG-0024";
    public override string[] Languages => ["go"];
}

public sealed class CollectionPassedToItsOwnMethodRuleDart : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-DART-BUG-0022";
    public override string[] Languages => ["dart"];
}

public sealed class CollectionPassedToItsOwnMethodRuleRuby : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-RB-BUG-0008";
    public override string[] Languages => ["rb"];
}

public sealed class CollectionPassedToItsOwnMethodRuleSwift : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-SW-BUG-0012";
    public override string[] Languages => ["swift"];
}

public sealed class CollectionPassedToItsOwnMethodRuleCss : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-CSS-BUG-0037";
    public override string[] Languages => ["css"];
}

public sealed class CollectionPassedToItsOwnMethodRuleHtml : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-HTML-BUG-0037";
    public override string[] Languages => ["html"];
}

public sealed class CollectionPassedToItsOwnMethodRuleXml : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-XML-BUG-0012";
    public override string[] Languages => ["xml"];
}

public sealed class CollectionPassedToItsOwnMethodRuleTerraform : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-TF-BUG-0007";
    public override string[] Languages => ["tf"];
}

public sealed class CollectionPassedToItsOwnMethodRuleDockerfile : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-DK-BUG-0014";
    public override string[] Languages => ["dk"];
}

public sealed class CollectionPassedToItsOwnMethodRuleKubernetes : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-K8-BUG-0007";
    public override string[] Languages => ["k8"];
}

public sealed class CollectionPassedToItsOwnMethodRuleCloudFormation : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-CF-BUG-0007";
    public override string[] Languages => ["cf"];
}

public sealed class CollectionPassedToItsOwnMethodRuleJson : CollectionPassedToItsOwnMethodRule
{
    public override string Key => "QG-JSON-BUG-0008";
    public override string[] Languages => ["json"];
}

public abstract class DiscardedPureResultRule : CorrectnessRuleBase
{
    /// <summary>Calls that only compute: dropping the result means the statement does nothing at all.</summary>
    /// <summary>
    /// Deliberately narrow: only names that are side-effect free in every mainstream library, so a
    /// project that defines a method of the same name on its own type is not reported by accident.
    /// Names such as map, join or reverse are left out — they mutate in at least one common library.
    /// </summary>
    private static readonly string[] PureNames =
    [
        "Substring", "substring", "ToUpper", "ToLower", "toUpperCase", "toLowerCase",
        "Trim", "trim", "TrimStart", "TrimEnd", "strip", "lstrip", "rstrip", "Replace", "replace",
        "PadLeft", "PadRight", "IndexOf", "indexOf", "LastIndexOf", "lastIndexOf",
        "StartsWith", "startsWith", "EndsWith", "endsWith", "ToString", "toString",
        "Abs", "Sqrt", "Pow", "Floor", "Ceiling", "Round"
    ];
    public override string Name => "The result of a pure call should be used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (call.Parent?.Kind != NodeKind.ExpressionStatement)
                continue;
            var name = SyntaxQuery.InvokedName(call);
            if (!PureNames.Contains(name, StringComparer.Ordinal))
                continue;
            // An optional chain is split by the parser and its tail arrives looking like a statement
            // of its own — 'a?.b?.[0]?.trim()' assigned to a name reached here as a bare call. The
            // tokens still carry the '?.', which the real statement form never does.
            if (call.Tokens.Any(t => t.Text == "?."))
                continue;
            // an in-place variant exists in some libraries: only report when there is a receiver to keep
            if (SyntaxQuery.Receiver(call).Length == 0)
                continue;
            // os.replace() is a side-effecting filesystem operation (renames a file), not a pure
            // string method.  The receiver 'os' makes the distinction: skip module-level calls.
            if (SyntaxQuery.Receiver(call) == "os")
                continue;

            context.Report(call, $"'{name}' returns a new value and changes nothing, so this statement has "
                                 + "no effect. Assign the result, or remove the line.");
        }
    }
}

public sealed class DiscardedPureResultRuleCs : DiscardedPureResultRule
{
    public override string Key => "QG-CS-BUG-0168";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class DiscardedPureResultRuleJava : DiscardedPureResultRule
{
    public override string Key => "QG-JV-BUG-0222";
    public override string[] Languages => ["java"];
}

public sealed class DiscardedPureResultRuleKotlin : DiscardedPureResultRule
{
    public override string Key => "QG-KT-BUG-0049";
    public override string[] Languages => ["kt"];
}

public sealed class DiscardedPureResultRuleJs : DiscardedPureResultRule
{
    public override string Key => "QG-JS-BUG-0166";
    public override string[] Languages => ["js", "ts"];
}

public sealed class DiscardedPureResultRulePython : DiscardedPureResultRule
{
    public override string Key => "QG-PY-BUG-0172";
    public override string[] Languages => ["py"];
}

public sealed class DiscardedPureResultRulePhp : DiscardedPureResultRule
{
    public override string Key => "QG-PP-BUG-0069";
    public override string[] Languages => ["php"];
}

public sealed class DiscardedPureResultRuleGo : DiscardedPureResultRule
{
    public override string Key => "QG-GO-BUG-0025";
    public override string[] Languages => ["go"];
}

public sealed class DiscardedPureResultRuleDart : DiscardedPureResultRule
{
    public override string Key => "QG-DART-BUG-0023";
    public override string[] Languages => ["dart"];
}

public sealed class DiscardedPureResultRuleRuby : DiscardedPureResultRule
{
    public override string Key => "QG-RB-BUG-0009";
    public override string[] Languages => ["rb"];
}

public sealed class DiscardedPureResultRuleSwift : DiscardedPureResultRule
{
    public override string Key => "QG-SW-BUG-0013";
    public override string[] Languages => ["swift"];
}

public sealed class DiscardedPureResultRuleCss : DiscardedPureResultRule
{
    public override string Key => "QG-CSS-BUG-0038";
    public override string[] Languages => ["css"];
}

public sealed class DiscardedPureResultRuleHtml : DiscardedPureResultRule
{
    public override string Key => "QG-HTML-BUG-0038";
    public override string[] Languages => ["html"];
}

public sealed class DiscardedPureResultRuleXml : DiscardedPureResultRule
{
    public override string Key => "QG-XML-BUG-0013";
    public override string[] Languages => ["xml"];
}

public sealed class DiscardedPureResultRuleTerraform : DiscardedPureResultRule
{
    public override string Key => "QG-TF-BUG-0008";
    public override string[] Languages => ["tf"];
}

public sealed class DiscardedPureResultRuleDockerfile : DiscardedPureResultRule
{
    public override string Key => "QG-DK-BUG-0015";
    public override string[] Languages => ["dk"];
}

public sealed class DiscardedPureResultRuleKubernetes : DiscardedPureResultRule
{
    public override string Key => "QG-K8-BUG-0008";
    public override string[] Languages => ["k8"];
}

public sealed class DiscardedPureResultRuleCloudFormation : DiscardedPureResultRule
{
    public override string Key => "QG-CF-BUG-0008";
    public override string[] Languages => ["cf"];
}

public sealed class DiscardedPureResultRuleJson : DiscardedPureResultRule
{
    public override string Key => "QG-JSON-BUG-0009";
    public override string[] Languages => ["json"];
}

public abstract class RepeatedUnaryOperatorRule : CorrectnessRuleBase
{
    public override string Name => "Unary operators should not be repeated";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        // In the script languages !! is the established way of converting a value to a boolean, and
        // in Kotlin it is a single operator that asserts a value is not null — not a negation
        // repeated. Reporting either would fight the language instead of finding a defect.
        var doubleNegationIsIdiomatic = context.Language.LanguageKey is "js" or "ts" or "php" or "kt";

        foreach (var unary in context.Root.OfKind(NodeKind.Unary))
        {
            if (unary.Text is not ("!" or "~" or "-" or "+" or "not"))
                continue;
            if (doubleNegationIsIdiomatic && unary.Text == "!")
                continue;
            var operand = unary.ChildAt(0);
            if (operand is not { Kind: NodeKind.Unary } || operand.Text != unary.Text)
                continue;

            var advice = unary.Text is "!" or "not"
                ? "two negations cancel out, so the value is used as it is — write the conversion you mean"
                : "the two operators cancel out";
            context.Report(unary, $"'{unary.Text}{unary.Text}' applied to the same operand: {advice}.");
        }
    }
}

public sealed class RepeatedUnaryOperatorRuleCs : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-CS-BUG-0169";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class RepeatedUnaryOperatorRuleJava : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-JV-BUG-0223";
    public override string[] Languages => ["java"];
}

public sealed class RepeatedUnaryOperatorRuleKotlin : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-KT-BUG-0050";
    public override string[] Languages => ["kt"];
}

public sealed class RepeatedUnaryOperatorRuleJs : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-JS-BUG-0167";
    public override string[] Languages => ["js", "ts"];
}

public sealed class RepeatedUnaryOperatorRulePython : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-PY-BUG-0173";
    public override string[] Languages => ["py"];
}

public sealed class RepeatedUnaryOperatorRulePhp : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-PP-BUG-0070";
    public override string[] Languages => ["php"];
}

public sealed class RepeatedUnaryOperatorRuleGo : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-GO-BUG-0026";
    public override string[] Languages => ["go"];
}

public sealed class RepeatedUnaryOperatorRuleDart : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-DART-BUG-0024";
    public override string[] Languages => ["dart"];
}

public sealed class RepeatedUnaryOperatorRuleRuby : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-RB-BUG-0010";
    public override string[] Languages => ["rb"];
}

public sealed class RepeatedUnaryOperatorRuleSwift : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-SW-BUG-0014";
    public override string[] Languages => ["swift"];
}

public sealed class RepeatedUnaryOperatorRuleCss : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-CSS-BUG-0039";
    public override string[] Languages => ["css"];
}

public sealed class RepeatedUnaryOperatorRuleHtml : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-HTML-BUG-0039";
    public override string[] Languages => ["html"];
}

public sealed class RepeatedUnaryOperatorRuleXml : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-XML-BUG-0014";
    public override string[] Languages => ["xml"];
}

public sealed class RepeatedUnaryOperatorRuleTerraform : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-TF-BUG-0009";
    public override string[] Languages => ["tf"];
}

public sealed class RepeatedUnaryOperatorRuleDockerfile : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-DK-BUG-0016";
    public override string[] Languages => ["dk"];
}

public sealed class RepeatedUnaryOperatorRuleKubernetes : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-K8-BUG-0009";
    public override string[] Languages => ["k8"];
}

public sealed class RepeatedUnaryOperatorRuleCloudFormation : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-CF-BUG-0009";
    public override string[] Languages => ["cf"];
}

public sealed class RepeatedUnaryOperatorRuleJson : RepeatedUnaryOperatorRule
{
    public override string Key => "QG-JSON-BUG-0010";
    public override string[] Languages => ["json"];
}

public abstract class PointlessShiftRule : CorrectnessRuleBase
{
    public override string Name => "Shift distances should be inside the width of the value";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var shift in context.Root.OfKind(NodeKind.Binary))
        {
            if (shift.Text is not ("<<" or ">>" or ">>>"))
                continue;
            var distance = shift.ChildAt(1);
            if (distance is not { Kind: NodeKind.NumberLiteral } || !int.TryParse(distance.Text, out var bits))
                continue;

            if (bits == 0)
            {
                context.Report(shift, "Shifting by zero leaves the value untouched; drop the shift or use "
                                      + "the distance the calculation needs.");
            }
            else if (bits >= 64)
            {
                context.Report(shift, $"A shift by {bits} is wider than any built-in integer, so the result "
                                      + "is not the zero it looks like — the distance wraps around. Use a "
                                      + "type wide enough, or rethink the arithmetic.");
            }
        }
    }
}

public sealed class PointlessShiftRuleCs : PointlessShiftRule
{
    public override string Key => "QG-CS-BUG-0170";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class PointlessShiftRuleJava : PointlessShiftRule
{
    public override string Key => "QG-JV-BUG-0224";
    public override string[] Languages => ["java"];
}

public sealed class PointlessShiftRuleKotlin : PointlessShiftRule
{
    public override string Key => "QG-KT-BUG-0051";
    public override string[] Languages => ["kt"];
}

public sealed class PointlessShiftRuleJs : PointlessShiftRule
{
    public override string Key => "QG-JS-BUG-0168";
    public override string[] Languages => ["js", "ts"];
}

public sealed class PointlessShiftRulePython : PointlessShiftRule
{
    public override string Key => "QG-PY-BUG-0174";
    public override string[] Languages => ["py"];
}

public sealed class PointlessShiftRulePhp : PointlessShiftRule
{
    public override string Key => "QG-PP-BUG-0071";
    public override string[] Languages => ["php"];
}

public sealed class PointlessShiftRuleGo : PointlessShiftRule
{
    public override string Key => "QG-GO-BUG-0027";
    public override string[] Languages => ["go"];
}

public sealed class PointlessShiftRuleDart : PointlessShiftRule
{
    public override string Key => "QG-DART-BUG-0025";
    public override string[] Languages => ["dart"];
}

public sealed class PointlessShiftRuleRuby : PointlessShiftRule
{
    public override string Key => "QG-RB-BUG-0011";
    public override string[] Languages => ["rb"];
}

public sealed class PointlessShiftRuleSwift : PointlessShiftRule
{
    public override string Key => "QG-SW-BUG-0015";
    public override string[] Languages => ["swift"];
}

public sealed class PointlessShiftRuleCss : PointlessShiftRule
{
    public override string Key => "QG-CSS-BUG-0040";
    public override string[] Languages => ["css"];
}

public sealed class PointlessShiftRuleHtml : PointlessShiftRule
{
    public override string Key => "QG-HTML-BUG-0040";
    public override string[] Languages => ["html"];
}

public sealed class PointlessShiftRuleXml : PointlessShiftRule
{
    public override string Key => "QG-XML-BUG-0015";
    public override string[] Languages => ["xml"];
}

public sealed class PointlessShiftRuleTerraform : PointlessShiftRule
{
    public override string Key => "QG-TF-BUG-0010";
    public override string[] Languages => ["tf"];
}

public sealed class PointlessShiftRuleDockerfile : PointlessShiftRule
{
    public override string Key => "QG-DK-BUG-0017";
    public override string[] Languages => ["dk"];
}

public sealed class PointlessShiftRuleKubernetes : PointlessShiftRule
{
    public override string Key => "QG-K8-BUG-0010";
    public override string[] Languages => ["k8"];
}

public sealed class PointlessShiftRuleCloudFormation : PointlessShiftRule
{
    public override string Key => "QG-CF-BUG-0010";
    public override string[] Languages => ["cf"];
}

public sealed class PointlessShiftRuleJson : PointlessShiftRule
{
    public override string Key => "QG-JSON-BUG-0011";
    public override string[] Languages => ["json"];
}

public abstract class LoopCounterMovesAwayFromBoundRule : CorrectnessRuleBase
{
    public override string Name => "A loop counter should move towards the bound that ends the loop";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            var condition = loop.Children.FirstOrDefault(c => c.Kind == NodeKind.Binary
                                                              && c.Text is "<" or "<=" or ">" or ">=");
            if (condition == null)
                continue;
            var counter = SyntaxQuery.DottedName(condition.ChildAt(0));
            if (counter.Length == 0)
                continue;

            var update = loop.Children.FirstOrDefault(c => c.Kind == NodeKind.Unary
                                                           && c.Text is "++" or "--"
                                                           && SyntaxQuery.DottedName(c.ChildAt(0)) == counter);
            if (update == null)
                continue;

            var goesUp = update.Text == "++";
            var needsUp = condition.Text is "<" or "<=";
            if (goesUp == needsUp)
                continue;

            context.Report(loop, $"'{counter}' moves {(goesUp ? "up" : "down")} while the loop runs as long "
                                 + $"as it stays {(needsUp ? "below" : "above")} the bound, so the condition "
                                 + "never becomes false. Reverse the update or the comparison.");
        }
    }
}

public sealed class LoopCounterMovesAwayFromBoundRuleCs : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-CS-BUG-0171";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleJava : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-JV-BUG-0225";
    public override string[] Languages => ["java"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleKotlin : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-KT-BUG-0052";
    public override string[] Languages => ["kt"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleJs : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-JS-BUG-0169";
    public override string[] Languages => ["js", "ts"];
}

public sealed class LoopCounterMovesAwayFromBoundRulePython : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-PY-BUG-0175";
    public override string[] Languages => ["py"];
}

public sealed class LoopCounterMovesAwayFromBoundRulePhp : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-PP-BUG-0072";
    public override string[] Languages => ["php"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleGo : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-GO-BUG-0028";
    public override string[] Languages => ["go"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleDart : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-DART-BUG-0026";
    public override string[] Languages => ["dart"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleRuby : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-RB-BUG-0012";
    public override string[] Languages => ["rb"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleSwift : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-SW-BUG-0016";
    public override string[] Languages => ["swift"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleCss : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-CSS-BUG-0041";
    public override string[] Languages => ["css"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleHtml : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-HTML-BUG-0041";
    public override string[] Languages => ["html"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleXml : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-XML-BUG-0016";
    public override string[] Languages => ["xml"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleTerraform : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-TF-BUG-0011";
    public override string[] Languages => ["tf"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleDockerfile : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-DK-BUG-0018";
    public override string[] Languages => ["dk"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleKubernetes : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-K8-BUG-0011";
    public override string[] Languages => ["k8"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleCloudFormation : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-CF-BUG-0011";
    public override string[] Languages => ["cf"];
}

public sealed class LoopCounterMovesAwayFromBoundRuleJson : LoopCounterMovesAwayFromBoundRule
{
    public override string Key => "QG-JSON-BUG-0012";
    public override string[] Languages => ["json"];
}

public abstract class LoopWithoutExitRule : CorrectnessRuleBase
{
    public override string Name => "An always-true loop should contain a way out";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (!IsAlwaysTrue(loop))
                continue;
            var body = loop.FirstChild(NodeKind.Block);
            if (body == null)
                continue;
            if (body.DescendantsAndSelf().Any(IsWayOut))
                continue;

            context.Report(loop, "This loop never ends: its condition is always true and the body contains "
                                 + "no break, return or throw. Add the exit that ends the work, or use a "
                                 + "condition that can become false.");
        }
    }

    private static bool IsAlwaysTrue(SyntaxNode loop)
    {
        var header = loop.Children.FirstOrDefault(c => c.Kind is not (NodeKind.Block or NodeKind.ParameterList));
        // `while (true)`, `for (;;)` and `loop` all read as "no condition that can fail"
        return header is null or { Kind: NodeKind.BooleanLiteral, Text: "true" or "True" };
    }

    private static bool IsWayOut(SyntaxNode node)
    {
        if (node.Kind == NodeKind.Jump)
        {
            return node.Text.StartsWith("break", StringComparison.Ordinal)
                   || node.Text.StartsWith("return", StringComparison.Ordinal)
                   || node.Text.StartsWith("goto", StringComparison.Ordinal)
                   || node.Text.StartsWith("yield", StringComparison.Ordinal);
        }
        // a throw is parsed as a statement in some dialects and as an expression in others
        return node.Text.StartsWith("throw", StringComparison.Ordinal)
               || (node.Kind == NodeKind.Invocation && SyntaxQuery.InvokedName(node) is "exit" or "Exit");
    }
}

public sealed class LoopWithoutExitRuleCs : LoopWithoutExitRule
{
    public override string Key => "QG-CS-BUG-0172";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class LoopWithoutExitRuleJava : LoopWithoutExitRule
{
    public override string Key => "QG-JV-BUG-0226";
    public override string[] Languages => ["java"];
}

public sealed class LoopWithoutExitRuleKotlin : LoopWithoutExitRule
{
    public override string Key => "QG-KT-BUG-0053";
    public override string[] Languages => ["kt"];
}

public sealed class LoopWithoutExitRuleJs : LoopWithoutExitRule
{
    public override string Key => "QG-JS-BUG-0170";
    public override string[] Languages => ["js", "ts"];
}

public sealed class LoopWithoutExitRulePython : LoopWithoutExitRule
{
    public override string Key => "QG-PY-BUG-0176";
    public override string[] Languages => ["py"];
}

public sealed class LoopWithoutExitRulePhp : LoopWithoutExitRule
{
    public override string Key => "QG-PP-BUG-0073";
    public override string[] Languages => ["php"];
}

public sealed class LoopWithoutExitRuleGo : LoopWithoutExitRule
{
    public override string Key => "QG-GO-BUG-0029";
    public override string[] Languages => ["go"];
}

public sealed class LoopWithoutExitRuleDart : LoopWithoutExitRule
{
    public override string Key => "QG-DART-BUG-0027";
    public override string[] Languages => ["dart"];
}

public sealed class LoopWithoutExitRuleRuby : LoopWithoutExitRule
{
    public override string Key => "QG-RB-BUG-0013";
    public override string[] Languages => ["rb"];
}

public sealed class LoopWithoutExitRuleSwift : LoopWithoutExitRule
{
    public override string Key => "QG-SW-BUG-0017";
    public override string[] Languages => ["swift"];
}

public sealed class LoopWithoutExitRuleCss : LoopWithoutExitRule
{
    public override string Key => "QG-CSS-BUG-0042";
    public override string[] Languages => ["css"];
}

public sealed class LoopWithoutExitRuleHtml : LoopWithoutExitRule
{
    public override string Key => "QG-HTML-BUG-0042";
    public override string[] Languages => ["html"];
}

public sealed class LoopWithoutExitRuleXml : LoopWithoutExitRule
{
    public override string Key => "QG-XML-BUG-0017";
    public override string[] Languages => ["xml"];
}

public sealed class LoopWithoutExitRuleTerraform : LoopWithoutExitRule
{
    public override string Key => "QG-TF-BUG-0012";
    public override string[] Languages => ["tf"];
}

public sealed class LoopWithoutExitRuleDockerfile : LoopWithoutExitRule
{
    public override string Key => "QG-DK-BUG-0019";
    public override string[] Languages => ["dk"];
}

public sealed class LoopWithoutExitRuleKubernetes : LoopWithoutExitRule
{
    public override string Key => "QG-K8-BUG-0012";
    public override string[] Languages => ["k8"];
}

public sealed class LoopWithoutExitRuleCloudFormation : LoopWithoutExitRule
{
    public override string Key => "QG-CF-BUG-0012";
    public override string[] Languages => ["cf"];
}

public sealed class LoopWithoutExitRuleJson : LoopWithoutExitRule
{
    public override string Key => "QG-JSON-BUG-0013";
    public override string[] Languages => ["json"];
}

public abstract class UselessIncrementRule : CorrectnessRuleBase
{
    public override string Name => "A value assigned to a local should be read before the local goes away";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var jump in context.Root.OfKind(NodeKind.Jump))
        {
            if (!jump.Text.StartsWith("return", StringComparison.Ordinal))
                continue;
            foreach (var unary in jump.Descendants().Where(d => d.Kind == NodeKind.Unary && d.Text is "++" or "--"))
            {
                // a post-increment inside a return computes the new value and then throws it away
                if (unary.Children.Count == 0 || !IsPostfix(unary))
                    continue;
                var operand = unary.ChildAt(0);
                var name = SyntaxQuery.DottedName(operand);
                // only a local or a parameter dies with the call; a field keeps the new value
                if (name.Length == 0 || operand?.Symbol is not { } symbol
                    || !(symbol.IsParameter || symbol.IsExplicitlyDeclared))
                    continue;

                context.Report(unary, $"'{name}{unary.Text}' returns the value from before the change, and "
                                      + $"'{name}' disappears with the call, so the {(unary.Text == "++" ? "increment" : "decrement")} "
                                      + "has no effect. Return the value you mean, and drop the operator.");
            }
        }
    }

    /// <summary>
    /// The parser marks a unary node at the operator, so an operand that starts before the node is the
    /// one the operator was applied to afterwards — that is exactly a postfix form.
    /// </summary>
    private static bool IsPostfix(SyntaxNode unary)
    {
        var operand = unary.ChildAt(0);
        if (operand == null)
            return false;
        return operand.Range.StartLine < unary.Range.StartLine
               || (operand.Range.StartLine == unary.Range.StartLine
                   && operand.Range.StartColumn < unary.Range.StartColumn);
    }
}

public sealed class UselessIncrementRuleCs : UselessIncrementRule
{
    public override string Key => "QG-CS-BUG-0173";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class UselessIncrementRuleJava : UselessIncrementRule
{
    public override string Key => "QG-JV-BUG-0227";
    public override string[] Languages => ["java"];
}

public sealed class UselessIncrementRuleKotlin : UselessIncrementRule
{
    public override string Key => "QG-KT-BUG-0054";
    public override string[] Languages => ["kt"];
}

public sealed class UselessIncrementRuleJs : UselessIncrementRule
{
    public override string Key => "QG-JS-BUG-0171";
    public override string[] Languages => ["js", "ts"];
}

public sealed class UselessIncrementRulePython : UselessIncrementRule
{
    public override string Key => "QG-PY-BUG-0177";
    public override string[] Languages => ["py"];
}

public sealed class UselessIncrementRulePhp : UselessIncrementRule
{
    public override string Key => "QG-PP-BUG-0074";
    public override string[] Languages => ["php"];
}

public sealed class UselessIncrementRuleGo : UselessIncrementRule
{
    public override string Key => "QG-GO-BUG-0030";
    public override string[] Languages => ["go"];
}

public sealed class UselessIncrementRuleDart : UselessIncrementRule
{
    public override string Key => "QG-DART-BUG-0028";
    public override string[] Languages => ["dart"];
}

public sealed class UselessIncrementRuleRuby : UselessIncrementRule
{
    public override string Key => "QG-RB-BUG-0014";
    public override string[] Languages => ["rb"];
}

public sealed class UselessIncrementRuleSwift : UselessIncrementRule
{
    public override string Key => "QG-SW-BUG-0018";
    public override string[] Languages => ["swift"];
}

public sealed class UselessIncrementRuleCss : UselessIncrementRule
{
    public override string Key => "QG-CSS-BUG-0043";
    public override string[] Languages => ["css"];
}

public sealed class UselessIncrementRuleHtml : UselessIncrementRule
{
    public override string Key => "QG-HTML-BUG-0043";
    public override string[] Languages => ["html"];
}

public sealed class UselessIncrementRuleXml : UselessIncrementRule
{
    public override string Key => "QG-XML-BUG-0018";
    public override string[] Languages => ["xml"];
}

public sealed class UselessIncrementRuleTerraform : UselessIncrementRule
{
    public override string Key => "QG-TF-BUG-0013";
    public override string[] Languages => ["tf"];
}

public sealed class UselessIncrementRuleDockerfile : UselessIncrementRule
{
    public override string Key => "QG-DK-BUG-0020";
    public override string[] Languages => ["dk"];
}

public sealed class UselessIncrementRuleKubernetes : UselessIncrementRule
{
    public override string Key => "QG-K8-BUG-0013";
    public override string[] Languages => ["k8"];
}

public sealed class UselessIncrementRuleCloudFormation : UselessIncrementRule
{
    public override string Key => "QG-CF-BUG-0013";
    public override string[] Languages => ["cf"];
}

public sealed class UselessIncrementRuleJson : UselessIncrementRule
{
    public override string Key => "QG-JSON-BUG-0014";
    public override string[] Languages => ["json"];
}
