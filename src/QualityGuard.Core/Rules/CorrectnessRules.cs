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
        new LoopWithAtMostOneIterationRule(),
        new NonsensicalSizeComparisonRule(),
        new CollectionPassedToItsOwnMethodRule(),
        new DiscardedPureResultRule(),
        new RepeatedUnaryOperatorRule(),
        new PointlessShiftRule(),
        new LoopCounterMovesAwayFromBoundRule(),
        new LoopWithoutExitRule(),
        new UselessIncrementRule()
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

public sealed class LoopWithAtMostOneIterationRule : CorrectnessRuleBase
{
    public override string Key => "QG-ALL-BUG-0016";
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

public sealed class NonsensicalSizeComparisonRule : CorrectnessRuleBase
{
    private static readonly string[] SizeNames =
        ["Count", "Length", "size", "length", "count", "len", "Size", "__len__"];

    public override string Key => "QG-ALL-BUG-0017";
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

public sealed class CollectionPassedToItsOwnMethodRule : CorrectnessRuleBase
{
    private static readonly string[] Suspicious =
    [
        "addAll", "AddRange", "removeAll", "RemoveAll", "retainAll", "containsAll", "contains", "Contains",
        "add", "Add", "remove", "Remove", "push", "extend", "update", "concat", "Union", "Intersect",
        "Except", "SequenceEqual", "copyOf", "CopyTo", "putAll", "merge"
    ];

    public override string Key => "QG-ALL-BUG-0018";
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

public sealed class DiscardedPureResultRule : CorrectnessRuleBase
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

    public override string Key => "QG-ALL-BUG-0019";
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
            // an in-place variant exists in some libraries: only report when there is a receiver to keep
            if (SyntaxQuery.Receiver(call).Length == 0)
                continue;

            context.Report(call, $"'{name}' returns a new value and changes nothing, so this statement has "
                                 + "no effect. Assign the result, or remove the line.");
        }
    }
}

public sealed class RepeatedUnaryOperatorRule : CorrectnessRuleBase
{
    public override string Key => "QG-ALL-BUG-0020";
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

public sealed class PointlessShiftRule : CorrectnessRuleBase
{
    public override string Key => "QG-ALL-BUG-0021";
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

public sealed class LoopCounterMovesAwayFromBoundRule : CorrectnessRuleBase
{
    public override string Key => "QG-ALL-BUG-0022";
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

public sealed class LoopWithoutExitRule : CorrectnessRuleBase
{
    public override string Key => "QG-ALL-BUG-0023";
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

public sealed class UselessIncrementRule : CorrectnessRuleBase
{
    public override string Key => "QG-ALL-BUG-0024";
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
