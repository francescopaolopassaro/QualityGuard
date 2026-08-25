using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Python rules on loops that fight the language's own iteration tools, on async functions that
/// block, and on the small contracts a function signs with its callers.
/// </summary>
public static class PyStyleGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PyDictionaryItemsIterationRule(),
        new PyConstantDictionaryPopulationRule(),
        new PyNestedLoopVariableReuseRule(),
        new PyEnumerateInsteadOfRangeLenRule(),
        new PyMembershipOnNonContainerRule(),
        new PyBlockingSleepInAsyncRule(),
        new PyTupleLengthConsistencyRule(),
        new PyFlaskSendFileMetadataRule(),
    ];
}

public abstract class PyStyleGapRule : RuleBase
{
    public override string[] Languages => ["py"];

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>The loop variable name, read from the header tokens between for and in.</summary>
    protected static string? LoopVariable(SyntaxNode loop)
    {
        var header = loop.Tokens.TakeWhile(t => t.Text != "in").ToList();
        var index = header.FindIndex(t => t.Text == "for");
        return index >= 0 && index + 1 < header.Count ? header[index + 1].Text : null;
    }

    /// <summary>The iterated expression: the first child that is not the declared variable.</summary>
    protected static SyntaxNode? IteratedOver(SyntaxNode loop)
        => loop.Children.FirstOrDefault(c => c.Kind != NodeKind.VariableDeclaration);

    protected static string Called(SyntaxNode call) => SyntaxQuery.InvokedName(call);

    protected static IReadOnlyList<SyntaxNode> Args(SyntaxNode call) => SyntaxQuery.Arguments(call);
}

/// <summary>Indexing the dictionary inside the loop is items() done by hand.</summary>
public sealed class PyDictionaryItemsIterationRule : PyStyleGapRule
{
    public override string Key => "QG-PY-SML-0180";
    public override string Name => "Iterate key-value pairs with items()";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (loop.Text != "for")
                continue;
            var variable = LoopVariable(loop);
            var over = IteratedOver(loop);
            if (variable == null || over?.Kind != NodeKind.Identifier)
                continue;
            var body = loop.LastChild(NodeKind.Block);
            if (body == null)
                continue;
            // d[<the same key variable>] read anywhere in the body
            var lookup = body.OfKind(NodeKind.Index).Any(ix =>
                ix.ChildAt(0)?.Text == over.Text
                && ix.ChildAt(1)?.SourceText() == variable);
            if (!lookup || body.OfKind(NodeKind.Assignment).Any(a =>
                    a.ChildAt(0)?.Kind == NodeKind.Index
                    && a.ChildAt(0).ChildAt(1)?.SourceText() == variable))
                continue;
            context.Report(loop,
                $"The loop walks `{over.Text}` key by key and then indexes `{over.Text}[{variable}]` "
                + "to get each value back. `for key, value in " + over.Text + ".items()` hands you "
                + "both at once - no second lookup to keep in sync.");
        }
    }
}

/// <summary>Filling every key with one constant is what dict.fromkeys exists for.</summary>
public sealed class PyConstantDictionaryPopulationRule : PyStyleGapRule
{
    public override string Key => "QG-PY-SML-0181";
    public override string Name => "Populate constant-valued dictionaries with fromkeys";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (loop.Text != "for")
                continue;
            var variable = LoopVariable(loop);
            var over = IteratedOver(loop);
            var body = loop.LastChild(NodeKind.Block);
            if (variable == null || over == null || body?.Children.Count != 1)
                continue;
            if (body.Children[0] is not { Kind: NodeKind.ExpressionStatement } statement
                || statement.ChildAt(0) is not { Kind: NodeKind.Assignment } assignment)
                continue;
            var target = assignment.ChildAt(0);
            var value = assignment.ChildAt(1);
            if (target?.Kind != NodeKind.Index
                || target.ChildAt(0)?.Kind != NodeKind.Identifier
                || target.ChildAt(1)?.SourceText() != variable
                || value == null
                || !value.Kind.IsLiteralLike())
                continue;
            context.Report(loop,
                "This loop writes the same constant under every key. `dict.fromkeys(" + 
                over.SourceText() + ", <constant>)` builds the identical mapping in one call, and "
                + "the reader sees immediately that the values do not vary per key.");
        }
    }
}

internal static class PyKindExtensions
{
    public static bool IsLiteralLike(this NodeKind kind)
        => kind is NodeKind.StringLiteral or NodeKind.NumberLiteral or NodeKind.BooleanLiteral
            or NodeKind.NullLiteral;
}

/// <summary>An inner loop reusing the outer name silently discards the outer iteration.</summary>
public sealed class PyNestedLoopVariableReuseRule : PyStyleGapRule
{
    public override string Key => "QG-PY-SML-0206";
    public override string Name => "Loop variables should not be reused in nested loops";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var outer in context.Root.OfKind(NodeKind.Loop))
        {
            var outerName = LoopVariable(outer);
            if (outerName == null)
                continue;
            foreach (var inner in outer.Descendants().Where(n =>
                         n.Kind == NodeKind.Loop && n != outer))
            {
                if (LoopVariable(inner) != outerName)
                    continue;
                context.Report(inner,
                    $"This inner loop reuses `{outerName}`, so when it finishes the outer loop "
                    + "resumes with whatever the inner one left behind - the classic way an "
                    + "iteration quietly skips half its elements. Rename one of them; two lines "
                    + "now save an hour of debugging later.");
            }
        }
    }
}

/// <summary>range(len(x)) counts what enumerate would hand over directly.</summary>
public sealed class PyEnumerateInsteadOfRangeLenRule : PyStyleGapRule
{
    public override string Key => "QG-PY-SML-0211";
    public override string Name => "Unpack enumerate() instead of indexing by range(len)";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (loop.Text != "for")
                continue;
            var over = IteratedOver(loop);
            if (over?.Kind != NodeKind.Invocation || Called(over) != "range" || !Args(over).Any())
                continue;
            var argument = Args(over)[0];
            if (argument.Kind != NodeKind.Invocation || Called(argument) != "len"
                || !SyntaxQuery.Arguments(argument).Any())
                continue;
            var sequence = SyntaxQuery.Arguments(argument)[0].SourceText();
            var body = loop.LastChild(NodeKind.Block);
            var usesIndex = body != null && body.OfKind(NodeKind.Index).Any(ix =>
                ix.ChildAt(0)?.SourceText() == sequence);
            if (!usesIndex)
                continue;
            context.Report(loop,
                "`range(len(...))` plus indexing counts positions to reach values that "
                + $"`enumerate({sequence})` yields directly, together with their position - and "
                + "works on any iterable, not only the ones len() accepts.");
        }
    }
}

/// <summary>A membership test against a number can never be true; the right side was meant elsewhere.</summary>
public sealed class PyMembershipOnNonContainerRule : PyStyleGapRule
{
    public override string Key => "QG-PY-BUG-0048";
    public override string Name => "in and not in should be used on objects supporting them";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("in" or "not in"))
                continue;
            var right = binary.ChildAt(1);
            if (right?.Kind is NodeKind.NumberLiteral or NodeKind.BooleanLiteral)
                context.Report(binary,
                    "The right side of this membership test is a number or a boolean: they hold no "
                    + "members, so the comparison answers False forever - usually a sign the "
                    + "intended container was a list or tuple one level up.");
        }
    }
}

/// <summary>An async function calling time.sleep parks the whole event loop.</summary>
public sealed class PyBlockingSleepInAsyncRule : PyStyleGapRule
{
    public override string Key => "QG-PY-BUG-0084";
    public override string Name => "Use non-blocking sleep functions in asynchronous code";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var function in context.Root.OfKind(
                     NodeKind.FunctionDeclaration, NodeKind.LocalFunction))
        {
            // the parser does not always keep the async marker as a modifier node; the function's
            // own tokens are the honest source
            if (!function.Tokens.Any(t => t.Text == "async"))
                continue;
            var body = function.LastChild(NodeKind.Block);
            if (body == null)
                continue;
            foreach (var call in SyntaxQuery.Invocations(body))
            {
                if (Called(call) != "sleep"
                    || SyntaxQuery.Receiver(call) is not ("time" or "twisted.internet.reactor"))
                    continue;
                context.Report(call,
                    "time.sleep() inside async code blocks the event loop itself: every other "
                    + "task, timer and connection freezes for the whole nap. Await "
                    + "asyncio.sleep() instead - it suspends only this coroutine.");
            }
        }
    }
}

/// <summary>A function returning tuples of different lengths breaks unpacking on one branch.</summary>
public sealed class PyTupleLengthConsistencyRule : PyStyleGapRule
{
    public override string Key => "QG-PY-SML-0201";
    public override string Name => "Functions should return tuples of consistent length";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var function in context.Root.OfKind(
                     NodeKind.FunctionDeclaration, NodeKind.LocalFunction))
        {
            var body = function.LastChild(NodeKind.Block);
            if (body == null)
                continue;
            var returned = body.DescendantsAndSelf()
                .Where(c => c is { Kind: NodeKind.Jump, Text: "return" })
                .Select(r => r.ChildAt(0))
                .Where(v => v is ({ Kind: NodeKind.ListLiteral, Text: "tuple" })
                            or { Kind: NodeKind.Tuple })
                .Select(v => v!.Children.Count)
                .Distinct()
                .ToList();
            if (returned.Count <= 1)
                continue;
            context.Report(function,
                $"{function.Text} returns tuples of {string.Join(" and ", returned.OrderBy(l => l))} "
                + "elements on different paths: whichever caller unpacks the result breaks on one "
                + "branch. Pad or trim so every exit agrees on the shape.");
        }
    }
}

/// <summary>Serving a file without saying what it is pushes the guess onto the client.</summary>
public sealed class PyFlaskSendFileMetadataRule : PyStyleGapRule
{
    public override string Key => "QG-PY-BUG-0103";
    public override string Name => "send_file should specify mimetype or download_name";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!context.Root.OfKind(NodeKind.ImportDeclaration).Any(i =>
                i.Text.Contains("flask", StringComparison.Ordinal)))
            return;
        foreach (var invocation in SyntaxQuery.Invocations(context.Root))
        {
            if (Called(invocation) != "send_file")
                continue;
            var keywords = invocation.OfKind(NodeKind.NamedArgument)
                .Select(a => a.Text.Split('=')[0].Trim())
                .ToHashSet(StringComparer.Ordinal);
            if (keywords.Contains("mimetype") || keywords.Contains("download_name"))
                continue;
            context.Report(invocation,
                "send_file without mimetype guesses the content type from the file extension - "
                + "and without download_name it exposes your server's path as the client's filename. "
                + "Pass both explicitly; downloads then open correctly and carry the name users "
                + "expect.");
        }
    }
}
