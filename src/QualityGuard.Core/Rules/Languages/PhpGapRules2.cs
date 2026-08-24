using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// PHP rules on the shapes the interpreter forgives at load time and punishes at run time: a catch
/// that names nothing throwable, an exception too generic to mean anything, a variable read before
/// anyone wrote it, and references smuggled through call sites.
/// </summary>
public static class PhpGapRuleSet2
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PhpDuplicateCatchTypeRule(),
        new PhpGenericExceptionThrownRule(),
        new PhpSetAccessibleRule(),
        new PhpForInvariantStopConditionRule(),
    ];
}

public abstract class PhpGapRule : RuleBase
{
    public override string[] Languages => ["php"];

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static string Called(SyntaxNode call) => SyntaxQuery.InvokedName(call);

    protected static IReadOnlyList<SyntaxNode> Args(SyntaxNode call) => SyntaxQuery.Arguments(call);

    protected static HashSet<string> ModifiersOf(SyntaxNode declaration)
        => declaration.Children.Where(c => c.Kind == NodeKind.Modifier)
            .Select(c => c.Text).ToHashSet(StringComparer.Ordinal);

    /// <summary>PHP identifiers keep their dollar sign; comparisons use the raw token text.</summary>
    protected static string LocalName(string identifier) => identifier.TrimStart('$');
}

/// <summary>A second catch of the same class never runs: the first one took everything.</summary>
public sealed class PhpDuplicateCatchTypeRule : PhpGapRule
{
    public override string Key => "QG-PP-BUG-0134";
    public override string Name => "A catch should not duplicate a type already caught";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var tryNode in context.Root.OfKind(NodeKind.Try))
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var catchClause in tryNode.Children.Where(c => c.Kind == NodeKind.Catch))
            {
                var typeName = catchClause.Children
                    .FirstOrDefault(c => c.Kind == NodeKind.TypeReference)?.Text;
                if (typeName == null || !seen.Add(typeName))
                    context.Report(catchClause,
                        $"This catch repeats `{typeName}`, which an earlier clause in the same try "
                        + "already handles: control never reaches here, and whoever reads it "
                        + "assumes a distinction that does not exist. Remove the duplicate, or "
                        + "catch a genuinely different type.");
            }
        }
    }
}

/// <summary>A caught class that is not defined anywhere cannot be thrown by anything either.</summary>
public sealed class PhpUndefinedCaughtClassRule : PhpGapRule
{
    private static readonly HashSet<string> Builtins = new(StringComparer.Ordinal)
    {
        "Exception", "ErrorException", "Error", "TypeError", "ValueError", "ArgumentCountError",
        "ArithmeticError", "DivisionByZeroError", "UnhandledMatchError", "JsonException",
        "PDOException", "DOMException", "LogicException", "RuntimeException",
        "UnexpectedValueException", "OutOfBoundsException", "LengthException",
        "DomainException", "InvalidArgumentException", "OutOfRangeException",
        "BadFunctionCallException", "BadMethodCallException", "OverflowException",
        "RangeException", "UnderflowException", "Throwable"
    };

    public override string Key => "QG-PP-BUG-0135";
    public override string Name => "The class of a caught exception should be defined";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        // single-file scans have no index: without it every foreign class looks undefined
        if (context.Project.Types.Count == 0)
            return;
        foreach (var catchClause in context.Root.OfKind(NodeKind.Catch))
        {
            var typeName = catchClause.Children
                .FirstOrDefault(c => c.Kind == NodeKind.TypeReference)?.Text;
            if (typeName == null || typeName.Contains('|'))
                continue;
            var simple = typeName.Split('\\')[^1];
            if (Builtins.Contains(simple))
                continue;
            if (context.Project.Types.Any(t =>
                    t.Name.Equals(simple, StringComparison.OrdinalIgnoreCase)))
                continue;
            context.Report(catchClause,
                $"Nothing in this code base defines `{simple}`: if the name is misspelled the "
                + "clause silently catches nothing and the error escapes; if the class comes from a "
                + "dependency, say so with its namespace so the reader can find it.");
        }
    }
}


/// <summary>Throwing the base class says nothing; callers cannot catch for a reason.</summary>
public sealed class PhpGenericExceptionThrownRule : PhpGapRule
{
    private static readonly string[] Generic =
    [
        "Exception", "RuntimeException", "ErrorException"
    ];

    public override string Key => "QG-PP-SML-0301";
    public override string Name => "Generic exceptions should not be thrown";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var thrown in context.Root.OfKind(NodeKind.Jump).Where(j => j.Text == "throw"))
        {
            var creation = thrown.ChildAt(0);
            if (creation?.Kind != NodeKind.ObjectCreation)
                continue;
            var typeName = creation.Text.Split('\\')[^1];
            if (!Generic.Contains(typeName, StringComparer.Ordinal))
                continue;
            context.Report(thrown,
                $"A bare `{typeName}` forces every caller to handle it generically - they cannot "
                + "catch what happened because the type says nothing about it. Name a domain "
                + "exception (`ConfigurationMissing`, `PaymentRejected`) so recovery can be "
                + "specific.");
        }
    }
}


/// <summary>Forcing accessibility open breaks the encapsulation someone chose deliberately.</summary>
public sealed class PhpSetAccessibleRule : PhpGapRule
{
    public override string Key => "QG-PP-SML-0303";
    public override string Name => "Reflection should not increase accessibility";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        // test code reflects over private members on purpose - that is how private behaviour gets
        // tested without widening it; the rule protects production encapsulation
        if (LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
            return;
        foreach (var invocation in SyntaxQuery.Invocations(context.Root))
        {
            if (Called(invocation) != "setAccessible")
                continue;
            var enabled = Args(invocation).Count == 0
                          || Args(invocation)[0] is { Kind: NodeKind.BooleanLiteral, Text: "true" };
            if (!enabled)
                continue;
            context.Report(invocation,
                "setAccessible(true) reaches past private and protected: whatever invariant those "
                + "modifiers guard can now be broken from outside, and the next refactor of the "
                + "owning class will not know this call exists. Use the public API, or make the "
                + "member internal@visible deliberately instead of prying it open here.");
        }
    }
}

/// <summary>A stop condition nobody touches cannot change: the loop runs once or forever.</summary>
public sealed class PhpForInvariantStopConditionRule : PhpGapRule
{
    public override string Key => "QG-PP-SML-0304";
    public override string Name => "for loop stop conditions should be invariant";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (loop.Text != "for")
                continue;
            var condition = loop.Children.FirstOrDefault(c => c.Kind == NodeKind.Binary);
            if (condition == null)
                continue;
            var watched = condition.DescendantsAndSelf()
                .Where(n => n.Kind == NodeKind.Identifier)
                .Select(n => n.Text)
                .Distinct()
                .ToList();
            if (watched.Count == 0)
                continue;
            // the header's own update clause and the body both count: a name that appears once -
            // in the condition alone - is what makes the stop condition invariant
            var allNames = loop.DescendantsAndSelf()
                .Where(n => n.Kind == NodeKind.Identifier)
                .Select(n => n.Text)
                .ToList();
            var invariant = watched.FirstOrDefault(name =>
                allNames.Count(n => n == name) <= 1);
            if (invariant == null)
                continue;
            context.Report(condition,
                $"Nothing in this loop ever changes `{invariant}`, so its stop condition cannot "
                + "turn: the body runs once against a condition that was already false, or never "
                + "terminates. Advance the value the condition reads, or compare against "
                + "something the loop actually moves.");
        }
    }
}
