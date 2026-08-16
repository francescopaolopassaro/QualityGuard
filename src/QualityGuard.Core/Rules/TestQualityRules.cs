using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Rules about the tests themselves. A test that cannot fail, or that fails with a message pointing
/// at the wrong value, costs more than no test at all: it occupies the place of the real one and
/// reports green while doing it.
/// </summary>
public static class TestQualityRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new AssertionOnItselfRule(),
        new AssertionArgumentOrderRule(),
        new CompositeAssertionRule(),
        new UndedicatedAssertionRule(),
        new TestClassWithoutTestsRule()
    ];
}

public abstract class TestRuleBase : RuleBase
{
    /// <summary>Assertions that take the two values being compared, in this order.</summary>
    protected static readonly string[] ComparingAssertions =
    [
        "assertEquals", "assertNotEquals", "assertSame", "assertNotSame", "assertArrayEquals",
        "AreEqual", "AreNotEqual", "AreSame", "AreNotSame", "assertEqual", "assertNotEqual",
        "assert_equal", "assertIs", "assertIsNot", "Same", "NotSame", "StrictEqual"
    ];

    /// <summary>Assertions that take a single condition.</summary>
    protected static readonly string[] BooleanAssertions =
        ["assertTrue", "assertFalse", "IsTrue", "IsFalse", "assert_true", "assert_false", "True", "False"];

    protected static readonly string[] TestAnnotations =
    [
        "Test", "ParameterizedTest", "RepeatedTest", "TestFactory", "TestTemplate", "Fact", "Theory",
        "TestMethod", "TestCase", "DataTestMethod", "Benchmark"
    ];

    public override string[] Languages => [];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "10min";

    protected static bool HasPreciseTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>True when the file is a test: rules here have nothing to say about production code.</summary>
    protected static bool IsTestCode(IRuleContext context)
        => Rules.Languages.LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName);

    protected static bool IsTestFunction(SyntaxNode function)
        => function.ChildrenOf(NodeKind.Attribute).Any(a => TestAnnotations.Any(
               t => a.Text.Contains(t, StringComparison.OrdinalIgnoreCase)))
           || function.ChildrenOf(NodeKind.Annotation).Any(a => TestAnnotations.Any(
               t => a.Text.Contains(t, StringComparison.OrdinalIgnoreCase)))
           || function.Text.StartsWith("test", StringComparison.OrdinalIgnoreCase)
           || function.Text.StartsWith("should", StringComparison.OrdinalIgnoreCase)
           || function.Text.EndsWith("Test", StringComparison.Ordinal);
}

public sealed class AssertionOnItselfRule : TestRuleBase
{
    public override string Key => "QG-ALL-BUG-0031";
    public override string Name => "An assertion should not compare a value with itself";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!ComparingAssertions.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;
            var arguments = SyntaxQuery.Arguments(call);
            if (arguments.Count < 2)
                continue;
            var first = arguments[0].SourceText().Trim();
            var second = arguments[1].SourceText().Trim();
            if (first.Length == 0 || first != second)
                continue;

            context.Report(call, $"This assertion compares '{first}' with itself, so it holds whatever the "
                                 + "code does. One of the two sides was meant to be the value produced by "
                                 + "the code under test.");
        }
    }
}

public sealed class AssertionArgumentOrderRule : TestRuleBase
{
    public override string Key => "QG-ALL-BUG-0032";
    public override string Name => "The expected value should come first in an assertion";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    /// <summary>Frameworks whose signature is assert(expected, actual).</summary>
    private static readonly string[] ExpectedFirst =
        ["assertEquals", "assertNotEquals", "assertSame", "assertArrayEquals", "AreEqual", "AreNotEqual"];

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("java" or "kt" or "cs" or "vb"))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!ExpectedFirst.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;
            var arguments = SyntaxQuery.Arguments(call);
            if (arguments.Count < 2)
                continue;
            // the constant is the expectation: when it sits second, the failure message names the two
            // values the wrong way round and sends the reader after the wrong one
            if (!SyntaxQuery.IsLiteral(arguments[1]) || SyntaxQuery.IsLiteral(arguments[0]))
                continue;

            context.Report(call, "The expected value is the second argument here. The framework prints it "
                                 + "as the actual one, so a failure describes the opposite of what happened; "
                                 + "swap the two arguments.");
        }
    }
}

public sealed class CompositeAssertionRule : TestRuleBase
{
    public override string Key => "QG-ALL-SML-0042";
    public override string Name => "An assertion should check one thing";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!BooleanAssertions.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;
            var arguments = SyntaxQuery.Arguments(call);
            if (arguments.Count == 0)
                continue;
            var condition = Unwrap(arguments[0]);
            if (condition is not { Kind: NodeKind.Binary } || condition.Text is not ("&&" or "and" or "&"))
                continue;

            context.Report(call, "This assertion checks two conditions at once, so a failure does not say "
                                 + "which one broke. Split it into one assertion per condition.");
        }
    }

    private static SyntaxNode? Unwrap(SyntaxNode node)
        => node.Kind == NodeKind.Parenthesized ? node.ChildAt(0) : node;
}

public sealed class UndedicatedAssertionRule : TestRuleBase
{
    public override string Key => "QG-ALL-SML-0043";
    public override string Name => "A comparison inside a boolean assertion should use the dedicated assertion";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!BooleanAssertions.Contains(name, StringComparer.Ordinal))
                continue;
            var arguments = SyntaxQuery.Arguments(call);
            if (arguments.Count == 0)
                continue;
            var condition = arguments[0].Kind == NodeKind.Parenthesized ? arguments[0].ChildAt(0) : arguments[0];
            if (condition is not { Kind: NodeKind.Binary } || condition.Text is not ("==" or "!=" or "==="))
                continue;

            var comparesNull = condition.Children.Any(c => c.Kind == NodeKind.NullLiteral);
            var suggestion = comparesNull ? "the null assertion" : "the equality assertion";
            context.Report(call, $"A comparison inside '{name}' loses both values: the failure only says "
                                 + $"that false is not true. Use {suggestion}, which prints what was "
                                 + "expected and what was found.");
        }
    }
}

public sealed class TestClassWithoutTestsRule : TestRuleBase
{
    public override string Key => "QG-ALL-SML-0044";
    public override string Name => "A test class should contain at least one test";
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || !IsTestCode(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!type.Text.EndsWith("Test", StringComparison.Ordinal)
                && !type.Text.EndsWith("Tests", StringComparison.Ordinal)
                && !type.Text.EndsWith("Spec", StringComparison.Ordinal))
                continue;
            if (type.ChildrenOf(NodeKind.Modifier).Any(m => m.Text is "abstract"))
                continue;

            var functions = type.OfKind(NodeKind.FunctionDeclaration)
                .Where(f => f.Ancestor(NodeKind.ClassDeclaration) == type)
                .ToList();
            if (functions.Count == 0 || functions.Any(IsTestFunction))
                continue;

            context.Report(type, $"'{type.Text}' is named as a test class but holds no test: the suite runs "
                                 + "green without ever exercising what this file is about. Add the test, or "
                                 + "give the class a name that says what it really is.");
        }
    }
}
