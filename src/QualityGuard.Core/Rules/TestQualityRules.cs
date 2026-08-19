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
        new AssertionOnItselfRuleCs(),
        new AssertionOnItselfRuleJava(),
        new AssertionOnItselfRuleKotlin(),
        new AssertionOnItselfRuleJs(),
        new AssertionOnItselfRulePython(),
        new AssertionOnItselfRulePhp(),
        new AssertionOnItselfRuleGo(),
        new AssertionOnItselfRuleDart(),
        new AssertionOnItselfRuleRuby(),
        new AssertionOnItselfRuleSwift(),
        new AssertionOnItselfRuleCss(),
        new AssertionOnItselfRuleHtml(),
        new AssertionOnItselfRuleXml(),
        new AssertionOnItselfRuleTerraform(),
        new AssertionOnItselfRuleDockerfile(),
        new AssertionOnItselfRuleKubernetes(),
        new AssertionOnItselfRuleCloudFormation(),
        new AssertionOnItselfRuleJson(),
        new AssertionArgumentOrderRuleCs(),
        new AssertionArgumentOrderRuleJava(),
        new AssertionArgumentOrderRuleKotlin(),
        new AssertionArgumentOrderRuleJs(),
        new AssertionArgumentOrderRulePython(),
        new AssertionArgumentOrderRulePhp(),
        new AssertionArgumentOrderRuleGo(),
        new AssertionArgumentOrderRuleDart(),
        new AssertionArgumentOrderRuleRuby(),
        new AssertionArgumentOrderRuleSwift(),
        new AssertionArgumentOrderRuleCss(),
        new AssertionArgumentOrderRuleHtml(),
        new AssertionArgumentOrderRuleXml(),
        new AssertionArgumentOrderRuleTerraform(),
        new AssertionArgumentOrderRuleDockerfile(),
        new AssertionArgumentOrderRuleKubernetes(),
        new AssertionArgumentOrderRuleCloudFormation(),
        new AssertionArgumentOrderRuleJson(),
        new CompositeAssertionRuleCs(),
        new CompositeAssertionRuleJava(),
        new CompositeAssertionRuleKotlin(),
        new CompositeAssertionRuleJs(),
        new CompositeAssertionRulePython(),
        new CompositeAssertionRulePhp(),
        new CompositeAssertionRuleGo(),
        new CompositeAssertionRuleDart(),
        new CompositeAssertionRuleRuby(),
        new CompositeAssertionRuleSwift(),
        new CompositeAssertionRuleCss(),
        new CompositeAssertionRuleHtml(),
        new CompositeAssertionRuleXml(),
        new CompositeAssertionRuleTerraform(),
        new CompositeAssertionRuleDockerfile(),
        new CompositeAssertionRuleKubernetes(),
        new CompositeAssertionRuleCloudFormation(),
        new CompositeAssertionRuleJson(),
        new UndedicatedAssertionRuleCs(),
        new UndedicatedAssertionRuleJava(),
        new UndedicatedAssertionRuleKotlin(),
        new UndedicatedAssertionRuleJs(),
        new UndedicatedAssertionRulePython(),
        new UndedicatedAssertionRulePhp(),
        new UndedicatedAssertionRuleGo(),
        new UndedicatedAssertionRuleDart(),
        new UndedicatedAssertionRuleRuby(),
        new UndedicatedAssertionRuleSwift(),
        new UndedicatedAssertionRuleCss(),
        new UndedicatedAssertionRuleHtml(),
        new UndedicatedAssertionRuleXml(),
        new UndedicatedAssertionRuleTerraform(),
        new UndedicatedAssertionRuleDockerfile(),
        new UndedicatedAssertionRuleKubernetes(),
        new UndedicatedAssertionRuleCloudFormation(),
        new UndedicatedAssertionRuleJson(),
        new TestClassWithoutTestsRuleCs(),
        new TestClassWithoutTestsRuleRuby(),
        new TestClassWithoutTestsRuleSwift(),
        new TestClassWithoutTestsRuleCss(),
        new TestClassWithoutTestsRuleHtml(),
        new TestClassWithoutTestsRuleXml(),
        new TestClassWithoutTestsRuleTerraform(),
        new TestClassWithoutTestsRuleDockerfile(),
        new TestClassWithoutTestsRuleKubernetes(),
        new TestClassWithoutTestsRuleCloudFormation(),
        new TestClassWithoutTestsRuleJson(),
        new TestClassWithoutTestsRuleJava(),
        new TestClassWithoutTestsRuleKotlin(),
        new TestClassWithoutTestsRuleJs(),
        new TestClassWithoutTestsRulePython(),
        new TestClassWithoutTestsRulePhp(),
        new TestClassWithoutTestsRuleGo(),
        new TestClassWithoutTestsRuleDart()
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

    /// <summary>
    /// The same question when the tree cannot answer it: '@Test fun x()' written on one line does not
    /// reach the tree as an annotation, so the marker is looked for in the tokens of the line the
    /// function opens on and the line above it. Without this every Kotlin test class read as empty.
    /// </summary>
    protected static bool IsTestFunction(IRuleContext context, SyntaxNode function)
    {
        if (IsTestFunction(function))
            return true;
        foreach (var token in context.Tokens)
        {
            if (token.Line < function.Line - 1 || token.Line > function.Line)
                continue;
            if (token.Text.Length > 1 && token.Text[0] == '@'
                && TestAnnotations.Any(t => token.Text.Contains(t, StringComparison.OrdinalIgnoreCase)))
                return true;
            if (token.Text == "@")
                continue;
            if (TestAnnotations.Any(t => string.Equals(token.Text, t, StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
    }

    protected static bool IsTestFunction(SyntaxNode function)
        => function.ChildrenOf(NodeKind.Attribute).Any(a => TestAnnotations.Any(
               t => a.Text.Contains(t, StringComparison.OrdinalIgnoreCase)))
           || function.ChildrenOf(NodeKind.Annotation).Any(a => TestAnnotations.Any(
               t => a.Text.Contains(t, StringComparison.OrdinalIgnoreCase)))
           || function.Text.StartsWith("test", StringComparison.OrdinalIgnoreCase)
           || function.Text.StartsWith("should", StringComparison.OrdinalIgnoreCase)
           || function.Text.EndsWith("Test", StringComparison.Ordinal);
}

public abstract class AssertionOnItselfRule : TestRuleBase
{
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

public sealed class AssertionOnItselfRuleCs : AssertionOnItselfRule
{
    public override string Key => "QG-CS-BUG-0180";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class AssertionOnItselfRuleJava : AssertionOnItselfRule
{
    public override string Key => "QG-JV-BUG-0234";
    public override string[] Languages => ["java"];
}

public sealed class AssertionOnItselfRuleKotlin : AssertionOnItselfRule
{
    public override string Key => "QG-KT-BUG-0061";
    public override string[] Languages => ["kt"];
}

public sealed class AssertionOnItselfRuleJs : AssertionOnItselfRule
{
    public override string Key => "QG-JS-BUG-0178";
    public override string[] Languages => ["js", "ts"];
}

public sealed class AssertionOnItselfRulePython : AssertionOnItselfRule
{
    public override string Key => "QG-PY-BUG-0184";
    public override string[] Languages => ["py"];
}

public sealed class AssertionOnItselfRulePhp : AssertionOnItselfRule
{
    public override string Key => "QG-PP-BUG-0081";
    public override string[] Languages => ["php"];
}

public sealed class AssertionOnItselfRuleGo : AssertionOnItselfRule
{
    public override string Key => "QG-GO-BUG-0037";
    public override string[] Languages => ["go"];
}

public sealed class AssertionOnItselfRuleDart : AssertionOnItselfRule
{
    public override string Key => "QG-DART-BUG-0035";
    public override string[] Languages => ["dart"];
}

public sealed class AssertionOnItselfRuleRuby : AssertionOnItselfRule
{
    public override string Key => "QG-RB-BUG-0041";
    public override string[] Languages => ["rb"];
}

public sealed class AssertionOnItselfRuleSwift : AssertionOnItselfRule
{
    public override string Key => "QG-SW-BUG-0045";
    public override string[] Languages => ["swift"];
}

public sealed class AssertionOnItselfRuleCss : AssertionOnItselfRule
{
    public override string Key => "QG-CSS-BUG-0070";
    public override string[] Languages => ["css"];
}

public sealed class AssertionOnItselfRuleHtml : AssertionOnItselfRule
{
    public override string Key => "QG-HTML-BUG-0070";
    public override string[] Languages => ["html"];
}

public sealed class AssertionOnItselfRuleXml : AssertionOnItselfRule
{
    public override string Key => "QG-XML-BUG-0045";
    public override string[] Languages => ["xml"];
}

public sealed class AssertionOnItselfRuleTerraform : AssertionOnItselfRule
{
    public override string Key => "QG-TF-BUG-0040";
    public override string[] Languages => ["tf"];
}

public sealed class AssertionOnItselfRuleDockerfile : AssertionOnItselfRule
{
    public override string Key => "QG-DK-BUG-0047";
    public override string[] Languages => ["dk"];
}

public sealed class AssertionOnItselfRuleKubernetes : AssertionOnItselfRule
{
    public override string Key => "QG-K8-BUG-0040";
    public override string[] Languages => ["k8"];
}

public sealed class AssertionOnItselfRuleCloudFormation : AssertionOnItselfRule
{
    public override string Key => "QG-CF-BUG-0040";
    public override string[] Languages => ["cf"];
}

public sealed class AssertionOnItselfRuleJson : AssertionOnItselfRule
{
    public override string Key => "QG-JSON-BUG-0041";
    public override string[] Languages => ["json"];
}

public abstract class AssertionArgumentOrderRule : TestRuleBase
{
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

public sealed class AssertionArgumentOrderRuleCs : AssertionArgumentOrderRule
{
    public override string Key => "QG-CS-BUG-0181";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class AssertionArgumentOrderRuleJava : AssertionArgumentOrderRule
{
    public override string Key => "QG-JV-BUG-0235";
    public override string[] Languages => ["java"];
}

public sealed class AssertionArgumentOrderRuleKotlin : AssertionArgumentOrderRule
{
    public override string Key => "QG-KT-BUG-0062";
    public override string[] Languages => ["kt"];
}

public sealed class AssertionArgumentOrderRuleJs : AssertionArgumentOrderRule
{
    public override string Key => "QG-JS-BUG-0179";
    public override string[] Languages => ["js", "ts"];
}

public sealed class AssertionArgumentOrderRulePython : AssertionArgumentOrderRule
{
    public override string Key => "QG-PY-BUG-0185";
    public override string[] Languages => ["py"];
}

public sealed class AssertionArgumentOrderRulePhp : AssertionArgumentOrderRule
{
    public override string Key => "QG-PP-BUG-0082";
    public override string[] Languages => ["php"];
}

public sealed class AssertionArgumentOrderRuleGo : AssertionArgumentOrderRule
{
    public override string Key => "QG-GO-BUG-0038";
    public override string[] Languages => ["go"];
}

public sealed class AssertionArgumentOrderRuleDart : AssertionArgumentOrderRule
{
    public override string Key => "QG-DART-BUG-0036";
    public override string[] Languages => ["dart"];
}

public sealed class AssertionArgumentOrderRuleRuby : AssertionArgumentOrderRule
{
    public override string Key => "QG-RB-BUG-0042";
    public override string[] Languages => ["rb"];
}

public sealed class AssertionArgumentOrderRuleSwift : AssertionArgumentOrderRule
{
    public override string Key => "QG-SW-BUG-0046";
    public override string[] Languages => ["swift"];
}

public sealed class AssertionArgumentOrderRuleCss : AssertionArgumentOrderRule
{
    public override string Key => "QG-CSS-BUG-0071";
    public override string[] Languages => ["css"];
}

public sealed class AssertionArgumentOrderRuleHtml : AssertionArgumentOrderRule
{
    public override string Key => "QG-HTML-BUG-0071";
    public override string[] Languages => ["html"];
}

public sealed class AssertionArgumentOrderRuleXml : AssertionArgumentOrderRule
{
    public override string Key => "QG-XML-BUG-0046";
    public override string[] Languages => ["xml"];
}

public sealed class AssertionArgumentOrderRuleTerraform : AssertionArgumentOrderRule
{
    public override string Key => "QG-TF-BUG-0041";
    public override string[] Languages => ["tf"];
}

public sealed class AssertionArgumentOrderRuleDockerfile : AssertionArgumentOrderRule
{
    public override string Key => "QG-DK-BUG-0048";
    public override string[] Languages => ["dk"];
}

public sealed class AssertionArgumentOrderRuleKubernetes : AssertionArgumentOrderRule
{
    public override string Key => "QG-K8-BUG-0041";
    public override string[] Languages => ["k8"];
}

public sealed class AssertionArgumentOrderRuleCloudFormation : AssertionArgumentOrderRule
{
    public override string Key => "QG-CF-BUG-0041";
    public override string[] Languages => ["cf"];
}

public sealed class AssertionArgumentOrderRuleJson : AssertionArgumentOrderRule
{
    public override string Key => "QG-JSON-BUG-0042";
    public override string[] Languages => ["json"];
}

public abstract class CompositeAssertionRule : TestRuleBase
{
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

public sealed class CompositeAssertionRuleCs : CompositeAssertionRule
{
    public override string Key => "QG-CS-SML-0536";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class CompositeAssertionRuleJava : CompositeAssertionRule
{
    public override string Key => "QG-JV-SML-0497";
    public override string[] Languages => ["java"];
}

public sealed class CompositeAssertionRuleKotlin : CompositeAssertionRule
{
    public override string Key => "QG-KT-SML-0119";
    public override string[] Languages => ["kt"];
}

public sealed class CompositeAssertionRuleJs : CompositeAssertionRule
{
    public override string Key => "QG-JS-SML-0413";
    public override string[] Languages => ["js", "ts"];
}

public sealed class CompositeAssertionRulePython : CompositeAssertionRule
{
    public override string Key => "QG-PY-SML-0292";
    public override string[] Languages => ["py"];
}

public sealed class CompositeAssertionRulePhp : CompositeAssertionRule
{
    public override string Key => "QG-PP-SML-0157";
    public override string[] Languages => ["php"];
}

public sealed class CompositeAssertionRuleGo : CompositeAssertionRule
{
    public override string Key => "QG-GO-SML-0071";
    public override string[] Languages => ["go"];
}

public sealed class CompositeAssertionRuleDart : CompositeAssertionRule
{
    public override string Key => "QG-DART-SML-0036";
    public override string[] Languages => ["dart"];
}

public sealed class CompositeAssertionRuleRuby : CompositeAssertionRule
{
    public override string Key => "QG-RB-SML-0067";
    public override string[] Languages => ["rb"];
}

public sealed class CompositeAssertionRuleSwift : CompositeAssertionRule
{
    public override string Key => "QG-SW-SML-0051";
    public override string[] Languages => ["swift"];
}

public sealed class CompositeAssertionRuleCss : CompositeAssertionRule
{
    public override string Key => "QG-CSS-SML-0072";
    public override string[] Languages => ["css"];
}

public sealed class CompositeAssertionRuleHtml : CompositeAssertionRule
{
    public override string Key => "QG-HTML-SML-0144";
    public override string[] Languages => ["html"];
}

public sealed class CompositeAssertionRuleXml : CompositeAssertionRule
{
    public override string Key => "QG-XML-SML-0059";
    public override string[] Languages => ["xml"];
}

public sealed class CompositeAssertionRuleTerraform : CompositeAssertionRule
{
    public override string Key => "QG-TF-SML-0051";
    public override string[] Languages => ["tf"];
}

public sealed class CompositeAssertionRuleDockerfile : CompositeAssertionRule
{
    public override string Key => "QG-DK-SML-0065";
    public override string[] Languages => ["dk"];
}

public sealed class CompositeAssertionRuleKubernetes : CompositeAssertionRule
{
    public override string Key => "QG-K8-SML-0059";
    public override string[] Languages => ["k8"];
}

public sealed class CompositeAssertionRuleCloudFormation : CompositeAssertionRule
{
    public override string Key => "QG-CF-SML-0052";
    public override string[] Languages => ["cf"];
}

public sealed class CompositeAssertionRuleJson : CompositeAssertionRule
{
    public override string Key => "QG-JSON-SML-0047";
    public override string[] Languages => ["json"];
}

public abstract class UndedicatedAssertionRule : TestRuleBase
{
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

public sealed class UndedicatedAssertionRuleCs : UndedicatedAssertionRule
{
    public override string Key => "QG-CS-SML-0537";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class UndedicatedAssertionRuleJava : UndedicatedAssertionRule
{
    public override string Key => "QG-JV-SML-0498";
    public override string[] Languages => ["java"];
}

public sealed class UndedicatedAssertionRuleKotlin : UndedicatedAssertionRule
{
    public override string Key => "QG-KT-SML-0120";
    public override string[] Languages => ["kt"];
}

public sealed class UndedicatedAssertionRuleJs : UndedicatedAssertionRule
{
    public override string Key => "QG-JS-SML-0414";
    public override string[] Languages => ["js", "ts"];
}

public sealed class UndedicatedAssertionRulePython : UndedicatedAssertionRule
{
    public override string Key => "QG-PY-SML-0293";
    public override string[] Languages => ["py"];
}

public sealed class UndedicatedAssertionRulePhp : UndedicatedAssertionRule
{
    public override string Key => "QG-PP-SML-0158";
    public override string[] Languages => ["php"];
}

public sealed class UndedicatedAssertionRuleGo : UndedicatedAssertionRule
{
    public override string Key => "QG-GO-SML-0072";
    public override string[] Languages => ["go"];
}

public sealed class UndedicatedAssertionRuleDart : UndedicatedAssertionRule
{
    public override string Key => "QG-DART-SML-0037";
    public override string[] Languages => ["dart"];
}

public sealed class UndedicatedAssertionRuleRuby : UndedicatedAssertionRule
{
    public override string Key => "QG-RB-SML-0068";
    public override string[] Languages => ["rb"];
}

public sealed class UndedicatedAssertionRuleSwift : UndedicatedAssertionRule
{
    public override string Key => "QG-SW-SML-0052";
    public override string[] Languages => ["swift"];
}

public sealed class UndedicatedAssertionRuleCss : UndedicatedAssertionRule
{
    public override string Key => "QG-CSS-SML-0073";
    public override string[] Languages => ["css"];
}

public sealed class UndedicatedAssertionRuleHtml : UndedicatedAssertionRule
{
    public override string Key => "QG-HTML-SML-0145";
    public override string[] Languages => ["html"];
}

public sealed class UndedicatedAssertionRuleXml : UndedicatedAssertionRule
{
    public override string Key => "QG-XML-SML-0060";
    public override string[] Languages => ["xml"];
}

public sealed class UndedicatedAssertionRuleTerraform : UndedicatedAssertionRule
{
    public override string Key => "QG-TF-SML-0052";
    public override string[] Languages => ["tf"];
}

public sealed class UndedicatedAssertionRuleDockerfile : UndedicatedAssertionRule
{
    public override string Key => "QG-DK-SML-0066";
    public override string[] Languages => ["dk"];
}

public sealed class UndedicatedAssertionRuleKubernetes : UndedicatedAssertionRule
{
    public override string Key => "QG-K8-SML-0060";
    public override string[] Languages => ["k8"];
}

public sealed class UndedicatedAssertionRuleCloudFormation : UndedicatedAssertionRule
{
    public override string Key => "QG-CF-SML-0053";
    public override string[] Languages => ["cf"];
}

public sealed class UndedicatedAssertionRuleJson : UndedicatedAssertionRule
{
    public override string Key => "QG-JSON-SML-0048";
    public override string[] Languages => ["json"];
}

public abstract class TestClassWithoutTestsRule : TestRuleBase
{
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
            if (functions.Count == 0 || functions.Any(f => IsTestFunction(context, f)))
                continue;

            context.Report(type, $"'{type.Text}' is named as a test class but holds no test: the suite runs "
                                 + "green without ever exercising what this file is about. Add the test, or "
                                 + "give the class a name that says what it really is.");
        }
    }
}

public sealed class TestClassWithoutTestsRuleCs : TestClassWithoutTestsRule
{
    public override string Key => "QG-CS-SML-0538";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class TestClassWithoutTestsRuleJava : TestClassWithoutTestsRule
{
    public override string Key => "QG-JV-SML-0499";
    public override string[] Languages => ["java"];
}

public sealed class TestClassWithoutTestsRuleKotlin : TestClassWithoutTestsRule
{
    public override string Key => "QG-KT-SML-0121";
    public override string[] Languages => ["kt"];
}

public sealed class TestClassWithoutTestsRuleJs : TestClassWithoutTestsRule
{
    public override string Key => "QG-JS-SML-0415";
    public override string[] Languages => ["js", "ts"];
}

public sealed class TestClassWithoutTestsRulePython : TestClassWithoutTestsRule
{
    public override string Key => "QG-PY-SML-0294";
    public override string[] Languages => ["py"];
}

public sealed class TestClassWithoutTestsRulePhp : TestClassWithoutTestsRule
{
    public override string Key => "QG-PP-SML-0159";
    public override string[] Languages => ["php"];
}

public sealed class TestClassWithoutTestsRuleGo : TestClassWithoutTestsRule
{
    public override string Key => "QG-GO-SML-0073";
    public override string[] Languages => ["go"];
}

public sealed class TestClassWithoutTestsRuleDart : TestClassWithoutTestsRule
{
    public override string Key => "QG-DART-SML-0038";
    public override string[] Languages => ["dart"];
}

public sealed class TestClassWithoutTestsRuleRuby : TestClassWithoutTestsRule
{
    public override string Key => "QG-RB-SML-0069";
    public override string[] Languages => ["rb"];
}

public sealed class TestClassWithoutTestsRuleSwift : TestClassWithoutTestsRule
{
    public override string Key => "QG-SW-SML-0053";
    public override string[] Languages => ["swift"];
}

public sealed class TestClassWithoutTestsRuleCss : TestClassWithoutTestsRule
{
    public override string Key => "QG-CSS-SML-0074";
    public override string[] Languages => ["css"];
}

public sealed class TestClassWithoutTestsRuleHtml : TestClassWithoutTestsRule
{
    public override string Key => "QG-HTML-SML-0146";
    public override string[] Languages => ["html"];
}

public sealed class TestClassWithoutTestsRuleXml : TestClassWithoutTestsRule
{
    public override string Key => "QG-XML-SML-0061";
    public override string[] Languages => ["xml"];
}

public sealed class TestClassWithoutTestsRuleTerraform : TestClassWithoutTestsRule
{
    public override string Key => "QG-TF-SML-0053";
    public override string[] Languages => ["tf"];
}

public sealed class TestClassWithoutTestsRuleDockerfile : TestClassWithoutTestsRule
{
    public override string Key => "QG-DK-SML-0067";
    public override string[] Languages => ["dk"];
}

public sealed class TestClassWithoutTestsRuleKubernetes : TestClassWithoutTestsRule
{
    public override string Key => "QG-K8-SML-0061";
    public override string[] Languages => ["k8"];
}

public sealed class TestClassWithoutTestsRuleCloudFormation : TestClassWithoutTestsRule
{
    public override string Key => "QG-CF-SML-0054";
    public override string[] Languages => ["cf"];
}

public sealed class TestClassWithoutTestsRuleJson : TestClassWithoutTestsRule
{
    public override string Key => "QG-JSON-SML-0049";
    public override string[] Languages => ["json"];
}
