using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Defects that live in Java test code: a test the runner silently skips, an assertion that can never
/// fail, a lifecycle method that runs in an order nobody chose. They are read from the annotations
/// rather than from the file name, because the annotation is what the runner itself looks at.
/// </summary>
public static class JavaTestRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PublicJUnit5MemberRuleJava(),
        new SilentlySkippedTestRuleJava(),
        new NestedTestClassRuleJava(),
        new CompetingTestAnnotationsRuleJava(),
        new OverloadedTestMethodRuleJava(),
        new LateAssertionContextRuleJava(),
        new RedundantArgumentMatcherRuleJava(),
        new RepeatedLifecycleHookRuleJava(),
        new AssertionAfterExpectedExceptionRuleJava(),
        new ExceptionTestWithSeveralCallsRuleJava(),
        new CheckedExceptionIdiomRuleJava(),
        new AssertionInsideCatchingTryRuleJava(),
        new AssertionInBackgroundRunRuleJava(),
        new UnannotatedFixtureMethodRuleJava()
    ];
}

public abstract class JavaTestRuleBase : TestRuleBase
{
    /// <summary>Annotations that make the runner treat a method as a test in its own right.</summary>
    protected static readonly string[] RunnableTestAnnotations =
        ["Test", "RepeatedTest", "ParameterizedTest", "TestFactory", "TestTemplate"];

    /// <summary>Annotations that make a method run around the tests rather than as one.</summary>
    protected static readonly string[] LifecycleAnnotations =
        ["Before", "After", "BeforeEach", "AfterEach", "BeforeAll", "AfterAll", "BeforeClass", "AfterClass"];

    public override string[] Languages => ["java"];

    protected static IEnumerable<SyntaxNode> Annotations(SyntaxNode declaration)
        => declaration.ChildrenOf(NodeKind.Attribute);

    protected static SyntaxNode? Annotation(SyntaxNode declaration, params string[] names)
        => Annotations(declaration).FirstOrDefault(a => names.Contains(a.Text, StringComparer.Ordinal));

    protected static bool Has(SyntaxNode declaration, params string[] names)
        => Annotation(declaration, names) != null;

    protected static string[] Modifiers(SyntaxNode declaration)
        => [.. declaration.ChildrenOf(NodeKind.Modifier).SelectMany(m => m.Text.Split(' ',
            StringSplitOptions.RemoveEmptyEntries))];

    /// <summary>Methods the runner would pick up, wherever in the file they are declared.</summary>
    protected static IEnumerable<SyntaxNode> TestMethods(SyntaxNode root)
        => root.OfKind(NodeKind.FunctionDeclaration).Where(m => Has(m, RunnableTestAnnotations));

    protected static IEnumerable<SyntaxNode> Classes(SyntaxNode root)
        => root.OfKind(NodeKind.ClassDeclaration);

    protected static IEnumerable<SyntaxNode> MethodsOf(SyntaxNode type)
        => type.FirstChild(NodeKind.Block) is { } body
            ? body.ChildrenOf(NodeKind.FunctionDeclaration)
            : [];

    /// <summary>
    /// Whether the file is written against the modern runner. Several rules only hold there — the
    /// older one required everything to be public, so applying them to it would be wrong advice.
    /// </summary>
    protected static bool TargetsJUnit5(IRuleContext context)
        => context.Root.OfKind(NodeKind.ImportDeclaration)
            .Any(i => i.Text.StartsWith("org.junit.jupiter", StringComparison.Ordinal));

    protected static bool IsAssertion(SyntaxNode invocation)
    {
        var name = SyntaxQuery.InvokedName(invocation);
        return name.StartsWith("assert", StringComparison.Ordinal)
               || name.StartsWith("verify", StringComparison.Ordinal)
               || name is "fail" or "assertThat";
    }
}

/// <summary>
/// The modern runner accepts any visibility except private, and package visibility is the convention.
/// A public test says "something outside this package calls me", which for a test is almost never true.
/// </summary>
public sealed class PublicJUnit5MemberRuleJava : JavaTestRuleBase
{
    public override string Key => "QG-JV-SML-0305";
    public override Severity Severity => Severity.Info;
    public override string RemediationEffort => "5min";
    public override string Name => "A test class or method should keep package visibility";

    public override void Execute(IRuleContext context)
    {
        if (!TargetsJUnit5(context))
            return;

        foreach (var method in TestMethods(context.Root)
                     .Concat(context.Root.OfKind(NodeKind.FunctionDeclaration)
                         .Where(m => Has(m, LifecycleAnnotations))))
        {
            if (Modifiers(method).FirstOrDefault(m => m is "public" or "protected") is { } visibility)
                Report(context, method, visibility, "method");
        }

        foreach (var type in Classes(context.Root))
        {
            if (!MethodsOf(type).Any(m => Has(m, RunnableTestAnnotations)))
                continue;
            if (Modifiers(type).FirstOrDefault(m => m is "public" or "protected") is { } visibility)
                Report(context, type, visibility, "class");
        }
    }

    private static void Report(IRuleContext context, SyntaxNode node, string visibility, string what)
        => context.Report(node, $"This test {what} is '{visibility}'. The runner does not need it, and "
                                + "package visibility is what tells the reader that nothing outside the "
                                + "package uses it. Remove the modifier.");
}

/// <summary>
/// The runner skips a private method, a static one and one that returns a value, and says nothing
/// about it. The test then sits in the file looking green while never having run.
/// </summary>
public sealed class SilentlySkippedTestRuleJava : JavaTestRuleBase
{
    public override string Key => "QG-JV-BUG-0117";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;
    public override string Name => "A test should not be silently ignored by the runner";

    public override void Execute(IRuleContext context)
    {
        if (!TargetsJUnit5(context))
            return;

        foreach (var method in TestMethods(context.Root))
        {
            var modifiers = Modifiers(method);
            var returns = method.FirstChild(NodeKind.TypeReference)?.Text;
            string? reason = null;
            if (modifiers.Contains("private"))
                reason = "it is private";
            else if (modifiers.Contains("static") && !Has(method, "TestFactory"))
                reason = "it is static";
            else if (returns is { Length: > 0 } and not "void" && !Has(method, "TestFactory"))
                reason = $"it returns '{returns}' instead of nothing";
            if (reason == null)
                continue;

            context.Report(method, $"The runner skips this test without a word because {reason}. Give it "
                                   + "package visibility, make it an instance method and let it return "
                                   + "nothing, or the suite reports green on a test that never ran.");
        }

        foreach (var type in Classes(context.Root))
        {
            if (!Has(type, "Nested") || !Modifiers(type).Contains("private"))
                continue;
            context.Report(type, "The runner skips this nested test class without a word because it is "
                                 + "private. Give it package visibility.");
        }
    }
}

/// <summary>
/// An inner class holding tests only runs when it is annotated as nested, and a static one annotated
/// as nested does not share the setup of the class around it. Both mistakes look identical in an IDE,
/// where the tests can still be started by hand.
/// </summary>
public sealed class NestedTestClassRuleJava : JavaTestRuleBase
{
    public override string Key => "QG-JV-BUG-0116";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;
    public override string Name => "An inner class holding tests should be annotated as nested";

    public override void Execute(IRuleContext context)
    {
        if (!TargetsJUnit5(context))
            return;

        foreach (var outer in Classes(context.Root))
        {
            foreach (var inner in (outer.FirstChild(NodeKind.Block)?.ChildrenOf(NodeKind.ClassDeclaration)
                                   ?? []))
            {
                if (!MethodsOf(inner).Any(m => Has(m, RunnableTestAnnotations)))
                    continue;

                var isStatic = Modifiers(inner).Contains("static");
                var nested = Has(inner, "Nested");
                if (!isStatic && !nested)
                {
                    context.Report(inner, "This inner class holds tests and is not annotated as nested, "
                                          + "so the build never runs them — only an IDE can, by hand. "
                                          + "Add the annotation.");
                }
                else if (isStatic && nested)
                {
                    context.Report(inner, "This class is static and annotated as nested, so it does not "
                                          + "share the setup and the state of the class around it. Drop "
                                          + "'static', or drop the annotation.");
                }
            }
        }
    }
}

/// <summary>
/// Two annotations that both start a test do not add up: the runner picks one, repeats the test an
/// unexpected number of times, or fails to resolve the parameters.
/// </summary>
public sealed class CompetingTestAnnotationsRuleJava : JavaTestRuleBase
{
    public override string Key => "QG-JV-BUG-0130";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string Name => "A test should carry one test annotation";

    public override void Execute(IRuleContext context)
    {
        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var carried = Annotations(method)
                .Select(a => a.Text)
                .Where(t => RunnableTestAnnotations.Contains(t, StringComparer.Ordinal))
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (carried.Length < 2)
                continue;

            context.Report(method, $"This test carries {string.Join(" and ", carried.Select(c => $"'@{c}'"))}, "
                                   + "which describe two different ways of running it. Keep the one that "
                                   + "matches what the test needs.");
        }
    }
}

/// <summary>
/// A test that checks many things fails for many reasons, and the failure no longer says which one.
/// The count is deliberately generous: this is about tests that grew into scripts.
/// </summary>
public sealed class OverloadedTestMethodRuleJava : JavaTestRuleBase
{
    private const int Limit = 25;

    public override string Key => "QG-JV-SML-0319";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "20min";
    public override string Name => "A test should not pile up assertions";

    public override void Execute(IRuleContext context)
    {
        foreach (var method in TestMethods(context.Root))
        {
            var body = SyntaxQuery.Body(method);
            if (body == null)
                continue;
            var assertions = SyntaxQuery.Invocations(body).Count(IsAssertion);
            if (assertions <= Limit)
                continue;

            context.ReportCosting($"This test makes {assertions} assertions against a limit of {Limit}. "
                                  + "A failure in the middle hides everything after it, so split the test "
                                  + "by the concept each group of assertions is about.",
                (assertions - Limit) * 2, method.Line);
        }
    }
}

/// <summary>
/// The description, the failure message and the comparator have to be set before the assertion runs.
/// Written after it they are simply never used, and the failure comes out with the default message.
/// </summary>
public sealed class LateAssertionContextRuleJava : JavaTestRuleBase
{
    private static readonly string[] ContextSetters =
        ["as", "describedAs", "withFailMessage", "overridingErrorMessage", "usingComparator",
            "usingRecursiveComparison", "withRepresentation"];

    public override string Key => "QG-JV-BUG-0119";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string Name => "The context of an assertion should be set before it runs";

    public override void Execute(IRuleContext context)
    {
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!ContextSetters.Contains(name, StringComparer.Ordinal))
                continue;

            // the receiver is the part of the chain written before this call: the assertion has
            // already happened if one of those links is the check itself
            var receiver = call.ChildAt(0)?.ChildAt(0);
            if (receiver == null || !StartsWithAssertThat(receiver) || !ChecksSomething(receiver))
                continue;

            context.Report(call, $"'{name}' is called after the assertion it describes, so it has nothing "
                                 + "left to change and the failure comes out with the default message. "
                                 + "Move it in front of the check.");
        }
    }

    private static bool StartsWithAssertThat(SyntaxNode chain)
        => chain.DescendantsAndSelf().Any(n => n.Kind == NodeKind.Invocation
                                               && SyntaxQuery.InvokedName(n) is "assertThat" or "assertThatObject");

    private static bool ChecksSomething(SyntaxNode chain)
        => chain.Kind == NodeKind.Invocation && SyntaxQuery.InvokedName(chain) is { Length: > 0 } name
           && (name.StartsWith("is", StringComparison.Ordinal)
               || name.StartsWith("has", StringComparison.Ordinal)
               || name.StartsWith("contains", StringComparison.Ordinal)
               || name.StartsWith("does", StringComparison.Ordinal)
               || name.StartsWith("starts", StringComparison.Ordinal)
               || name.StartsWith("ends", StringComparison.Ordinal)
               || name.StartsWith("matches", StringComparison.Ordinal));
}

/// <summary>
/// The mocking framework only needs the matcher wrapper when at least one argument is a real matcher.
/// Wrapping every argument says nothing more than passing the values themselves.
/// </summary>
public sealed class RedundantArgumentMatcherRuleJava : JavaTestRuleBase
{
    private static readonly string[] MockingCalls = ["verify", "when", "given", "doReturn", "doThrow"];

    public override string Key => "QG-JV-SML-0328";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";
    public override string Name => "An argument matcher should not wrap every argument";

    public override void Execute(IRuleContext context)
    {
        if (!context.Root.OfKind(NodeKind.ImportDeclaration)
                .Any(i => i.Text.Contains("mockito", StringComparison.OrdinalIgnoreCase)))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            foreach (var mocked in MockedCalls(call))
            {
                var arguments = SyntaxQuery.Arguments(mocked);
                if (arguments.Count == 0 || !arguments.All(IsEqMatcher))
                    continue;

                context.Report(mocked, "Every argument here is wrapped in the equality matcher, which is "
                                       + "only needed next to a real matcher. Pass the values directly.");
                break;
            }
        }
    }

    /// <summary>The calls whose arguments the mocking framework is matching, in either spelling.</summary>
    private static IEnumerable<SyntaxNode> MockedCalls(SyntaxNode call)
    {
        var path = SyntaxQuery.InvokedDottedName(call).Split('.');
        if (path.Length >= 2 && MockingCalls.Contains(path[^2], StringComparer.Ordinal))
            yield return call;

        if (!MockingCalls.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
            yield break;
        foreach (var inner in SyntaxQuery.Arguments(call).SelectMany(a => a.DescendantsAndSelf())
                     .Where(n => n.Kind == NodeKind.Invocation))
            yield return inner;
    }

    private static bool IsEqMatcher(SyntaxNode argument)
        => argument.Kind == NodeKind.Invocation && SyntaxQuery.InvokedName(argument) == "eq"
           && SyntaxQuery.Arguments(argument).Count == 1;
}

/// <summary>
/// Two setup methods of the same kind run in an order the runner does not promise. The suite passes
/// until the day the order flips, and then fails somewhere that has nothing to do with the change.
/// </summary>
public sealed class RepeatedLifecycleHookRuleJava : JavaTestRuleBase
{
    public override string Key => "QG-JV-BUG-0166";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string Name => "A test class should declare one lifecycle method of each kind";

    public override void Execute(IRuleContext context)
    {
        foreach (var type in Classes(context.Root))
        {
            var byKind = new Dictionary<string, List<SyntaxNode>>(StringComparer.Ordinal);
            foreach (var method in MethodsOf(type))
            {
                if (Annotation(method, LifecycleAnnotations) is not { } annotation)
                    continue;
                if (!byKind.TryGetValue(annotation.Text, out var found))
                    byKind[annotation.Text] = found = [];
                found.Add(method);
            }

            foreach (var (kind, methods) in byKind.Where(p => p.Value.Count > 1))
            {
                context.Report(methods[1], $"This class declares {methods.Count} '@{kind}' methods, and "
                                           + "the runner does not promise an order between them. Put the "
                                           + "setup in one method, or make the order explicit in code.");
            }
        }
    }
}

/// <summary>
/// When the annotation declares the expected exception, everything after the call that throws it is
/// dead: the assertions below read as if they run, and they never do.
/// </summary>
public sealed class AssertionAfterExpectedExceptionRuleJava : JavaTestRuleBase
{
    public override string Key => "QG-JV-SML-0302";
    public override Severity Severity => Severity.Major;
    public override string Name => "A test expecting an exception should not assert after it";

    public override void Execute(IRuleContext context)
    {
        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (Annotation(method, "Test") is not { } annotation)
                continue;
            if (!annotation.DescendantsAndSelf().Any(n => n.Text.Contains("expected", StringComparison.Ordinal)))
                continue;
            var body = SyntaxQuery.Body(method);
            if (body == null || !SyntaxQuery.Invocations(body).Any(IsAssertion))
                continue;

            context.Report(method, "This test declares the exception it expects on the annotation, so "
                                   + "nothing after the throwing call runs — the assertions below it are "
                                   + "dead. Assert the throw itself, and keep the other checks in their "
                                   + "own test.");
        }
    }
}

/// <summary>
/// When the call under test is nested inside another call, the assertion no longer says which of the
/// two is expected to throw — and it passes just the same if the wrong one does.
/// </summary>
public sealed class ExceptionTestWithSeveralCallsRuleJava : JavaTestRuleBase
{
    public override string Key => "QG-JV-SML-0303";
    public override Severity Severity => Severity.Major;
    public override string Name => "A throw should be asserted on one call only";

    public override void Execute(IRuleContext context)
    {
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (SyntaxQuery.InvokedName(call) is not ("assertThrows" or "assertThatThrownBy"))
                continue;
            var lambda = SyntaxQuery.Arguments(call).FirstOrDefault(a => a.Kind == NodeKind.Lambda);
            if (lambda == null)
                continue;

            var calls = lambda.DescendantsAndSelf().Count(n => n.Kind == NodeKind.Invocation);
            if (calls < 2)
                continue;

            context.Report(call, $"The code under this assertion makes {calls} calls, so the test passes "
                                 + "whichever of them throws. Prepare the value first and leave only the "
                                 + "call being tested inside.");
        }
    }
}

/// <summary>
/// The same defect written the older way: a try block that ends with a call to fail, holding more than
/// the one call whose throw is being tested.
/// </summary>
public sealed class CheckedExceptionIdiomRuleJava : JavaTestRuleBase
{
    public override string Key => "QG-JV-BUG-0115";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string Name => "A try-and-fail test should hold one call only";

    public override void Execute(IRuleContext context)
    {
        foreach (var tryStatement in context.Root.OfKind(NodeKind.Try))
        {
            var body = tryStatement.FirstChild(NodeKind.Block);
            if (body == null)
                continue;
            var calls = SyntaxQuery.Invocations(body).ToList();
            if (!calls.Any(c => SyntaxQuery.InvokedName(c) == "fail"))
                continue;
            // the call to fail is the marker, not one of the calls under test
            if (calls.Count(c => SyntaxQuery.InvokedName(c) != "fail") < 2)
                continue;

            context.Report(tryStatement, "This block tests a throw and makes more than one call, so it "
                                         + "passes whichever of them throws. Keep only the call under "
                                         + "test inside, or assert the throw directly.");
        }
    }
}

/// <summary>
/// A catch that swallows an assertion error also swallows the failure of the test: the call to fail
/// lands in the catch, and the test reports green whatever the code does.
/// </summary>
public sealed class AssertionInsideCatchingTryRuleJava : JavaTestRuleBase
{
    private static readonly string[] SwallowedTypes = ["AssertionError", "Throwable", "Error"];

    public override string Key => "QG-JV-BUG-0114";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string Name => "An assertion should not be caught by its own test";

    public override void Execute(IRuleContext context)
    {
        foreach (var tryStatement in context.Root.OfKind(NodeKind.Try))
        {
            var body = tryStatement.FirstChild(NodeKind.Block);
            if (body == null || !SyntaxQuery.Invocations(body).Any(IsAssertion))
                continue;

            var caught = tryStatement.ChildrenOf(NodeKind.Catch)
                .Select(c => c.FirstChild(NodeKind.TypeReference)?.Text ?? string.Empty)
                .FirstOrDefault(t => SwallowedTypes.Contains(t, StringComparer.Ordinal));
            if (caught == null)
                continue;

            context.Report(tryStatement, $"An assertion runs inside a block whose catch takes '{caught}', "
                                         + "so the failure this test is supposed to report is swallowed "
                                         + "by the test itself. Assert the throw directly instead.");
        }
    }
}

/// <summary>
/// An assertion that runs on another thread fails on that thread. The test that started it sees
/// nothing, finishes, and reports green.
/// </summary>
public sealed class AssertionInBackgroundRunRuleJava : JavaTestRuleBase
{
    public override string Key => "QG-JV-SML-0163";
    public override Severity Severity => Severity.Critical;
    public override string Name => "An assertion should not run on another thread";

    public override void Execute(IRuleContext context)
    {
        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (method.Text != "run" || SyntaxQuery.Parameters(method).Any())
                continue;
            var body = SyntaxQuery.Body(method);
            if (body == null)
                continue;

            foreach (var assertion in SyntaxQuery.Invocations(body).Where(IsAssertion))
            {
                context.Report(assertion, "This assertion runs inside 'run', so it fails on the thread "
                                          + "that executes it and not in the test that started it — the "
                                          + "suite stays green. Collect the result and assert it in the "
                                          + "test itself.");
                break;
            }
        }
    }
}

/// <summary>
/// A method named for a fixture, without the annotation that makes it one, is a setup that never runs.
/// The tests then fail on state nobody prepared, far from the method that was supposed to prepare it.
/// </summary>
public sealed class UnannotatedFixtureMethodRuleJava : JavaTestRuleBase
{
    private static readonly string[] FixtureNames = ["setUp", "tearDown", "setup", "teardown"];

    public override string Key => "QG-JV-SML-0308";
    public override Severity Severity => Severity.Major;
    public override string Name => "A fixture method should carry its lifecycle annotation";

    public override void Execute(IRuleContext context)
    {
        foreach (var type in Classes(context.Root))
        {
            if (!MethodsOf(type).Any(m => Has(m, RunnableTestAnnotations)))
                continue;

            foreach (var method in MethodsOf(type))
            {
                if (!FixtureNames.Contains(method.Text, StringComparer.Ordinal))
                    continue;
                if (Has(method, LifecycleAnnotations) || Has(method, "Override"))
                    continue;

                context.Report(method, $"'{method.Text}' is named for a fixture and carries no lifecycle "
                                       + "annotation, so the runner never calls it and every test starts "
                                       + "from state nobody prepared. Annotate it.");
            }
        }
    }
}
