using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Kotlin idioms on the dedicated tree. The language has a way of writing almost everything more
/// directly than the Java habits it grew out of, and each rule here is one of those habits: a call
/// that hides an operator, a chain that builds a list nobody reads, a class that reimplements what
/// the language spells with one keyword.
/// </summary>
public static class KotlinIdiomRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new KotlinEqualsOperatorRule(),
        new KotlinFindComparedToNullRule(),
        new KotlinSizeComparedToZeroRule(),
        new KotlinExplicitItParameterRule(),
        new KotlinLiftReturnFromBranchesRule(),
        new KotlinWhenInsteadOfIfChainRule(),
        new KotlinAccessorPatternRule(),
        new KotlinSingleFunctionInterfaceRule(),
        new KotlinSamLambdaRule(),
        new KotlinSingletonObjectRule(),
        new KotlinPreconditionRule(),
        new KotlinDataClassArrayEqualityRule(),
        new KotlinSuspendReturningFlowRule(),
        new KotlinCoroutineScopeExtensionRule(),
        new KotlinMutableFlowExposureRule(),
        new KotlinUnusedSequenceOperationRule(),
        new KotlinUnusedFlowOperationRule(),
        new KotlinIgnoredOperationStatusRule(),
        new KotlinMultilineAnchorRegexRule(),
        new KotlinPreparedStatementIndexRule(),
        new KotlinGradleHardcodedVersionRule(),
        new KotlinGradleCorePluginIdRule(),
        new KotlinRedundantDataClassConstructorRule(),
        new KotlinUselessNullCheckRule(),
        new KotlinNotNullAssertionOnMapRule(),
        new KotlinDeprecatedUsageRule(),
        new KotlinGuavaImportRule(),
        new KotlinAbstractClassWithoutStateRule(),
    ];
}

/// <summary>Shared reading of the Kotlin tree: calls, arguments, modifiers and receivers.</summary>
public abstract class KotlinTreeRule : RuleBase
{
    public override string[] Languages => ["kt"];

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static string Called(SyntaxNode call) => SyntaxQuery.InvokedName(call);

    protected static IReadOnlyList<SyntaxNode> Args(SyntaxNode call) => SyntaxQuery.Arguments(call);

    protected static bool IsNull(SyntaxNode? node) => node is { Kind: NodeKind.NullLiteral };

    protected static bool IsNumber(SyntaxNode? node, string text)
        => node is { Kind: NodeKind.NumberLiteral } && node.Text == text;

    /// <summary>The modifier keywords written on a declaration.</summary>
    protected static HashSet<string> ModifiersOf(SyntaxNode declaration)
        => declaration.Children.Where(c => c.Kind == NodeKind.Modifier)
            .Select(c => c.Text).ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// The type the function extends, when it is an extension: the receiver sits before the
    /// parameter list and is kept as a type reference since the parser learned to keep it.
    /// </summary>
    protected static string? ExtensionReceiver(SyntaxNode function)
    {
        var children = function.Children;
        for (var i = 0; i < children.Count; i++)
        {
            if (children[i].Kind != NodeKind.ParameterList)
                continue;
            return i > 0 && children[i - 1] is { Kind: NodeKind.TypeReference } receiver
                ? receiver.Text
                : null;
        }
        return null;
    }

    /// <summary>The declared return type of a function, which follows its parameter list.</summary>
    protected static string? ReturnType(SyntaxNode function)
    {
        var seenParameters = false;
        foreach (var child in function.Children)
        {
            if (child.Kind == NodeKind.ParameterList)
                seenParameters = true;
            else if (seenParameters && child.Kind == NodeKind.TypeReference)
                return child.Text;
        }
        return null;
    }

    /// <summary>
    /// The calls of a fluent chain, from the outermost inwards. Whether a chain ever materialises
    /// its result is only visible by walking it to the receiver.
    /// </summary>
    protected static IEnumerable<SyntaxNode> Chain(SyntaxNode call)
    {
        var node = call;
        while (node != null)
        {
            if (node.Kind == NodeKind.Invocation)
                yield return node;
            var head = node.ChildAt(0);
            node = head?.Kind switch
            {
                NodeKind.Invocation => head,
                NodeKind.MemberSelect => head.ChildAt(0),
                _ => null
            };
        }
    }

    protected static bool IsKotlinFile(IRuleContext context)
        => context.File.Path.EndsWith(".kt", StringComparison.OrdinalIgnoreCase)
           || context.File.Path.EndsWith(".kts", StringComparison.OrdinalIgnoreCase);

    protected static bool IsGradleScript(IRuleContext context)
        => context.File.Path.EndsWith(".gradle.kts", StringComparison.OrdinalIgnoreCase)
           || context.File.Path.EndsWith(".gradle", StringComparison.OrdinalIgnoreCase);

    protected static bool IsStringLiteral(SyntaxNode? node) => node is { Kind: NodeKind.StringLiteral };

    protected static string StringValue(SyntaxNode literal)
        => literal.Text.Trim('"');
}

// ------------------------------------------------------- idiomatic replacements

/// <summary>Kotlin's == already means structural equality, so calling equals by name buys nothing.</summary>
public sealed class KotlinEqualsOperatorRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0066";
    public override string Name => "Structural equality should be tested with == or !=";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Called(call).Equals("equals", StringComparison.Ordinal)
                || Args(call).Count != 1
                || call.ChildAt(0)?.Kind != NodeKind.MemberSelect)
                continue;
            context.Report(call,
                "This call to equals() says in Java what Kotlin already says with ==. The operator "
                + "also tolerates null on either side, which equals() does not. Replace "
                + "a.equals(b) with a == b, or !a.equals(b) with a != b.");
        }
    }
}

/// <summary>A find compared against null is a predicate: any(), none() or contains() say it directly.</summary>
public sealed class KotlinFindComparedToNullRule : KotlinTreeRule
{
    private static readonly string[] Finders =
    [
        "find", "findLast", "firstOrNull", "lastOrNull", "singleOrNull", "indexOfFirst"
    ];

    public override string Key => "QG-KT-SML-0070";
    public override string Name => "A find result compared to null should be any, none or contains";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("==" or "!="))
                continue;
            var left = binary.ChildAt(0);
            var right = binary.ChildAt(1);
            var finder = FinderSide(left, right);
            if (finder != null)
                context.Report(binary,
                    $"Comparing the result of {finder}() to null asks whether the collection holds "
                    + "a matching element, and the standard library has a word for that. Use "
                    + "any { } for != null, none { } for == null, or contains(x) when a plain value "
                    + "is being looked for.");
        }
    }

    private static string? FinderSide(SyntaxNode? left, SyntaxNode? right)
    {
        if (IsNull(right) && left?.Kind == NodeKind.Invocation)
            return Finders.Contains(Called(left)) ? Called(left) : null;
        if (IsNull(left) && right?.Kind == NodeKind.Invocation)
            return Finders.Contains(Called(right)) ? Called(right) : null;
        return null;
    }
}

/// <summary>Comparing a size to zero is what isEmpty() and isNotEmpty() are spelled for.</summary>
public sealed class KotlinSizeComparedToZeroRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0071";
    public override string Name => "Emptiness should be asked with isEmpty or isNotEmpty";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("==" or "!="))
                continue;
            var left = binary.ChildAt(0);
            var right = binary.ChildAt(1);
            if (IsZeroTest(left, right, context) || IsZeroTest(right, left, context))
                context.Report(binary,
                    "Reading a size and comparing it to zero counts what isEmpty() answers without "
                    + "counting. Replace size == 0 with isEmpty(), and size != 0 with "
                    + "isNotEmpty().");
        }
    }

    private static bool IsZeroTest(SyntaxNode? candidate, SyntaxNode? other, IRuleContext context)
    {
        if (!IsNumber(other, "0"))
            return false;
        // arrays have no isEmpty(); without a known non-array type the comparison stays silent
        if (candidate is { Kind: NodeKind.MemberSelect } select
            && select.ChildAt(1) is { Text: "size" })
            return !LooksLikeArray(select.ChildAt(0), context);
        return candidate is { Kind: NodeKind.Invocation } call
               && Called(call) == "count"
               && Args(call).Count == 0;
    }

    private static bool LooksLikeArray(SyntaxNode? expression, IRuleContext context)
    {
        var type = context.Types.TypeOf(expression);
        return type != null && type.Contains("Array", StringComparison.Ordinal);
    }
}

/// <summary>A lambda parameter named it duplicates the implicit one and reads as noise.</summary>
public sealed class KotlinExplicitItParameterRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0075";
    public override string Name => "A lambda parameter should not be named it";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var lambda in context.Root.OfKind(NodeKind.Lambda))
        {
            var parameters = lambda.FirstChild(NodeKind.ParameterList);
            if (parameters?.Children.Any(p => p.Kind == NodeKind.Parameter
                                              && p.Text == "it") == true)
                context.Report(lambda,
                    "Writing the parameter as it -> shadows the implicit it every lambda already "
                    + "has, and a reader stops to ask whether they differ. Drop the declaration and "
                    + "use the implicit it, or give the parameter a name that says what it holds.");
        }
    }
}

/// <summary>Every branch returning is a single return whose expression is the condition.</summary>
public sealed class KotlinLiftReturnFromBranchesRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0058";
    public override string Name => "A return should be lifted out of branches that all return";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var body = SyntaxQuery.Body(function);
            if (body == null)
                continue;
            foreach (var statement in body.Children)
            {
                if (statement.Kind == NodeKind.If && AllPathsReturn(statement))
                    context.Report(statement,
                        "Both branches of this if end in a return, so the branching decides only "
                        + "what comes back. Lift the return in front of the if - return if (cond) "
                        + "a else b, or return when (x) { ... } - and the shape of the decision "
                        + "becomes visible.");
            }
        }
    }

    /// <summary>True when every path out of the branch ends in a return.</summary>
    private static bool AllPathsReturn(SyntaxNode branch)
    {
        // the first block is the then-arm; taking the last one here would read an else-less if as
        // two returning branches and flag every guard clause in the file
        var thenBlock = branch.Children.FirstOrDefault(c => c.Kind == NodeKind.Block);
        var elseClause = branch.Children.FirstOrDefault(c => c.Kind == NodeKind.Else);
        if (thenBlock == null || !EndsWithReturn(thenBlock))
            return false;
        var elseBlock = elseClause?.LastChild(NodeKind.Block);
        if (elseBlock == null || elseBlock.Children.Count == 0)
            return false;
        var last = elseBlock.Children[^1];
        if (last is { Kind: NodeKind.Jump, Text: "return" })
            return true;
        // else-if chains count: the inner if is itself the last thing on its path
        return last.Kind == NodeKind.If && AllPathsReturn(last);
    }

    private static bool EndsWithReturn(SyntaxNode block)
        => block.Children[^1] is { Kind: NodeKind.Jump, Text: "return" };
}

/// <summary>A chain of else-if over type tests is the exact job of when.</summary>
public sealed class KotlinWhenInsteadOfIfChainRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0059";
    public override string Name => "Chained if statements over types should be a when";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var statement in context.Root.OfKind(NodeKind.If))
            if (TypeTestsInChain(statement) >= 2)
                context.Report(statement,
                    "This if/else chain dispatches on types, which is what a when expression is "
                    + "written for. One when (value) { is Foo -> ... } lists the cases side by side, "
                    + "without the nesting that pushes each new case further right.");
    }

    private static int TypeTestsInChain(SyntaxNode statement)
    {
        var count = 0;
        var node = statement;
        while (node is { Kind: NodeKind.If })
        {
            if (node.ChildAt(0) is { Kind: NodeKind.Binary, Text: "is" })
                count++;
            var elseClause = node.Children.FirstOrDefault(c => c.Kind == NodeKind.Else);
            var elseBlock = elseClause?.LastChild(NodeKind.Block);
            node = elseBlock?.Children.FirstOrDefault(c => c.Kind == NodeKind.If);
        }
        return count;
    }
}

/// <summary>Java-style accessors hide what a Kotlin property writes directly.</summary>
public sealed class KotlinAccessorPatternRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0060";
    public override string Name => "A getter or setter pattern should be a property";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    private static bool IsAccessorName(string name, out string field)
    {
        field = string.Empty;
        if (name.Length <= 3)
            return false;
        var stem = name[..3];
        if (stem is not ("get" or "set") || !char.IsUpper(name[3]))
            return false;
        field = char.ToLowerInvariant(name[3]) + name[4..];
        return true;
    }

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var fields = type.Descendants()
                .Where(n => n.Kind == NodeKind.FieldDeclaration
                            && n.Ancestor(NodeKind.FunctionDeclaration) == null)
                .Select(n => n.Text).ToHashSet(StringComparer.Ordinal);
            foreach (var function in SyntaxQuery.Functions(type))
            {
                if (!IsAccessorName(function.Text, out var field)
                    || !fields.Contains(field))
                    continue;
                if (function.Text.StartsWith("get", StringComparison.Ordinal)
                    && BodyMentionsField(function, field))
                    Report(context, function, "get", field);
                else if (function.Text.StartsWith("set", StringComparison.Ordinal)
                         && AssignsField(function, field))
                    Report(context, function, "set", field);
            }
        }
    }

    private static bool BodyMentionsField(SyntaxNode function, string field)
        => function.FirstChild(NodeKind.ParameterList) is { Children.Count: 0 }
           && SyntaxQuery.Body(function) is { } body
           && body.Descendants().Any(n => n.Kind == NodeKind.Identifier && n.Text == field);

    private static bool AssignsField(SyntaxNode function, string field)
    {
        var parameters = function.FirstChild(NodeKind.ParameterList);
        if (parameters is null || parameters.Children.Count != 1)
            return false;
        return SyntaxQuery.Body(function) is { } body
               && body.OfKind(NodeKind.Assignment).Any(a =>
                   a.ChildAt(0) is { Kind: NodeKind.Identifier } target && target.Text == field);
    }

    private static void Report(IRuleContext context, SyntaxNode function, string kind, string field)
        => context.Report(function,
            $"This {kind}{char.ToUpperInvariant(field[0]) + field[1..]}() method is the Java "
            + $"spelling of a property. In Kotlin the same code reads as `var {field}: T` with its "
            + "custom get() and set() beside it, callers write the name without parentheses, and "
            + "the intent is visible at the declaration instead of buried in methods.");
}

/// <summary>An interface with exactly one abstract member accepts lambdas once declared fun.</summary>
public sealed class KotlinSingleFunctionInterfaceRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0064";
    public override string Name => "An interface with one function should be a functional interface";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var modifiers = ModifiersOf(type);
            if (!modifiers.Contains("interface") || modifiers.Contains("fun"))
                continue;
            var body = type.LastChild(NodeKind.Block);
            if (body == null)
                continue;
            var functions = body.Children.Where(c => c.Kind == NodeKind.FunctionDeclaration).ToList();
            if (functions.Count != 1
                || body.Children.Any(c => c.Kind == NodeKind.FieldDeclaration))
                continue;
            context.Report(type,
                $"This interface declares only {functions[0].Text}, so every call site that passes "
                + "one as a value has to spell out an object. Declaring it as `fun interface` lets "
                + "callers pass a lambda instead, and the call site says what it does rather than "
                + "how it is wired.");
        }
    }
}

/// <summary>A single-method object expression is the SAM case a lambda writes directly.</summary>
public sealed class KotlinSamLambdaRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0063";
    public override string Name => "A single-function instance should use SAM conversion";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            // the Java spelling is new X() { ... }; the Kotlin one is object : X { ... }.
            // Both carry their supertype as the first child.
            if (creation.ChildAt(0)?.Kind != NodeKind.TypeReference)
                continue;
            // interfaces take no constructor call - `object : Runnable { }`, never
            // `object : Runnable() { }` - so parentheses name a class, which no lambda replaces
            if (creation.FirstChild(NodeKind.ArgumentList) != null)
                continue;
            var body = creation.LastChild(NodeKind.Block);
            if (body == null)
                continue;
            var members = body.Children.ToList();
            if (members.Count != 1 || members[0].Kind != NodeKind.FunctionDeclaration)
                continue;
            context.Report(creation,
                $"This anonymous instance overrides just {members[0].Text}. Where the supertype is "
                + "a functional interface - Runnable, Comparator, a fun interface of your own - the "
                + "same value is a lambda: `Runnable { doIt() }`. The wiring disappears and what "
                + "remains is the behaviour that matters.");
        }
    }
}

/// <summary>The INSTANCE-field singleton is the Java spelling of a Kotlin object declaration.</summary>
public sealed class KotlinSingletonObjectRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0062";
    public override string Name => "The singleton pattern should use an object declaration";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            // a private constructor is either written out in the body or spelled on the primary:
            // `class Registry private constructor()` keeps its visibility on the type itself
            var hasPrivateCtor =
                type.Descendants().Any(n =>
                    n.Kind == NodeKind.ConstructorDeclaration && ModifiersOf(n).Contains("private"))
                || (ModifiersOf(type).Contains("private")
                    && type.FirstChild(NodeKind.ParameterList) != null);
            if (!hasPrivateCtor)
                continue;
            // Kotlin writes the construction without new: `Registry()` is an invocation
            var selfCreated = type.Descendants().FirstOrDefault(n =>
                n.Kind == NodeKind.FieldDeclaration
                && n.Text is ("INSTANCE" or "instance")
                && n.OfKind(NodeKind.ObjectCreation).Concat(n.OfKind(NodeKind.Invocation))
                    .Any(c => c.Text == type.Text));
            if (selfCreated != null)
                context.Report(selfCreated,
                    $"A private constructor plus a self-created {selfCreated.Text} field is how "
                    + "Java builds a singleton. Kotlin has the keyword for it: an `object` "
                    + "declaration gives you the single instance, its laziness and its thread "
                    + "safety from the language, instead of from this plumbing.");
        }
    }
}

/// <summary>Kotlin spells argument validation with require and check; a thrown if predates it.</summary>
public sealed class KotlinPreconditionRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0074";
    public override string Name => "Argument checks should use require, check or their NotNull helpers";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    private const string IllegalArgument = "IllegalArgumentException";
    private const string IllegalState = "IllegalStateException";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            // require(x != null) says in two words what requireNotNull(x) says in one
            var name = Called(call);
            if (name is "require" or "check"
                && Args(call).Count == 1
                && Args(call)[0] is { Kind: NodeKind.Binary } condition
                && condition.Text == "!="
                && IsPlainIdentifierVersusNull(condition))
                context.Report(call,
                    $"{name}(value != null) builds the message from a comparison that the library "
                    + $"already writes for you. Use {name}NotNull(value): the intent is named, the "
                    + "exception carries the value, and one less lambda-shaped thing is read.");
        }

        foreach (var branch in context.Root.OfKind(NodeKind.If))
        {
            if (branch.ChildAt(0) is not { Kind: NodeKind.Binary } test)
                continue;
            var thrown = ThrownExceptionName(branch);
            if (thrown == null)
                continue;

            if (test.Text == "=="
                && IsPlainIdentifierVersusNull(test)
                && thrown is IllegalArgument or IllegalState)
                context.Report(branch,
                    "An if that throws on null is the long form of a standard helper. Replace it "
                    + $"with requireNotNull(value) when the state is caller-supplied, or "
                    + $"checkNotNull(value) when it is this object's own invariant - both fail with "
                    + "the offending expression already named.");

            if (test.Text is "<" or "<=" or ">" or ">="
                && thrown == IllegalArgument
                && ComparesToLiteral(test))
                context.Report(branch,
                    "This if throws exactly what require(condition) throws, minus the readability: "
                    + "a reader sees the guard only after reading past the throw. Move the "
                    + "condition into require(...) and the function starts with its contract.");
        }
    }

    private static bool IsPlainIdentifierVersusNull(SyntaxNode binary)
        => (binary.ChildAt(0) is { Kind: NodeKind.Identifier } && IsNull(binary.ChildAt(1)))
           || (binary.ChildAt(1) is { Kind: NodeKind.Identifier } && IsNull(binary.ChildAt(0)));

    private static string? ThrownExceptionName(SyntaxNode branch)
    {
        var block = branch.LastChild(NodeKind.Block);
        if (block?.Children.Count != 1 || block.Children[0] is not { Kind: NodeKind.Jump } jump)
            return null;
        var thrown = jump.ChildAt(0);
        while (thrown?.Kind == NodeKind.Parenthesized)
            thrown = thrown.ChildAt(0);
        if (thrown is not { Kind: NodeKind.Invocation } invocation)
            return null;
        var name = BaseName(invocation);
        return name != null
               && (name.StartsWith(IllegalArgument, StringComparison.Ordinal)
                   || name.StartsWith(IllegalState, StringComparison.Ordinal))
            ? name
            : null;
    }

    private static string? BaseName(SyntaxNode invocation)
    {
        var text = invocation.Text;
        var open = text.IndexOf('(');
        return open > 0 ? text[..open] : text;
    }

    private static bool ComparesToLiteral(SyntaxNode binary)
        => binary.ChildAt(0)?.Kind is NodeKind.Identifier or NodeKind.MemberSelect
           && binary.ChildAt(1)?.Kind is NodeKind.NumberLiteral;
}

/// <summary>Data classes generate equals over references; array fields make that wrong silently.</summary>
public sealed class KotlinDataClassArrayEqualityRule : KotlinTreeRule
{
    public override string Key => "QG-KT-BUG-0027";
    public override string Name => "A data class with array fields should override equals and hashCode";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!ModifiersOf(type).Contains("data"))
                continue;
            var primary = type.FirstChild(NodeKind.ParameterList);
            if (primary == null || !primary.Children.Any(IsArrayParameter))
                continue;
            var body = type.LastChild(NodeKind.Block);
            if (body != null && body.Children.Any(c =>
                    c.Kind == NodeKind.FunctionDeclaration
                    && c.Text is "equals" or "hashCode"))
                continue;
            context.Report(type,
                $"The generated equals() of {type.Text} compares its array fields by reference, so "
                + "two instances holding identical content compare unequal - and they disappear "
                + "from sets and map lookups for no visible reason. Override equals() and "
                + "hashCode() to compare contentEquals / contentHashCode(), or hold List instead "
                + "of Array so the generated members are correct.");
        }
    }

    private static bool IsArrayParameter(SyntaxNode parameter)
        => parameter.Children.Any(c => c.Kind == NodeKind.TypeReference
                                       && c.Text.EndsWith("Array", StringComparison.Ordinal));
}

/// <summary>A flow is cold: suspending to hand one back blocks the caller without doing any work.</summary>
public sealed class KotlinSuspendReturningFlowRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0049";
    public override string Name => "A function returning Flow or Channel should not be suspending";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            if (!ModifiersOf(function).Contains("suspend"))
                continue;
            var returnType = ReturnType(function);
            if (returnType != null && IsFlowType(returnType))
                context.Report(function,
                    $"{function.Text} suspends and returns {returnType}, but building a flow does "
                    + "no work yet - the work happens at collection. The suspend modifier makes "
                    + "every call site wait in turn for something that finishes immediately. Drop "
                    + "the modifier, or return the flow directly and let flow { } do the "
                    + "suspending inside.");
        }
    }

    internal static bool IsFlowType(string type) => NormalizeTypeName(type) is "Flow" or "Channel"
        or "ReceiveChannel" or "SendChannel" or "MutableSharedFlow";

    private static string NormalizeTypeName(string type)
    {
        var genericStart = type.IndexOf('<');
        var name = genericStart > 0 ? type[..genericStart] : type;
        return name.Split('.', '+')[^1];
    }
}

/// <summary>An extension on CoroutineScope that suspends hides where the coroutine actually runs.</summary>
public sealed class KotlinCoroutineScopeExtensionRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0052";
    public override string Name => "An extension on CoroutineScope should not be suspending";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            if (!ModifiersOf(function).Contains("suspend"))
                continue;
            var receiver = ExtensionReceiver(function);
            if (receiver == null || !receiver.EndsWith("CoroutineScope", StringComparison.Ordinal))
                continue;
            context.Report(function,
                $"{receiver}.{function.Text}() blurs two different things: being inside a scope and "
                + "waiting for a result. Callers inherit whichever dispatcher happens to own the "
                + "receiver, and structured concurrency stops applying. Take the scope as a plain "
                + "parameter and launch explicitly, or drop suspend and let callers decide how the "
                + "work runs.");
        }
    }
}

/// <summary>A mutable state flow published as a property lets any caller corrupt the source.</summary>
public sealed class KotlinMutableFlowExposureRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0046";
    public override string Name => "MutableStateFlow and MutableSharedFlow should stay encapsulated";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var field in context.Root.OfKind(NodeKind.FieldDeclaration))
        {
            // the type may be written (`val s: MutableStateFlow<Int>`) or inferred from the
            // constructor call (`val s = MutableStateFlow(0)`); either spelling exposes it
            var declaresMutableFlow =
                field.Children.Any(c => c.Kind == NodeKind.TypeReference && IsMutableFlowType(c.Text))
                || field.OfKind(NodeKind.ObjectCreation).Concat(field.OfKind(NodeKind.Invocation))
                    .Any(c => IsMutableFlowType(c.Text));
            if (!declaresMutableFlow)
                continue;
            var modifiers = ModifiersOf(field);
            if (modifiers.Contains("private") || modifiers.Contains("protected")
                || modifiers.Contains("internal"))
                continue;
            context.Report(field,
                $"{field.Text} exposes a mutable flow: anyone who can see it can emit values into "
                + "your state machine and compete with its owner. Keep the mutable instance "
                + "private and publish it as StateFlow/SharedFlow - readers keep their updates, "
                + "and only the owning class decides what changes.");
        }
    }

    private static bool IsMutableFlowType(string text)
    {
        var name = text;
        var genericStart = name.IndexOf('<');
        if (genericStart > 0)
            name = name[..genericStart];
        return name is "MutableStateFlow" or "MutableSharedFlow";
    }
}

/// <summary>Shared reading for chains whose result is built and then dropped.</summary>
public abstract class KotlinUnusedIntermediateRule : KotlinTreeRule
{
    /// <summary>Operations that only reshape a sequence; none of them runs it.</summary>
    internal static readonly string[] Shaping =
    [
        "map", "mapIndexed", "mapNotNull", "filter", "filterNot", "filterIndexed",
        "filterNotNull", "flatMap", "flatMapIndexed", "distinct", "distinctBy", "sorted",
        "sortedBy", "sortedByDescending", "sortedDescending", "reversed", "take", "takeWhile",
        "takeLast", "drop", "dropWhile", "dropLast", "zip", "zipWithNext", "onEach", "chunked",
        "windowed", "flatten"
    ];

    /// <summary>Operations that exist only on flows, which is what makes them recognisable.</summary>
    internal static readonly string[] FlowShaping =
    [
        "debounce", "conflate", "buffer", "combine", "combineTransform", "flatMapLatest",
        "flatMapConcat", "flatMapMerge", "mapLatest", "sample", "transformWhile", "retryWhen"
    ];

    /// <summary>Operations that run a chain and produce something from it.</summary>
    internal static readonly string[] Running =
    [
        "toList", "toSet", "toMutableList", "toCollection", "toArray", "first", "firstOrNull",
        "last", "lastOrNull", "single", "singleOrNull", "count", "any", "none", "all", "sum",
        "sumOf", "max", "maxOf", "min", "minOf", "joinToString", "joinTo", "forEach",
        "forEachIndexed", "fold", "reduce", "associate", "associateBy", "associateWith",
        "groupBy", "partition", "elementAt", "find", "findLast", "contains", "iterator",
        "collect", "collectIndexed", "collectLatest", "launchIn", "produceIn", "shareIn",
        "stateIn", "asIterable", "average", "component1", "component2", "minByOrNull",
        "maxByOrNull", "indexOfFirst"
    ];

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var statement in context.Root.OfKind(NodeKind.ExpressionStatement))
        {
            var expression = statement.ChildAt(0);
            if (expression?.Kind != NodeKind.Invocation)
                continue;
            // as the last expression of a lambda or function the value is the return value
            if (statement.Parent?.Parent.Kind is NodeKind.Lambda
                    or NodeKind.FunctionDeclaration or NodeKind.LocalFunction
                && statement.Parent.Children[^1] == statement)
                continue;

            var chain = Chain(expression).ToList();
            if (chain.Any(c => Running.Contains(Called(c))))
                continue;
            var shapingOps = chain.Select(Called).Where(n => Shaping.Contains(n)).ToList();
            if (shapingOps.Count == 0)
                continue;
            var flowRoot = chain[^1].ChildAt(0)?.SourceText()
                ?.Contains("flow", StringComparison.OrdinalIgnoreCase) == true;
            var flowSpecific = shapingOps.Any(n => FlowShaping.Contains(n));
            Report(context, statement, shapingOps, flowRoot || flowSpecific);
        }
    }

    protected abstract void Report(IRuleContext context, SyntaxNode statement,
        List<string> operations, bool isFlowChain);
}

/// <summary>Sequence chains that are never run did nothing but allocate.</summary>
public sealed class KotlinUnusedSequenceOperationRule : KotlinUnusedIntermediateRule
{
    public override string Key => "QG-KT-BUG-0022";
    public override string Name => "The result of intermediate Sequence operations should be used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    protected override void Report(IRuleContext context, SyntaxNode statement,
        List<string> operations, bool isFlowChain)
    {
        if (isFlowChain)
            return; // the flow-specific rule owns those chains
        context.Report(statement,
            $"This statement builds {string.Join(" → ", operations.AsEnumerable().Reverse())} and "
            + "throws the result away: sequences are lazy, so not one element has even been read. "
            + "Assign it, pass it to a terminal operation such as toList() or first(), or delete "
            + "the line.");
    }
}

/// <summary>A flow nobody collects never emits: the pipeline exists only on paper.</summary>
public sealed class KotlinUnusedFlowOperationRule : KotlinUnusedIntermediateRule
{
    public override string Key => "QG-KT-BUG-0028";
    public override string Name => "The result of Flow operations should be collected";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    protected override void Report(IRuleContext context, SyntaxNode statement,
        List<string> operations, bool isFlowChain)
    {
        if (!isFlowChain)
            return;
        context.Report(statement,
            $"This pipeline ({string.Join(" → ", operations.AsEnumerable().Reverse())}) ends without "
            + "a collector: flows do no work until collect() - or launchIn(scope) - asks for values. "
            + "As written it starts nothing. Collect it, launch it in a scope, or remove it.");
    }
}

/// <summary>Some booleans answer a question callers cannot afford to ignore.</summary>
public sealed class KotlinIgnoredOperationStatusRule : KotlinTreeRule
{
    private static readonly string[] StatusReturns =
    [
        "delete", "deleteRecursively", "mkdir", "mkdirs", "renameTo", "setLastModified",
        "setReadable", "setWritable", "setExecutable", "setReadOnly", "tryLock", "offer"
    ];

    public override string Key => "QG-KT-BUG-0030";
    public override string Name => "An operation status should not be ignored";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var statement in context.Root.OfKind(NodeKind.ExpressionStatement))
        {
            if (statement.ChildAt(0) is not { Kind: NodeKind.Invocation } call
                || !StatusReturns.Contains(Called(call))
                || call.ChildAt(0)?.Kind != NodeKind.MemberSelect)
                continue;
            context.Report(call,
                $"{Called(call)}() reports whether anything actually happened, and this call drops "
                + "the answer: a failed delete becomes a file that is still there at the next "
                + "read, a failed mkdir becomes an exception pages later. Check the result and "
                + "decide what its failure means here.");
        }
    }
}

/// <summary>Multiline makes ^ and $ match every line; anchors alone then match empty ones.</summary>
public sealed class KotlinMultilineAnchorRegexRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0040";
    public override string Name => "Empty lines should not be tested with the MULTILINE flag";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = Called(call);
            if (name is not ("compile" or "Regex"))
                continue;
            var arguments = Args(call);
            var pattern = arguments.Count > 0 && IsStringLiteral(arguments[0])
                ? StringValue(arguments[0])
                : null;
            if (pattern == null)
                continue;
            var hadInlineFlags = StripInlineFlags(pattern, out var stripped);
            if (!HasMultilineFlag(arguments.Skip(1)) && !hadInlineFlags)
                continue;
            if (OnlyAnchors(stripped))
                context.Report(call,
                    "This pattern is made of anchors alone and relies on MULTILINE to mean \"an "
                    + "empty line\" - which also makes it match between every pair of lines in the "
                    + "text, blanks included. Test what you mean directly: split on newlines, or "
                    + "match \\n\\n when two breaks in a row are the actual question.");
        }
    }

    private static bool HasMultilineFlag(IEnumerable<SyntaxNode> arguments)
        => arguments.SelectMany(a => a.DescendantsAndSelf())
            .Any(n => n.Kind == NodeKind.MemberSelect && n.Text.EndsWith(".MULTILINE")
                      || n is { Kind: NodeKind.Identifier, Text: "MULTILINE" });

    private static bool StripInlineFlags(string pattern, out string stripped)
    {
        stripped = pattern;
        var start = 0;
        while (start < pattern.Length && char.IsWhiteSpace(pattern[start]))
            start++;
        if (!pattern.AsSpan(start).StartsWith("(?"))
            return false;
        var close = pattern.IndexOf(')', start);
        if (close < 0)
            return false;
        var flags = pattern[(start + 2)..close];
        stripped = pattern[(close + 1)..];
        return flags.Contains('m');
    }

    private static bool OnlyAnchors(string pattern)
        => pattern.Length > 0
           && pattern.All(c => c is '^' or '$' or '\n' or '\r' or ' ' or '\t');
}

/// <summary>JDBC indices start at one; zero compiles and fails only when it runs.</summary>
public sealed class KotlinPreparedStatementIndexRule : KotlinTreeRule
{
    private static readonly string[] IndexedCalls =
    [
        "setInt", "setString", "setLong", "setDouble", "setFloat", "setShort", "setByte",
        "setBoolean", "setObject", "setDate", "setTime", "setTimestamp", "setBigDecimal",
        "setBytes", "setBlob", "setClob", "setNull", "getInt", "getString", "getLong",
        "getDouble", "getFloat", "getBoolean", "getObject", "getDate", "getTime",
        "getTimestamp", "getBytes", "getBlob", "getClob", "getBigDecimal", "updateInt",
        "updateString", "updateLong", "updateDouble", "updateObject"
    ];

    public override string Key => "QG-KT-BUG-0021";
    public override string Name => "PreparedStatement and ResultSet methods should get valid indices";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!IndexedCalls.Contains(Called(call)))
                continue;
            var receiver = call.ChildAt(0) is { Kind: NodeKind.MemberSelect } select
                ? select.ChildAt(0)
                : null;
            var type = context.Types.TypeOf(receiver);
            if (type == null || !(type.Contains("PreparedStatement") || type.Contains("ResultSet")))
                continue;
            if (IsNumber(Args(call).FirstOrDefault(), "0"))
                context.Report(call,
                    $"JDBC numbers parameters from 1: this index 0 passed to {Called(call)} throws "
                    + "SQLException at runtime, on the first request that reaches the statement. "
                    + "The first placeholder is 1.");
        }
    }
}

/// <summary>A version written into the dependency string pins every consumer to edit-by-hand.</summary>
public sealed class KotlinGradleHardcodedVersionRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0079";
    public override string Name => "Dependency versions should not be hard-coded";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!IsGradleScript(context))
            return;
        foreach (var literal in context.Root.OfKind(NodeKind.StringLiteral))
        {
            var value = StringValue(literal);
            if (value.Contains('$') || value.Length < 5)
                continue;
            var segments = value.Split(':');
            // group : artifact : version - three non-empty parts is a pinned coordinate
            if (segments.Length != 3
                || segments.Any(string.IsNullOrWhiteSpace)
                || !segments.All(s => s.All(c => char.IsLetterOrDigit(c) || c is '.' or '_' or '-')))
                continue;
            context.Report(literal,
                "This dependency carries its version inline. One upgrade now means editing every "
                + "module that repeats the string. Put the version in a version catalog entry, a "
                + "gradle.properties key, or a platform BOM, and reference the alias here.");
        }
    }
}

/// <summary>Kotlin plugins have shortcut syntax; the long id hides behind it for no reason.</summary>
public sealed class KotlinGradleCorePluginIdRule : KotlinTreeRule
{
    private static readonly Dictionary<string, string> Shortcuts = new()
    {
        ["org.jetbrains.kotlin.jvm"] = "kotlin(\"jvm\")",
        ["org.jetbrains.kotlin.multiplatform"] = "kotlin(\"multiplatform\")",
        ["org.jetbrains.kotlin.android"] = "kotlin(\"android\")",
        ["org.jetbrains.kotlin.js"] = "kotlin(\"js\")",
        ["org.jetbrains.kotlin.kapt"] = "kotlin(\"kapt\")",
        ["org.jetbrains.kotlin.plugin.serialization"] = "kotlin(\"plugin.serialization\")"
    };

    public override string Key => "QG-KT-SML-0084";
    public override string Name => "Core plugin ids should use their shortcuts";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!IsGradleScript(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (Called(call) != "id"
                || Args(call).Count != 1
                || !IsStringLiteral(Args(call)[0]))
                continue;
            var plugin = StringValue(Args(call)[0]);
            if (Shortcuts.TryGetValue(plugin, out var shortcut))
                context.Report(call,
                    $"`id(\"{plugin}\")` spells out an id the Kotlin Gradle DSL already names. "
                    + $"Write `{shortcut}` and the build reads as the language it configures.");
        }
    }
}

/// <summary>A secondary constructor that mirrors the primary adds a second way to write nothing.</summary>
public sealed class KotlinRedundantDataClassConstructorRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0045";
    public override string Name => "A redundant constructor should be removed";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var primary = type.FirstChild(NodeKind.ParameterList);
            var body = type.LastChild(NodeKind.Block);
            if (primary == null || primary.Children.Count == 0 || body == null)
                continue;
            foreach (var secondary in body.Children.Where(
                         c => c.Kind == NodeKind.ConstructorDeclaration))
            {
                var parameters = secondary.FirstChild(NodeKind.ParameterList);
                if (parameters == null
                    || parameters.Children.Count != primary.Children.Count)
                    continue;
                var sameTypes = parameters.Children.Zip(primary.Children, (s, p) =>
                        (s.Children.FirstOrDefault(c => c.Kind == NodeKind.TypeReference)?.Text,
                         p.Children.FirstOrDefault(c => c.Kind == NodeKind.TypeReference)?.Text))
                    .All(pair => pair.Item1 == pair.Item2 && pair.Item1 != null);
                var delegatesToPrimary = secondary.OfKind(NodeKind.Invocation).Any(i =>
                    Called(i) == "this"
                    && SyntaxQuery.Arguments(i).Count == primary.Children.Count);
                if (sameTypes && delegatesToPrimary)
                    context.Report(secondary,
                        $"This constructor takes exactly what {type.Text}'s primary constructor "
                        + "takes and forwards every argument to it. It adds a second spelling of "
                        + "the same creation. Delete it; the primary constructor already accepts "
                        + "these values.");
            }
        }
    }
}

/// <summary>A non-nullable value cannot be null: the check answers a question already settled.</summary>
public sealed class KotlinUselessNullCheckRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0077";
    public override string Name => "Null checks should be useful";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("==" or "!=" or "===" or "!=="))
                continue;
            var identifier = IdentifierVersusNull(binary);
            if (identifier == null || !IsDeclaredNonNull(identifier, context))
                continue;
            context.Report(binary,
                $"{identifier.Text} is declared as a non-null type, so this comparison is decided "
                + "before it runs - always false for == null, always true for != null. The type "
                + "system already made the promise; delete the check, or change the declaration to "
                + "a nullable type when null really can arrive.");
        }
    }

    private static SyntaxNode? IdentifierVersusNull(SyntaxNode binary)
    {
        var (left, right) = (binary.ChildAt(0), binary.ChildAt(1));
        if (IsNull(right) && left?.Kind == NodeKind.Identifier)
            return left;
        if (IsNull(left) && right?.Kind == NodeKind.Identifier)
            return right;
        return null;
    }

    /// <summary>
    /// Kotlin parameters are immutable and their types are enforced at every call, so a parameter
    /// of non-null type never holds null; the same holds for values whose declared type says so.
    /// </summary>
    private static bool IsDeclaredNonNull(SyntaxNode identifier, IRuleContext context)
    {
        foreach (var ancestor in identifier.Ancestors())
        {
            switch (ancestor.Kind)
            {
                case NodeKind.FunctionDeclaration or NodeKind.LocalFunction:
                    foreach (var parameter in SyntaxQuery.Parameters(ancestor))
                        if (parameter.Text == identifier.Text
                            && HasNonNullType(parameter))
                            return true;
                    break;
                case NodeKind.ClassDeclaration:
                    var fields = ancestor.Descendants()
                        .Where(n => n.Kind == NodeKind.FieldDeclaration
                                    && n.Ancestor(NodeKind.FunctionDeclaration) == null);
                    foreach (var field in fields)
                        if (field.Text == identifier.Text && HasNonNullType(field))
                            return true;
                    return false; // nothing else above a type can declare the name
            }
        }
        return false;
    }

    private static bool HasNonNullType(SyntaxNode declaration)
        => declaration.Children.FirstOrDefault(c => c.Kind == NodeKind.TypeReference)?.Text
           is { } type
           && !type.EndsWith("?", StringComparison.Ordinal);
}

/// <summary>map[key]!! turns one absent key into an exception nobody planned for.</summary>
public sealed class KotlinNotNullAssertionOnMapRule : KotlinTreeRule
{
    public override string Key => "QG-KT-BUG-0029";
    public override string Name => "Map values should be accessed safely";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var assertion in context.Root.OfKind(NodeKind.Unary))
        {
            // map[key]!! reads as two '!' unary nodes over the index
            if (assertion.Text != "!")
                continue;
            var inner = assertion.ChildAt(0);
            if (inner is not { Kind: NodeKind.Unary, Text: "!" })
                continue;
            var index = inner.ChildAt(0);
            if (index is not { Kind: NodeKind.Index })
                continue;
            var receiver = context.Types.TypeOf(index.ChildAt(0));
            if (receiver == null || !receiver.Contains("Map", StringComparison.Ordinal))
                continue;
            context.Report(assertion,
                "The !! on this lookup promises the key is there, and pays with a "
                + "NullPointerException the first time it is not. Say what happens instead: "
                + "getValue(key) names the failure, read[key] ?: default supplies a fallback, and "
                + "getOrPut(key) { ... } builds the value once.");
        }
    }
}

/// <summary>A deprecated call keeps working today and breaks on the upgrade nobody scheduled.</summary>
public sealed class KotlinDeprecatedUsageRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0033";
    public override string Name => "Code annotated as deprecated should not be used";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        var deprecated = context.Root.OfKind(NodeKind.FunctionDeclaration)
            .Concat(context.Root.OfKind(NodeKind.ClassDeclaration))
            .Where(d => d.Children.Any(c =>
                c.Kind == NodeKind.Attribute
                && (c.Text == "Deprecated" || c.Text.EndsWith(".Deprecated"))))
            .Select(d => d.Text)
            .ToHashSet(StringComparer.Ordinal);
        if (deprecated.Count == 0)
            return;
        foreach (var node in context.Root.OfKind(NodeKind.Invocation, NodeKind.ObjectCreation))
        {
            var name = node.Kind == NodeKind.ObjectCreation ? node.Text : Called(node);
            if (!deprecated.Contains(name))
                continue;
            context.Report(node,
                $"{name} is marked @Deprecated: its replacement exists, and the next version bump "
                + "removes this one from under you. Move to what the annotation names, or say why "
                + "this call site still needs the old path.");
        }
    }
}

/// <summary>The collections Guava predates are part of the language now.</summary>
public sealed class KotlinGuavaImportRule : KotlinTreeRule
{
    private static readonly Dictionary<string, string> Replacements = new()
    {
        ["com.google.common.collect.Lists"] = "mutableListOf()",
        ["com.google.common.collect.Sets"] = "mutableSetOf()",
        ["com.google.common.collect.Maps"] = "mutableMapOf()",
        ["com.google.common.collect.Iterables"] = "asIterable() / sequence helpers",
        ["com.google.common.collect.Collections2"] = "map/filter on collections",
        ["com.google.common.base.Charsets"] = "Charsets (kotlin.text)",
        ["com.google.common.base.Strings"] = "String? extensions",
        ["com.google.common.base.Preconditions"] = "require()/check()"
    };

    public override string Key => "QG-KT-SML-0037";
    public override string Name => "Native features should be preferred to Guava";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!IsKotlinFile(context))
            return;
        foreach (var import in context.Root.OfKind(NodeKind.ImportDeclaration))
        {
            if (!Replacements.TryGetValue(import.Text, out var native))
                continue;
            context.Report(import,
                $"Guava's {import.Text.Split('.')[^1]} predates the standard library features that "
                + $"replaced it: here that is {native}. Every Guava import is also a dependency the "
                + "build has to carry for one utility. Prefer the Kotlin/Java standard form.");
        }
    }
}

/// <summary>An abstract class without state or constructors is an interface waiting to be used.</summary>
public sealed class KotlinAbstractClassWithoutStateRule : KotlinTreeRule
{
    public override string Key => "QG-KT-SML-0068";
    public override string Name => "An abstract class without state should be an interface";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var modifiers = ModifiersOf(type);
            if (!modifiers.Contains("abstract")
                || modifiers.Contains("sealed") || modifiers.Contains("data")
                || modifiers.Contains("interface")
                // expect/actual declarations are completed elsewhere and read as empty here, and a
                // test base class is a fixture by design rather than a contract looking for an
                // interface
                || modifiers.Contains("expect") || modifiers.Contains("actual")
                || type.Text.Contains("Test", StringComparison.Ordinal))
                continue;
            var body = type.LastChild(NodeKind.Block);
            if (body == null
                || body.Children.Any(c => c.Kind is NodeKind.FieldDeclaration
                                              or NodeKind.ConstructorDeclaration)
                || !body.Children.Any(c => c.Kind == NodeKind.FunctionDeclaration))
                continue;
            context.Report(type,
                $"{type.Text} declares no state and no constructor: everything it offers is "
                + "behaviour. An interface does the same job while letting implementers keep their "
                + "own base class - the one inheritance slot a class gets stays free.");
        }
    }
}



