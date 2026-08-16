using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Java on the tree. Java has a real parser here, so these rules read declarations, catches,
/// switches and calls rather than lines — which is what lets them stay quiet on the shapes that only
/// look like the defect.
/// </summary>
public static class JavaAstRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JavaFinalizeOverrideRule(),
        new JavaStringValueOfConcatenationRule(),
        new JavaCaseInsensitiveComparisonRule(),
        new JavaWrapperForConversionRule(),
        new JavaCatchLosesCauseRule(),
        new JavaInternalPackageRule(),
        new JavaInstanceOfInCatchRule(),
        new JavaExtendsErrorRule(),
        new JavaSwitchWithNonCaseLabelRule(),
        new JavaMisspelledObjectMethodRule(),
        new JavaMethodNamedLikeTypeRule(),
        new JavaMutableStaticFieldRule(),
        new JavaToStringOnStringRule(),
        new JavaIteratorHasNextCallsNextRule(),
        new JavaInvertedBooleanCheckRule(),
        new JavaBigDecimalFromDoubleRule(),
        new JavaMainThrowsRule(),
        new JavaSingleStatementLambdaBlockRule()
    ];
}

public abstract class JavaAstRuleBase : RuleBase
{
    public override string[] Languages => ["java"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    /// <summary>Java always has a real parser here, but a rule must still say so before it reads shapes.</summary>
    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>The modifiers written on a declaration, lower-cased.</summary>
    protected static HashSet<string> Modifiers(SyntaxNode declaration)
        => declaration.ChildrenOf(NodeKind.Modifier)
            .Select(m => m.Text.ToLowerInvariant())
            .ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// The name a catch binds its exception to, or an empty string. Java writes the binding as a
    /// declaration inside the catch, not as a parameter list, so both shapes are read here.
    /// </summary>
    protected static string CaughtName(SyntaxNode catchNode)
    {
        var declared = catchNode.ChildrenOf(NodeKind.VariableDeclaration).FirstOrDefault();
        if (declared is { Text.Length: > 0 })
            return declared.Text;
        var parameter = catchNode.OfKind(NodeKind.Parameter).FirstOrDefault();
        if (parameter == null)
            return string.Empty;
        var identifier = parameter.OfKind(NodeKind.Identifier).LastOrDefault();
        return identifier?.Text ?? parameter.Text;
    }
}

public sealed class JavaFinalizeOverrideRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-BUG-0179";
    public override string Name => "finalize should not be overridden";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (method.Text != "finalize" || SyntaxQuery.Parameters(method).Any())
                continue;

            context.Report("Nothing says when — or whether — finalize runs. The collector may call it "
                           + "long after the object became unreachable, on a thread nobody chose, and "
                           + "an exception thrown inside it is discarded. Meanwhile the object survives "
                           + "one extra collection cycle. Release the resource in close and let the "
                           + "caller use try-with-resources.", method.Range.StartLine);
        }
    }
}

public sealed class JavaStringValueOfConcatenationRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-SML-0435";
    public override string Name => "String.valueOf should not be concatenated to a string";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var concatenation in context.Root.OfKind(NodeKind.Binary))
        {
            if (concatenation.Text != "+")
                continue;
            if (!concatenation.Children.Any(SyntaxQuery.IsStringLiteral))
                continue;

            foreach (var child in concatenation.Children)
            {
                if (child.Kind != NodeKind.Invocation)
                    continue;
                if (SyntaxQuery.InvokedDottedName(child) is not ("String.valueOf" or "valueOf"))
                    continue;
                if (SyntaxQuery.InvokedDottedName(child) == "valueOf")
                    continue; // Integer.valueOf and friends: the receiver decides, and it is not String here

                context.Report("Concatenating with a string already converts the value, so this call "
                               + "does the same work twice and hides what is being appended.",
                    child.Range.StartLine);
            }
        }
    }
}

public sealed class JavaCaseInsensitiveComparisonRule : JavaAstRuleBase
{
    private static readonly string[] Casing = ["toUpperCase", "toLowerCase"];

    public override string Key => "QG-JV-BUG-0180";
    public override string Name => "Case-insensitive comparison should not go through case conversion";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "equals", "compareTo"))
        {
            var receiver = call.ChildAt(0);
            var receiverCall = receiver?.ChildAt(0);
            var argument = SyntaxQuery.ArgumentAt(call, 0);

            var receiverCased = receiverCall is { Kind: NodeKind.Invocation }
                                && Casing.Contains(SyntaxQuery.InvokedName(receiverCall));
            var argumentCased = argument is { Kind: NodeKind.Invocation }
                                && Casing.Contains(SyntaxQuery.InvokedName(argument));
            if (!receiverCased || !argumentCased)
                continue;

            var method = SyntaxQuery.InvokedName(call);
            var replacement = method == "equals" ? "equalsIgnoreCase" : "compareToIgnoreCase";
            context.Report($"Both sides are converted only to be compared, which allocates two strings "
                           + "on every call and gets the answer wrong in locales where changing case "
                           + $"changes the length of the text. Use {replacement}.", call.Range.StartLine);
        }
    }
}

public sealed class JavaWrapperForConversionRule : JavaAstRuleBase
{
    private static readonly string[] Wrappers =
        ["Integer", "Long", "Double", "Float", "Short", "Byte", "Boolean", "Character"];

    public override string Key => "QG-JV-SML-0436";
    public override string Name => "A wrapper should not be created just to convert a primitive";
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "toString", "compareTo"))
        {
            var receiver = call.ChildAt(0)?.ChildAt(0);
            if (receiver is not { Kind: NodeKind.ObjectCreation })
                continue;
            var type = SyntaxQuery.SimpleName(receiver.ChildAt(0)) is { Length: > 0 } named
                ? named
                : receiver.Text;
            if (!Wrappers.Contains(type))
                continue;

            var method = SyntaxQuery.InvokedName(call);
            var replacement = method == "toString" ? $"{type}.toString(value)" : $"{type}.compare(a, b)";
            context.Report($"A whole {type} is allocated and thrown away to call {method}. Use the "
                           + $"static form, {replacement}, which does the same work without the object.",
                call.Range.StartLine);
        }
    }
}

public sealed class JavaCatchLosesCauseRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-SML-0437";
    public override string Name => "A rethrown exception should carry the original";
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var catchNode in context.Root.OfKind(NodeKind.Catch))
        {
            var caught = CaughtName(catchNode);
            if (caught.Length == 0)
                continue;
            var body = catchNode.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            // the exception is used somewhere — logged, inspected, wrapped: the trace is not lost
            if (SyntaxQuery.MentionsIdentifier(body, caught))
                continue;

            var thrown = body.OfKind(NodeKind.Jump).FirstOrDefault(j => j.Text == "throw");
            if (thrown == null)
                continue;

            context.Report($"The exception is replaced without passing '{caught}' as its cause, so the "
                           + "stack trace stops here and whoever reads the log sees the symptom with no "
                           + "trace of what actually failed. Pass the original to the constructor of "
                           + "the new exception.", thrown.Range.StartLine);
        }
    }
}

public sealed class JavaInternalPackageRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-SML-0438";
    public override string Name => "Internal JDK packages should not be used";
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "1h";

    public override void Execute(IRuleContext context)
    {
        foreach (var import in context.Root.OfKind(NodeKind.ImportDeclaration))
        {
            var name = import.Text;
            if (!name.StartsWith("sun.", StringComparison.Ordinal)
                && !name.StartsWith("com.sun.", StringComparison.Ordinal)
                && !name.StartsWith("jdk.internal.", StringComparison.Ordinal))
                continue;

            context.Report($"'{name}' is an internal package: it carries no compatibility promise, the "
                           + "module system blocks it by default since Java 9, and an upgrade can remove "
                           + "it without notice. Use the public API that replaced it.",
                import.Range.StartLine);
        }
    }
}

public sealed class JavaInstanceOfInCatchRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-SML-0439";
    public override string Name => "A catch should not sort exceptions with instanceof";
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var catchNode in context.Root.OfKind(NodeKind.Catch))
        {
            var caught = CaughtName(catchNode);
            var body = catchNode.FirstChild(NodeKind.Block);
            if (caught.Length == 0 || body == null)
                continue;

            foreach (var test in body.OfKind(NodeKind.Binary, NodeKind.Pattern))
            {
                if (test.Text != "instanceof")
                    continue;
                if (SyntaxQuery.SimpleName(test.ChildAt(0)) != caught)
                    continue;

                context.Report("This catch takes everything and then sorts it out by type, which is what "
                               + "the catch clauses are for. Write one catch per exception the code "
                               + "really handles and let the rest travel up.", test.Range.StartLine);
                break;
            }
        }
    }
}

public sealed class JavaExtendsErrorRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-BUG-0181";
    public override string Name => "Error should not be extended";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            // the base list is not on the node: the project index is what records who extends whom
            var indexed = context.Project.FindTypes(type.Text)
                .FirstOrDefault(t => t.File == context.File.Path);
            var bases = indexed?.BaseNames ?? [];
            if (!bases.Any(b => b is "Error" or "java.lang.Error"))
                continue;

            context.Report($"'{type.Text}' extends Error, which the platform reserves for failures no "
                           + "application can recover from — out of memory, a broken class file. Code "
                           + "that catches Exception will never see it, so the failure escapes every "
                           + "handler. Extend RuntimeException instead.", type.Range.StartLine);
        }
    }
}

public sealed class JavaSwitchWithNonCaseLabelRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-BUG-0182";
    public override string Name => "A switch should not contain a label of its own";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var match in context.Root.OfKind(NodeKind.Match))
        {
            foreach (var label in match.OfKind(NodeKind.Label))
                Report(context, label.Text, label.Range.StartLine);

            // a label the parser did not fold into one node: a bare name followed by a colon, which
            // is what a misspelled 'default' leaves behind. The name has to follow a jump — the end
            // of a finished case — because a case that lists several constants over several lines
            // leaves exactly the same shape, and there the name is a real case label.
            foreach (var section in match.OfKind(NodeKind.Block, NodeKind.SwitchSection))
            {
                var children = section.Children;
                for (var i = 1; i + 1 < children.Count; i++)
                {
                    if (children[i - 1].Kind != NodeKind.Jump)
                        continue;
                    if (!IsSingle(children[i], NodeKind.Identifier) || !IsSingle(children[i + 1], NodeKind.Unknown))
                        continue;
                    if (children[i + 1].Children[0].Text != ":")
                        continue;
                    Report(context, children[i].Children[0].Text, children[i].Range.StartLine);
                }
            }
        }
    }

    private static bool IsSingle(SyntaxNode statement, NodeKind kind)
        => statement is { Kind: NodeKind.ExpressionStatement, Children.Count: 1 }
           && statement.Children[0].Kind == kind;

    private static void Report(IRuleContext context, string name, int line)
    {
        context.Report($"'{name}:' inside a switch reads exactly like a case but is a jump target: the "
                       + "code under it runs as part of whatever section precedes it, and never on its "
                       + "own. A misspelled 'default' becomes a label like this one, silently, and the "
                       + "compiler accepts it.", line);
    }
}

public sealed class JavaMisspelledObjectMethodRule : JavaAstRuleBase
{
    /// <summary>
    /// The near-misses, with the number of parameters the real method takes. The count matters: a
    /// static 'equalsTo(a, b)' helper is not a failed override, and reporting it is how a rule like
    /// this one gets switched off.
    /// </summary>
    private static readonly Dictionary<string, (string Intended, int Parameters)> Intended =
        new(StringComparer.Ordinal)
        {
            ["tostring"] = ("toString", 0),
            ["hashcode"] = ("hashCode", 0),
            ["equal"] = ("equals", 1),
            ["equalsTo"] = ("equals", 1)
        };

    public override string Key => "QG-JV-BUG-0183";
    public override string Name => "A method should not almost override Object";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!Intended.TryGetValue(method.Text, out var expected))
                continue;
            if (SyntaxQuery.Parameters(method).Count() != expected.Parameters)
                continue;
            if (Modifiers(method).Contains("static"))
                continue;

            context.Report($"'{method.Text}' is one letter away from '{expected.Intended}' and overrides nothing. "
                           + "Everything that prints, compares or hashes this object keeps using the "
                           + "default from Object, and the method here is never called.",
                method.Range.StartLine);
        }
    }
}

public sealed class JavaMethodNamedLikeTypeRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-BUG-0184";
    public override string Name => "A method should not be named after its class";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (type.Text.Length == 0)
                continue;
            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            foreach (var method in body.ChildrenOf(NodeKind.FunctionDeclaration))
            {
                if (method.Text != type.Text)
                    continue;

                context.Report($"'{method.Text}' has the name of its class but a return type, so it is a "
                               + "method, not the constructor everyone will read it as. A call to "
                               + $"'new {type.Text}()' runs the real constructor and this code never "
                               + "executes.", method.Range.StartLine);
            }
        }
    }
}

public sealed class JavaMutableStaticFieldRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-BUG-0185";
    public override string Name => "A public static field should be final";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var field in context.Root.OfKind(NodeKind.FieldDeclaration))
        {
            var modifiers = Modifiers(field);
            if (!modifiers.Contains("public") || !modifiers.Contains("static") || modifiers.Contains("final"))
                continue;

            context.Report($"'{field.Text}' can be replaced by any code in the process, at any moment, "
                           + "from any thread — and every reader of it sees the change. That is a global "
                           + "variable with a class name in front. Make it final, or hide it behind "
                           + "accessors that control the change.", field.Range.StartLine);
        }
    }
}

public sealed class JavaToStringOnStringRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-SML-0440";
    public override string Name => "toString should not be called on a string";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "toString"))
        {
            var receiver = call.ChildAt(0)?.ChildAt(0);
            if (receiver == null)
                continue;
            var isString = receiver.Kind == NodeKind.StringLiteral
                           || (receiver.Kind == NodeKind.Invocation
                               && SyntaxQuery.InvokedName(receiver) is "toString" or "substring" or "trim"
                                   or "concat" or "replace" or "toUpperCase" or "toLowerCase");
            if (!isString)
                continue;

            context.Report("The value is already a string, so this call returns the same object and only "
                           + "makes the reader look for a conversion that is not there.",
                call.Range.StartLine);
        }
    }
}

public sealed class JavaIteratorHasNextCallsNextRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-BUG-0186";
    public override string Name => "hasNext should not consume the iterator";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (method.Text != "hasNext" || SyntaxQuery.Parameters(method).Any())
                continue;
            var body = SyntaxQuery.Body(method);
            if (body == null)
                continue;

            var consuming = SyntaxQuery.InvocationsNamed(body, "next").FirstOrDefault();
            if (consuming == null)
                continue;

            context.Report("hasNext is a question, and this one advances the iterator to answer it. Every "
                           + "caller that checks before reading then skips an element, and a loop that "
                           + "checks twice skips two.", consuming.Range.StartLine);
        }
    }
}

public sealed class JavaInvertedBooleanCheckRule : JavaAstRuleBase
{
    private static readonly Dictionary<string, string> Opposite = new(StringComparer.Ordinal)
    {
        ["=="] = "!=",
        ["!="] = "==",
        ["<"] = ">=",
        [">"] = "<=",
        ["<="] = ">",
        [">="] = "<"
    };

    public override string Key => "QG-JV-SML-0441";
    public override string Name => "A comparison should not be negated";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var negation in context.Root.OfKind(NodeKind.Unary))
        {
            if (negation.Text != "!")
                continue;
            var operand = negation.ChildAt(0);
            if (operand is { Kind: NodeKind.Parenthesized })
                operand = operand.ChildAt(0);
            if (operand is not { Kind: NodeKind.Binary })
                continue;
            if (!Opposite.TryGetValue(operand.Text, out var opposite))
                continue;

            context.Report($"Negating '{operand.Text}' says the same thing as '{opposite}' with one more "
                           + "step for the reader to undo. Use the opposite operator.",
                negation.Range.StartLine);
        }
    }
}

public sealed class JavaBigDecimalFromDoubleRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-BUG-0187";
    public override string Name => "BigDecimal should not be built from a double";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            if (SyntaxQuery.SimpleName(creation.ChildAt(0)) != "BigDecimal" && creation.Text != "BigDecimal")
                continue;
            var argument = creation.OfKind(NodeKind.ArgumentList).FirstOrDefault()?.ChildAt(0);
            if (argument is not { Kind: NodeKind.NumberLiteral } || !argument.Text.Contains('.'))
                continue;
            if (argument.Text.EndsWith('f') || argument.Text.EndsWith('F'))
                continue;

            context.Report($"The double {argument.Text} is not exactly that value, and this constructor "
                           + "faithfully copies the binary approximation — digits and all — into the "
                           + $"BigDecimal. Use new BigDecimal(\"{argument.Text}\") or BigDecimal.valueOf, "
                           + "which read the decimal you wrote.", creation.Range.StartLine);
        }
    }
}

public sealed class JavaMainThrowsRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-SML-0442";
    public override string Name => "main should not let exceptions escape";
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (method.Text != "main" || !Modifiers(method).Contains("static"))
                continue;
            var line = LanguageRuleSupport.Lines(context).ElementAtOrDefault(method.Range.StartLine - 1)
                       ?? string.Empty;
            if (!line.Contains("throws", StringComparison.Ordinal))
                continue;

            context.Report("An exception that leaves main reaches the default handler, which prints a "
                           + "stack trace at the user and exits with a code nobody chose. Catch it, say "
                           + "what went wrong in a sentence, and exit with a status the caller can act "
                           + "on.", method.Range.StartLine);
        }
    }
}

public sealed class JavaSingleStatementLambdaBlockRule : JavaAstRuleBase
{
    public override string Key => "QG-JV-SML-0443";
    public override string Name => "A one-statement lambda should not need a block";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var lambda in context.Root.OfKind(NodeKind.Lambda))
        {
            var body = lambda.FirstChild(NodeKind.Block);
            if (body is not { Children.Count: 1 })
                continue;
            var statement = body.Children[0];
            if (statement.Kind is not (NodeKind.ExpressionStatement or NodeKind.Jump))
                continue;
            if (statement.Kind == NodeKind.Jump && statement.Text != "return")
                continue;
            // a statement that spans several lines reads better inside the braces it already has
            if (statement.Range.EndLine != statement.Range.StartLine)
                continue;

            context.Report("The braces, the semicolon and the return around a single expression add "
                           + "three pieces of syntax to something that fits on the arrow. Write the "
                           + "expression directly.", lambda.Range.StartLine);
        }
    }
}
