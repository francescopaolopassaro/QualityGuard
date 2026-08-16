using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Java rules about the contracts the platform expects a type to honour — what an iterator promises,
/// what a comparison promises, what a lock protects — and the declarations that say one thing and do
/// another.
/// </summary>
public static class JavaContractRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JavaIteratorWithoutNoSuchElementRule(),
        new JavaWaitOutsideLoopRule(),
        new JavaNullFromBooleanMethodRule(),
        new JavaIndexOfPositiveRule(),
        new JavaThreadStartedInConstructorRule(),
        new JavaIteratorReturningThisRule(),
        new JavaJdbcIndexRule(),
        new JavaPointlessBitOperationRule(),
        new JavaWeekYearFormatRule(),
        new JavaComparableOverloadRule(),
        new JavaStaticOnlyClassRule(),
        new JavaDefaultInitializationRule(),
        new JavaRedundantModifierRule(),
        new JavaDoubleBraceInitializationRule(),
        new JavaCloneOverrideRule(),
        new JavaStaticNestedEnumRule(),
        new JavaMethodReturningConstantRule(),
        new JavaInstanceWritesStaticRule(),
        new JavaStraySemicolonRule()
    ];
}

public abstract class JavaContractRuleBase : RuleBase
{
    public override string[] Languages => ["java"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static HashSet<string> Modifiers(SyntaxNode declaration)
        => declaration.ChildrenOf(NodeKind.Modifier)
            .Select(m => m.Text.ToLowerInvariant())
            .ToHashSet(StringComparer.Ordinal);

    protected static IEnumerable<SyntaxNode> Members(SyntaxNode type)
        => type.FirstChild(NodeKind.Block)?.Children ?? [];

    /// <summary>The declared return type of a method, as written.</summary>
    protected static string ReturnType(SyntaxNode method)
        => method.ChildrenOf(NodeKind.TypeReference).FirstOrDefault()?.Text ?? string.Empty;

    /// <summary>
    /// Whether a type declaration is introduced by the given keyword. Only the tokens before the
    /// name count: the body of an enum can perfectly well contain a field called
    /// associatedInterface, and searching the whole declaration finds the word there.
    /// </summary>
    protected static bool DeclaredWith(SyntaxNode type, string keyword)
    {
        foreach (var token in type.Tokens)
        {
            if (token.Text == type.Text)
                return false;
            if (token.Text == keyword)
                return true;
        }
        return false;
    }

    /// <summary>The type created by a new expression, or an empty string.</summary>
    protected static string CreatedType(SyntaxNode creation)
    {
        var named = SyntaxQuery.SimpleName(creation.ChildAt(0));
        return named.Length > 0 ? named : creation.Text;
    }
}

public sealed class JavaIteratorWithoutNoSuchElementRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-BUG-0188";
    public override string Name => "next should refuse to run past the end";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (method.Text != "next" || SyntaxQuery.Parameters(method).Any())
                continue;
            // only an iterator's next: the class has to offer hasNext beside it
            var type = SyntaxQuery.EnclosingType(method);
            if (type == null || !Members(type).Any(m => m is { Kind: NodeKind.FunctionDeclaration, Text: "hasNext" }))
                continue;

            var body = SyntaxQuery.Body(method);
            if (body == null)
                continue;
            var throws = body.OfKind(NodeKind.Jump)
                .Where(j => j.Text == "throw")
                .Select(j => CreatedType(j.Children.FirstOrDefault() ?? j))
                .ToList();
            if (throws.Contains("NoSuchElementException"))
                continue;

            context.Report("Every caller is entitled to assume that next throws NoSuchElementException "
                           + "once the elements run out — that is what the interface promises. This one "
                           + "does something else instead, so a loop that reads one element too many "
                           + "gets a null, an index error, or silence.", method.Range.StartLine);
        }
    }
}

public sealed class JavaWaitOutsideLoopRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-BUG-0189";
    public override string Name => "wait should be called in a loop";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "wait", "await"))
        {
            if (SyntaxQuery.Arguments(call).Count > 1)
                continue;
            if (call.Ancestors().Any(a => a.Kind == NodeKind.Loop))
                continue;
            // a call inside a lambda or another method belongs to that scope, not to this loop
            var enclosing = SyntaxQuery.EnclosingFunction(call);
            if (enclosing != null && enclosing.OfKind(NodeKind.Loop).Any(l => l.OfKind(NodeKind.Invocation).Contains(call)))
                continue;

            context.Report("A thread can come back from wait without anyone having signalled it — the "
                           + "specification allows it, and it happens. Without a loop around the call "
                           + "the code carries on as if the condition held, on a state that has not "
                           + "changed. Wrap it in while (!condition).", call.Range.StartLine);
        }
    }
}

public sealed class JavaNullFromBooleanMethodRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-BUG-0190";
    public override string Name => "A Boolean method should not return null";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (ReturnType(method) != "Boolean")
                continue;
            var body = SyntaxQuery.Body(method);
            if (body == null)
                continue;

            foreach (var jump in body.OfKind(NodeKind.Jump))
            {
                if (jump.Text != "return" || jump.Children.Count == 0)
                    continue;
                if (jump.Children[0].Kind != NodeKind.NullLiteral)
                    continue;
                if (SyntaxQuery.EnclosingFunction(jump) != method)
                    continue;

                context.Report($"'{method.Text}' answers a yes-or-no question, and this branch answers "
                               + "neither. Every caller that writes 'if (method())' unboxes the result "
                               + "and gets a NullPointerException on a line that contains no visible "
                               + "dereference. Return false, or change the type to make the third "
                               + "answer explicit.", jump.Range.StartLine);
            }
        }
    }
}

public sealed class JavaIndexOfPositiveRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-BUG-0191";
    public override string Name => "A search result should be tested against zero";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not (">" or "<="))
                continue;
            var call = comparison.ChildAt(0);
            if (call is not { Kind: NodeKind.Invocation })
                continue;
            if (SyntaxQuery.InvokedName(call) is not ("indexOf" or "lastIndexOf"))
                continue;
            var literal = comparison.ChildAt(1);
            if (literal is not { Kind: NodeKind.NumberLiteral } || literal.Text != "0")
                continue;

            var replacement = comparison.Text == ">" ? ">= 0" : "< 0";
            context.Report($"The search answers 0 when the match sits at the very beginning, and this "
                           + $"comparison reads that as 'not found'. Use {replacement}, or contains().",
                comparison.Range.StartLine);
        }
    }
}

public sealed class JavaThreadStartedInConstructorRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-BUG-0192";
    public override string Name => "A thread should not be started from a constructor";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var constructor in context.Root.OfKind(NodeKind.ConstructorDeclaration))
        {
            var body = constructor.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            foreach (var call in SyntaxQuery.InvocationsNamed(body, "start"))
            {
                var receiver = SyntaxQuery.Receiver(call);
                if (receiver.Length == 0 || !LooksLikeThread(receiver))
                    continue;

                context.Report("The object is not finished being built: its subclass constructor has not "
                               + "run and its final fields are not guaranteed to be visible to another "
                               + "thread. The new thread can therefore see the object half-initialised, "
                               + "and only sometimes. Start it from a separate method the caller "
                               + "invokes.", call.Range.StartLine);
            }
        }
    }

    private static bool LooksLikeThread(string receiver)
    {
        var name = receiver.Split('.').Last();
        return name.Contains("thread", StringComparison.OrdinalIgnoreCase)
               || name.Contains("worker", StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class JavaIteratorReturningThisRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-BUG-0193";
    public override string Name => "iterator should not return the collection itself";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (method.Text != "iterator" || SyntaxQuery.Parameters(method).Any())
                continue;
            var body = SyntaxQuery.Body(method);
            if (body is not { Children.Count: 1 })
                continue;
            var jump = body.Children[0];
            if (jump is not { Kind: NodeKind.Jump, Text: "return" } || jump.Children.Count != 1)
                continue;
            if (SyntaxQuery.SimpleName(jump.Children[0]) != "this")
                continue;

            context.Report("Returning the object itself gives every caller the same iterator, so the "
                           + "second loop over this collection starts where the first one stopped — and "
                           + "two nested loops interfere with each other. Return a new iterator each "
                           + "time.", jump.Range.StartLine);
        }
    }
}

public sealed class JavaJdbcIndexRule : JavaContractRuleBase
{
    /// <summary>
    /// The typed accessors of PreparedStatement and ResultSet. The name is what identifies the API:
    /// the receiver is called ps, stmt, rs or anything else a team happens to prefer.
    /// </summary>
    private static readonly HashSet<string> JdbcAccessors = new(StringComparer.Ordinal)
    {
        "setString", "setInt", "setLong", "setShort", "setByte", "setDouble", "setFloat",
        "setBoolean", "setDate", "setTime", "setTimestamp", "setBigDecimal", "setBytes",
        "setObject", "setNull", "setBlob", "setClob", "setArray", "setBinaryStream",
        "getString", "getInt", "getLong", "getShort", "getByte", "getDouble", "getFloat",
        "getBoolean", "getDate", "getTime", "getTimestamp", "getBigDecimal", "getBytes",
        "getBlob", "getClob", "getArray"
    };

    public override string Key => "QG-JV-BUG-0194";
    public override string Name => "JDBC parameters are numbered from one";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!JdbcAccessors.Contains(name))
                continue;

            var arguments = SyntaxQuery.Arguments(call);
            var isSetter = name.StartsWith("set", StringComparison.Ordinal);
            if ((isSetter && arguments.Count != 2) || (!isSetter && arguments.Count != 1))
                continue;
            if (arguments[0] is not { Kind: NodeKind.NumberLiteral } index || index.Text != "0")
                continue;

            context.Report($"'{name}' counts its columns from one, not from zero, so index 0 throws "
                           + "SQLException at run time — on the first query that reaches this line, "
                           + "which may well be in production.", call.Range.StartLine);
        }
    }
}

public sealed class JavaPointlessBitOperationRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-BUG-0195";
    public override string Name => "A bit operation should change something";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var operation in context.Root.OfKind(NodeKind.Binary))
        {
            if (operation.Text is not ("|" or "&" or "^"))
                continue;
            var right = operation.ChildAt(1);
            if (right is not { Kind: NodeKind.NumberLiteral })
                continue;

            var pointless = operation.Text switch
            {
                "|" or "^" => right.Text == "0",
                "&" => right.Text is "-1" or "0xFFFFFFFF",
                _ => false
            };
            if (!pointless)
                continue;

            context.Report($"'{operation.Text} {right.Text}' returns the left operand unchanged, so the "
                           + "operation does nothing. Either the constant is wrong or the line can go.",
                operation.Range.StartLine);
        }
    }
}

public sealed class JavaWeekYearFormatRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-BUG-0196";
    public override string Name => "A date format should use the calendar year";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var literal in context.Root.OfKind(NodeKind.StringLiteral))
        {
            var text = literal.Text;
            if (!text.Contains("YYYY", StringComparison.Ordinal) && !text.Contains("YY", StringComparison.Ordinal))
                continue;
            // it has to look like a date pattern, not a sentence that happens to contain the letters
            if (!text.Contains("MM", StringComparison.Ordinal) && !text.Contains("dd", StringComparison.Ordinal))
                continue;

            context.Report("Upper-case Y is the week year, not the calendar year: for the last days of "
                           + "December it already reports the year that is about to start. The bug "
                           + "appears once a year, in production, on dates nobody tested. Use lower-case "
                           + "y.", literal.Range.StartLine);
        }
    }
}

public sealed class JavaComparableOverloadRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-BUG-0197";
    public override string Name => "compareTo should not be overloaded";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var overloads = Members(type)
                .Where(m => m is { Kind: NodeKind.FunctionDeclaration, Text: "compareTo" })
                .ToList();
            if (overloads.Count < 2)
                continue;

            context.Report($"'{type.Text}' declares compareTo more than once, so which one runs depends "
                           + "on the static type at the call site. A sorted collection holds its "
                           + "elements as Comparable and calls the general one — not the specific one "
                           + "this class was written around.", overloads[1].Range.StartLine);
        }
    }
}

public sealed class JavaStaticOnlyClassRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-SML-0444";
    public override string Name => "A class of static members should not be instantiable";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var modifiers = Modifiers(type);
            if (modifiers.Contains("abstract") || modifiers.Contains("interface"))
                continue;

            var members = Members(type)
                .Where(m => m.Kind is NodeKind.FunctionDeclaration or NodeKind.FieldDeclaration)
                .ToList();
            if (members.Count == 0 || members.Any(m => !Modifiers(m).Contains("static")))
                continue;

            var constructors = Members(type).Where(m => m.Kind == NodeKind.ConstructorDeclaration).ToList();
            if (constructors.Count == 0)
            {
                context.Report($"Every member of '{type.Text}' is static, and the implicit constructor "
                               + "is public, so nothing stops someone from creating an instance that "
                               + "can do nothing. Declare a private constructor.", type.Range.StartLine);
                continue;
            }

            foreach (var constructor in constructors.Where(c => !Modifiers(c).Contains("private")))
            {
                context.Report($"Every member of '{type.Text}' is static, so an instance of it can do "
                               + "nothing at all — and this constructor invites one.",
                    constructor.Range.StartLine);
            }
        }
    }
}

public sealed class JavaDefaultInitializationRule : JavaContractRuleBase
{
    private static readonly Dictionary<string, string> Defaults = new(StringComparer.Ordinal)
    {
        ["int"] = "0",
        ["long"] = "0",
        ["short"] = "0",
        ["byte"] = "0",
        ["double"] = "0",
        ["float"] = "0",
        ["char"] = "0",
        ["boolean"] = "false"
    };

    public override string Key => "QG-JV-SML-0445";
    public override string Name => "A field should not be set to the value it already has";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var field in context.Root.OfKind(NodeKind.FieldDeclaration))
        {
            var modifiers = Modifiers(field);
            if (modifiers.Contains("final"))
                continue; // a blank final has to be assigned somewhere

            var type = field.ChildrenOf(NodeKind.TypeReference).FirstOrDefault()?.Text ?? string.Empty;
            var value = field.FirstChild(NodeKind.Assignment)?.ChildAt(1);
            if (value == null)
                continue;

            var redundant = value.Kind == NodeKind.NullLiteral
                ? !Defaults.ContainsKey(type) && type.Length > 0
                : Defaults.TryGetValue(type, out var expected)
                  && value.Kind is NodeKind.NumberLiteral or NodeKind.BooleanLiteral
                  && Normalize(value.Text) == expected;
            if (!redundant)
                continue;

            context.Report($"A field of this type already holds {(value.Kind == NodeKind.NullLiteral ? "null" : value.Text)} "
                           + "before any code runs, so the initializer repeats what the language "
                           + "guarantees — and adds a write the constructor has to perform.",
                field.Range.StartLine);
        }
    }

    private static string Normalize(string number)
        => number.TrimEnd('L', 'l', 'f', 'F', 'd', 'D').TrimEnd('.', '0') is { Length: 0 } ? "0" : number;
}

public sealed class JavaRedundantModifierRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-SML-0446";
    public override string Name => "A modifier that is already implied should be dropped";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var isInterface = DeclaredWith(type, "interface");
            if (!isInterface)
                continue;

            var nested = type.OfKind(NodeKind.ClassDeclaration).ToList();

            foreach (var member in Members(type))
            {
                // A type nested in the interface — an enum, a static class — has its own rules, and
                // the parser can leave its members among the children of the interface body. The
                // line range of the nested type is what settles who the member belongs to.
                if (nested.Any(n => member.Range.StartLine >= n.Range.StartLine
                                    && member.Range.StartLine <= n.Range.EndLine))
                    continue;

                foreach (var modifier in member.ChildrenOf(NodeKind.Modifier))
                {
                    var text = modifier.Text.ToLowerInvariant();
                    var implied = member.Kind switch
                    {
                        NodeKind.FunctionDeclaration => text is "public" or "abstract",
                        NodeKind.FieldDeclaration => text is "public" or "static" or "final",
                        _ => false
                    };
                    if (!implied)
                        continue;

                    context.Report($"Everything an interface declares is already {text}, so the keyword "
                                   + "adds nothing but suggests that the members without it are "
                                   + "different.", modifier.Range.StartLine);
                }
            }
        }
    }
}

public sealed class JavaDoubleBraceInitializationRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-SML-0447";
    public override string Name => "A collection should not be filled with double brace initialization";
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            var body = creation.FirstChild(NodeKind.ObjectInitializer) ?? creation.FirstChild(NodeKind.Block);
            if (body == null)
                continue;
            // the inner brace pair is what makes it a double brace: the outer one opens an anonymous
            // subclass, the inner one is the instance initializer that fills the collection
            var inner = body.Children.FirstOrDefault(
                c => c.Kind is NodeKind.ObjectInitializer or NodeKind.Block);
            if (inner == null || inner.Children.Count == 0)
                continue;
            // An anonymous class that declares or overrides something is a different thing
            // entirely, and its members sit inside the same braces — so the whole initializer has to
            // be free of them, not just its first level.
            if (body.OfKind(NodeKind.FunctionDeclaration, NodeKind.FieldDeclaration, NodeKind.Attribute).Any())
                continue;
            // What is left has to be nothing but calls. An anonymous class that overrides a method
            // opens the same braces, and inside a brace-delimited initializer the parser does not
            // always mark its members as declarations — so the shape decides: fill calls, and
            // nothing else.
            if (inner.Children.Count == 0
                || inner.Children.Any(c => c.Kind is not (NodeKind.Invocation or NodeKind.Unknown)))
                continue;
            if (!inner.Children.Any(c => c.Kind == NodeKind.Invocation))
                continue;

            context.Report("The braces create an anonymous subclass whose initializer runs the "
                           + "statements inside. That subclass keeps a reference to the object that "
                           + "built it, so the enclosing instance stays alive as long as the collection "
                           + "does — and the collection can no longer be serialized. Use List.of, or "
                           + "fill it after construction.", creation.Range.StartLine);
        }
    }
}

public sealed class JavaCloneOverrideRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-SML-0448";
    public override string Name => "clone should not be overridden";
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (method.Text != "clone" || SyntaxQuery.Parameters(method).Any())
                continue;

            context.Report("Cloneable does not declare clone, the copy it produces is shallow, and the "
                           + "constructor of the class never runs — so a final field cannot be set "
                           + "correctly in the copy. A copy constructor or a static factory says what "
                           + "it copies and can be tested.", method.Range.StartLine);
        }
    }
}

public sealed class JavaStaticNestedEnumRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-SML-0449";
    public override string Name => "A nested enum is already static";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var isEnum = DeclaredWith(type, "enum");
            if (!isEnum || SyntaxQuery.EnclosingType(type) == null)
                continue;
            var modifier = type.ChildrenOf(NodeKind.Modifier)
                .FirstOrDefault(m => m.Text.Equals("static", StringComparison.OrdinalIgnoreCase));
            if (modifier == null)
                continue;

            context.Report("A nested enum is static whether or not it says so, because its constants "
                           + "are created before any instance of the enclosing class exists. The "
                           + "keyword only makes the reader wonder what the enums without it do "
                           + "differently.", modifier.Range.StartLine);
        }
    }
}

public sealed class JavaMethodReturningConstantRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-SML-0450";
    public override string Name => "A method that always returns the same value should be a constant";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var modifiers = Modifiers(method);
            if (modifiers.Contains("abstract") || modifiers.Contains("native"))
                continue;
            if (SyntaxQuery.Parameters(method).Any())
                continue;
            // an override answers for its own type, and the constant is the point of it
            if (method.ChildrenOf(NodeKind.Attribute).Any(a => a.Text == "Override"))
                continue;

            var body = SyntaxQuery.Body(method);
            if (body is not { Children.Count: 1 })
                continue;
            var jump = body.Children[0];
            if (jump is not { Kind: NodeKind.Jump, Text: "return" } || jump.Children.Count != 1)
                continue;
            var value = jump.Children[0];
            if (value.Kind is not (NodeKind.NumberLiteral or NodeKind.StringLiteral or NodeKind.BooleanLiteral))
                continue;

            context.Report($"'{method.Text}' takes nothing and always answers '{value.Text}'. A constant "
                           + "says that plainly; a method suggests the answer depends on something.",
                method.Range.StartLine);
        }
    }
}

public sealed class JavaInstanceWritesStaticRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-SML-0451";
    public override string Name => "An instance method should not write to a static field";
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var statics = Members(type)
                .Where(m => m.Kind == NodeKind.FieldDeclaration && Modifiers(m).Contains("static")
                            && !Modifiers(m).Contains("final"))
                .Select(m => m.Text)
                .ToHashSet(StringComparer.Ordinal);
            if (statics.Count == 0)
                continue;

            foreach (var method in Members(type))
            {
                if (method.Kind != NodeKind.FunctionDeclaration || Modifiers(method).Contains("static"))
                    continue;
                var body = SyntaxQuery.Body(method);
                if (body == null)
                    continue;

                foreach (var assignment in body.OfKind(NodeKind.Assignment))
                {
                    if (!assignment.Text.EndsWith('=') || assignment.Text is "==" or "!=" or ">=" or "<=")
                        continue;
                    var target = SyntaxQuery.SimpleName(assignment.ChildAt(0));
                    if (!statics.Contains(target))
                        continue;

                    context.Report($"'{target}' is shared by every instance of {type.Text} and by every "
                                   + "thread, and this method writes to it from one instance. Two "
                                   + "objects that look independent are not, and nothing in the "
                                   + "signature says so.", assignment.Range.StartLine);
                }
            }
        }
    }
}

public sealed class JavaStraySemicolonRule : JavaContractRuleBase
{
    public override string Key => "QG-JV-CNV-0002";
    public override string Name => "A statement should not be empty";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        var tokens = context.Tokens;
        for (var i = 1; i < tokens.Count; i++)
        {
            if (tokens[i].Text != ";" || tokens[i - 1].Text != ";")
                continue;
            // a for header is written with two semicolons in a row when a clause is empty
            if (InForHeader(tokens, i))
                continue;

            context.Report("This semicolon closes nothing: it is an empty statement. Placed after an if "
                           + "or a loop it silently becomes the whole body, which is how a loop ends up "
                           + "doing nothing at all.", tokens[i].Line);
        }
    }

    private static bool InForHeader(IReadOnlyList<Tokenization.Token> tokens, int index)
    {
        var depth = 0;
        for (var i = index; i >= 0 && index - i < 64; i--)
        {
            var text = tokens[i].Text;
            if (text == ")")
                depth++;
            else if (text == "(")
            {
                if (depth == 0)
                    return i > 0 && tokens[i - 1].Text is "for";
                depth--;
            }
            else if (text is "{" or "}")
            {
                return false;
            }
        }
        return false;
    }
}
