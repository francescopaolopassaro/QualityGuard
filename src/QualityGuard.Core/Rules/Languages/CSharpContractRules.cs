using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// C# and VB.NET rules on the contract a member signs and the APIs that answer it: equality pairs
/// that miss half of their promise, format strings that ask for arguments nobody passed, logging
/// templates that repeat themselves, and platform entry points whose defaults are wrong.
/// </summary>
public static class CSharpContractRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new IsWithThisRule(),
        new InstanceWritesStaticRule(),
        new LambdaUnsubscribeRule(),
        new EmptyCollectionAccessRule(),
        new RawControlCharacterRule(),
        new EmptyNamespaceRule(),
        new CompositeFormatArityRule(),
        new GetTypeOnTypeInstanceRule(),
        new StaticFieldAssignedInStaticConstructorRule(),
        new AttributeWithoutUsageRule(),
        new PublicNativeMethodRule(),
        new OutdatedBaseTypeRule(),
        new OrderByBeforeWhereRule(),
        new LoggerTypeMismatchRule(),
        new DuplicateLogPlaceholderRule(),
        new LowercaseLogPlaceholderRule(),
        new BlockingCallInAsyncAzureFunctionRule(),
        new AzureFunctionInstanceStateRule(),
        new ComparableWithoutEqualsRule(),
    ];
}

public abstract class CSharpContractRule : RuleBase
{
    public override string[] Languages => ["cs", "vb"];

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static string Called(SyntaxNode call) => SyntaxQuery.InvokedName(call);

    protected static IReadOnlyList<SyntaxNode> Args(SyntaxNode call) => SyntaxQuery.Arguments(call);

    /// <summary>The modifier keywords written on a declaration.</summary>
    protected static HashSet<string> ModifiersOf(SyntaxNode declaration)
        => declaration.Children.Where(c => c.Kind == NodeKind.Modifier)
            .Select(c => c.Text).ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// Whether the file carries an Azure Functions trigger attribute; every rule of the functions
    /// family stays silent outside hosting code.
    /// </summary>
    protected static bool IsAzureFunctionsFile(IRuleContext context)
        => context.Root.OfKind(NodeKind.Attribute).Any(a =>
            a.Text is "FunctionName" or "Function" or ("Microsoft.Azure.WebJobs.FunctionName"));

    /// <summary>Extracts {name} placeholders from a composite-format literal, honouring {{ escapes.</summary>
    protected static IReadOnlyList<string> Placeholders(string literal)
    {
        var names = new List<string>();
        var i = 0;
        while (i < literal.Length - 1)
        {
            if (literal[i] == '{' && literal[i + 1] == '{')
            {
                i += 2;
                continue;
            }
            if (literal[i] == '}' && literal[i + 1] == '}')
            {
                i += 2;
                continue;
            }
            if (literal[i] == '{')
            {
                var close = literal.IndexOf('}', i);
                if (close > i)
                {
                    var inner = literal[(i + 1)..close];
                    var colon = inner.IndexOf(':');
                    if (colon >= 0)
                        inner = inner[..colon];
                    var comma = inner.IndexOf(',');
                    if (comma >= 0)
                        inner = inner[..comma];
                    names.Add(inner.Trim());
                    i = close + 1;
                    continue;
                }
            }
            i++;
        }
        return names;
    }

    private static readonly System.Text.RegularExpressions.Regex NumericPlaceholder =
        new("^\\{\\s*(\\d+)\\s*(,|:|})");

    /// <summary>The highest {N} index inside a composite format string, or -1.</summary>
    protected static int HighestIndex(string literal)
    {
        var highest = -1;
        foreach (System.Text.RegularExpressions.Match match in
                 System.Text.RegularExpressions.Regex.Matches(literal,
                     "\\{\\s*(\\d+)\\s*(?:,[^{}]*)?(?::[^{}]*)?\\}"))
            highest = Math.Max(highest, int.Parse(match.Groups[1].Value));
        return highest;
    }

    protected static bool IsNumericPlaceholderForm(string literal)
        => NumericPlaceholder.IsMatch(literal);
}

/// <summary>this is never null and already has its type: an is-test on it answers nothing.</summary>
public sealed class IsWithThisRule : CSharpContractRule
{
    public override string Key => "QG-CS-SML-0169";
    public override string Name => "is should not be used with this";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            // only the type-test operator: this == other and this != other are ordinary
            // comparisons that happen to start from this
            if (binary.Text != "is"
                || binary.ChildAt(0) is not { Kind: NodeKind.Identifier, Text: "this" })
                continue;
            context.Report(binary,
                "`this` can never be null here and its type is fixed at compile time, so this test "
                + "either always succeeds or never compiles to anything useful. Say what you mean "
                + "directly: drop the check when the type is guaranteed, or pattern-match "
                + "(`if (this is IPart)` still reads better as a plain interface use) only where "
                + "the target genuinely varies.");
        }
    }
}

/// <summary>An instance method writing a bare static field couples every object to one value.</summary>
public sealed class InstanceWritesStaticRule : CSharpContractRule
{
    public override string Key => "QG-CS-SML-0158";
    public override string Name => "Instance members should not write to static fields";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var staticFields = type.Descendants()
                .Where(n => n.Kind == NodeKind.FieldDeclaration
                            && n.Ancestor(NodeKind.FunctionDeclaration) == null
                            && ModifiersOf(n).Contains("static"))
                .Select(n => n.Text).ToHashSet(StringComparer.Ordinal);
            if (staticFields.Count == 0)
                continue;
            foreach (var function in SyntaxQuery.Functions(type))
            {
                if (ModifiersOf(function).Contains("static"))
                    continue;
                var body = SyntaxQuery.Body(function);
                if (body == null)
                    continue;
                foreach (var name in WritesTo(body))
                {
                    if (!staticFields.Contains(name))
                        continue;
                    context.Report(body,
                        $"{function.Text}() is per-instance but writes the static field {name}: "
                        + "two objects calling it race on the same storage, and the last writer "
                        + "wins for everyone. Make the field instance state, make the method "
                        + "static, or guard the field explicitly.");
                }
            }
        }
    }

    private static IEnumerable<string> WritesTo(SyntaxNode block)
    {
        foreach (var assignment in block.OfKind(NodeKind.Assignment))
            if (assignment.ChildAt(0) is { Kind: NodeKind.Identifier } target)
                yield return target.Text;
        foreach (var unary in block.OfKind(NodeKind.Unary))
            if (unary.Text is "++" or "--"
                && unary.ChildAt(0)?.Kind == NodeKind.Identifier)
                yield return unary.ChildAt(0).Text;
    }
}

/// <summary>Unsubscribing a fresh lambda removes nothing: it is a different object.</summary>
public sealed class LambdaUnsubscribeRule : CSharpContractRule
{
    public override string Key => "QG-CS-BUG-0063";
    public override string Name => "Anonymous delegates should not be used to unsubscribe";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            if (assignment.Text != "-=" || assignment.ChildAt(1)?.Kind != NodeKind.Lambda)
                continue;
            context.Report(assignment,
                "This -= removes a handler by identity, and a lambda written inline creates a new "
                + "one each time: the subscription you meant to remove stays attached and leaks "
                + "with it. Keep the delegate in a field (or a local that lives as long as the "
                + "subscription), pass that to both += and -=, and unsubscription actually "
                + "happens.");
        }
    }
}

/// <summary>Reading an empty collection literal returns nothing and iterating it runs nothing.</summary>
public sealed class EmptyCollectionAccessRule : CSharpContractRule
{
    private static readonly string[] Readers =
    [
        "First", "FirstOrDefault", "Last", "LastOrDefault", "Single", "SingleOrDefault",
        "Any", "All", "Count", "ElementAt", "ElementAtOrDefault", "Min", "Max", "Sum",
        "Average", "Aggregate", "ToArray", "ToList", "CopyTo", "Contains", "MaxBy", "MinBy"
    ];

    private static readonly string[] Creators =
    [
        "List", "Dictionary", "HashSet", "SortedSet", "SortedDictionary", "SortedDictionary",
        "Queue", "Stack", "LinkedList", "Collection", "ArrayList", "Hashtable"
    ];

    public override string Key => "QG-CS-BUG-0085";
    public override string Name => "Empty collections should not be accessed or iterated";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Readers.Contains(Called(call)))
                continue;
            var receiver = call.ChildAt(0) is { Kind: NodeKind.MemberSelect } select
                ? select.ChildAt(0)
                : null;
            if (IsFreshlyCreatedAndStillEmpty(receiver))
                context.Report(call,
                    $"This {Called(call)}() runs against a collection created empty right here, so "
                    + "the result is decided before the line executes - an exception for First, "
                    + "false for Any, zero for Count. The empty literal is either leftover "
                    + "scaffolding or a stand-in for data that should arrive.");
        }
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (loop.Text != "foreach")
                continue;
            // the iterated expression follows the declared variable
            var children = loop.Children.Where(c => c.Kind != NodeKind.VariableDeclaration).ToList();
            if (children.Count > 0 && IsFreshlyCreatedAndStillEmpty(children[0]))
                context.Report(loop,
                    "This loop iterates a collection created empty on the spot: the body never "
                    + "runs. Iterate the real source, or delete the loop when the emptiness is "
                    + "the point.");
        }
    }

    private static bool IsFreshlyCreatedAndStillEmpty(SyntaxNode? expression)
    {
        if (expression is { Kind: NodeKind.ObjectCreation } creation
            && Creators.Contains(creation.Text.Split('<')[0])
            && (creation.FirstChild(NodeKind.ArgumentList)?.Children.Count ?? 0) == 0
            && !creation.OfKind(NodeKind.ObjectInitializer).Any())
            return true;
        return expression is { Kind: NodeKind.ListLiteral, Text: "collection" };
    }
}

/// <summary>A raw tab or newline inside a normal literal is invisible at the call site.</summary>
public sealed class RawControlCharacterRule : CSharpContractRule
{
    public override string Key => "QG-CS-SML-0156";
    public override string Name => "Whitespace characters in literals should be escaped";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var literal in context.Root.OfKind(NodeKind.StringLiteral))
        {
            // verbatim literals (@") may span lines by design; interpolated ones carry their own
            // holes, which this rule does not try to read
            var text = literal.Text;
            if (text.Length < 2 || text.Contains('@') || text.Contains('$'))
                continue;
            if (text.Any(c => char.IsControl(c) && c != '\0'))
                context.Report(literal,
                    "This literal holds a raw control character - most often a tab typed instead "
                    + "of \\t. It renders as ordinary whitespace in the editor and travels into "
                    + "comparisons and output unchanged. Replace it with its escape sequence so "
                    + "the reader sees what the program sees.");
        }
    }
}

/// <summary>A namespace that declares nothing is scaffolding someone forgot to fill.</summary>
public sealed class EmptyNamespaceRule : CSharpContractRule
{
    public override string Key => "QG-CS-SML-0191";
    public override string Name => "Namespaces should not be empty";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var space in context.Root.OfKind(NodeKind.PackageDeclaration))
        {
            var body = space.LastChild(NodeKind.Block);
            if (body != null && body.Children.Count == 0)
                context.Report(space,
                    $"The namespace {space.Text} declares no types. Either its content moved and "
                    + "this shell stayed behind, or the file was created from a template and "
                    + "never filled. Delete the namespace and the file with it.");
        }
    }
}

/// <summary>A format hole with no argument behind it prints braces instead of data.</summary>
public sealed class CompositeFormatArityRule : CSharpContractRule
{
    private static readonly string[] Formatters =
    [
        "Format", "WriteLine", "Write", "AppendFormat"
    ];

    public override string Key => "QG-CS-SML-0215";
    public override string Name => "Composite format strings should match their arguments";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Formatters.Contains(Called(call)) || Args(call).Count < 2)
                continue;
            // the template is either the first argument or follows an IFormatProvider
            var templateIndex = SyntaxQuery.IsStringLiteral(Args(call)[0]) ? 0
                : Args(call).Count > 2 && SyntaxQuery.IsStringLiteral(Args(call)[1]) ? 1 : -1;
            if (templateIndex < 0)
                continue;
            var literal = SyntaxQuery.ConstantString(Args(call)[templateIndex]);
            if (literal == null || !literal.Contains('{'))
                continue;
            var argumentCount = Args(call).Count - templateIndex - 1;
            var highest = HighestIndex(literal);
            if (highest >= argumentCount && highest >= 0)
                context.Report(call,
                    $"The format string asks for {{{highest}}} but only {argumentCount} "
                    + $"argument{(argumentCount == 1 ? "" : "s")} follow{(argumentCount == 1 ? "s" : "")}: "
                    + "at run time the hole stays unfilled or a FormatException stops the call. "
                    + "Renumber the placeholders from zero without gaps, and pass one argument per "
                    + "hole.");
        }
    }
}

/// <summary>GetType() on something already known to be Type answers typeof(Type).</summary>
public sealed class GetTypeOnTypeInstanceRule : CSharpContractRule
{
    public override string Key => "QG-CS-SML-0209";
    public override string Name => "Type should not be examined on System.Type instances";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (Called(call) != "GetType" || Args(call).Count != 0)
                continue;
            var receiver = call.ChildAt(0) is { Kind: NodeKind.MemberSelect } select
                ? select.ChildAt(0)
                : null;
            var type = context.Types.TypeOf(receiver);
            if (type != null && type.Contains("Type", StringComparison.Ordinal))
                context.Report(call,
                    "This value already is a Type object; GetType() on it returns typeof(Type), "
                    + "which says nothing about the type it describes. Compare it against another "
                    + "Type directly (`someType == typeof(string)`), or read its properties such "
                    + "as Name and IsClass.");
        }
    }
}

/// <summary>A static constructor exists to do work; assigning constants belongs on the field.</summary>
public sealed class StaticFieldAssignedInStaticConstructorRule : CSharpContractRule
{
    public override string Key => "QG-CS-SML-0245";
    public override string Name => "static fields should be initialized inline";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var staticFields = type.Descendants()
                .Where(n => n.Kind == NodeKind.FieldDeclaration
                            && n.Ancestor(NodeKind.FunctionDeclaration) == null
                            && ModifiersOf(n).Contains("static"));
            foreach (var constructor in type.Descendants()
                         .Where(n => n.Kind == NodeKind.ConstructorDeclaration
                                     && ModifiersOf(n).Contains("static")))
            {
                var body = SyntaxQuery.Body(constructor);
                if (body == null)
                    continue;
                foreach (var assignment in body.OfKind(NodeKind.Assignment))
                {
                    if (assignment.ChildAt(0)?.Kind != NodeKind.Identifier)
                        continue;
                    // only a literal could move onto the declaration; work done in the static
                    // constructor - reading files, building objects - is exactly what the
                    // constructor is for, and inlining it is not on offer
                    if (assignment.ChildAt(1)?.Kind != NodeKind.NumberLiteral
                        && assignment.ChildAt(1)?.Kind != NodeKind.StringLiteral)
                        continue;
                    var name = assignment.ChildAt(0).Text;
                    if (!staticFields.Any(f => f.Text == name))
                        continue;
                    context.Report(assignment,
                        $"The static constructor only copies a constant into {name}. Moving the "
                        + "value onto the declaration (`static ... {name} = ...`) removes the "
                        + "constructor entirely, and with it the hidden ordering between static "
                        + "initialisation and first use.");
                }
            }
        }
    }
}

/// <summary>An attribute nobody can restrict is applicable everywhere, including nonsense targets.</summary>
public sealed class AttributeWithoutUsageRule : CSharpContractRule
{
    public override string Key => "QG-CS-SML-0253";
    public override string Name => "Custom attributes should be marked with AttributeUsage";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (ModifiersOf(type).Contains("abstract")
                || !type.Children.Where(c => c.Kind == NodeKind.TypeReference)
                    .Any(baseType => baseType.Text.Split('<')[0]
                        .EndsWith("Attribute", StringComparison.Ordinal)))
                continue;
            if (type.Children.Any(c => c.Kind == NodeKind.Attribute
                                       && c.Text.Contains("AttributeUsage")))
                continue;
            context.Report(type,
                $"{type.Text} declares no AttributeUsage, so the compiler allows it on every "
                + "target - classes, parameters, return values - whether that makes sense or not. "
                + "Add [AttributeUsage(AttributeTargets.X)] naming where it legitimately applies, "
                + "and decide AllowMultiple while you are there.");
        }
    }
}

/// <summary>A native import published as API drags platform plumbing into the public surface.</summary>
public sealed class PublicNativeMethodRule : CSharpContractRule
{
    public override string Key => "QG-CS-SML-0292";
    public override string Name => "Native methods should not be exposed publicly";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            if (!function.Children.Any(c =>
                    c.Kind == NodeKind.Attribute && c.Text.Contains("DllImport")))
                continue;
            var modifiers = ModifiersOf(function);
            if (!modifiers.Contains("public"))
                continue;
            context.Report(function,
                $"The P/Invoke entry point {function.Text} is public: callers now depend on a raw "
                + "platform signature - pointers, calling conventions, error codes. Keep the "
                + "import internal and wrap it in a managed method that marshals arguments and "
                + "translates failures into exceptions.");
        }
    }
}

/// <summary>Inheriting concrete collections freezes storage decisions into the public contract.</summary>
public sealed class OutdatedBaseTypeRule : CSharpContractRule
{
    private static readonly string[] Bases =
    [
        "List", "Dictionary", "LinkedList", "SortedDictionary", "SortedList"
    ];

    public override string Key => "QG-CS-SML-0280";
    public override string Name => "Types should not extend outdated base types";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        // test fixtures extend collections on purpose to exercise serialisation; the contract the
        // rule protects is the production API surface
        if (LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!ModifiersOf(type).Contains("public"))
                continue;
            var baseType = type.Children.FirstOrDefault(c =>
                c.Kind == NodeKind.TypeReference
                && Bases.Contains(c.Text.Split('<', ',')[0].Trim()));
            if (baseType == null)
                continue;
            context.Report(type,
                $"{type.Text} inherits {baseType.Text} directly, so its entire storage - and every "
                + "mutator the collection carries - becomes part of the public contract forever. "
                + "Compose instead: hold the collection privately and expose the operations your "
                + "callers actually need, so the implementation can change.");
        }
    }
}

/// <summary>Sorting before filtering orders rows that are about to be thrown away.</summary>
public sealed class OrderByBeforeWhereRule : CSharpContractRule
{
    public override string Key => "QG-CS-SML-0326";
    public override string Name => "The collection should be filtered before sorting";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (Called(call) != "Where" || call.ChildAt(0)?.Kind != NodeKind.MemberSelect)
                continue;
            var receiver = call.ChildAt(0).ChildAt(0);
            if (receiver?.Kind != NodeKind.Invocation
                || Called(receiver) is not ("OrderBy" or "OrderByDescending" or "ThenBy"
                    or "ThenByDescending"))
                continue;
            context.Report(call,
                "Where after OrderBy sorts elements that are then discarded: the comparison work "
                + "on the survivors could have been done on far fewer. Filter first - "
                + ".Where(...).OrderBy(...) - and the result is identical at a fraction of the "
                + "cost when most rows fail the predicate.");
        }
    }
}

/// <summary>The logger's category should name the type that logs through it.</summary>
public sealed class LoggerTypeMismatchRule : CSharpContractRule
{
    private static readonly System.Text.RegularExpressions.Regex GenericLogger =
        new("^ILogger<(.+)>$");

    public override string Key => "QG-CS-SML-0336";
    public override string Name => "Generic logger injection should match enclosing type";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var constructor in context.Root.OfKind(NodeKind.ConstructorDeclaration))
        {
            var owner = constructor.Ancestor(NodeKind.ClassDeclaration);
            if (owner == null)
                continue;
            foreach (var parameter in SyntaxQuery.Parameters(constructor))
            {
                var declared = parameter.Children
                    .FirstOrDefault(c => c.Kind == NodeKind.TypeReference)?.Text;
                if (declared == null)
                    continue;
                var match = GenericLogger.Match(declared);
                if (!match.Success || match.Groups[1].Value == owner.Text)
                    continue;
                context.Report(parameter,
                    $"The logger is categorised as {match.Groups[1].Value} but lives in "
                    + $"{owner.Text}: log lines carry the wrong source name, and filtering by "
                    + "namespace sends them to the wrong place. Ask for ILogger<"
                    + $"{owner.Text}> - the DI container supplies it automatically.");
            }
        }
    }
}

/// <summary>Two placeholders with one name print the first argument twice and lose the second.</summary>
public abstract class LogPlaceholderRule : CSharpContractRule
{
    protected abstract bool Violation(IReadOnlyList<string> placeholders);

    protected virtual bool Applies(IReadOnlyList<string> placeholders) => true;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Called(call).StartsWith("Log", StringComparison.Ordinal) || Args(call).Count < 2)
                continue;
            var template = SyntaxQuery.ConstantString(Args(call)[0]);
            if (template == null || !template.Contains('{'))
                continue;
            var placeholders = Placeholders(template)
                .Where(p => p.Length > 0 && char.IsLetter(p[0])).ToList();
            if (placeholders.Count == 0 || !Applies(placeholders))
                continue;
            if (Violation(placeholders))
                Report(context, call, placeholders);
        }
    }

    protected abstract void Report(IRuleContext context, SyntaxNode call,
        IReadOnlyList<string> placeholders);
}

public sealed class DuplicateLogPlaceholderRule : LogPlaceholderRule
{
    public override string Key => "QG-CS-BUG-0095";
    public override string Name => "Message template placeholders should be unique";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    protected override bool Violation(IReadOnlyList<string> placeholders)
        => placeholders.GroupBy(p => p, StringComparer.Ordinal).Any(g => g.Count() > 1);

    protected override void Report(IRuleContext context, SyntaxNode call,
        IReadOnlyList<string> placeholders)
    {
        var repeated = placeholders
            .GroupBy(p => p, StringComparer.Ordinal).First(g => g.Count() > 1).Key;
        context.Report(call,
            $"The template uses {{{repeated}}} more than once. Structured logging matches "
            + "placeholders to arguments positionally: the duplicate binds to the same first "
            + "value twice and the second argument never reaches the sink. Rename the second "
            + "occurrence and pass both values.");
    }
}

public sealed class LowercaseLogPlaceholderRule : LogPlaceholderRule
{
    public override string Key => "QG-CS-SML-0338";
    public override string Name => "Use PascalCase for named placeholders";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    protected override bool Violation(IReadOnlyList<string> placeholders)
        => placeholders.Any(p => char.IsLower(p[0]));

    protected override void Report(IRuleContext context, SyntaxNode call,
        IReadOnlyList<string> placeholders)
    {
        var offender = placeholders.First(p => char.IsLower(p[0]));
        context.Report(call,
            $"The placeholder {{{offender}}} starts lowercase. Template names become property "
            + "names on the structured event, and sinks and dashboards expect the C# convention - "
            + "a mixed casing splits `{user}` and `{User}` into two different fields downstream.");
    }
}

/// <summary>.Result inside an async Azure Function parks a thread on the hosting pool.</summary>
public sealed class BlockingCallInAsyncAzureFunctionRule : CSharpContractRule
{
    private static readonly string[] Blocks =
    [
        "Result", "Wait", "GetAwaiter"
    ];

    public override string Key => "QG-CS-SML-0311";
    public override string Name => "Calls to async methods should not block in Azure Functions";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!IsAzureFunctionsFile(context))
            return;
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            if (!ModifiersOf(function).Contains("async"))
                continue;
            var body = SyntaxQuery.Body(function);
            if (body == null)
                continue;
            foreach (var access in body.OfKind(NodeKind.MemberSelect))
            {
                if (!Blocks.Contains(access.ChildAt(1)?.Text))
                    continue;
                context.Report(access,
                    "Blocking on an asynchronous call inside an async function holds a hosting "
                    + "thread hostage while awaiting I/O - under load the plan starves and "
                    + "requests queue behind idle waits. Await the task instead, and let the "
                    + "thread return to the pool.");
            }
        }
    }
}

/// <summary>An instance field in a functions class survives between invocations you cannot order.</summary>
public sealed class AzureFunctionInstanceStateRule : CSharpContractRule
{
    public override string Key => "QG-CS-SML-0308";
    public override string Name => "Azure Functions should be stateless";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!IsAzureFunctionsFile(context))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            foreach (var field in type.Descendants()
                         .Where(n => n.Kind == NodeKind.FieldDeclaration
                                     && n.Ancestor(NodeKind.FunctionDeclaration) == null))
            {
                var modifiers = ModifiersOf(field);
                if (modifiers.Contains("static") || modifiers.Contains("const")
                    || modifiers.Contains("readonly"))
                    continue;
                context.Report(field,
                    $"{field.Text} is instance state in a functions class: the host reuses and "
                    + "recycles instances as it likes, so the value may carry over between calls "
                    + "- or vanish. Make it static readonly for shared resources, or move it into "
                    + "the invocation's locals.");
            }
        }
    }
}

/// <summary>IComparable promises ordering; consumers also expect equality to agree with it.</summary>
public sealed class ComparableWithoutEqualsRule : CSharpContractRule
{
    public override string Key => "QG-CS-SML-0098";
    public override string Name => "Equals and operators should agree with IComparable";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!type.Children.Where(c => c.Kind == NodeKind.TypeReference)
                    .Any(baseType => baseType.Text.StartsWith("IComparable", StringComparison.Ordinal)))
                continue;
            var overridesEquals = type.Descendants().Any(n =>
                n.Kind == NodeKind.FunctionDeclaration
                && n.Text == "equals");
            var overridesClrEquals = type.Descendants().Any(n =>
                n.Kind == NodeKind.FunctionDeclaration
                && n.Text == "Equals"
                && ModifiersOf(n).Contains("override"));
            if (overridesClrEquals || overridesEquals)
                continue;
            context.Report(type,
                $"{type.Text} implements IComparable but keeps reference Equals: sorted "
                + "collections will treat two equal-valued objects as equal while Contains and "
                + "dictionary lookups treat them as different. Override Equals (and GetHashCode), "
                + "then align == and != with CompareTo's notion of sameness.");
        }
    }
}
