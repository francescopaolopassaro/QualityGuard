using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;
using QualityGuard.Core.Analysis;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Checks the .NET profiles turn on by default, written once for C# and VB.NET. Most read
/// attributes, signatures and declarations on the tree; the few that are VB syntax alone say so.
/// A rule that cannot see enough stays silent — none of them guesses from a name alone.
/// </summary>
public static class CSharpVbGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PureMethodReturnsValueRule(),
        new ExpectedExceptionAttributeRule(),
        new DebuggerDisplayReferencesRule(),
        new ConstructorArgumentMismatchRule(),
        new SerializationEventHandlerSignatureRule(),
        new OnlyPrivateConstructorsRule(),
        new PublicExceptionTypeRule(),
        new MultidimensionalArrayParameterRule(),
        new MultiParameterIndexerRule(),
        new ParamArrayArrayArgumentRule(),
        new OverrideParameterNameRule(),
        new OverloadsShouldBeGroupedRule(),
        new ToStringReturnsNullRule(),
        new AsyncMethodReturnsNullRule(),
        new GeneralExceptionThrownRule(),
        new HardcodedUriRule(),
        new NullableValueWithoutCheckRule(),
        new DateTimeWithoutKindRule(),
        new FlagsEnumMemberNotPowerOfTwoRule(),
        new FlagsEnumZeroMemberRule(),
        new ArrayCreationWithInitializerRule(),
        new DisposeTwiceRule(),
        new ShiftByNonIntegerRule(),
        new ArithmeticNearOverflowRule(),
        new ExitSelectRedundantRule(),
        new OnErrorStatementRule(),
        new FunctionNameAssignmentRule(),
        new OptionStrictDisabledRule(),
        new OptionExplicitDisabledRule(),
        new RouteTemplateLeadingSlashRule(),
        new LockReleaseMismatchRule(),
        new SharedPartCreatedWithNewRule(),
        new UseUnixEpochRule(),
        new BooleanLiteralUnnecessaryRule(),
        new FindInsteadOfFirstOrDefaultRule(),
        new UseTrueForAllRule(),
        new UseIndexingInsteadOfLinqMethodsRule(),
    ];
}

// ------------------------------------------------------------------ attribute-driven

public abstract class VbGapRuleBase : RuleBase
{
    internal static bool HasAttribute(SyntaxNode member, string name) =>
        member.ChildrenOf(NodeKind.Attribute).Any(a => a.Text.EndsWith(name, StringComparison.OrdinalIgnoreCase));

    internal static bool HasAttribute(SyntaxNode member, params string[] names) =>
        names.Any(n => HasAttribute(member, n));
}

public sealed class PureMethodReturnsValueRule : VbGapRuleBase
{
    public override string Key => "QG-CS-BUG-0122";
    public override string Name => "A method marked [Pure] should return a value";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!HasAttribute(function, "Pure"))
                continue;
            var returns = function.OfKind(NodeKind.Jump).Any(j => j.Text == "return" && j.Children.Count > 0)
                          || function.OfKind(NodeKind.Block).Any(b => b.Text == "expression")
                          || SyntaxQuery.Body(function)?.Children.Count == 0;
            if (returns)
                continue;
            context.Report(function, $"'{function.Text}' is marked [Pure] but never returns a value; "
                                     + "the annotation promises callers a result they can trust.");
        }
    }

}

public sealed class ExpectedExceptionAttributeRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0417";
    public override string Name => "[ExpectedException] should not select the whole test";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!HasAttribute(function, "ExpectedException"))
                continue;
            context.Report(function, $"'{function.Text}' expects its exception through the attribute, "
                                     + "so any earlier line can throw it and the test still passes. "
                                     + "Assert the exception where it is raised instead "
                                     + "(Assert.Throws / Record.Exception).");
        }
    }
}

public sealed class DebuggerDisplayReferencesRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0434";
    public override string Name => "[DebuggerDisplay] should reference existing members";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var attribute = type.ChildrenOf(NodeKind.Attribute)
                .FirstOrDefault(a => a.Text.EndsWith("DebuggerDisplay", StringComparison.Ordinal));
            if (attribute == null)
                continue;
            var literal = attribute.Descendants().OfType<SyntaxNode>()
                .FirstOrDefault(n => n.Kind == NodeKind.StringLiteral)?.Text ?? string.Empty;
            if (literal.Length < 3)
                continue;

            var own = type.OfKind(NodeKind.FunctionDeclaration).Select(f => f.Text)
                .Concat(type.OfKind(NodeKind.FieldDeclaration).Select(f => f.Text))
                .Concat(type.OfKind(NodeKind.PropertyDeclaration).Select(f => f.Text))
                .ToHashSet(StringComparer.Ordinal);

            foreach (System.Text.RegularExpressions.Match m in
                     System.Text.RegularExpressions.Regex.Matches(literal, @"\{([\w\.]+)[^}]*\}"))
            {
                var member = m.Groups[1].Value.Split('.')[0];
                if (own.Contains(member) || member is "nq" or "@" )
                    continue;
                context.Report(attribute, $"The [DebuggerDisplay] of '{type.Text}' references "
                                          + $"'{member}', which no member of the type provides. The "
                                          + "debugger will print an error instead of the value.");
                break;
            }
        }
    }
}

public sealed class ConstructorArgumentMismatchRule : VbGapRuleBase
{
    public override string Key => "QG-CS-BUG-0133";
    public override string Name => "[ConstructorArgument] should name an existing constructor parameter";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var parameters = type.Descendants()
                .Where(n => n.Kind is NodeKind.ConstructorDeclaration or NodeKind.FunctionDeclaration
                            && n.Text == type.Text)
                .SelectMany(n => n.FirstChild(NodeKind.ParameterList)?
                    .ChildrenOf(NodeKind.Parameter).Select(p => p.Text) ?? [])
                .ToHashSet(StringComparer.Ordinal);
            if (parameters.Count == 0)
                continue;

            foreach (var property in type.OfKind(NodeKind.PropertyDeclaration))
            {
                var argument = property.ChildrenOf(NodeKind.Attribute)
                    .FirstOrDefault(a => a.Text.EndsWith("ConstructorArgument", StringComparison.Ordinal));
                if (argument != null && !parameters.Contains(property.Text))
                    context.Report(argument, $"The property '{property.Text}' claims to be constructor "
                                             + $"argument {argument.Text}, but no constructor of "
                                             + "'{type.Text}' takes it.");
            }

            foreach (var field in type.OfKind(NodeKind.FieldDeclaration))
            {
                var argument = field.ChildrenOf(NodeKind.Attribute)
                    .FirstOrDefault(a => a.Text.EndsWith("ConstructorArgument", StringComparison.Ordinal));
                if (argument != null && !parameters.Contains(field.Text))
                    context.Report(argument, $"The field '{field.Text}' claims to be constructor "
                                             + "argument that no constructor declares.");
            }
        }
    }
}

public sealed class SerializationEventHandlerSignatureRule : VbGapRuleBase
{
    private static readonly string[] Events = ["OnSerializing", "OnSerialized", "OnDeserializing", "OnDeserialized"];

    public override string Key => "QG-CS-BUG-0126";
    public override string Name => "Serialization event handlers should take a StreamingContext";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var attribute = function.ChildrenOf(NodeKind.Attribute)
                .FirstOrDefault(a => Events.Any(e => a.Text.EndsWith(e, StringComparison.Ordinal)));
            if (attribute == null)
                continue;
            var parameters = function.FirstChild(NodeKind.ParameterList)?
                .ChildrenOf(NodeKind.Parameter).ToList();
            var right = parameters is { Count: 1 }
                        && (parameters[0].FirstChild(NodeKind.TypeReference)?.Text ?? "")
                            .Contains("StreamingContext", StringComparison.OrdinalIgnoreCase);
            if (right)
                continue;
            context.Report(function, $"'{function.Text}' handles a serialization event, so the runtime "
                                     + "calls it with one StreamingContext argument; any other "
                                     + "signature is silently skipped.");
        }
    }
}

// ------------------------------------------------------------- type/member shape

public sealed class OnlyPrivateConstructorsRule : VbGapRuleBase
{
    public override string Key => "QG-CS-BUG-0118";
    public override string Name => "A class with only private constructors should be static or sealed-factory";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var constructors = type.OfKind(NodeKind.ConstructorDeclaration).ToList();
            if (constructors.Count == 0 || constructors.Any(c =>
                    !c.ChildrenOf(NodeKind.Modifier).Any(m => m.Text is "private" or "internal")))
                continue;
            // static factories answer every construction themselves: the class is a factory, not a
            // type somebody is meant to instantiate. Only instance members make the check matter.
            var hasInstanceMembers = type.OfKind(NodeKind.FunctionDeclaration)
                .Any(f => !f.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "static"));
            if (!hasInstanceMembers)
                continue;
            context.Report(type, $"'{type.Text}' declares only non-public constructors while carrying "
                                 + "instance members: nothing outside can ever build it. Make it "
                                 + "static, or add the intended entry point.");
        }
    }
}

public sealed class PublicExceptionTypeRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0420";
    public override string Name => "Exception types should not be public";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var baseType = type.Descendants().FirstOrDefault(n => n.Kind == NodeKind.TypeReference)?.Text ?? "";
            if (!type.Text.EndsWith("Exception", StringComparison.Ordinal)
                || !baseType.Contains("Exception", StringComparison.Ordinal))
                continue;
            if (!type.ChildrenOf(NodeKind.Modifier).Any(m => m.Text is "public"))
                continue;
            context.Report(type, $"'{type.Text}' is public: callers start catching it and the type can "
                                 + "never change again. Keep exception types internal and let the "
                                 + "public surface stay exception-free.");
        }
    }
}

public sealed class MultidimensionalArrayParameterRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0400";
    public override string Name => "Public methods should not take multidimensional arrays";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!function.ChildrenOf(NodeKind.Modifier).Any(m => m.Text is "public" or "protected"))
                continue;
            foreach (var parameter in function.FirstChild(NodeKind.ParameterList)?
                         .ChildrenOf(NodeKind.Parameter) ?? [])
            {
                var typeText = parameter.FirstChild(NodeKind.TypeReference)?.Text ?? "";
                if (typeText.Contains("[,") || typeText.Contains(",,"))
                    context.Report(parameter, $"'{function.Text}' takes the multidimensional array "
                                              + $"'{parameter.Text}': every caller has to build that "
                                              + "shape. Take IEnumerable<T> rows or a jagged array "
                                              + "instead.");
            }
        }
    }
}

public sealed class MultiParameterIndexerRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0391";
    public override string Name => "Indexers should take at most one parameter";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var indexer in context.Root.OfKind(NodeKind.IndexerDeclaration))
        {
            var count = indexer.FirstChild(NodeKind.ParameterList)?.ChildrenOf(NodeKind.Parameter).Count() ?? 0;
            if (count <= 1)
                continue;
            context.Report(indexer, "This indexer takes several arguments, which reads as a hidden "
                                    + "method call. Replace it with a named method that says what "
                                    + "the lookup means.");
        }
    }
}

public sealed class ParamArrayArrayArgumentRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0421";
    public override string Name => "Do not pass an explicit array where the signature asks for params";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            var arguments = invocation.FirstChild(NodeKind.ArgumentList);
            if (arguments == null || arguments.Children.Count != 1)
                continue;
            var only = arguments.Children[0];
            if (only.Kind is not (NodeKind.ArrayCreation or NodeKind.ListLiteral))
                continue;
            var callee = invocation.Text.Split('.').LastOrDefault() ?? "";
            if (callee.Length < 2 || char.IsUpper(callee[0]))
                continue;
            context.Report(only, $"Pass the elements of this array to '{callee}' directly: the "
                                 + "parameter is declared params, and wrapping them hides that "
                                 + "from the reader.");
        }
    }
}

public sealed class OverrideParameterNameRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0463";
    public override string Name => "Override parameter names should match the declaration they refine";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        if (context.Project.Types.Count == 0)
            return;
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!function.ChildrenOf(NodeKind.Modifier).Any(m => m.Text is "override"))
                continue;
            var name = function.Text;
            if (name.Length == 0)
                continue;
            var expected = context.Project.ParameterNames(name);
            if (expected == null || expected.Count == 0)
                continue;
            var actual = function.FirstChild(NodeKind.ParameterList)?
                .ChildrenOf(NodeKind.Parameter).Select(p => p.Text).ToList();
            if (actual == null || actual.Count != expected.Count)
                continue;
            for (var i = 0; i < actual.Count; i++)
            {
                if (expected[i].Length > 0 && actual[i].Length > 0 && expected[i] != actual[i])
                    context.Report(function, $"'{name}' renames parameter '{expected[i]}' to "
                                             + $"'{actual[i]}': named arguments at the call sites of "
                                             + "the base type stop compiling. Keep the original name.");
            }
        }
    }
}

public sealed class OverloadsShouldBeGroupedRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0431";
    public override string Name => "Overloads of a method should be declared together";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var positions = new Dictionary<string, List<int>>(StringComparer.Ordinal);
            var order = 0;
            foreach (var member in type.Children)
            {
                if (member.Kind == NodeKind.FunctionDeclaration && member.Text.Length > 0)
                {
                    if (!positions.TryGetValue(member.Text, out var list))
                        positions[member.Text] = list = [];
                    list.Add(order);
                }
                order++;
            }

            foreach (var (name, list) in positions)
            {
                if (list.Count < 2 || list[^1] - list[0] == list.Count - 1)
                    continue;
                context.Report($"The overloads of '{name}' are separated by other members: a reader "
                               + "scanning the type misses half of them. Declare them side by side.",
                    null);
                break;
            }
        }
    }
}

// ------------------------------------------------------------- returns & throws

public sealed class ToStringReturnsNullRule : VbGapRuleBase
{
    public override string Key => "QG-CS-BUG-0111";
    public override string Name => "ToString should not return null";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (function.Text != "ToString")
                continue;
            foreach (var jump in function.OfKind(NodeKind.Jump))
            {
                if (jump.Text != "return" || jump.ChildAt(0)?.Kind != NodeKind.NullLiteral)
                    continue;
                context.Report(jump, "'ToString' returning null breaks every caller that prints or "
                                     + "concatenates the object. Return string.Empty for the empty "
                                     + "case.");
            }
        }
    }
}

public sealed class AsyncMethodReturnsNullRule : VbGapRuleBase
{
    public override string Key => "QG-CS-BUG-0138";
    public override string Name => "A Task-returning method should not return null";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var returnType = function.ChildrenOf(NodeKind.TypeReference).LastOrDefault()?.Text ?? "";
            if (!returnType.StartsWith("Task", StringComparison.Ordinal))
                continue;
            foreach (var jump in function.OfKind(NodeKind.Jump))
            {
                if (jump.Text != "return" || jump.ChildAt(0)?.Kind != NodeKind.NullLiteral)
                    continue;
                context.Report(jump, "Returning null here hands callers a Task that explodes when "
                                     + "awaited. Return Task.CompletedTask, or Task.FromResult for "
                                     + "a value.");
            }
        }
    }
}

public sealed class GeneralExceptionThrownRule : VbGapRuleBase
{
    private static readonly HashSet<string> General = new(StringComparer.Ordinal)
        { "Exception", "ApplicationException", "SystemException" };

    public override string Key => "QG-CS-SML-0466";
    public override string Name => "General or reserved exceptions should not be thrown";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var jump in context.Root.OfKind(NodeKind.Jump))
        {
            if (jump.Text != "throw")
                continue;
            var thrown = SyntaxQuery.DottedName(jump.ChildAt(0)) ?? "";
            var simple = thrown.Split('.').LastOrDefault() ?? "";
            var creation = jump.Descendants().FirstOrDefault(n => n.Kind == NodeKind.ObjectCreation);
            simple = (creation?.Text ?? thrown).Split('.').LastOrDefault() ?? "";
            if (!General.Contains(simple))
                continue;
            context.Report(jump, $"Throwing '{simple}' tells the caller nothing about what failed. "
                                 + "Throw the most specific type, or one of your own that says it.");
        }
    }
}

// ------------------------------------------------------------ expressions & literals

public sealed class HardcodedUriRule : VbGapRuleBase
{
    private static readonly System.Text.RegularExpressions.Regex Uri =
        new(@"^(https?|ftp)://[\w\.\-]{2,}", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    public override string Key => "QG-CS-SML-0363";
    public override string Name => "URIs should not be hardcoded";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        if (IsTestOrConfig(context.File.Path))
            return;
        foreach (var literal in context.Root.OfKind(NodeKind.StringLiteral))
        {
            if (!Uri.IsMatch(literal.Text.Trim('"', ' ')))
                continue;
            context.Report(literal, $"This address ('{literal.Text}') is baked into the source: moving "
                                    + "environments means recompiling. Read it from configuration "
                                    + "and keep only the scheme default here.");
        }
    }

    internal static bool IsTestOrConfig(string path) =>
        path.Contains("Test", StringComparison.OrdinalIgnoreCase)
        || path.Contains("Sample", StringComparison.OrdinalIgnoreCase)
        || path.Contains("Example", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".designer.cs", StringComparison.OrdinalIgnoreCase);
}



public sealed class NullableValueWithoutCheckRule : VbGapRuleBase
{
    public override string Key => "QG-CS-BUG-0123";
    public override string Name => ".Value should follow a HasValue check";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        // only a receiver the file itself declares as nullable — 'int? id' — is known enough;
        // every other '.Value' belongs to a type this scan cannot see and stays silent
        var nullableNames = context.Root.OfKind(NodeKind.VariableDeclaration)
            .Concat(context.Root.OfKind(NodeKind.Parameter))
            .Where(d => (d.FirstChild(NodeKind.TypeReference)?.Text ?? "").EndsWith("?"))
            .Select(d => d.Text)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var access in context.Root.OfKind(NodeKind.MemberSelect))
        {
            if (access.Text?.EndsWith(".Value", StringComparison.Ordinal) != true)
                continue;
            var receiver = access.ChildAt(0)?.Text ?? "";
            if (!nullableNames.Contains(receiver))
                continue;
            var guarded = context.Tokens.Any(t =>
                t.Kind == TokenKind.Identifier && t.Text == receiver
                && t.Line >= access.Line - 4 && t.Line < access.Line
                && context.Tokens.Any(u => u.Line == t.Line && u.Text is "HasValue" or "??"));
            if (guarded)
                continue;
            context.Report(access, $"'{receiver}.Value' throws when the nullable is empty, and no "
                                   + "check guards it here. Test HasValue, use GetValueOrDefault, "
                                   + "or pattern-match.");
        }
    }
}

public sealed class DateTimeWithoutKindRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0443";
    public override string Name => "new DateTime should say which kind of time it holds";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            if ((creation.Text ?? "").Split('.').LastOrDefault() != "DateTime")
                continue;
            var arguments = creation.FirstChild(NodeKind.ArgumentList);
            if (arguments == null || arguments.Children.Count == 0 || arguments.Children.Count >= 3
                && arguments.Children.Any(a => (SyntaxQuery.DottedName(a) ?? "")
                    .Contains("DateTimeKind", StringComparison.OrdinalIgnoreCase)))
                continue;
            context.Report(creation, "This DateTime leaves DateTimeKind unset, so comparisons across "
                                     + "machines shift by the local offset. Pass Utc or Local "
                                     + "explicitly.");
        }
    }
}

// ------------------------------------------------------------------ enums & arrays

public sealed class FlagsEnumMemberNotPowerOfTwoRule : VbGapRuleBase
{
    public override string Key => "QG-CS-BUG-0113";
    public override string Name => "[Flags] members should combine, not overlap";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!HasAttribute(type, "Flags"))
                continue;
            foreach (var member in type.OfKind(NodeKind.EnumMember))
            {
                var value = member.ChildAt(0);
                if (value?.Kind != NodeKind.NumberLiteral)
                    continue;
                var digits = value.Text.TrimEnd('u', 'U', 'l', 'L')
                    .Replace("_", string.Empty);
                var hex = digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
                if (!long.TryParse(hex ? digits[2..] : digits,
                        System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out var number)
                    && !long.TryParse(digits,
                        System.Globalization.NumberStyles.Integer,
                        System.Globalization.CultureInfo.InvariantCulture, out number))
                    continue;
                if (number == 0 || (number & (number - 1)) == 0)
                    continue;
                context.Report(member, $"'{member.Text}' = {value.Text} sets more than one bit, so it "
                                       + "matches combinations other members already name. Give each "
                                       + "member a single bit and compose combinations explicitly.");
            }
        }
    }
}

public sealed class FlagsEnumZeroMemberRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0389";
    public override string Name => "The zero member of a [Flags] enum should be called None";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!HasAttribute(type, "Flags"))
                continue;
            var zero = type.OfKind(NodeKind.EnumMember).FirstOrDefault(m =>
            {
                var value = m.ChildAt(0);
                return value?.Kind == NodeKind.NumberLiteral && value.Text.TrimEnd('u', 'U') == "0";
            });
            if (zero == null || zero.Text.Equals("None", StringComparison.OrdinalIgnoreCase))
                continue;
            context.Report(zero, $"'{zero.Text}' holds the value 0 of a [Flags] enum: every test like "
                                 + "`value & X` treats it as belonging to all groups. Name it None so "
                                 + "the empty set reads as such.");
        }
    }
}

public sealed class ArrayCreationWithInitializerRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0393";
    public override string Name => "Use the array initializer, not the creation expression";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var creation in context.Root.OfKind(NodeKind.ArrayCreation))
        {
            var hasInitializer = creation.Children.Any(c => c.Kind is NodeKind.ObjectInitializer or NodeKind.ListLiteral);
            if (!hasInitializer)
                continue;
            context.Report(creation, "'new T[] { … }' repeats the type the compiler already knows. "
                                     + "Write '[ … ]' or '{ … }' and let the initializer speak.");
        }
    }
}

// ------------------------------------------------------------------ statements

public sealed class DisposeTwiceRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0425";
    public override string Name => "An object should not be disposed twice";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var block in context.Root.OfKind(NodeKind.Block))
        {
            SyntaxNode? previous = null;
            foreach (var statement in block.Children)
            {
                var target = statement.OfKind(NodeKind.Invocation)
                    .FirstOrDefault(i => i.Text?.EndsWith(".Dispose", StringComparison.Ordinal) == true)
                    ?.ChildAt(0)?.Text;
                if (target != null && previous != null &&
                    previous.OfKind(NodeKind.Invocation)
                        .Any(i => i.Text?.EndsWith(".Dispose", StringComparison.Ordinal) == true
                                  && i.ChildAt(0)?.Text == target))
                {
                    context.Report(statement, $"'{target}' was disposed on the previous line already: "
                                              + "the second call either throws or hides the real "
                                              + "cleanup order. Keep one.");
                    previous = null;
                    continue;
                }
                previous = target != null ? statement : null;
            }
        }
    }
}


public sealed class ShiftByNonIntegerRule : VbGapRuleBase
{
    public override string Key => "QG-CS-BUG-0117";
    public override string Name => "Shift counts should be integers";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("<<" or ">>"))
                continue;
            var right = binary.ChildAt(binary.Children.Count > 1 ? 1 : 0);
            if (right == null || right.Kind is NodeKind.NumberLiteral or NodeKind.Identifier)
                continue;
            context.Report(right, $"Shifting by '{right.SourceText()}' truncates the count to int and "
                                  + "reads as a mistake. Shift by an integer constant.");
        }
    }
}

public sealed class ArithmeticNearOverflowRule : VbGapRuleBase
{
    public override string Key => "QG-CS-BUG-0127";
    public override string Name => "Arithmetic on the integer bounds overflows before it runs";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("+" or "-" or "*"))
                continue;
            var bound = binary.Children.Any(c => c.Kind == NodeKind.NumberLiteral
                                                 && c.Text.TrimEnd('u','U','l','L') is "2147483647"
                                                     or "-2147483648" or "9223372036854775807");
            if (!bound)
                continue;
            context.Report(binary, $"Adding to, subtracting from, or multiplying the integer bound "
                                   + "overflows before this line finishes. Use long arithmetic, "
                                   + "checked, or the Math.Clamp you actually meant.");
        }
    }
}

// --------------------------------------------------------------- VB-only syntax

public sealed class ExitSelectRedundantRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0412";
    public override string Name => "Exit Select at the end of a Case is redundant";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.Tokens.Select(t => (t.Text, t.Line)).ToList();
        for (var i = 0; i < lines.Count - 1; i++)
        {
            if (lines[i].Text is not ("Exit" or "exit")) continue;
            if (lines[i + 1].Text is not ("Select" or "select")) continue;
            var nextMeaningful = lines.Skip(i + 2).FirstOrDefault(t =>
                t.Text is not ("Case" or "Else" or ";") && t.Text.TrimStart().Length > 0);
            if (nextMeaningful.Text is "Case" or "End" or "Else" or "")
                continue;
            context.Report("'Exit Select' as the last statement of a Case changes nothing: the Case "
                           + "ends there anyway. Remove it.", lines[i].Line);
        }
    }
}

public sealed class OnErrorStatementRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0396";
    public override string Name => "On Error statements should not be used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (token.Text != "On")
                continue;
            var index = context.Tokens.ToList().IndexOf(token);
            if (index + 1 >= context.Tokens.Count || context.Tokens[index + 1].Text != "Error")
                continue;
            context.Report("Unstructured error handling rewinds execution to a label and hides the "
                           + "stack of everything that failed on the way. Use Try/Catch.",
                token.Line);
        }
    }
}

public sealed class FunctionNameAssignmentRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0437";
    public override string Name => "Use Return instead of assigning to the function name";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (function.Text.Length == 0)
                continue;
            var body = SyntaxQuery.Body(function);
            if (body == null)
                continue;
            foreach (var assignment in body.OfKind(NodeKind.Assignment))
            {
                var target = assignment.ChildAt(0);
                if (target?.Kind == NodeKind.Identifier && target.Text == function.Text)
                    context.Report(assignment, $"'{function.Text} = …' assigns to the function name, "
                                               + "which keeps executing after the value is set. Use "
                                               + "'Return' to make the exit explicit.");
            }
        }
    }
}

public sealed class OptionStrictDisabledRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0438";
    public override string Name => "Option Strict should be enabled";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        CheckOption(context, "Strict", "QG-CS-SML-0438");
    }

    internal static void CheckOption(IRuleContext context, string option, string key)
    {
        var tokens = context.Tokens.ToList();
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            if (tokens[i].Text is not ("Option" or "option")) continue;
            if (tokens[i + 1].Text != option) continue;
            if (tokens[i + 2].Text is "Off" or "off")
                context.Report($"Option {option} Off lets the compiler accept what it cannot prove: "
                               + "late binding and narrowing conversions move failures to runtime. "
                               + "Turn Option " + option + " On and fix what it points at.",
                    tokens[i].Line);
            return;
        }
        // no statement at all: the project default decides, and the file stays silent here
    }
}

public sealed class OptionExplicitDisabledRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0439";
    public override string Name => "Option Explicit should be enabled";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        OptionStrictDisabledRule.CheckOption(context, "Explicit", "QG-CS-SML-0439");
    }
}

// ------------------------------------------------------------------- platform

public sealed class RouteTemplateLeadingSlashRule : VbGapRuleBase
{
    public override string Key => "QG-CS-SML-0460";
    public override string Name => "Action route templates should not start with '/'";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            foreach (var attribute in function.ChildrenOf(NodeKind.Attribute))
            {
                if (!attribute.Text.StartsWith("Http", StringComparison.OrdinalIgnoreCase))
                    continue;
                var literal = attribute.Descendants().FirstOrDefault(n => n.Kind == NodeKind.StringLiteral);
                var template = literal?.Text?.Trim('"', ' ');
                if (string.IsNullOrEmpty(template) || !template.StartsWith("/"))
                    continue;
                context.Report(attribute, $"'{function.Text}' anchors its route at the site root "
                                          + $"('{template}'), detaching it from the controller's "
                                          + "prefix. Drop the leading slash.");
            }
        }
    }
}


public sealed class LockReleaseMismatchRule : VbGapRuleBase
{
    public override string Key => "QG-CS-BUG-0295";
    public override string Name => "A write lock should not be released as a read lock";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var block in context.Root.OfKind(NodeKind.Block))
        {
            string? entered = null;
            int? enterLine = null;
            foreach (var call in block.OfKind(NodeKind.Invocation))
            {
                var name = call.Text?.Split('.').LastOrDefault() ?? "";
                switch (name)
                {
                    case "EnterWriteLock":
                        entered = call.ChildAt(0)?.Text;
                        enterLine = call.Line;
                        break;
                    case "ExitWriteLock":
                        entered = null;
                        break;
                    case "ExitReadLock" when entered != null:
                        context.Report(call, $"'{entered}' entered a WRITE lock on line {enterLine}, "
                                             + "but releases the read lock: the write lock leaks and "
                                             + "every later reader waits forever. Release the kind "
                                             + "that was taken.");
                        entered = null;
                        break;
                }
            }
        }
    }
}

public sealed class SharedPartCreatedWithNewRule : VbGapRuleBase
{
    public override string Key => "QG-CS-BUG-0135";
    public override string Name => "Shared parts should not be created with new";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        var sharedTypes = context.Root.OfKind(NodeKind.ClassDeclaration)
            .Where(t => t.ChildrenOf(NodeKind.Attribute)
                .Any(a => a.Text.EndsWith("Shared", StringComparison.Ordinal)
                          || a.Text.EndsWith("Export", StringComparison.Ordinal)))
            .Select(t => t.Text)
            .ToHashSet(StringComparer.Ordinal);
        if (sharedTypes.Count == 0)
            return;

        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            var name = (creation.Text ?? "").Split('.').LastOrDefault() ?? "";
            if (!sharedTypes.Contains(name))
                continue;
            context.Report(creation, $"'{name}' is a shared part: the container builds one instance "
                                     + "per policy, and 'new' bypasses it, producing a second copy "
                                     + "with its own state. Ask the container instead.");
        }
    }
}

public sealed class UseUnixEpochRule : VbGapRuleBase
{
    private const long EpochTicks = 621_355_968_000_000_000;

    public override string Key => "QG-CS-SML-1081";
    public override string Name => "Use the UnixEpoch field instead of creating an epoch instance";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var isVb = context.Language.LanguageKey == "vb";
        var creations = isVb
            ? context.Root.OfKind(NodeKind.Invocation).Where(i => IsVbNewConstruction(context, i))
            : context.Root.OfKind(NodeKind.ObjectCreation).Cast<SyntaxNode>();

        // A nested type whose simple name matches the BCL type (e.g. 'class DateTime' inside
        // 'class FakeDateTime') shadows the BCL name for unqualified constructions anywhere in the
        // enclosing type; reading those as the Unix epoch would be a false positive. The shadow
        // region is the enclosing type's range, keyed by the shadowed name.
        var allClasses = context.Root.OfKind(NodeKind.ClassDeclaration).ToList();
        var shadowRanges = new List<(int Start, int End, string Name)>();
        foreach (var shadow in allClasses.Where(c => c.Text is "DateTime" or "DateTimeOffset" or "Date"))
        foreach (var enclosing in allClasses.Where(p => p != shadow
             && p.Range.StartLine <= shadow.Range.StartLine
             && p.Range.EndLine >= shadow.Range.EndLine))
            shadowRanges.Add((enclosing.Range.StartLine, enclosing.Range.EndLine, shadow.Text!));

        foreach (var creation in creations)
        {
            var typeName = creation.Text ?? "";
            var baseName = (typeName.Split('.').LastOrDefault() ?? "").ToLowerInvariant();
            var isDateTime = baseName is "datetime" or "datetimeoffset"
                             || (baseName == "date" && isVb);
            if (!isDateTime)
                continue;

            // An unqualified construction that lands inside a type whose nested type shadows this
            // name is that nested type, not the BCL one.
            if (!typeName.Contains('.')
                && shadowRanges.Any(r => r.Name == (typeName.Split('.').LastOrDefault() ?? "")
                    && creation.Range.StartLine >= r.Start
                    && creation.Range.EndLine <= r.End))
                continue;

            var argumentList = creation.FirstChild(NodeKind.ArgumentList);
            if (argumentList == null)
                continue;

            var arguments = argumentList.Children.ToList();
            var suggested = baseName == "datetimeoffset" ? "DateTimeOffset" : "DateTime";

            // named arguments: when every argument is named we can order them by parameter name; a
            // mixed or unresolvable list stays silent rather than guess at an order.
            var hasNamed = HasNamedArgument(argumentList);
            var named = hasNamed ? NamedArgumentMap(context, argumentList, arguments) : null;
            if (hasNamed && named == null)
                continue;

            if (named != null)
            {
                if (named.Count == 1 && named.TryGetValue("ticks", out var ticks) && IsValue(ticks, EpochTicks))
                    context.Report(creation, CreateMessage(typeName));
                else if (IsNamedDateForm(named))
                    context.Report(creation, CreateMessage(suggested));
                continue;
            }

            if (arguments.Count == 1 && IsValue(arguments[0], EpochTicks))
            {
                context.Report(creation, CreateMessage(typeName));
            }
            else if (IsDateForm(arguments))
            {
                context.Report(creation, CreateMessage(suggested));
            }
        }
    }

    // In VB.NET the VB parser reads 'New DateTime(...)' as an Invocation whose first child is the
    // type name; a plain method call has a MemberSelect there. Only a construction is preceded, on
    // the source line, by the 'New' keyword. Every other shape stays silent.
    private static bool IsVbNewConstruction(IRuleContext context, SyntaxNode invocation)
    {
        if (invocation.FirstChild(NodeKind.ArgumentList) == null)
            return false;
        var child0 = invocation.ChildAt(0);
        if (child0?.Kind != NodeKind.Identifier || child0.Text != invocation.Text)
            return false;

        var tokens = context.Tokens.ToList();
        var line = invocation.Line;
        var startColumn = invocation.Range.StartColumn;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Line != line || tokens[i].Text != invocation.Text)
                continue;
            if (tokens[i].Column < startColumn)
                continue;
            return i > 0 && tokens[i - 1].Line == line
                   && tokens[i - 1].Text.Equals("New", StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }

    private static string CreateMessage(string type) => $"{type} points at the Unix epoch (1 January 1970, "
        + "UTC): prefer the ready-made \"" + type + ".UnixEpoch\" field, which says what the value is "
        + "and cannot drift from the epoch.";

    private static bool IsDateForm(IReadOnlyList<SyntaxNode> arguments)
    {
        if (arguments.Count < 3)
            return false;
        return IsValue(arguments[0], 1970)
               && IsValue(arguments[1], 1)
               && IsValue(arguments[2], 1)
               && arguments.Skip(3).All(IsZeroOrMarker);
    }

    // hour/minute/second/millisecond/microsecond are 0; kind is DateTimeKind.Utc;
    // calendar is Gregorian; offset is TimeSpan.Zero or new TimeSpan(0).
    private static bool IsZeroOrMarker(SyntaxNode node) =>
        IsValue(node, 0)
        || (node is { Kind: NodeKind.MemberSelect, Text: not null }
            && (node.Text.EndsWith(".Utc", StringComparison.OrdinalIgnoreCase)
                || node.Text.EndsWith(".Zero", StringComparison.OrdinalIgnoreCase)))
        || (node is { Kind: NodeKind.ObjectCreation, Text: not null }
            && (node.Text.EndsWith("GregorianCalendar", StringComparison.OrdinalIgnoreCase)
                || (node.Text.EndsWith("TimeSpan", StringComparison.OrdinalIgnoreCase)
                    && node.FirstChild(NodeKind.ArgumentList)?.Children.Count == 1
                    && IsValue(node.FirstChild(NodeKind.ArgumentList)!.Children[0], 0))));

    private static bool IsValue(SyntaxNode node, long value) =>
        node is { Kind: NodeKind.NumberLiteral }
        && long.TryParse(node.Text, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
        && parsed == value;

    private static bool HasNamedArgument(SyntaxNode argumentList)
    {
        var tokens = argumentList.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text == ":=")
                return true;
            if (tokens[i].Kind == TokenKind.Identifier
                && i + 1 < tokens.Count
                && tokens[i + 1].Text == ":")
                return true;
        }
        return false;
    }

    // Orders the arguments by parameter name when every argument is named. VB.NET keeps each named
    // argument as an 'Assignment ':='' node; C# drops the name from the tree but leaves it in the
    // argument-list tokens, so the two are rebuilt the same way. Returns null when the list is
    // positional or mixed — never guess at an order that the source did not name.
    private static Dictionary<string, SyntaxNode>? NamedArgumentMap(IRuleContext context,
        SyntaxNode argumentList, IReadOnlyList<SyntaxNode> children)
    {
        var map = new Dictionary<string, SyntaxNode>(StringComparer.OrdinalIgnoreCase);
        if (context.Language.LanguageKey == "vb")
        {
            foreach (var child in children)
            {
                if (child.Kind != NodeKind.Assignment || child.Text != ":=")
                    return null;
                var name = child.ChildAt(0)?.Text;
                var value = child.ChildAt(1);
                if (string.IsNullOrEmpty(name) || value == null)
                    return null;
                map[name] = value;
            }
            return map.Count == 0 ? null : map;
        }

        var names = new List<string>();
        var tokens = argumentList.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Kind == TokenKind.Identifier && tokens[i + 1].Text == ":")
                names.Add(tokens[i].Text);
        }
        if (names.Count != children.Count)
            return null;
        for (var i = 0; i < children.Count; i++)
            map[names[i]] = children[i];
        return map.Count == 0 ? null : map;
    }

    // The date form only when every date component that appears is the epoch's: 1970-01-01, with
    // the time parts all zero, a Gregorian calendar and Utc kind (or, for DateTimeOffset, a zero
    // offset). Anything named that is not the epoch's value stops the check.
    private static bool IsNamedDateForm(Dictionary<string, SyntaxNode> named)
    {
        if (!named.TryGetValue("year", out var year) || !IsValue(year, 1970)) return false;
        if (!named.TryGetValue("month", out var month) || !IsValue(month, 1)) return false;
        if (!named.TryGetValue("day", out var day) || !IsValue(day, 1)) return false;

        foreach (var (name, node) in named)
        {
            switch (name)
            {
                case "year" or "month" or "day":
                    break;
                case "hour" or "minute" or "second" or "millisecond" or "microsecond":
                    if (!IsValue(node, 0))
                        return false;
                    break;
                case "calendar":
                    if (!IsGregorian(node))
                        return false;
                    break;
                case "kind":
                    if (!IsMarker(node, "Utc"))
                        return false;
                    break;
                case "offset":
                    if (!IsZeroOffset(node))
                        return false;
                    break;
                default:
                    return false;
            }
        }
        return true;
    }

    private static bool IsGregorian(SyntaxNode node) =>
        node is { Kind: NodeKind.ObjectCreation, Text: not null }
        && node.Text.EndsWith("GregorianCalendar", StringComparison.OrdinalIgnoreCase);

    private static bool IsMarker(SyntaxNode node, string name) =>
        node is { Kind: NodeKind.MemberSelect, Text: not null }
        && node.Text.EndsWith("." + name, StringComparison.OrdinalIgnoreCase);

    private static bool IsZeroOffset(SyntaxNode node) =>
        IsMarker(node, "Zero")
        || (node is { Kind: NodeKind.ObjectCreation, Text: not null }
            && node.Text.EndsWith("TimeSpan", StringComparison.OrdinalIgnoreCase)
            && node.FirstChild(NodeKind.ArgumentList)?.Children.Count == 1
            && IsValue(node.FirstChild(NodeKind.ArgumentList)!.Children[0], 0));
}

public sealed class BooleanLiteralUnnecessaryRule : VbGapRuleBase
{
    // S1125: a Boolean literal used as the operand of a comparison or a logical operator is
    // redundant — 'a == true' means 'a', 'x && false' is always false. The check stays silent when
    // removing the literal would change the value: a nullable bool (bool?/Boolean?) or an object or
    // dynamic side cannot be simplified that way, because 'c == true' keeps a meaning that 'c' does
    // not have. Only a side we can positively confirm as a non-nullable bool is simplified.
    public override string Key => "QG-CS-SML-1082";
    public override string Name => "Remove the unnecessary Boolean literal";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["cs", "vb"];

    private static readonly string[] VBLogical = ["AndAlso", "OrElse", "And", "Or"];

    public override void Execute(IRuleContext context)
    {
        if (context.Language.LanguageKey == "vb")
            CheckVb(context);
        else
            CheckCSharp(context);
    }

    private void CheckCSharp(IRuleContext context)
    {
        // 'for (;; true; )' — the reference flags only a literal-true for-loop condition, and only
        // the condition: a literal false (or a variable) is a different meaning.
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (loop.Text == "for"
                && loop.Children.OfType<SyntaxNode>().Any(c => IsLiteral(c, true)))
                context.Report(loop, Message);
        }

        foreach (var node in context.Root.OfKind(NodeKind.Binary, NodeKind.Unary, NodeKind.Conditional))
        {
            switch (node.Kind)
            {
                case NodeKind.Unary when node.Text == "!":
                    var operand = StripParens(node.ChildAt(0));
                    if (IsBoolLiteral(operand))
                        context.Report(node, Message);
                    break;

                case NodeKind.Binary when node.Text is "&&" or "||":
                    CheckLogicalBinary(context, node);
                    break;

                case NodeKind.Binary when node.Text is "==" or "!=":
                    CheckEquality(context, node);
                    break;

                case NodeKind.Binary when node.Text == "is":
                    CheckIsPattern(context, node);
                    break;

                case NodeKind.Conditional:
                    CheckTernary(context, node);
                    break;
            }
        }
    }

    // '&&' and '||' only accept a non-nullable bool on either side, so removing the literal is safe
    // no matter what shape that bool comes from. The redundant side depends on the literal:
    // '&& false' / '|| true' always answer a constant, so the other side is dead.
    private void CheckLogicalBinary(IRuleContext context, SyntaxNode binary)
    {
        var left = StripParens(binary.ChildAt(0));
        var right = StripParens(binary.ChildAt(1));
        var leftLit = IsBoolLiteral(left);
        var rightLit = IsBoolLiteral(right);
        if (!leftLit && !rightLit)
            return;

        var reportOnBinaryLine = leftLit && rightLit;
        if (!reportOnBinaryLine)
        {
            // the redundant side is the one that does not decide the result
            var isAnd = binary.Text == "&&";
            var redundantSideIsLeft = (isAnd && leftLit && !IsLiteral(left, false))
                                   || (!isAnd && leftLit && !IsLiteral(left, true));
            var redundant = redundantSideIsLeft ? left : right;
            if (redundant != null)
            {
                context.Report(redundant, Message);
                return;
            }
        }
        context.Report(binary, Message);
    }

    private void CheckEquality(IRuleContext context, SyntaxNode binary)
    {
        var left = StripParens(binary.ChildAt(0));
        var right = StripParens(binary.ChildAt(1));
        var leftLit = IsBoolLiteral(left);
        var rightLit = IsBoolLiteral(right);
        if (leftLit && rightLit)
        {
            context.Report(binary, Message);
            return;
        }
        if (leftLit && IsNonNullableBool(right, context))
            context.Report(left, Message);
        else if (rightLit && IsNonNullableBool(left, context))
            context.Report(right, Message);
    }

    private void CheckIsPattern(IRuleContext context, SyntaxNode isNode)
    {
        var left = StripParens(isNode.ChildAt(0));
        var pattern = PatternBoolValue(isNode.ChildAt(1));
        if (pattern == null)
            return;
        if (IsBoolLiteral(left) || IsNonNullableBool(left, context))
            context.Report(isNode, Message);
    }

    private void CheckTernary(IRuleContext context, SyntaxNode conditional)
    {
        var whenTrue = StripParens(conditional.ChildAt(1));
        var whenFalse = StripParens(conditional.ChildAt(2));
        if (IsThrow(whenTrue) || IsThrow(whenFalse))
            return;

        var trueLit = IsBoolLiteral(whenTrue);
        var falseLit = IsBoolLiteral(whenFalse);

        if (trueLit && falseLit)
        {
            if (IsLiteral(whenTrue, true) != IsLiteral(whenFalse, true))
                context.Report(conditional, Message);
            return;
        }
        if (trueLit && IsNonNullableBool(whenFalse, context))
            context.Report(whenTrue, Message);
        else if (falseLit && IsNonNullableBool(whenTrue, context))
            context.Report(whenFalse, Message);
    }

    private static bool IsLiteral(SyntaxNode node, bool value)
        => node is { Kind: NodeKind.BooleanLiteral }
           && string.Equals(node.Text, value ? "true" : "false", StringComparison.OrdinalIgnoreCase);

    private static bool IsBoolLiteral(SyntaxNode? node)
        => node is { Kind: NodeKind.BooleanLiteral };

    private static bool IsThrow(SyntaxNode? node)
        => node != null
           && node.DescendantsAndSelf().Any(d => string.Equals(d.Text, "throw", StringComparison.OrdinalIgnoreCase));

    // The pattern side of 'is'. A constant pattern is a 'Pattern' node whose text is true/false; a
    // parenthesized constant arrives as a 'Pattern' titled 'group' that wraps the inner one.
    private static bool? PatternBoolValue(SyntaxNode? node)
    {
        if (node == null)
            return null;
        if (node.Kind == NodeKind.BooleanLiteral)
            return string.Equals(node.Text, "true", StringComparison.OrdinalIgnoreCase);
        if (node.Kind != NodeKind.Pattern && node.Kind != NodeKind.Parenthesized)
            return null;
        if (string.Equals(node.Text, "true", StringComparison.OrdinalIgnoreCase)) return true;
        if (string.Equals(node.Text, "false", StringComparison.OrdinalIgnoreCase)) return false;
        foreach (var child in node.Children)
        {
            if (PatternBoolValue(child) is { } inner)
                return inner;
        }
        return null;
    }

    private static SyntaxNode? StripParens(SyntaxNode? node)
    {
        while (node is { Kind: NodeKind.Parenthesized } && node.Children.Count > 0)
            node = node.ChildAt(0);
        return node;
    }

    // A side is safe to strip the literal from only when we can prove it is a non-nullable bool:
    // another literal, a comparison or logical expression (always bool), a name declared bool, or a
    // member on a type declared bool in the scan. Anything nullable, object-typed or unresolved
    // stays untouched — 'bool? c' keeps a meaning in 'c == true' that it loses in 'c'.
    private static bool IsNonNullableBool(SyntaxNode? node, IRuleContext context)
    {
        node = StripParens(node);
        if (node == null)
            return false;
        switch (node.Kind)
        {
            case NodeKind.BooleanLiteral:
                return true;
            case NodeKind.Binary when node.Text is "==" or "!=" or "<" or ">" or "<=" or ">=" or "&&" or "||" or "is":
                return true;
            case NodeKind.Unary when node.Text is "!" or "Not":
                return true;
            case NodeKind.Identifier:
                return RawIsBool(context.Semantics.Resolve(node)?.DeclaredType);
            case NodeKind.MemberSelect:
                var owner = context.Semantics.Resolve(StripParens(node.ChildAt(0)) as SyntaxNode ?? node.ChildAt(0))?.DeclaredType;
                var member = node.ChildAt(1)?.Text;
                return owner != null && member != null && RawIsBool(context.Project.MemberType(Normalized(owner), member));
            case NodeKind.Invocation:
                var callee = StripParens(node.ChildAt(0));
                if (callee is { Kind: NodeKind.MemberSelect })
                {
                    var invOwner = context.Semantics.Resolve(StripParens(callee.ChildAt(0)) as SyntaxNode ?? callee.ChildAt(0))?.DeclaredType;
                    var invMember = callee.ChildAt(1)?.Text;
                    return invOwner != null && invMember != null
                           && RawIsBool(context.Project.MemberType(Normalized(invOwner), invMember));
                }
                return RawIsBool(context.Project.ReturnType(SyntaxQuery.InvokedName(node)));
            default:
                return false;
        }
    }

    private static string Normalized(string type)
    {
        var text = type.Trim().TrimEnd('?');
        var generic = text.IndexOf('<');
        if (generic > 0) text = text[..generic];
        return text.Trim();
    }

    private static bool RawIsBool(string? raw)
        => raw is "bool" or "Boolean";

    private const string Message = "Remove the unnecessary Boolean literal: the comparison or "
        + "operator already answers that value, and keeping the literal hides what the condition "
        + "really means.";

    // ------------------------------------------------------------------- VB.NET
    // VB.NET has no dedicated parser, so the tree rebuilds the expressions from structural guesses:
    // an infix operator is an 'Identifier' inside a nested 'Unknown', and '=' shows up as an
    // 'Assignment'. The shapes below are read from that tree and stay silent on anything that does
    // not match exactly.
    private void CheckVb(IRuleContext context)
    {
        foreach (var node in context.Root.OfKind(NodeKind.Unknown, NodeKind.Invocation, NodeKind.Assignment, NodeKind.Unary)
                     .Cast<SyntaxNode>().ToList())
        {
            // 'Not True' / 'Not False' — the 'Not' is an Identifier in an Assignment whose sibling in
            // the wrapping Unknown is the operand literal.
            if (node.Kind == NodeKind.Unknown && HasVbNot(node))
            {
                context.Report(node, Message);
                continue;
            }

            // 'A AndAlso/OrElse/And/Or B' with a literal on at least one side.
            if (node.Kind == NodeKind.Unknown && TryReportVbLogical(context, node))
                continue;

            // 'A = True/False' comparison, only when it is not the outer statement or a declaration
            // initializer (the parser wraps 'Dim x = True' in a VariableDeclaration, not a statement).
            if (node.Kind == NodeKind.Assignment && node.Text == "="
                && node.Parent is not { Kind: NodeKind.ExpressionStatement }
                && node.Parent is not { Kind: NodeKind.VariableDeclaration }
                && IsBoolLiteral(node.ChildAt(1))
                && IsNonNullableBool(node.ChildAt(0), context))
                context.Report(node.ChildAt(1)!, Message);
        }

        // 'If(cond, then, else)' — three-argument ternary.
        foreach (var call in context.Root.OfKind(NodeKind.Invocation))
        {
            if (call.Text != "If")
                continue;
            var args = call.FirstChild(NodeKind.ArgumentList)?.Children.ToList();
            if (args is not { Count: 3 } || IsThrow(args[1]) || IsThrow(args[2]))
                continue;
            CheckTernary(context, call, args);
        }
    }

    private static bool HasVbNot(SyntaxNode unknown)
    {
        foreach (var child in unknown.Children)
        {
            if (child.Kind == NodeKind.Assignment
                && string.Equals(child.ChildAt(1)?.Text, "Not", StringComparison.OrdinalIgnoreCase)
                && unknown.Children.Any(c => IsBoolLiteral(c)))
                return true;
        }
        return false;
    }

    private bool TryReportVbLogical(IRuleContext context, SyntaxNode unknown)
    {
        // The operator name sits as an Identifier at one nesting level, with the two operands as a
        // BooleanLiteral sibling and the other expression. Collect the operator and the literal(s)
        // found in this Unknown; a single literal operand is enough to report the line, because the
        // logical operators in VB accept only a bool on each side.
        string? op = null;
        var literals = new List<SyntaxNode>();
        foreach (var d in unknown.DescendantsAndSelf())
        {
            if (d.Kind == NodeKind.Identifier && VBLogical.Contains(d.Text, StringComparer.OrdinalIgnoreCase))
                op = d.Text;
            else if (IsBoolLiteral(d))
                literals.Add(d);
        }
        if (op == null || literals.Count == 0)
            return false;
        context.Report(literals.Count == 1 ? literals[0] : (SyntaxNode)unknown, Message);
        return true;
    }

    private static void CheckTernary(IRuleContext context, SyntaxNode conditional, IReadOnlyList<SyntaxNode> branches)
    {
        var whenTrue = StripParens(branches[1]);
        var whenFalse = StripParens(branches[2]);
        if (IsThrow(whenTrue) || IsThrow(whenFalse))
            return;

        var trueLit = IsBoolLiteral(whenTrue);
        var falseLit = IsBoolLiteral(whenFalse);

        if (trueLit && falseLit)
        {
            if (IsLiteral(whenTrue, true) != IsLiteral(whenFalse, true))
                context.Report(conditional, Message);
            return;
        }
        if (trueLit && IsNonNullableBool(whenFalse, context))
            context.Report(whenTrue, Message);
        else if (falseLit && IsNonNullableBool(whenTrue, context))
            context.Report(whenFalse, Message);
    }
}

public sealed class FindInsteadOfFirstOrDefaultRule : VbGapRuleBase
{
    // S6602: on a List<T> (or an array) the LINQ "FirstOrDefault" is a poorer fit than the
    // collection's own "Find": it allocates a closure where the method exists natively. The check
    // fires only when we can resolve the receiver to a List-like or array type declared in the scan
    // (or an explicit List/ImmutableList/array), so a firstOrDefault on any other type stays quiet.
    public override string Key => "QG-CS-SML-1083";
    public override string Name => "Use the collection's own Find instead of FirstOrDefault";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var call in context.Root.OfKind(NodeKind.Invocation).Cast<SyntaxNode>().ToList())
        {
            var callee = call.ChildAt(0) as SyntaxNode;
            if (callee is not { Kind: NodeKind.MemberSelect } || callee.ChildAt(1)?.Text != "FirstOrDefault")
                continue;
            var args = call.FirstChild(NodeKind.ArgumentList)?.Children.ToList();
            if (args is not { Count: 1 })           // 'FirstOrDefault()' (no predicate) is a different thing
                continue;
            if (!IsPredicateArg(args[0]))            // only the Func<T,bool> overload is about Find
                continue;
            if (InsideLambda(call))                  // an expression tree or delegated callback — type unknown
                continue;

            var receiver = callee.ChildAt(0) as SyntaxNode;
            var (type, isArray) = ResolveReceiverType(receiver, context);
            if (type == null || !IsListLike(type, context))
                continue;
            if (HidesFirstOrDefault(type, context.Project))   // a subclass that declares its own FirstOrDefault
                continue;

            context.Report(callee.ChildAt(1)!, isArray
                ? "Use the static \"Array.Find\" method instead of the \"FirstOrDefault\" extension."
                : "Use the collection's own \"Find\" method instead of the \"FirstOrDefault\" extension.");
        }
    }

    // A FirstOrDefault nested inside any lambda is either an expression tree (where the fix does not
    // apply) or a callback whose receiver we cannot resolve here — stay silent instead of guessing.
    private static bool InsideLambda(SyntaxNode call)
    {
        var p = call.Parent;
        int guard = 0;
        while (p != null && guard++ < 64)
        {
            if (p.Kind == NodeKind.Lambda)
                return true;
            p = p.Parent;
        }
        return false;
    }

    // The predicate overload takes a Func<T,bool>: a lambda or a method group. Everything else is the
    // default-value overload (FirstOrDefault(value)) or another shape, which is not the subject of
    // this check.
    private static bool IsPredicateArg(SyntaxNode arg)
    {
        arg = StripParens2(arg);
        if (arg == null)
            return false;
        return arg.Kind is NodeKind.Lambda or NodeKind.Identifier or NodeKind.MemberSelect;
    }

    // A type that declares its own FirstOrDefault method must not be told to use Find instead.
    private static bool HidesFirstOrDefault(string type, ProjectIndex project)
    {
        if (TypeResolver.Normalize(type) is "List" or "ImmutableList")
            return false;
        return project.FindType(TypeResolver.Normalize(type))?.MemberNames.Contains("FirstOrDefault") == true;
    }

    private static bool IsListLike(string? type, IRuleContext context)
    {
        if (type == null)
            return false;
        var n = TypeResolver.Normalize(type);
        if (n is "List" or "ImmutableList")
            return true;
        if (n.EndsWith("[]") || n.EndsWith("]"))
            return true;
        return context.Types.IsOrDerivesFrom(type, "List", "ImmutableList");
    }

    // Walks the receiver expression back to a concrete type name. Returns null when the type cannot
    // be pinned down; the (type, isArray) pair lets the caller pick the right message.
    private static (string? Type, bool IsArray) ResolveReceiverType(SyntaxNode? expr, IRuleContext context)
    {
        expr = StripParens2(expr);
        if (expr == null)
            return (null, false);
        switch (expr.Kind)
        {
            case NodeKind.Identifier:
                return (RawType(context.Semantics.Resolve(expr)?.DeclaredType), false);
            case NodeKind.Conditional:
                return FirstKnown(ResolveReceiverType(expr.ChildAt(1) as SyntaxNode, context),
                                  ResolveReceiverType(expr.ChildAt(2) as SyntaxNode, context));
            case NodeKind.Binary when expr.Text == "??":
                return FirstKnown(ResolveReceiverType(expr.ChildAt(0) as SyntaxNode, context),
                                  ResolveReceiverType(expr.ChildAt(1) as SyntaxNode, context));
            case NodeKind.MemberSelect:
                var owner = expr.ChildAt(0) as SyntaxNode;
                var member = expr.ChildAt(1)?.Text;
                if (owner == null || member == null)
                    return (null, false);
                if (owner is { Kind: NodeKind.Identifier } && IsDeclaredType(owner.Text, context.Project))
                    return (RawType(context.Project.MemberType(owner.Text, member)), false);
                var ownerType = ResolveReceiverType(owner, context).Type;
                return ownerType == null ? (null, false)
                                         : (RawType(context.Project.MemberType(TypeResolver.Normalize(ownerType), member)), false);
            case NodeKind.Invocation:
                return ResolveInvocationReceiver(expr, context);
            default:
                return (null, false);
        }
    }

    private static (string? Type, bool IsArray) ResolveInvocationReceiver(SyntaxNode inv, IRuleContext context)
    {
        var callee = inv.ChildAt(0) as SyntaxNode;
        if (callee is { Kind: NodeKind.MemberSelect })
        {
            var owner = callee.ChildAt(0) as SyntaxNode;
            var member = callee.ChildAt(1)?.Text;
            if (member == "ToList")
                return ("List", false);
            if (owner != null && member != null)
            {
                if (owner is { Kind: NodeKind.Identifier } && IsDeclaredType(owner.Text, context.Project))
                    return (RawType(context.Project.MemberType(owner.Text, member)), false);
                var ownerType = ResolveReceiverType(owner, context).Type;
                if (ownerType != null)
                    return (RawType(context.Project.MemberType(TypeResolver.Normalize(ownerType), member)), false);
            }
            return (null, false);
        }

        // a bare call lambda() / DoWorkReturnGroup(): resolve from the declared return type, or from a
        // Func<...> parameter.
        var name = SyntaxQuery.InvokedName(inv);
        if (name != null && context.Project.ReturnType(name) is { } ret)
            return (RawType(ret), false);
        var id = callee is { Kind: NodeKind.Identifier } ? callee : (SyntaxNode?)null;
        var paramType = id != null ? context.Semantics.Resolve(id)?.DeclaredType : null;
        if (paramType != null && paramType.StartsWith("Func<", StringComparison.Ordinal))
        {
            var inner = FuncTypeArgument(paramType);
            if (inner != null)
                return (RawType(inner), false);
        }
        return (null, false);
    }

    private static string? FuncTypeArgument(string funcType)
    {
        var open = funcType.IndexOf('<');
        if (open < 0 || !funcType.EndsWith(">"))
            return null;
        return funcType[(open + 1)..^1];
    }

    private static (string? Type, bool IsArray) FirstKnown((string? Type, bool IsArray) a, (string? Type, bool IsArray) b)
        => a.Type != null ? a : b;

    private static string? RawType(string? t)
        => string.IsNullOrEmpty(t) ? null : t;

    private static SyntaxNode? StripParens2(SyntaxNode? node)
    {
        while (node is { Kind: NodeKind.Parenthesized } && node.Children.Count > 0)
            node = node.ChildAt(0) as SyntaxNode;
        return node;
    }

    private static bool IsDeclaredType(string name, ProjectIndex project)
        => project.FindType(name) != null;
}

public sealed class UseTrueForAllRule : VbGapRuleBase
{
    // S6603: on a List<T>, an array or an ImmutableList<T> the "All" extension wraps the element in
    // a closure where the collection already has a native "TrueForAll" that matches every element
    // without allocating. The check fires only when the receiver resolves to one of those types (or
    // a type declared to derive from them) and does not shadow "All" with a method of its own, so a
    // "All" on any other type stays quiet.
    public override string Key => "QG-CS-SML-1085";
    public override string Name => "Use the collection-specific TrueForAll instead of the All extension";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        var initializers = CollectionLinq.CollectInitializers(context.Root);
        foreach (var call in context.Root.OfKind(NodeKind.Invocation).Cast<SyntaxNode>().ToList())
        {
            var callee = call.ChildAt(0) as SyntaxNode;
            if (callee is not { Kind: NodeKind.MemberSelect } || callee.ChildAt(1)?.Text != "All")
                continue;
            var receiver = callee.ChildAt(0) as SyntaxNode;
            var type = CollectionLinq.ResolveReceiverType(receiver, context, initializers);
            if (type == null || !CollectionLinq.IsListArrayOrImmutable(type, context))
                continue;
            if (CollectionLinq.HidesMember(type, "All", context.Project))
                continue;
            context.Report(callee.ChildAt(1)!, "Use the collection-specific \"TrueForAll\" method "
                + "instead of the \"All\" extension: it matches every element without the closure "
                + "the extension allocates for the predicate.");
        }
    }
}

public sealed class UseIndexingInsteadOfLinqMethodsRule : VbGapRuleBase
{
    // S6608: on anything that is already indexable (an IList/IReadOnlyList, a List<T> or an array)
    // the Indexer is the native way to reach an element, while "First"/"Last"/"ElementAt" run the
    // LINQ enumeration. The check fires only when the receiver resolves to an indexable type and the
    // call takes no predicate (so it really is just "give me the nth element"). A "First(x => …)"
    // with a predicate, or a "First" on a type we cannot confirm as indexable, stays silent.
    public override string Key => "QG-CS-SML-1086";
    public override string Name => "Use the indexer instead of First, Last or ElementAt";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        var initializers = CollectionLinq.CollectInitializers(context.Root);
        foreach (var call in context.Root.OfKind(NodeKind.Invocation).Cast<SyntaxNode>().ToList())
        {
            var callee = call.ChildAt(0) as SyntaxNode;
            if (callee is not { Kind: NodeKind.MemberSelect })
                continue;
            var method = callee.ChildAt(1)?.Text;
            var args = call.FirstChild(NodeKind.ArgumentList)?.Children.Count ?? 0;
            if (method == "First" && args != 0) continue;
            if (method == "Last" && args != 0) continue;
            if (method == "ElementAt" && args != 1) continue;
            if (method is not ("First" or "Last" or "ElementAt"))
                continue;

            var receiver = callee.ChildAt(0) as SyntaxNode;
            var type = CollectionLinq.ResolveReceiverType(receiver, context, initializers);
            if (type == null || !CollectionLinq.IsIndexable(type, context))
                continue;

            var at = method switch
            {
                "First" => " at index 0",
                "Last" => " at index Count-1",
                _ => "",
            };
            context.Report(callee.ChildAt(1)!, $"Use the indexer{at} instead of the \"Enumerable\" "
                + $"extension method \"{method}\": the collection is already indexable, so walking "
                + "the whole enumeration to reach one element is wasted work.");
        }
    }
}

// Shared receiver-resolution for the LINQ "use the collection-specific method" family. Walks an
// invocation chain (fluent calls, ToList/ToArray, ternary/coalesce, method returns and lambda
// parameters) back to a concrete type name, or returns null when the type cannot be pinned down —
// a rule that cannot see the receiver stays silent instead of guessing.
internal static class CollectionLinq
{
    public static string? ResolveReceiverType(SyntaxNode? expr, IRuleContext context,
        IReadOnlyDictionary<string, SyntaxNode>? initializers = null)
    {
        expr = Strip(expr);
        if (expr == null)
            return null;
        switch (expr.Kind)
        {
            case NodeKind.Identifier:
                if (expr.Text == "this")
                {
                    // 'this' is the enclosing type: a class that derives from List<T> is itself
                    // the collection it is calling "All" on.
                    return SyntaxQuery.EnclosingType(expr)?.Text;
                }
                var declared = Raw(context.Semantics.Resolve(expr)?.DeclaredType);
                if (declared != null)
                    return declared;
                // 'var x = new T[...]' / 'var x = Some.Type.Member' — the lite semantic model does not
                // infer these. Fall back to the type of the initializer expression itself.
                return initializers != null && initializers.TryGetValue(expr.Text, out var init)
                    ? ResolveInitializerType(init, context, initializers)
                    : null;
            case NodeKind.ObjectCreation:
                return expr.Text;
            case NodeKind.ArrayCreation:
                return "T[]";
            case NodeKind.Cast:
                // (IList<int>)x — the explicit target is the type the call runs on.
                return expr.Text;
            case NodeKind.Conditional:
                return FirstKnown(ResolveReceiverType(expr.ChildAt(1) as SyntaxNode, context, initializers),
                                  ResolveReceiverType(expr.ChildAt(2) as SyntaxNode, context, initializers));
            case NodeKind.Binary when expr.Text == "??":
                return FirstKnown(ResolveReceiverType(expr.ChildAt(0) as SyntaxNode, context, initializers),
                                  ResolveReceiverType(expr.ChildAt(1) as SyntaxNode, context, initializers));
            case NodeKind.Binary when expr.Text == "as":
                // (x as IReadOnlyList<int>) — the target type is the right operand.
                return expr.ChildAt(1)?.Text;
            case NodeKind.MemberSelect:
                var owner = expr.ChildAt(0) as SyntaxNode;
                var member = expr.ChildAt(1)?.Text;
                if (owner == null || member == null)
                    return null;
                if (owner is { Kind: NodeKind.Identifier } && IsDeclaredType(owner.Text, context.Project))
                    return Raw(context.Project.MemberType(owner.Text, member));
                var ownerType = ResolveReceiverType(owner, context, initializers);
                return ownerType == null ? null
                                         : Raw(context.Project.MemberType(TypeResolver.Normalize(ownerType), member));
            case NodeKind.Invocation:
                return ResolveInvocation(expr, context, initializers);
            default:
                return null;
        }
    }

    // The type of a variable-initializer expression, for the 'var' shapes the lite semantic model
    // leaves untyped. Returns a marker "T[]" for an array creation, so array checks can detect it.
    public static string? ResolveInitializerType(SyntaxNode? expr, IRuleContext context,
        IReadOnlyDictionary<string, SyntaxNode>? initializers = null)
    {
        expr = Strip(expr);
        if (expr == null)
            return null;
        switch (expr.Kind)
        {
            case NodeKind.Identifier:
                return ResolveReceiverType(expr, context, initializers);
            case NodeKind.ArrayCreation:
                return "T[]";
            case NodeKind.ObjectCreation:
                return expr.Text;
            case NodeKind.Invocation:
                return ResolveInvocation(expr, context, initializers);
            case NodeKind.MemberSelect:
                // 'ImmutableList<int>.Empty' is the static entry point of the type itself.
                var dot = expr.Text?.LastIndexOf('.');
                if (dot is > 0 && dot + 1 < (expr.Text?.Length ?? 0))
                {
                    var member = expr.Text![(dot.Value + 1)..];
                    var owner = expr.Text![..dot.Value];
                    if (member == "Empty" && TypeResolver.Normalize(owner) == "ImmutableList")
                        return "ImmutableList";
                }
                return null;
            case NodeKind.Conditional:
                return FirstKnown(ResolveInitializerType(expr.ChildAt(1) as SyntaxNode, context, initializers),
                                  ResolveInitializerType(expr.ChildAt(2) as SyntaxNode, context, initializers));
            case NodeKind.Binary when expr.Text == "??":
                return FirstKnown(ResolveInitializerType(expr.ChildAt(0) as SyntaxNode, context, initializers),
                                  ResolveInitializerType(expr.ChildAt(1) as SyntaxNode, context, initializers));
            default:
                return null;
        }
    }

    // Builds name -> initializer-value for every 'var x = …' in the file, so an identifier whose type
    // the lite model could not infer can be resolved through the expression that gave it its value.
    public static Dictionary<string, SyntaxNode> CollectInitializers(SyntaxNode root)
    {
        var map = new Dictionary<string, SyntaxNode>(StringComparer.Ordinal);
        foreach (var decl in root.OfKind(NodeKind.VariableDeclaration))
        {
            var assignment = decl.Children.OfType<SyntaxNode>().FirstOrDefault(c => c.Kind == NodeKind.Assignment && c.Text == "=");
            var value = assignment?.ChildAt(1);
            if (value != null && decl.Text.Length > 0)
                map[decl.Text] = value;
        }
        return map;
    }

    private static string? ResolveInvocation(SyntaxNode inv, IRuleContext context,
        IReadOnlyDictionary<string, SyntaxNode>? initializers)
    {
        var callee = inv.ChildAt(0) as SyntaxNode;
        if (callee is { Kind: NodeKind.MemberSelect })
        {
            var owner = callee.ChildAt(0) as SyntaxNode;
            var member = callee.ChildAt(1)?.Text;
            if (member == "ToList")
                return "List";
            if (member == "ToArray")
                return "T[]";
            if (owner != null && member != null)
            {
                if (owner is { Kind: NodeKind.Identifier } && IsDeclaredType(owner.Text, context.Project))
                    return Raw(context.Project.MemberType(owner.Text, member));
                var ownerType = ResolveReceiverType(owner, context, initializers);
                if (ownerType != null)
                    return Raw(context.Project.MemberType(TypeResolver.Normalize(ownerType), member));
            }
            return null;
        }

        // a bare call lambda() / DoWorkReturn(): resolve from the declared return type or from a
        // Func<...> parameter typed in the enclosing declaration.
        var name = SyntaxQuery.InvokedName(inv);
        if (name != null && context.Project.ReturnType(name) is { } ret)
            return Raw(ret);
        var id = callee is { Kind: NodeKind.Identifier } ? callee : (SyntaxNode?)null;
        var paramType = id != null ? context.Semantics.Resolve(id)?.DeclaredType : null;
        if (paramType != null && paramType.StartsWith("Func<", StringComparison.Ordinal))
        {
            var inner = FuncTypeArgument(paramType);
            if (inner != null)
                return Raw(inner);
        }
        return null;
    }

    // The LINQ family "use the collection method" targets List<T>, ImmutableList<T> and arrays.
    public static bool IsListArrayOrImmutable(string? type, IRuleContext context)
    {
        if (type == null)
            return false;
        if (IsArray(type))
            return true;
        var n = TypeResolver.Normalize(type);
        if (n is "List" or "ImmutableList")
            return true;
        return context.Types.IsOrDerivesFrom(n, "List", "ImmutableList");
    }

    // The indexer family targets anything whose interface is indexable: IList/IReadOnlyList, plus the
    // concrete List<T> and arrays. A declared type that implements one of those interfaces counts.
    public static bool IsIndexable(string? type, IRuleContext context)
    {
        if (type == null)
            return false;
        if (IsArray(type))
            return true;
        var n = TypeResolver.Normalize(type);
        if (n is "List" or "IList" or "IReadOnlyList")
            return true;
        return context.Types.IsOrDerivesFrom(n, "List", "IList", "IReadOnlyList");
    }

    // A type that declares the method itself must not be told to switch to the collection-specific
    // one: its "All"/"First" is its own, not the extension.
    public static bool HidesMember(string type, string member, ProjectIndex project)
    {
        var n = TypeResolver.Normalize(type);
        if (n is "List" or "ImmutableList" or "IList" or "IReadOnlyList" || IsArray(type))
            return false;
        return project.FindType(n)?.MemberNames.Contains(member) == true;
    }

    private static bool IsArray(string? type)
        => type != null && (type.Contains('[') || type.StartsWith("T[", StringComparison.Ordinal));

    private static string? FuncTypeArgument(string funcType)
    {
        var open = funcType.IndexOf('<');
        if (open < 0 || !funcType.EndsWith(">"))
            return null;
        return funcType[(open + 1)..^1];
    }

    private static string? FirstKnown(string? a, string? b)
        => a ?? b;

    private static string? Raw(string? t)
        => string.IsNullOrEmpty(t) ? null : t;

    private static SyntaxNode? Strip(SyntaxNode? node)
    {
        while (node is { Kind: NodeKind.Parenthesized } && node.Children.Count > 0)
            node = node.ChildAt(0) as SyntaxNode;
        return node;
    }

    private static bool IsDeclaredType(string name, ProjectIndex project)
        => project.FindType(name) != null;
}

