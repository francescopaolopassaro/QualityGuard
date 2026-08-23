using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

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
