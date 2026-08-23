
using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Python checks that need the TypeResolver: operators between values whose types the resolver
/// can infer from declarations or literals.
/// </summary>
public static class PythonTypeGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PyIncompatibleOperatorRule(),
        new PyFormatArgumentMismatchRule(),
    ];
}

public sealed class PyIncompatibleOperatorRule : RuleBase
{
    public override string Key => "QG-PY-BUG-0046";
    public override string Name => "Operators should be used on compatible types";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            var op = binary.Text;
            if (op is not ("+" or "-" or "*" or "/"))
                continue;
            var left = binary.ChildAt(0);
            var right = binary.ChildAt(binary.Children.Count > 1 ? 1 : 0);
            if (left == null || right == null)
                continue;
            var leftType = context.Types.TypeOf(left);
            var rightType = context.Types.TypeOf(right);
            if (leftType == null || rightType == null)
                continue;
            if (!context.Types.IsKnownType(leftType) || !context.Types.IsKnownType(rightType))
                continue;
            // str + int, list + int, dict + str: none of these make sense
            var incompatible = (leftType, rightType) switch
            {
                ("string", _) when rightType is "int" or "double" or "bool" or "collection" => true,
                (_, "string") when leftType is "int" or "double" or "bool" or "collection" => true,
                ("collection", _) when rightType is "int" or "double" => true,
                (_, "collection") when leftType is "int" or "double" => true,
                _ => false
            };
            if (!incompatible)
                continue;
            context.Report(binary, $"'{leftType} {op} {rightType}' raises TypeError at runtime: "
                                          + "convert one side or use the correct operator.");
        }
    }
}

public sealed class PyFormatArgumentMismatchRule : RuleBase
{
    public override string Key => "QG-PY-BUG-0033";
    public override string Name => "%-format placeholders should match the argument tuple";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text != "%")
                continue;
            var left = binary.ChildAt(0);
            if (left?.Kind != NodeKind.StringLiteral)
                continue;
            var format = left.Text.Trim('"', '\'');
            var placeholders = CountPlaceholders(format);
            if (placeholders == 0)
                continue;
            var right = binary.ChildAt(binary.Children.Count > 1 ? 1 : 0);
            var argCount = CountArgs(right);
            if (argCount == placeholders)
                continue;
            context.Report(binary, $"The format string has {placeholders} placeholder(s) but "
                                          + $"{argCount} argument(s): this raises TypeError at "
                                          + "runtime.");
        }
    }

    private static int CountPlaceholders(string format)
    {
        var count = 0;
        for (var i = 0; i < format.Length - 1; i++)
        {
            if (format[i] == '%' && format[i + 1] != '%')
            {
                count++;
                i++; // skip the conversion character
            }
        }
        return count;
    }

    private static int CountArgs(SyntaxNode? expression)
    {
        if (expression == null) return 0;
        if (expression.Kind == NodeKind.Tuple) return expression.Children.Count;
        return 1;
    }
}
