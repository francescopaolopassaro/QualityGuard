using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Scala rules on the dedicated tree. The language joins the C-family parser with a dialect of its
/// own, so the shared structural families read Scala declarations, branches and matches directly.
/// </summary>
public static class ScalaRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new ScalaEmptyFunctionRule(),
        new ScalaMergeableIfRule(),
        new ScalaBooleanLiteralComparisonRule(),
        new ScalaUnusedInternalMemberRule(),
        new ScalaHardcodedIpRule(),
        new ScalaUnusedLocalVariableRule(),
        new ScalaInvertedBooleanCheckRule(),
        new ScalaCognitiveComplexityRule(),
        new ScalaUnusedParameterRule(),
        new ScalaIdenticalBranchesRule(),
        new ScalaIdenticalBodiesRule(),
        new ScalaEmptyCommentRule(),
        new ScalaConstantConditionRule(),
        new ScalaSelfAssignmentRule(),
        new ScalaUnreachableCodeAfterJumpRule(),
        new ScalaDuplicateConditionRule(),
    ];
}

public sealed class ScalaEmptyFunctionRule : EmptyFunctionRule
{
    public override string Key => "QG-SC-SML-0024";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaMergeableIfRule : MergeableIfRule
{
    public override string Key => "QG-SC-SML-0025";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaBooleanLiteralComparisonRule : BooleanLiteralComparisonRule
{
    public override string Key => "QG-SC-SML-0026";
    public override string[] Languages => ["scala"];
}

/// <summary>
/// A private member nothing reaches. When the whole project is indexed this is the rule that
/// answers, so the file-only variant stands down rather than reporting the same declaration twice.
/// </summary>
public sealed class ScalaUnusedInternalMemberRule : UnusedInternalMemberRule
{
    public override string Key => "QG-SC-SML-0027";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaHardcodedIpRule : HardcodedIpRule
{
    public override string Key => "QG-SC-SML-0028";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaUnusedLocalVariableRule : UnusedLocalVariableRule
{
    public override string Key => "QG-SC-SML-0029";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaInvertedBooleanCheckRule : InvertedBooleanCheckRule
{
    public override string Key => "QG-SC-SML-0030";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaCognitiveComplexityRule : CognitiveComplexityRule
{
    public override string Key => "QG-SC-SML-0031";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaUnusedParameterRule : UnusedParameterRule
{
    public override string Key => "QG-SC-SML-0035";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaIdenticalBranchesRule : IdenticalBranchesRule
{
    public override string Key => "QG-SC-BUG-0010";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaIdenticalBodiesRule : IdenticalBodiesRule
{
    public override string Key => "QG-SC-SML-0037";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaEmptyCommentRule : EmptyCommentRule
{
    public override string Key => "QG-SC-SML-0038";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaConstantConditionRule : ConstantConditionRule
{
    public override string Key => "QG-SC-BUG-0006";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaSelfAssignmentRule : SelfAssignmentRule
{
    public override string Key => "QG-SC-BUG-0007";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaUnreachableCodeAfterJumpRule : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-SC-BUG-0008";
    public override string[] Languages => ["scala"];
}

public sealed class ScalaDuplicateConditionRule : DuplicateConditionRule
{
    public override string Key => "QG-SC-BUG-0009";
    public override string[] Languages => ["scala"];
}
