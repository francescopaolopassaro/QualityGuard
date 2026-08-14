using QualityGuard.Core.Models;

namespace QualityGuard.Core.Evaluation;

public static class BuiltInQualityGate
{
    public const string Name = "Default";
    public const int FudgeFactorMinLines = 20;

    public static readonly IReadOnlyList<Condition> Conditions =
    [
        new(CoreMetrics.NewCoverage, MetricOperator.LessThan, 80.0),
        new(CoreMetrics.NewDuplicatedLinesDensity, MetricOperator.GreaterThan, 3.0),
        new(CoreMetrics.NewSecurityHotspotsReviewed, MetricOperator.LessThan, 100.0),
        new(CoreMetrics.NewReliabilityRating, MetricOperator.GreaterThan, 1.0),
        new(CoreMetrics.NewMaintainabilityRating, MetricOperator.GreaterThan, 1.0)
    ];
}