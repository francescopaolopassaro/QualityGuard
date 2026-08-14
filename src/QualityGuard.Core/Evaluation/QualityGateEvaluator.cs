using QualityGuard.Core.Models;

namespace QualityGuard.Core.Evaluation;

public sealed class QualityGateEvaluator
{
    private const double FudgeFactorMinLines = 20;
    private static readonly HashSet<string> FudgeFactorMetrics =
        new(StringComparer.Ordinal)
        {
            CoreMetrics.NewCoverage,
            CoreMetrics.NewDuplicatedLinesDensity
        };

    public QualityGateResult Evaluate(
        IReadOnlyDictionary<string, double> metrics,
        IEnumerable<Condition> conditions)
    {
        var results = new List<ConditionResult>();
        metrics.TryGetValue(CoreMetrics.NewLines, out var newLines);

        foreach (var condition in conditions)
        {
            if (!metrics.TryGetValue(condition.MetricKey, out var measured))
            {
                results.Add(new ConditionResult(condition, ConditionStatus.Ok, double.NaN, null));
                continue;
            }

            if (FudgeFactorMetrics.Contains(condition.MetricKey) && newLines < FudgeFactorMinLines)
            {
                results.Add(new ConditionResult(condition, ConditionStatus.Ok, measured,
                    $"Condition skipped: fewer than {FudgeFactorMinLines} new lines."));
                continue;
            }

            var failed = condition.Operator switch
            {
                MetricOperator.GreaterThan => measured > condition.Threshold,
                MetricOperator.LessThan => measured < condition.Threshold,
                _ => false
            };

            if (failed)
            {
                var message = BuildMessage(condition, measured);
                results.Add(new ConditionResult(condition, ConditionStatus.Error, measured, message));
            }
            else
            {
                results.Add(new ConditionResult(condition, ConditionStatus.Ok, measured, null));
            }
        }

        var status = results.Any(r => r.Status == ConditionStatus.Error)
            ? QualityGateStatus.Failed
            : QualityGateStatus.Passed;

        return new QualityGateResult(status, results);
    }

    private static string BuildMessage(Condition condition, double measured)
    {
        var label = MetricName(condition.MetricKey);
        var opLabel = condition.Operator == MetricOperator.GreaterThan ? "greater than" : "less than";
        return $"{label} is {Format(condition.MetricKey, measured)}, which is {opLabel} {Format(condition.MetricKey, condition.Threshold)}";
    }

    private static string Format(string metricKey, double value)
    {
        var isPercent = metricKey is CoreMetrics.NewCoverage or CoreMetrics.NewDuplicatedLinesDensity
            or CoreMetrics.NewSecurityHotspotsReviewed;
        return value.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + (isPercent ? "%" : "");
    }

    private static string MetricName(string key) => key switch
    {
        CoreMetrics.NewCoverage => "Coverage on New Code",
        CoreMetrics.NewDuplicatedLinesDensity => "Duplicated Lines on New Code",
        CoreMetrics.NewSecurityRating => "Security Rating on New Code",
        CoreMetrics.NewReliabilityRating => "Reliability Rating on New Code",
        CoreMetrics.NewMaintainabilityRating => "Maintainability Rating on New Code",
        CoreMetrics.NewSecurityHotspotsReviewed => "Security Hotspots Reviewed on New Code",
        _ => key
    };
}