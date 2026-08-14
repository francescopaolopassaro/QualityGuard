using System.Text.Json.Serialization;

namespace QualityGuard.Core.Models;

public sealed record Condition(string MetricKey, MetricOperator Operator, double Threshold)
{
    public string MetricKey { get; } = MetricKey;
    public MetricOperator Operator { get; } = Operator;
    public double Threshold { get; } = Threshold;

    public override string ToString() => $"{MetricKey} {Operator} {Threshold}";
}

public sealed record ConditionResult(Condition Condition, ConditionStatus Status, double Measured, string? Message)
{
    public ConditionStatus Status { get; } = Status;
    public double Measured { get; } = Measured;
    public string? Message { get; } = Message;
}

public sealed record QualityGateResult(QualityGateStatus Status, IReadOnlyList<ConditionResult> Conditions)
{
    public QualityGateStatus Status { get; } = Status;
    public IReadOnlyList<ConditionResult> Conditions { get; } = Conditions;
}