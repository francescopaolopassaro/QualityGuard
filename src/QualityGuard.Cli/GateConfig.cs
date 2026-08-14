using System.Text.Json;
using System.Text.Json.Serialization;
using QualityGuard.Core.Models;
using QualityGuard.Core.Evaluation;

namespace QualityGuard.Cli;

public static class GateConfig
{
    public static IReadOnlyList<Condition> LoadDefault() => BuiltInQualityGate.Conditions;

    public static IReadOnlyList<Condition> Load(string path)
    {
        var json = File.ReadAllText(path);
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("conditions", out var conditions))
            throw new InvalidDataException("Missing 'conditions' array in gate config.");

        var result = new List<Condition>();
        foreach (var c in conditions.EnumerateArray())
        {
            var metricKey = c.GetProperty("metricKey").GetString();
            var op = c.GetProperty("operator").GetString();
            var threshold = c.GetProperty("threshold").GetDouble();
            var operatorKind = op switch
            {
                "LESS_THAN" => MetricOperator.LessThan,
                "GREATER_THAN" => MetricOperator.GreaterThan,
                "LT" => MetricOperator.LessThan,
                "GT" => MetricOperator.GreaterThan,
                _ => throw new InvalidDataException($"Unsupported operator '{op}'")
            };
            result.Add(new Condition(metricKey!, operatorKind, threshold));
        }
        return result;
    }
}