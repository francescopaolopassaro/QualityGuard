using System.Text.Json;
using System.Text.Json.Nodes;
using QualityGuard.Core.Models;

namespace QualityGuard.Sources.Sarif;

public sealed class SarifReader
{
    public SarifReport Read(string path)
    {
        using var stream = File.OpenRead(path);
        return Read(stream);
    }

    public SarifReport Read(Stream stream)
    {
        using var doc = JsonDocument.Parse(stream);
        var root = doc.RootElement;
        var metrics = new Dictionary<string, double>();
        var issues = new List<Issue>();

        if (root.TryGetProperty("runs", out var runs))
        {
            foreach (var run in runs.EnumerateArray())
            {
                ExtractMetrics(run, metrics);
                ExtractIssues(run, issues);
            }
        }

        return new SarifReport(metrics, issues);
    }

    private static void ExtractMetrics(JsonElement run, Dictionary<string, double> metrics)
    {
        if (run.TryGetProperty("properties", out var props) && props.ValueKind == JsonValueKind.Object)
            ReadMetricProperties(props, metrics);

        if (run.TryGetProperty("invocations", out var invocations) && invocations.ValueKind == JsonValueKind.Array)
        {
            foreach (var invocation in invocations.EnumerateArray())
            {
                if (invocation.TryGetProperty("properties", out var invProps) && invProps.ValueKind == JsonValueKind.Object)
                    ReadMetricProperties(invProps, metrics);
            }
        }
    }

    private static void ReadMetricProperties(JsonElement props, Dictionary<string, double> metrics)
    {
        foreach (var prop in props.EnumerateObject())
        {
            if (prop.Value.ValueKind is JsonValueKind.Number or JsonValueKind.String)
            {
                if (TryParseDouble(prop.Value, out var value))
                    metrics[prop.Name] = value;
            }
            else if (prop.Value.ValueKind == JsonValueKind.Object && prop.Name == "metrics")
            {
                foreach (var metric in prop.Value.EnumerateObject())
                {
                    if (TryParseDouble(metric.Value, out var value))
                        metrics[metric.Name] = value;
                }
            }
        }
    }

    private static void ExtractIssues(JsonElement run, List<Issue> issues)
    {
        if (!run.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
            return;

        var rules = ExtractRules(run);

        foreach (var result in results.EnumerateArray())
        {
            var ruleId = GetString(result, "ruleId");
            if (ruleId == null && result.TryGetProperty("ruleIndex", out var ruleIndex))
            {
                var idx = ruleIndex.GetInt32();
                if (idx >= 0 && idx < rules.Count)
                    ruleId = rules[idx];
            }

            var level = GetString(result, "level") ?? "warning";
            var severity = MapSeverity(level);
            var message = GetMessage(result);
            var file = GetFile(result);
            var line = GetLine(result);
            var kind = MapKind(ruleId ?? "");

            issues.Add(new Issue(ruleId ?? "unknown", message, severity, kind, file, line));
        }
    }

    private static List<string?> ExtractRules(JsonElement run)
    {
        var rules = new List<string?>();
        if (!run.TryGetProperty("tool", out var tool) ||
            !tool.TryGetProperty("driver", out var driver) ||
            !driver.TryGetProperty("rules", out var rulesArray))
            return rules;

        foreach (var rule in rulesArray.EnumerateArray())
            rules.Add(GetString(rule, "id") ?? GetString(rule, "name"));
        return rules;
    }

    private static string GetMessage(JsonElement result)
    {
        if (result.TryGetProperty("message", out var msg))
        {
            if (msg.TryGetProperty("text", out var text))
                return text.GetString() ?? "";
            if (msg.TryGetProperty("markdown", out var md))
                return md.GetString() ?? "";
        }
        return "";
    }

    private static string? GetFile(JsonElement result)
    {
        if (!result.TryGetProperty("locations", out var locs) || locs.GetArrayLength() == 0)
            return null;
        var first = locs[0];
        if (!first.TryGetProperty("physicalLocation", out var phys))
            return null;
        if (!phys.TryGetProperty("artifactLocation", out var artifact))
            return null;
        if (!artifact.TryGetProperty("uri", out var uri))
            return null;
        return uri.GetString();
    }

    private static int? GetLine(JsonElement result)
    {
        if (!result.TryGetProperty("locations", out var locs) || locs.GetArrayLength() == 0)
            return null;
        var first = locs[0];
        if (!first.TryGetProperty("physicalLocation", out var phys))
            return null;
        if (!phys.TryGetProperty("region", out var region))
            return null;
        if (!region.TryGetProperty("startLine", out var line))
            return null;
        return line.GetInt32();
    }

    private static string? GetString(JsonElement el, string name)
    {
        if (el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String)
            return v.GetString();
        return null;
    }

    private static bool TryParseDouble(JsonElement el, out double value)
    {
        value = 0;
        if (el.ValueKind == JsonValueKind.Number && el.TryGetDouble(out value))
            return true;
        if (el.ValueKind == JsonValueKind.String && double.TryParse(el.GetString(),
                System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out value))
            return true;
        return false;
    }

    private static Severity MapSeverity(string level) => level switch
    {
        "error" => Severity.Blocker,
        "warning" => Severity.Major,
        "note" => Severity.Info,
        _ => Severity.Minor
    };

    private static IssueKind MapKind(string ruleId) => ruleId.ToLowerInvariant() switch
    {
        _ => IssueKind.CodeSmell
    };
}

public sealed record SarifReport(IReadOnlyDictionary<string, double> Metrics, IReadOnlyList<Issue> Issues);