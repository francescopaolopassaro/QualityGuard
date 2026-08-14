using System.Text.Json.Nodes;
using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Sources.Sarif;

public static class SarifWriter
{
    public static void Write(string path, IReadOnlyList<FileAnalysis> analyses, QualityGateResult gate)
    {
        var log = BuildLog(analyses, gate);
        using var stream = File.Create(path);
        using var writer = new System.Text.Json.Utf8JsonWriter(stream, new System.Text.Json.JsonWriterOptions { Indented = true });
        log.WriteTo(writer);
    }

    public static JsonNode BuildLog(IReadOnlyList<FileAnalysis> analyses, QualityGateResult gate)
    {
        var results = new JsonArray();
        var rules = new JsonArray();
        var ruleById = new Dictionary<string, int>();

        foreach (var analysis in analyses)
        {
            foreach (var issue in analysis.Issues)
            {
                if (!ruleById.ContainsKey(issue.RuleKey))
                {
                    ruleById[issue.RuleKey] = rules.Count;
                    rules.Add(BuildRule(issue.RuleKey));
                }

                var result = new JsonObject
                {
                    ["ruleId"] = issue.RuleKey,
                    ["ruleIndex"] = ruleById[issue.RuleKey],
                    ["level"] = Level(issue.Severity),
                    ["message"] = new JsonObject { ["text"] = issue.Message }
                };

                if (issue.HowToFix is { Length: > 0 } fix)
                    result["properties"] = new JsonObject { ["howToFix"] = fix };

                if (issue.Flow is { Count: > 0 } flow)
                {
                    var locations = new JsonArray();
                    foreach (var step in flow)
                    {
                        locations.Add(new JsonObject
                        {
                            ["location"] = new JsonObject
                            {
                                ["physicalLocation"] = new JsonObject
                                {
                                    ["artifactLocation"] = new JsonObject { ["uri"] = issue.File?.Replace('\\', '/') },
                                    ["region"] = new JsonObject { ["startLine"] = step.Line }
                                },
                                ["message"] = new JsonObject { ["text"] = step.Description }
                            }
                        });
                    }
                    result["codeFlows"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["threadFlows"] = new JsonArray
                            {
                                new JsonObject { ["locations"] = locations }
                            }
                        }
                    };
                }

                if (issue.Line is not null)
                {
                    result["locations"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["physicalLocation"] = new JsonObject
                            {
                                ["artifactLocation"] = new JsonObject { ["uri"] = issue.File?.Replace('\\', '/') },
                                ["region"] = new JsonObject { ["startLine"] = issue.Line }
                            }
                        }
                    };
                }
                results.Add(result);
            }
        }

        var metrics = new JsonObject();
        foreach (var analysis in analyses)
        {
            foreach (var (key, value) in analysis.Metrics)
                metrics[key] = JsonValue.Create(value);
        }
        metrics["files"] = analyses.Count;

        var invocations = new JsonArray
        {
            new JsonObject
            {
                ["executionSuccessful"] = true,
                ["properties"] = new JsonObject { ["qualityGate"] = gate.Status.ToString() }
            }
        };

        var run = new JsonObject
        {
            ["tool"] = new JsonObject
            {
                ["driver"] = new JsonObject
                {
                    ["name"] = "QualityGuard",
                    ["informationUri"] = "https://qualityguard.example",
                    ["rules"] = rules
                }
            },
            ["results"] = results,
            ["invocations"] = invocations,
            ["properties"] = new JsonObject { ["metrics"] = metrics }
        };

        return new JsonObject
        {
            ["version"] = "2.1.0",
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["runs"] = new JsonArray { run }
        };
    }

    /// <summary>Full reporting descriptor: title, explanation and the fix steps, so a viewer can show them.</summary>
    private static JsonObject BuildRule(string key)
    {
        var rule = Core.Rules.RuleRepository.Find(key);
        if (rule == null)
            return new JsonObject { ["id"] = key, ["name"] = key };

        var descriptor = new JsonObject
        {
            ["id"] = key,
            ["name"] = rule.Name,
            ["shortDescription"] = new JsonObject { ["text"] = rule.Name },
            ["fullDescription"] = new JsonObject { ["text"] = rule.Description.Summary },
            ["help"] = new JsonObject
            {
                ["text"] = rule.Description.HowToFix,
                ["markdown"] = rule.Description.ToMarkdown(rule.Key, rule.Name)
            },
            ["defaultConfiguration"] = new JsonObject { ["level"] = Level(rule.Severity) }
        };

        var properties = new JsonObject
        {
            ["issueKind"] = rule.Kind.ToString(),
            ["remediationEffort"] = rule.RemediationEffort
        };
        var tags = new JsonArray();
        foreach (var tag in rule.Tags)
            tags.Add(tag);
        foreach (var cwe in rule.Cwe)
            tags.Add($"CWE-{cwe}");
        foreach (var owasp in rule.Owasp)
            tags.Add($"OWASP-{owasp}");
        if (tags.Count > 0)
            properties["tags"] = tags;
        descriptor["properties"] = properties;

        return descriptor;
    }

    private static string Level(Core.Models.Severity severity) => severity switch
    {
        Core.Models.Severity.Blocker => "error",
        Core.Models.Severity.Critical => "error",
        Core.Models.Severity.Major => "warning",
        Core.Models.Severity.Minor => "note",
        Core.Models.Severity.Info => "note",
        _ => "none"
    };
}