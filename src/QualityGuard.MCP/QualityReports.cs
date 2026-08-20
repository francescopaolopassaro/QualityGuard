using System.Text.Json;
using System.Text.Json.Serialization;
using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Mcp;

/// <summary>JSON shapes returned by the structured tools. Serialized with the invariant culture, so
/// the numbers read the same on every machine.</summary>
public static class QualityReports
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static string ToJson(object value) => JsonSerializer.Serialize(value, value.GetType(), Json);

    public static object BuildAnalyzeData(ScanOutcome outcome, int issueLimit, bool includeFixHints)
    {
        var analyses = outcome.Analyses;
        var metrics = outcome.Metrics;
        var issues = outcome.AllIssues;

        return new
        {
            QualityGate = new
            {
                Status = outcome.Gate.Status == QualityGateStatus.Passed ? "PASSED" : "FAILED",
                Conditions = outcome.Gate.Conditions.Select(c => new
                {
                    Metric = c.Condition.MetricKey,
                    MetricName = MetricDisplayName(c.Condition.MetricKey),
                    Operator = c.Condition.Operator.ToString(),
                    Threshold = c.Condition.Threshold,
                    Measured = double.IsNaN(c.Measured) ? (double?)null : c.Measured,
                    Status = c.Status == ConditionStatus.Ok ? "OK" : "ERROR",
                    Message = c.Message
                }).ToList()
            },
            Scan = new
            {
                Files = analyses.Count,
                Ncloc = (long)metrics.GetValueOrDefault(CoreMetrics.Ncloc),
                Lines = (long)metrics.GetValueOrDefault(CoreMetrics.Lines),
                CommentLines = (long)metrics.GetValueOrDefault(CoreMetrics.CommentLines),
                Complexity = (long)metrics.GetValueOrDefault(CoreMetrics.Complexity),
                CognitiveComplexity = (long)metrics.GetValueOrDefault(CoreMetrics.CognitiveComplexity),
                Functions = (long)metrics.GetValueOrDefault(CoreMetrics.Functions),
                DuplicatedLinesDensity = Round(metrics.GetValueOrDefault(CoreMetrics.DuplicatedLinesDensity))
            },
            Issues = BuildIssuesSummary(issues, metrics.GetValueOrDefault(CoreMetrics.Ncloc)),
            Ratings = new
            {
                Reliability = QualityRatings.Letter(metrics.GetValueOrDefault(CoreMetrics.ReliabilityRating, 1)),
                Security = QualityRatings.Letter(metrics.GetValueOrDefault(CoreMetrics.SecurityRating, 1)),
                Maintainability = QualityRatings.Letter(metrics.GetValueOrDefault(CoreMetrics.MaintainabilityRating, 1)),
                TechnicalDebtMinutes = (long)QualityRatings.TotalDebtMinutes(issues.Where(i => i.Kind == IssueKind.CodeSmell)),
                TechnicalDebtRatio = Round(metrics.GetValueOrDefault(CoreMetrics.DebtRatio))
            },
            Coverage = outcome.Coverage is null ? null : new
            {
                Coverage = Round(outcome.Coverage.Coverage),
                LineCoverage = Round(outcome.Coverage.LineCoverage),
                BranchCoverage = Round(outcome.Coverage.BranchCoverage),
                LinesToCover = outcome.Coverage.LinesToCover,
                UncoveredLines = outcome.Coverage.UncoveredLines,
                ConditionsToCover = outcome.Coverage.ConditionsToCover,
                UncoveredConditions = outcome.Coverage.UncoveredConditions,
                Files = outcome.Coverage.Files.Count
            },
            NewCode = outcome.NewCodeBase is null
                ? null
                : BuildNewCode(metrics, outcome.NewCodeBase),
            Findings = issues
                .OrderByDescending(i => i.Severity)
                .ThenBy(i => i.File, StringComparer.OrdinalIgnoreCase)
                .Take(Math.Max(0, issueLimit))
                .Select(i => new
                {
                    Rule = i.RuleKey,
                    Severity = i.Severity.ToString().ToUpperInvariant(),
                    Kind = i.Kind.ToString(),
                    Message = i.Message,
                    File = i.File,
                    Line = i.Line,
                    HowToFix = includeFixHints ? i.HowToFix : null,
                    Effort = i.RemediationEffort,
                    Flow = i.Flow is { Count: > 0 }
                        ? i.Flow.Select(f => $"{f.Description} (line {f.Line})").ToList()
                        : null
                })
                .ToList(),
            Warnings = outcome.Warnings
        };
    }

    /// <summary>Evaluate a gate over a SARIF report without scanning any source tree.</summary>
    public static object BuildSarifData(string sarifPath, string? gatePath)
    {
        var report = new QualityGuard.Sources.Sarif.SarifReader().Read(sarifPath);
        var conditions = gatePath is null
            ? QualityGuard.Cli.GateConfig.LoadDefault()
            : QualityGuard.Cli.GateConfig.Load(gatePath);
        var result = new QualityGuard.Core.Evaluation.QualityGateEvaluator().Evaluate(report.Metrics, conditions);

        return new
        {
            Source = sarifPath,
            Metrics = report.Metrics.OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => new { Key = kv.Key, Value = kv.Value })
                .ToList(),
            QualityGate = new
            {
                Status = result.Status == QualityGateStatus.Passed ? "PASSED" : "FAILED",
                Conditions = result.Conditions.Select(c => new
                {
                    Metric = c.Condition.MetricKey,
                    MetricName = MetricDisplayName(c.Condition.MetricKey),
                    Operator = c.Condition.Operator.ToString(),
                    Threshold = c.Condition.Threshold,
                    Measured = double.IsNaN(c.Measured) ? (double?)null : c.Measured,
                    Status = c.Status == ConditionStatus.Ok ? "OK" : "ERROR",
                    Message = c.Message
                }).ToList()
            },
            Issues = report.Issues.Select(i => new
            {
                Rule = i.RuleKey,
                Severity = i.Severity.ToString().ToUpperInvariant(),
                Kind = i.Kind.ToString(),
                Message = i.Message,
                File = i.File,
                Line = i.Line
            }).ToList()
        };
    }

    private static object BuildIssuesSummary(IReadOnlyList<Issue> issues, double ncloc)
    {
        var bySeverity = new Dictionary<string, int>();
        foreach (var severity in Enum.GetValues<Severity>())
        {
            var count = issues.Count(i => i.Severity == severity);
            if (count > 0)
                bySeverity[severity.ToString().ToLowerInvariant()] = count;
        }

        return new
        {
            Total = issues.Count,
            Bugs = issues.Count(i => i.Kind == IssueKind.Bug),
            Vulnerabilities = issues.Count(i => i.Kind == IssueKind.Vulnerability),
            SecurityHotspots = issues.Count(i => i.Kind == IssueKind.SecurityHotspot),
            CodeSmells = issues.Count(i => i.Kind == IssueKind.CodeSmell),
            BySeverity = bySeverity,
            Per1kLines = ncloc > 0 ? Round(issues.Count / ncloc * 1000.0) : 0
        };
    }

    private static object BuildNewCode(IReadOnlyDictionary<string, double> metrics, string baseRef)
    {
        var uncoveredLines = metrics.GetValueOrDefault(CoreMetrics.NewUncoveredLines);
        var uncoveredConditions = metrics.GetValueOrDefault(CoreMetrics.NewUncoveredConditions);
        return new
        {
            Base = baseRef,
            NewLines = (long)metrics.GetValueOrDefault(CoreMetrics.NewLines),
            NewLinesToCover = (long)metrics.GetValueOrDefault(CoreMetrics.NewLinesToCover),
            NewUncoveredLines = (long)uncoveredLines,
            NewConditionsToCover = (long)metrics.GetValueOrDefault(CoreMetrics.NewConditionsToCover),
            NewUncoveredConditions = (long)uncoveredConditions,
            NewCoverage = Has(metrics, CoreMetrics.NewCoverage) ? (double?)Round(metrics[CoreMetrics.NewCoverage]) : null,
            NewLineCoverage = Has(metrics, CoreMetrics.NewLineCoverage) ? (double?)Round(metrics[CoreMetrics.NewLineCoverage]) : null,
            NewBranchCoverage = Has(metrics, CoreMetrics.NewBranchCoverage) ? (double?)Round(metrics[CoreMetrics.NewBranchCoverage]) : null,
            NewReliabilityRating = Has(metrics, CoreMetrics.NewReliabilityRating) ? QualityRatings.Letter(metrics[CoreMetrics.NewReliabilityRating]) : null,
            NewSecurityRating = Has(metrics, CoreMetrics.NewSecurityRating) ? QualityRatings.Letter(metrics[CoreMetrics.NewSecurityRating]) : null,
            NewMaintainabilityRating = Has(metrics, CoreMetrics.NewMaintainabilityRating) ? QualityRatings.Letter(metrics[CoreMetrics.NewMaintainabilityRating]) : null,
            NewSecurityHotspotsReviewed = Has(metrics, CoreMetrics.NewSecurityHotspotsReviewed) ? (double?)Round(metrics[CoreMetrics.NewSecurityHotspotsReviewed]) : null
        };
    }

    private static bool Has(IReadOnlyDictionary<string, double> metrics, string key) => metrics.ContainsKey(key);

    private static double Round(double value) => Math.Round(value, 2);

    private static string MetricDisplayName(string key)
        => CoreMetrics.All.FirstOrDefault(m => m.Key == key)?.Name ?? key;
}