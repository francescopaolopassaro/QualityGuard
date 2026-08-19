using QualityGuard.Cli.ReportHTML;
using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Cli.Reporting;

/// <summary>
/// Turns the result of a scan into the shape the HTML report reads. The page is one file with its
/// data inside it, so somebody can keep it, mail it or open it on a machine that has never heard of
/// this tool — which is the whole point of exporting rather than printing.
/// </summary>
public static class HtmlReportData
{
    public static ReportData From(IReadOnlyList<FileAnalysis> analyses,
                                  IReadOnlyDictionary<string, double> metrics,
                                  QualityGateResult gate)
    {
        var issues = analyses.SelectMany(a => a.Issues.Select(i => (Analysis: a, Issue: i))).ToList();

        var data = new ReportData
        {
            QualityGateStatus = gate.Status == QualityGateStatus.Passed ? "PASSED" : "FAILED",
            Conditions = gate.Conditions.Select(c => new QGCondition
            {
                Metric = c.Condition.MetricKey,
                Actual = Format(c.Measured),
                Expected = $"{Symbol(c.Condition.Operator)} {c.Condition.Threshold:0.##}",
                Status = c.Status == ConditionStatus.Ok ? "OK" : "FAILED"
            }).ToList(),
            Summary = SummaryOf(analyses, metrics, issues.Select(x => x.Issue).ToList()),
            Folders = FoldersOf(analyses)
        };

        // The page lists what a reader acts on first: everything that is not a minor smell, worst
        // severity first, and the file it happens in. The rest stays in the counts above it.
        data.Issues = issues
            .Where(x => x.Issue.Severity >= Severity.Major)
            .OrderByDescending(x => x.Issue.Severity)
            .ThenBy(x => x.Analysis.File.Path, StringComparer.OrdinalIgnoreCase)
            .Take(500)
            .Select(x => new ReportHTML.Issue
            {
                Severity = x.Issue.Severity.ToString().ToUpperInvariant(),
                Rule = x.Issue.RuleKey,
                Message = x.Issue.Message,
                File = x.Analysis.File.FileName,
                Line = x.Issue.Line ?? 0,
                Flow = x.Issue.Flow?.Select(step => $"{step.Description} (line {step.Line})").ToList() ?? []
            })
            .ToList();

        return data;
    }

    private static Summary SummaryOf(IReadOnlyList<FileAnalysis> analyses,
                                     IReadOnlyDictionary<string, double> metrics,
                                     IReadOnlyList<Core.Models.Issue> issues)
    {
        var ncloc = metrics.GetValueOrDefault(CoreMetrics.Ncloc);
        var debt = QualityRatings.TotalDebtMinutes(issues);

        return new Summary
        {
            Files = analyses.Count,
            Ncloc = (int)ncloc,
            Complexity = (int)metrics.GetValueOrDefault(CoreMetrics.Complexity),
            Duplicated = metrics.GetValueOrDefault(CoreMetrics.DuplicatedLinesDensity),
            TechDebt = FormatDebt(debt),
            TechDebtRatio = Math.Round(QualityRatings.DebtRatio(debt, ncloc), 2),
            Bugs = Detail(issues, IssueKind.Bug, "Reliability"),
            Vulnerabilities = Detail(issues, IssueKind.Vulnerability, "Security"),
            SecurityHotspots = Detail(issues, IssueKind.SecurityHotspot, "Review"),
            CodeSmells = Detail(issues, IssueKind.CodeSmell, "Maintainability")
        };
    }

    private static MetricDetail Detail(IReadOnlyList<Core.Models.Issue> issues, IssueKind kind, string category)
    {
        var ofKind = issues.Where(i => i.Kind == kind).ToList();
        return new MetricDetail
        {
            Count = ofKind.Count,
            Category = category,
            Rating = QualityRatings.Letter(QualityRatings.RatingFromSeverity(ofKind)),
            Breakdown = ofKind.GroupBy(i => i.Severity)
                .OrderByDescending(g => g.Key)
                .ToDictionary(g => g.Key.ToString().ToLowerInvariant(), g => g.Count()),
            FrequentRules = ofKind.GroupBy(i => i.RuleKey, StringComparer.Ordinal)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => new RuleInfo
                {
                    Id = g.Key,
                    Name = Shorten(g.First().Message),
                    Count = g.Count()
                })
                .ToList()
        };
    }

    private static List<FolderStats> FoldersOf(IReadOnlyList<FileAnalysis> analyses)
        => analyses
            .GroupBy(a => Path.GetDirectoryName(a.File.Path) ?? string.Empty, StringComparer.OrdinalIgnoreCase)
            .Select(g => new FolderStats
            {
                Name = Path.GetFileName(g.Key) is { Length: > 0 } name ? name : g.Key,
                Files = g.Count(),
                Ncloc = (int)g.Sum(a => a.Metrics.GetValueOrDefault("ncloc")),
                Bugs = g.Sum(a => a.Issues.Count(i => i.Kind == IssueKind.Bug)),
                Vuln = g.Sum(a => a.Issues.Count(i => i.Kind == IssueKind.Vulnerability)),
                Smells = g.Sum(a => a.Issues.Count(i => i.Kind == IssueKind.CodeSmell))
            })
            .OrderByDescending(f => f.Bugs + f.Vuln + f.Smells)
            .Take(30)
            .ToList();

    /// <summary>Minutes as the working time a reader thinks in: hours in a day, days in a sprint.</summary>
    private static string FormatDebt(int minutes)
    {
        if (minutes < 60)
            return $"{minutes}min";
        if (minutes < 60 * 8)
            return $"{minutes / 60.0:0.#}h";
        return $"{minutes / (60.0 * 8):0.#}d";
    }

    private static string Shorten(string message)
        => message.Length <= 90 ? message : message[..87] + "...";

    private static string Format(double? value)
        => value is null || double.IsNaN(value.Value)
            ? "not measured"
            : value.Value % 1 == 0 ? $"{value:0}" : $"{value:0.0}";

    private static string Symbol(MetricOperator op)
        => op == MetricOperator.GreaterThan ? ">" : "<";
}
