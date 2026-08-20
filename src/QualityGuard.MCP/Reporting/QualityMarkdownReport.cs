using System.Globalization;
using System.Text;
using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Mcp.Reporting;

/// <summary>
/// The full QualityGuard picture as one Markdown document, written for an AI or a reviewer who is
/// asked to improve the code: every parameter the engine measures is in it — coverage, code smells,
/// security, maintainability, the A–E ratings, the gate conditions, duplication, debt, the per-1k
/// densities and the new-code metrics — so the instructions derived from it rest on the same numbers
/// the gate was decided on.
/// </summary>
public static class QualityMarkdownReport
{
    public static string Render(ScanOutcome outcome, int issueLimit = 100, bool includeFixHints = true)
    {
        var sb = new StringBuilder();
        var metrics = outcome.Metrics;
        var issues = outcome.AllIssues;
        var ncloc = metrics.GetValueOrDefault(CoreMetrics.Ncloc);
        var debt = QualityRatings.TotalDebtMinutes(issues.Where(i => i.Kind == IssueKind.CodeSmell));
        var time = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

        sb.AppendLine("# QualityGuard report");
        sb.AppendLine();
        sb.AppendLine($"**Quality Gate**: **{(outcome.Gate.Status == QualityGateStatus.Passed ? "PASSED" : "FAILED")}**");
        sb.AppendLine($"**Generated**: {time}");
        sb.AppendLine();

        foreach (var warning in outcome.Warnings)
        {
            sb.AppendLine($"> {Escape(warning)}");
            sb.AppendLine();
        }

        sb.AppendLine("---");
        sb.AppendLine();
        sb.AppendLine("## Scan summary");
        sb.AppendLine();
        sb.AppendLine("| Metric | Value |");
        sb.AppendLine("|--------|-------|");
        sb.AppendLine($"| Files | {outcome.Analyses.Count:N0} |");
        sb.AppendLine($"| Lines of code (NCLOC) | {FormatInt(metrics.GetValueOrDefault(CoreMetrics.Ncloc))} |");
        sb.AppendLine($"| Physical lines | {FormatInt(metrics.GetValueOrDefault(CoreMetrics.Lines))} |");
        sb.AppendLine($"| Comment lines | {FormatInt(metrics.GetValueOrDefault(CoreMetrics.CommentLines))} |");
        sb.AppendLine($"| Cyclomatic complexity | {FormatInt(metrics.GetValueOrDefault(CoreMetrics.Complexity))} |");
        sb.AppendLine($"| Cognitive complexity | {FormatInt(metrics.GetValueOrDefault(CoreMetrics.CognitiveComplexity))} |");
        sb.AppendLine($"| Functions | {FormatInt(metrics.GetValueOrDefault(CoreMetrics.Functions))} |");
        sb.AppendLine($"| Duplicated lines density | {FormatPercent(metrics.GetValueOrDefault(CoreMetrics.DuplicatedLinesDensity))} |");
        sb.AppendLine();

        sb.AppendLine("## Quality Gate conditions");
        sb.AppendLine();
        if (outcome.Gate.Conditions.Count == 0)
        {
            sb.AppendLine("_No conditions._");
            sb.AppendLine();
        }
        else
        {
            sb.AppendLine("| Metric | Measured | Threshold | Operator | Status |");
            sb.AppendLine("|--------|----------|-----------|----------|--------|");
            foreach (var condition in outcome.Gate.Conditions)
            {
                var measured = double.IsNaN(condition.Measured)
                    ? "N/A"
                    : condition.Condition.MetricKey.EndsWith("rating", StringComparison.Ordinal)
                        ? QualityRatings.Letter(condition.Measured)
                        : FormatDouble(condition.Measured);
                sb.AppendLine($"| {condition.Condition.MetricKey} | {measured} | {FormatDouble(condition.Condition.Threshold)} | {condition.Condition.Operator} | {condition.Status} |");
                if (condition.Message is not null)
                {
                    sb.AppendLine();
                    sb.AppendLine($"> {Escape(condition.Message)}");
                    sb.AppendLine();
                }
            }
            sb.AppendLine();
        }

        sb.AppendLine("## Quality metrics");
        sb.AppendLine();
        sb.AppendLine("| Category | Count | Rating | Per 1k lines | Severity breakdown |");
        sb.AppendLine("|----------|-------|--------|--------------|--------------------|");
        AppendMetricRow(sb, "Bugs", IssueKind.Bug, "Reliability", issues, ncloc);
        AppendMetricRow(sb, "Vulnerabilities", IssueKind.Vulnerability, "Security", issues, ncloc);
        AppendMetricRow(sb, "Security hotspots", IssueKind.SecurityHotspot, "Review", issues, ncloc);
        AppendMetricRow(sb, "Code smells", IssueKind.CodeSmell, "Maintainability", issues, ncloc);
        sb.AppendLine();

        sb.AppendLine("### Ratings (A = best, E = worst)");
        sb.AppendLine();
        sb.AppendLine("| Aspect | Rating |");
        sb.AppendLine("|--------|--------|");
        sb.AppendLine($"| Reliability (bugs) | **{QualityRatings.Letter(metrics.GetValueOrDefault(CoreMetrics.ReliabilityRating, 1))}** |");
        sb.AppendLine($"| Security (vulnerabilities) | **{QualityRatings.Letter(metrics.GetValueOrDefault(CoreMetrics.SecurityRating, 1))}** |");
        sb.AppendLine($"| Maintainability (debt ratio) | **{QualityRatings.Letter(metrics.GetValueOrDefault(CoreMetrics.MaintainabilityRating, 1))}** |");
        sb.AppendLine();
        sb.AppendLine("Ratings come from the worst severity found: A = nothing, B = minor, C = major, D = critical, E = blocker. Maintainability is a ratio of technical debt to the cost of writing the code (A ≤ 5 %, B ≤ 10 %, C ≤ 20 %, D ≤ 50 %, E above).");
        sb.AppendLine();

        sb.AppendLine("## Technical debt");
        sb.AppendLine();
        sb.AppendLine("| Metric | Value |");
        sb.AppendLine("|--------|-------|");
        sb.AppendLine($"| Technical debt | {FormatDebt(debt)} |");
        sb.AppendLine($"| Debt ratio | {FormatPercent(metrics.GetValueOrDefault(CoreMetrics.DebtRatio))} of the estimated writing cost |");
        sb.AppendLine();

        if (outcome.Coverage is { } coverage)
        {
            sb.AppendLine("## Test coverage");
            sb.AppendLine();
            sb.AppendLine("| Metric | Value |");
            sb.AppendLine("|--------|-------|");
            sb.AppendLine($"| Overall coverage | {FormatPercent(coverage.Coverage)} |");
            sb.AppendLine($"| Line coverage | {FormatPercent(coverage.LineCoverage)} |");
            sb.AppendLine($"| Branch coverage | {FormatPercent(coverage.BranchCoverage)} |");
            sb.AppendLine($"| Lines to cover | {coverage.LinesToCover:N0} |");
            sb.AppendLine($"| Uncovered lines | {coverage.UncoveredLines:N0} |");
            sb.AppendLine($"| Conditions to cover | {coverage.ConditionsToCover:N0} |");
            sb.AppendLine($"| Uncovered conditions | {coverage.UncoveredConditions:N0} |");
            sb.AppendLine($"| Files with coverage | {coverage.Files.Count:N0} |");
            sb.AppendLine();
        }

        if (outcome.NewCodeBase is not null)
        {
            sb.AppendLine($"## New code since {Escape(outcome.NewCodeBase)}");
            sb.AppendLine();
            sb.AppendLine("| Metric | Value |");
            sb.AppendLine("|--------|-------|");
            sb.AppendLine($"| New/changed lines (git) | {FormatInt(metrics.GetValueOrDefault(CoreMetrics.NewLines))} |");
            if (metrics.ContainsKey(CoreMetrics.NewCoverage))
            {
                sb.AppendLine($"| New code coverage | {FormatPercent(metrics[CoreMetrics.NewCoverage])} |");
                sb.AppendLine($"| New line coverage | {FormatPercent(metrics.GetValueOrDefault(CoreMetrics.NewLineCoverage))} |");
                sb.AppendLine($"| New branch coverage | {FormatPercent(metrics.GetValueOrDefault(CoreMetrics.NewBranchCoverage))} |");
                sb.AppendLine($"| New lines to cover | {FormatInt(metrics.GetValueOrDefault(CoreMetrics.NewLinesToCover))} |");
                sb.AppendLine($"| New uncovered lines | {FormatInt(metrics.GetValueOrDefault(CoreMetrics.NewUncoveredLines))} |");
                sb.AppendLine($"| New conditions to cover | {FormatInt(metrics.GetValueOrDefault(CoreMetrics.NewConditionsToCover))} |");
                sb.AppendLine($"| New uncovered conditions | {FormatInt(metrics.GetValueOrDefault(CoreMetrics.NewUncoveredConditions))} |");
            }
            if (metrics.ContainsKey(CoreMetrics.NewReliabilityRating))
                sb.AppendLine($"| New reliability rating | {QualityRatings.Letter(metrics[CoreMetrics.NewReliabilityRating])} |");
            if (metrics.ContainsKey(CoreMetrics.NewSecurityRating))
                sb.AppendLine($"| New security rating | {QualityRatings.Letter(metrics[CoreMetrics.NewSecurityRating])} |");
            if (metrics.ContainsKey(CoreMetrics.NewMaintainabilityRating))
                sb.AppendLine($"| New maintainability rating | {QualityRatings.Letter(metrics[CoreMetrics.NewMaintainabilityRating])} |");
            if (metrics.ContainsKey(CoreMetrics.NewSecurityHotspotsReviewed))
                sb.AppendLine($"| New security hotspots reviewed | {FormatPercent(metrics[CoreMetrics.NewSecurityHotspotsReviewed])} |");
            sb.AppendLine();
        }

        AppendFindings(sb, issues, issueLimit, includeFixHints);
        AppendFrequentRules(sb, issues);
        AppendFolders(sb, outcome.Analyses);
        AppendRecommendations(sb, issues, debt, metrics, ncloc);

        sb.AppendLine("---");
        sb.AppendLine();
        sb.AppendLine("*Report generated by QualityGuard*");
        return sb.ToString();
    }

    private static void AppendMetricRow(StringBuilder sb, string category, IssueKind kind, string aspect,
        IReadOnlyList<Issue> issues, double ncloc)
    {
        var ofKind = issues.Where(i => i.Kind == kind).ToList();
        var breakdown = ofKind.GroupBy(i => i.Severity)
            .OrderByDescending(g => g.Key)
            .Select(g => $"{g.Key.ToString().ToLowerInvariant()} {g.Count()}");
        var per1k = ncloc > 0 ? ofKind.Count / ncloc * 1000.0 : 0;
        sb.AppendLine($"| {category} | {ofKind.Count:N0} | {QualityRatings.Letter(QualityRatings.RatingFromSeverity(ofKind))} | {FormatDouble(per1k)} | {string.Join(", ", breakdown)} |");
    }

    private static void AppendFindings(StringBuilder sb, IReadOnlyList<Issue> issues, int limit, bool includeFixHints)
    {
        var findings = issues
            .OrderByDescending(i => i.Severity)
            .ThenBy(i => i.File, StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(0, limit))
            .ToList();

        sb.AppendLine("## Findings");
        sb.AppendLine();
        if (findings.Count == 0)
        {
            sb.AppendLine("_No findings_");
            sb.AppendLine();
            return;
        }

        foreach (var issue in findings)
        {
            sb.AppendLine($"### {issue.Severity.ToString().ToUpperInvariant()} · {issue.Kind} · {issue.RuleKey}");
            sb.AppendLine();
            sb.AppendLine($"> **{Escape(issue.Message)}**");
            sb.AppendLine();
            sb.AppendLine($"**File**: `{Escape(issue.File ?? "-")}`{(issue.Line is null ? "" : $":{issue.Line}")}");
            if (issue.RemediationEffort is { Length: > 0 } effort)
                sb.AppendLine($"**Effort**: {effort}");
            sb.AppendLine();
            if (issue.Flow is { Count: > 0 })
            {
                sb.AppendLine("**Data flow:**");
                foreach (var step in issue.Flow)
                    sb.AppendLine($"- {Escape(step.Description)} (line {step.Line})");
                sb.AppendLine();
            }
            if (includeFixHints && issue.HowToFix is { Length: > 0 } fix)
            {
                sb.AppendLine("**How to fix it:**");
                sb.AppendLine();
                foreach (var line in fix.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    sb.AppendLine(line.Trim());
                sb.AppendLine();
            }
            sb.AppendLine("---");
            sb.AppendLine();
        }

        if (issues.Count > findings.Count)
            sb.AppendLine($"_{issues.Count - findings.Count} more findings of the same kind are in the full scan._");
        sb.AppendLine();
    }

    private static void AppendFrequentRules(StringBuilder sb, IReadOnlyList<Issue> issues)
    {
        var groups = issues.GroupBy(i => i.RuleKey, StringComparer.Ordinal)
            .OrderByDescending(g => g.Count())
            .Take(10)
            .ToList();
        if (groups.Count == 0)
            return;

        sb.AppendLine("## Most frequent rules");
        sb.AppendLine();
        sb.AppendLine("| Rule | Count | Kind | Example message |");
        sb.AppendLine("|------|-------|------|-----------------|");
        foreach (var group in groups)
        {
            var first = group.First();
            var message = first.Message.Length > 90 ? first.Message[..87] + "..." : first.Message;
            sb.AppendLine($"| `{group.Key}` | {group.Count()} | {first.Kind} | {Escape(message)} |");
        }
        sb.AppendLine();
    }

    private static void AppendFolders(StringBuilder sb, IReadOnlyList<FileAnalysis> analyses)
    {
        var folders = analyses
            .GroupBy(a => Path.GetDirectoryName(a.File.Path) ?? string.Empty, StringComparer.OrdinalIgnoreCase)
            .Select(g => new
            {
                Name = g.Key,
                Files = g.Count(),
                Ncloc = (long)g.Sum(a => a.Metrics.GetValueOrDefault(CoreMetrics.Ncloc)),
                Bugs = g.Sum(a => a.Issues.Count(i => i.Kind == IssueKind.Bug)),
                Vuln = g.Sum(a => a.Issues.Count(i => i.Kind == IssueKind.Vulnerability)),
                Smells = g.Sum(a => a.Issues.Count(i => i.Kind == IssueKind.CodeSmell))
            })
            .OrderByDescending(f => f.Bugs + f.Vuln + f.Smells)
            .Take(30)
            .ToList();
        if (folders.Count == 0)
            return;

        sb.AppendLine("## Folder breakdown");
        sb.AppendLine();
        sb.AppendLine("| Folder | Files | NCLOC | Bugs | Vulnerabilities | Smells |");
        sb.AppendLine("|--------|-------|-------|------|----------------|--------|");
        foreach (var folder in folders)
        {
            var name = folder.Name.Length > 50 ? folder.Name[..47] + "..." : folder.Name;
            sb.AppendLine($"| `{Escape(name)}` | {folder.Files} | {folder.Ncloc:N0} | {folder.Bugs} | {folder.Vuln} | {folder.Smells} |");
        }
        sb.AppendLine();
    }

    private static void AppendRecommendations(StringBuilder sb, IReadOnlyList<Issue> issues, int debt,
        IReadOnlyDictionary<string, double> metrics, double ncloc)
    {
        sb.AppendLine("## What to do first");
        sb.AppendLine();

        var recommendations = new List<string>();
        var criticalVulns = issues.Count(i => i.Kind == IssueKind.Vulnerability && i.Severity == Severity.Critical);
        var criticalSmells = issues.Count(i => i.Kind == IssueKind.CodeSmell && i.Severity == Severity.Critical);
        var blocks = issues.Count(i => i.Severity == Severity.Blocker);
        var dup = metrics.GetValueOrDefault(CoreMetrics.DuplicatedLinesDensity);

        if (blocks > 0)
            recommendations.Add($"- **Fix the blockers first**: {blocks} finding(s) rated BLOCKER can break or expose the service. No other work comes before them.");
        if (criticalVulns > 0)
            recommendations.Add($"- **Security first**: {criticalVulns} critical vulnerabilities are open. Nothing else in this list comes before them.");
        if (criticalSmells > 0)
            recommendations.Add($"- **Maintainability**: {criticalSmells} critical smells make the next change more expensive than it needs to be.");
        if (debt > 0)
        {
            var ratio = QualityRatings.DebtRatio(debt, ncloc);
            if (ratio > 5)
                recommendations.Add($"- **Technical debt** stands at {FormatPercent(ratio)} of the effort it took to write the code. Plan the repayment rather than discovering it.");
        }
        if (dup > 5)
            recommendations.Add($"- **Duplication**: {FormatPercent(dup)} of the lines are copies. A fix applied to one copy is a fix missing from the others.");
        if (NewCodeCoverageBelowThreshold(metrics))
            recommendations.Add("- **New code is not covered**: the lines added since the base have no coverage data. Add tests for the new behaviour before merging.");

        if (recommendations.Count == 0)
            recommendations.Add("- Nothing needs attention beyond what is listed above.");

        foreach (var recommendation in recommendations)
            sb.AppendLine(recommendation);
        sb.AppendLine();
    }

    private static bool NewCodeCoverageBelowThreshold(IReadOnlyDictionary<string, double> metrics)
        => metrics.ContainsKey(CoreMetrics.NewCoverage) && metrics[CoreMetrics.NewCoverage] < 80.0;

    private static string FormatInt(double value) => ((long)value).ToString("N0", CultureInfo.InvariantCulture);

    private static string FormatDouble(double value) => value.ToString("0.##", CultureInfo.InvariantCulture);

    private static string FormatPercent(double value) => value.ToString("0.0", CultureInfo.InvariantCulture) + "%";

    private static string FormatDebt(int minutes)
    {
        if (minutes < 60)
            return $"{minutes}min";
        if (minutes < 60 * 8)
            return $"{minutes / 60.0:0.#}h";
        return $"{minutes / (60.0 * 8):0.#}d";
    }

    private static string Escape(string text)
        => text.Replace("|", "\\|", StringComparison.Ordinal);
}