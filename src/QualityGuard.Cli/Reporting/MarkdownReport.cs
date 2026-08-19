using System.Text;
using QualityGuard.Cli.ReportHTML;

namespace QualityGuard.Cli.Reporting;

/// <summary>
/// The same report as one Markdown file. It exists for a different reader: a diff on a pull request,
/// a chat window, an assistant asked to summarise what changed. Tables and headings survive being
/// pasted anywhere, which a page full of script does not.
/// </summary>
public static class MarkdownReport
{
    public static void Write(string outputPath, ReportData data)
    {
        File.WriteAllText(outputPath, Render(data));
        Console.WriteLine($"  Markdown report written to {Path.GetFullPath(outputPath)}");
    }

    public static string Render(ReportData data)
        {
            var sb = new StringBuilder();
            
            // Header
            sb.AppendLine($"# QualityGuard report");
            sb.AppendLine();
            sb.AppendLine($"**Quality Gate**: {(data.QualityGateStatus == "PASSED" ? "**PASSED**" : "**FAILED**")}");
            sb.AppendLine($"**Generated**: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();
            sb.AppendLine("---");
            sb.AppendLine();

            // Summary
            var s = data.Summary;
            sb.AppendLine("## Summary");
            sb.AppendLine();
            sb.AppendLine("| Metric | Value |");
            sb.AppendLine("|--------|-------|");
            sb.AppendLine($"| Files | {s.Files} |");
            sb.AppendLine($"| NCLOC | {s.Ncloc:N0} |");
            sb.AppendLine($"| Complexity | {s.Complexity:N0} |");
            sb.AppendLine($"| Duplicated Lines | {s.Duplicated}% |");
            sb.AppendLine($"| Technical Debt | {s.TechDebt} ({s.TechDebtRatio}%) |");
            sb.AppendLine();

            // Quality Metrics
            sb.AppendLine("## Quality Metrics");
            sb.AppendLine();
            sb.AppendLine("| Category | Count | Rating | Breakdown |");
            sb.AppendLine("|----------|-------|--------|-----------|");
            
            if (s.Bugs.Count > 0)
            {
                var bd = s.Bugs.Breakdown;
                sb.AppendLine($"| Bugs | {s.Bugs.Count} | {s.Bugs.Rating} | Critical: {(bd.TryGetValue("critical", out var c) ? c : 0)}, Major: {(bd.TryGetValue("major", out var m) ? m : 0)}, Minor: {(bd.TryGetValue("minor", out var mi) ? mi : 0)} |");
            }
            
            if (s.Vulnerabilities.Count > 0)
            {
                var bd = s.Vulnerabilities.Breakdown;
                sb.AppendLine($"| Vulnerabilities | {s.Vulnerabilities.Count} | {s.Vulnerabilities.Rating} | Critical: {(bd.TryGetValue("critical", out var c) ? c : 0)}, Major: {(bd.TryGetValue("major", out var m) ? m : 0)} |");
            }
            
            if (s.CodeSmells.Count > 0)
            {
                var bd = s.CodeSmells.Breakdown;
                sb.AppendLine($"| Code Smells | {s.CodeSmells.Count} | {s.CodeSmells.Rating} | Critical: {(bd.TryGetValue("critical", out var c) ? c : 0)}, Major: {(bd.TryGetValue("major", out var m) ? m : 0)}, Minor: {(bd.TryGetValue("minor", out var mi) ? mi : 0)} |");
            }
            
            if (s.SecurityHotspots.Count > 0)
            {
                sb.AppendLine($"| Security Hotspots | {s.SecurityHotspots.Count} | {s.SecurityHotspots.Rating} | - |");
            }
            
            sb.AppendLine();

            // Quality Gate Conditions
            if (data.Conditions.Count > 0)
            {
                sb.AppendLine("## Quality Gate Conditions");
                sb.AppendLine();
                sb.AppendLine("| Metric | Actual | Expected | Status |");
                sb.AppendLine("|--------|--------|----------|--------|");
                
                foreach (var cond in data.Conditions)
                {
                    var status = cond.Status.ToLower() == "passed" ? "Passed" : " Failed";
                    sb.AppendLine($"| {cond.Metric} | {cond.Actual} | {cond.Expected} | {status} |");
                }
                sb.AppendLine();
            }

            // A file somebody pastes into a review or a prompt has to stay readable: the worst
            // findings are listed one by one and the tail is counted, because a hundred pages of
            // findings is a report nobody opens twice.
            const int listed = 40;
            if (data.Issues.Count > 0)
            {
                sb.AppendLine("## Issues worth acting on");
                sb.AppendLine();

                foreach (var issue in data.Issues.Take(listed))
                {
                    sb.AppendLine($"### {issue.Severity}: {issue.Rule}");
                    sb.AppendLine();
                    sb.AppendLine($"> **{issue.Message}**");
                    sb.AppendLine();
                    sb.AppendLine($"**File**: `{issue.File}:{issue.Line}`");
                    sb.AppendLine();
                    
                    if (issue.Flow.Count > 0)
                    {
                        sb.AppendLine("**Data Flow:**");
                        sb.AppendLine();
                        foreach (var flow in issue.Flow)
                        {
                            sb.AppendLine($"- {flow}");
                        }
                        sb.AppendLine();
                    }
                    
                    sb.AppendLine("---");
                    sb.AppendLine();
                }

                if (data.Issues.Count > listed)
                {
                    sb.AppendLine($"_{data.Issues.Count - listed} more findings of the same kind are "
                                  + "in the full report._");
                    sb.AppendLine();
                }
            }

            // Frequent Rules
            sb.AppendLine("## Most Frequent Rules");
            sb.AppendLine();
            
            var allRules = new List<(string Category, string Id, string Name, int Count)>();
            
            if (s.Bugs.FrequentRules.Count > 0)
                allRules.AddRange(s.Bugs.FrequentRules.Select(r => ("Bugs", r.Id, r.Name, r.Count)));
            if (s.Vulnerabilities.FrequentRules.Count > 0)
                allRules.AddRange(s.Vulnerabilities.FrequentRules.Select(r => ("Vulnerabilities", r.Id, r.Name, r.Count)));
            if (s.CodeSmells.FrequentRules.Count > 0)
                allRules.AddRange(s.CodeSmells.FrequentRules.Select(r => ("Code Smells", r.Id, r.Name, r.Count)));
            
            if (allRules.Count > 0)
            {
                sb.AppendLine("| Category | Rule ID | Name | Count |");
                sb.AppendLine("|----------|---------|------|-------|");
                
                foreach (var rule in allRules.OrderByDescending(r => r.Count).Take(10))
                {
                    sb.AppendLine($"| {rule.Category} | `{rule.Id}` | {rule.Name} | {rule.Count} |");
                }
                sb.AppendLine();
            }

            // Folder Breakdown
            if (data.Folders.Count > 0)
            {
                sb.AppendLine("## Folder Breakdown");
                sb.AppendLine();
                sb.AppendLine("| Folder | Files | NCLOC | Bugs | Vuln | Smells |");
                sb.AppendLine("|--------|-------|-------|------|------|--------|");
                
                foreach (var f in data.Folders)
                {
                    var folderName = f.Name.Length > 50 ? f.Name.Substring(0, 47) + "..." : f.Name;
                    sb.AppendLine($"| `{folderName}` | {f.Files} | {f.Ncloc:N0} | {f.Bugs} | {f.Vuln} | {f.Smells} |");
                }
                sb.AppendLine();
            }

            // Recommendations
            sb.AppendLine("## What to do first");
            sb.AppendLine();
            
            var recommendations = new List<string>();
            
            if (s.Bugs.Count > 10)
                recommendations.Add($"- **Reliability first**: {s.Bugs.Count} bugs are waiting, and the critical and major ones are the ones users meet.");
            
            if (s.Vulnerabilities.Breakdown.TryGetValue("critical", out var critVuln) && critVuln > 0)
                recommendations.Add($"- **Security**: {critVuln} critical vulnerabilities are open. Nothing else in this list comes before them.");
            
            if (s.CodeSmells.Breakdown.TryGetValue("critical", out var critSmells) && critSmells > 0)
                recommendations.Add($"- **Maintainability**: {critSmells} critical smells make the next change more expensive than it needs to be.");
            
            if (s.TechDebtRatio > 5)
                recommendations.Add($"- **Technical debt** stands at {s.TechDebtRatio}% of the effort it took to write the code. Plan the repayment rather than discovering it.");
            
            if (s.Duplicated > 5)
                recommendations.Add($"- **Duplication**: {s.Duplicated}% of the lines are copies. A fix applied to one copy is a fix missing from the others.");
            
            if (recommendations.Count == 0)
                recommendations.Add("- Nothing needs attention beyond what is listed above.");
            
            foreach (var rec in recommendations)
            {
                sb.AppendLine(rec);
            }
            
            sb.AppendLine();
            sb.AppendLine("---");
            sb.AppendLine();
            sb.AppendLine("*Report generated by QualityGuard*");

            return sb.ToString();
        }
}
