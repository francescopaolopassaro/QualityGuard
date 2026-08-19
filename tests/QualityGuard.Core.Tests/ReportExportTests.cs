using QualityGuard.Cli.Reporting;
using QualityGuard.Core.Models;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The exported report. What is pinned here is that the file says what the scan found: a report that
/// quietly disagrees with the console is worse than no report at all.
/// </summary>
public class ReportExportTests
{
    private static readonly string Code = """
        public class Demo
        {
            public void Run(string input)
            {
                var command = "cmd /c " + input;
                System.Diagnostics.Process.Start("cmd.exe", command);
            }
        }
        """;

    private static (QualityGuard.Cli.ReportHTML.ReportData Data, int Findings) Report()
    {
        var analysis = Analyze.WithRules("Demo.cs", Code);
        var metrics = new Dictionary<string, double>
        {
            [CoreMetrics.Ncloc] = analysis.Metrics["ncloc"],
            [CoreMetrics.Complexity] = analysis.Metrics["complexity"]
        };
        var gate = new QualityGateResult(QualityGateStatus.Failed, []);
        return (HtmlReportData.From([analysis], metrics, gate), analysis.Issues.Count);
    }

    [Fact]
    public void The_report_counts_what_the_scan_found()
    {
        var (data, findings) = Report();
        var counted = data.Summary.Bugs.Count + data.Summary.Vulnerabilities.Count
                      + data.Summary.CodeSmells.Count + data.Summary.SecurityHotspots.Count;

        Assert.True(findings > 0, "the sample has to produce findings for this test to mean anything");
        Assert.Equal(findings, counted);
        Assert.Equal("FAILED", data.QualityGateStatus);
    }

    [Fact]
    public void The_markdown_report_states_the_verdict_and_the_numbers()
    {
        var (data, _) = Report();
        var markdown = MarkdownReport.Render(data);

        Assert.Contains("# QualityGuard report", markdown, StringComparison.Ordinal);
        Assert.Contains("**FAILED**", markdown, StringComparison.Ordinal);
        Assert.Contains($"| Files | {data.Summary.Files} |", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void The_page_carries_its_data_inside_it()
    {
        var (data, _) = Report();
        var path = Path.Combine(Path.GetTempPath(), $"qg-report-{Guid.NewGuid():N}.html");
        try
        {
            QualityGuard.Cli.ReportHTML.ReportGenerator.Generate(path, data);
            var page = File.ReadAllText(path);

            // nothing is fetched: the payload, the styles and the script travel with the file
            Assert.Contains("qualityGateStatus", page, StringComparison.Ordinal);
            Assert.DoesNotContain("/*__REPORT_DATA__*/", page, StringComparison.Ordinal);
            Assert.DoesNotContain("<script src=", page, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("<link rel=\"stylesheet\"", page, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
