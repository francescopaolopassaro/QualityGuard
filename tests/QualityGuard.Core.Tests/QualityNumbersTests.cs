using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The numbers a gate is argued about: counts, remediation effort, debt ratio and the letter each
/// rating lands on. They have to be reproducible, so they are pinned here.
/// </summary>
public class QualityNumbersTests
{
    private static Issue Finding(IssueKind kind, Severity severity, string effort = "10min")
        => new("QG-CS-BUG-0150", "message", severity, kind, "File.cs", 1, effort);

    [Theory]
    [InlineData("5min", 5)]
    [InlineData("20min", 20)]
    [InlineData("1h", 60)]
    [InlineData("1h30min", 90)]
    [InlineData("2d", 960)]
    [InlineData("", 0)]
    [InlineData("as long as it takes", 0)]
    public void Remediation_effort_is_read_in_minutes(string effort, int expected)
        => Assert.Equal(expected, QualityRatings.EffortMinutes(effort));

    [Fact]
    public void The_worst_finding_decides_the_rating()
    {
        Assert.Equal(1, QualityRatings.RatingFromSeverity([]));
        Assert.Equal(2, QualityRatings.RatingFromSeverity([Finding(IssueKind.Bug, Severity.Minor)]));
        Assert.Equal(5, QualityRatings.RatingFromSeverity(
        [
            Finding(IssueKind.Bug, Severity.Minor),
            Finding(IssueKind.Bug, Severity.Blocker),
            Finding(IssueKind.Bug, Severity.Major)
        ]));
    }

    [Fact]
    public void A_single_blocker_outweighs_many_minor_findings()
    {
        var many = Enumerable.Range(0, 50).Select(_ => Finding(IssueKind.Bug, Severity.Minor)).ToList();
        var one = new[] { Finding(IssueKind.Bug, Severity.Blocker) };

        Assert.True(QualityRatings.RatingFromSeverity(one) > QualityRatings.RatingFromSeverity(many));
    }

    [Theory]
    [InlineData(0, "A")]
    [InlineData(4.9, "A")]
    [InlineData(9, "B")]
    [InlineData(15, "C")]
    [InlineData(40, "D")]
    [InlineData(80, "E")]
    public void The_maintainability_letter_follows_the_debt_ratio(double ratio, string letter)
        => Assert.Equal(letter, QualityRatings.Letter(QualityRatings.MaintainabilityRating(ratio)));

    [Fact]
    public void Debt_is_the_effort_of_the_code_smells_and_the_ratio_uses_the_size_of_the_code()
    {
        var issues = new List<Issue>
        {
            Finding(IssueKind.CodeSmell, Severity.Minor, "30min"),
            Finding(IssueKind.CodeSmell, Severity.Major, "1h"),
            Finding(IssueKind.Bug, Severity.Blocker, "1d")
        };

        var metrics = QualityRatings.ComputeMetrics(issues, ncloc: 100);

        // only the smells count towards debt: a bug is a defect to fix, not a maintenance cost
        Assert.Equal(90, metrics[CoreMetrics.TechnicalDebt]);
        Assert.Equal(3.0, metrics[CoreMetrics.DebtRatio], 3);
        Assert.Equal(1, metrics[CoreMetrics.MaintainabilityRating]);
        Assert.Equal(5, metrics[CoreMetrics.ReliabilityRating]);
        Assert.Equal(1, metrics[CoreMetrics.SecurityRating]);
        Assert.Equal(1, metrics[CoreMetrics.Bugs]);
        Assert.Equal(2, metrics[CoreMetrics.CodeSmells]);
    }

    [Fact]
    public void A_catalog_of_data_is_not_measured_as_duplicated_code()
    {
        // the same field skeleton repeated is what a catalog is; counting it as duplication buries
        // the number that describes the code
        var repeated = string.Concat(Enumerable.Range(0, 40).Select(i => $"""
            - key: QG-CS-SEC-{i:0000}
              name: A rule
              languages: [cs]
              category: SEC
              severity: major
              message: Something is wrong here.

            """));

        var analysis = Analyze.File("catalog.yaml", repeated);
        Assert.Empty(analysis.Duplicates);
    }

    [Fact]
    public void A_copied_block_of_code_is_still_reported_as_duplicated()
    {
        var body = string.Join('\n', Enumerable.Range(0, 12).Select(i =>
            $"        total{i} = compute(first{i}, second{i}) + adjust(third{i}, fourth{i}) * factor{i};"));
        var code = $$"""
            public class Report
            {
                public void First()
                {
            {{body}}
                }

                public void Second()
                {
            {{body}}
                }
            }
            """;

        var analysis = Analyze.File("Report.cs", code);
        Assert.NotEmpty(analysis.Duplicates);
    }
}
