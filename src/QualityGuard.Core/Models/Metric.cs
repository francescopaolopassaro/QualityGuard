namespace QualityGuard.Core.Models;

public sealed class Metric
{
    public Metric(string key, string name, string description)
    {
        Key = key;
        Name = name;
        Description = description;
    }

    public string Key { get; }
    public string Name { get; }
    public string Description { get; }

    public override string ToString() => Key;
}

public static class CoreMetrics
{
    public const string Coverage = "coverage";
    public const string NewCoverage = "new_coverage";
    public const string LineCoverage = "line_coverage";
    public const string BranchCoverage = "branch_coverage";
    public const string NewLineCoverage = "new_line_coverage";
    public const string NewBranchCoverage = "new_branch_coverage";
    public const string LinesToCover = "lines_to_cover";
    public const string UncoveredLines = "uncovered_lines";
    public const string ConditionsToCover = "conditions_to_cover";
    public const string UncoveredConditions = "uncovered_conditions";
    public const string NewLinesToCover = "new_lines_to_cover";
    public const string NewUncoveredLines = "new_uncovered_lines";
    public const string NewConditionsToCover = "new_conditions_to_cover";
    public const string NewUncoveredConditions = "new_uncovered_conditions";
    public const string NewDuplicatedLinesDensity = "new_duplicated_lines_density";
    public const string NewSecurityRating = "new_security_rating";
    public const string NewReliabilityRating = "new_reliability_rating";
    public const string NewMaintainabilityRating = "new_maintainability_rating";
    public const string NewSecurityHotspotsReviewed = "new_security_hotspots_reviewed";
    public const string NewLines = "new_lines";

    public const string Ncloc = "ncloc";
    public const string Lines = "lines";
    public const string CommentLines = "comment_lines";
    public const string Complexity = "complexity";
    public const string DuplicatedLinesDensity = "duplicated_lines_density";
    public const string SuspectedIssues = "violations";
    public const string Bugs = "bugs";
    public const string Vulnerabilities = "vulnerabilities";
    public const string CodeSmells = "code_smells";
    public const string SecurityHotspots = "security_hotspots";
    public const string ReliabilityRating = "reliability_rating";
    public const string SecurityRating = "security_rating";
    public const string MaintainabilityRating = "squale_rating";
    public const string Files = "files";
    public const string Functions = "functions";
    public const string CognitiveComplexity = "cognitive_complexity";

    /// <summary>Remediation effort of every code smell, in minutes.</summary>
    public const string TechnicalDebt = "sqale_index";

    /// <summary>Debt as a percentage of the estimated cost of writing the code.</summary>
    public const string DebtRatio = "sqale_debt_ratio";

    public static readonly IReadOnlyList<Metric> All =
    [
        new Metric(Coverage, "Coverage", "Share of lines and conditions the tests reach"),
        new Metric(NewCoverage, "Coverage on New Code", "Coverage of new/changed code"),
        new Metric(LineCoverage, "Line Coverage", "Share of executable lines the tests reach"),
        new Metric(BranchCoverage, "Branch Coverage", "Share of conditions the tests reach"),
        new Metric(NewLineCoverage, "Line Coverage on New Code", "Line coverage of new code"),
        new Metric(NewBranchCoverage, "Branch Coverage on New Code", "Branch coverage of new code"),
        new Metric(LinesToCover, "Lines to Cover", "Executable lines the tests should reach"),
        new Metric(UncoveredLines, "Uncovered Lines", "Executable lines the tests never reach"),
        new Metric(ConditionsToCover, "Conditions to Cover", "Conditions the tests should reach"),
        new Metric(UncoveredConditions, "Uncovered Conditions", "Conditions the tests never reach"),
        new Metric(NewLinesToCover, "Lines to Cover on New Code", "Executable lines of new code"),
        new Metric(NewUncoveredLines, "Uncovered Lines on New Code", "Uncovered lines on new code"),
        new Metric(NewConditionsToCover, "Conditions to Cover on New Code", "Conditions of new code"),
        new Metric(NewUncoveredConditions, "Uncovered Conditions on New Code", "Uncovered conditions on new code"),
        new Metric(NewDuplicatedLinesDensity, "Duplicated Lines on New Code", "Duplicated lines on new code"),
        new Metric(NewSecurityRating, "Security Rating on New Code", "Security rating of new code"),
        new Metric(NewReliabilityRating, "Reliability Rating on New Code", "Reliability rating of new code"),
        new Metric(NewMaintainabilityRating, "Maintainability Rating on New Code", "Maintainability rating of new code"),
        new Metric(NewSecurityHotspotsReviewed, "Security Hotspots Reviewed on New Code", "Reviewed security hotspots on new code"),
        new Metric(Ncloc, "Lines of Code", "Non-commenting lines of code"),
        new Metric(Lines, "Lines", "Number of physical lines"),
        new Metric(CommentLines, "Comment Lines", "Number of comment lines"),
        new Metric(Complexity, "Complexity", "Cyclomatic complexity"),
        new Metric(DuplicatedLinesDensity, "Duplicated Lines Density", "Duplicated lines density"),
        new Metric(Files, "Files", "Number of analyzed files"),
        new Metric(Functions, "Functions", "Number of functions"),
        new Metric(TechnicalDebt, "Technical Debt", "Remediation effort of the code smells, in minutes"),
        new Metric(DebtRatio, "Technical Debt Ratio", "Debt as a share of the estimated development cost"),
        new Metric(CognitiveComplexity, "Cognitive Complexity", "Cognitive complexity")
    ];
}