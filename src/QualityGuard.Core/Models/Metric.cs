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
    public const string NewCoverage = "new_coverage";
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

    public static readonly IReadOnlyList<Metric> All =
    [
        new Metric(NewCoverage, "Coverage on New Code", "Coverage of new/changed code"),
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
        new Metric(CognitiveComplexity, "Cognitive Complexity", "Cognitive complexity")
    ];
}