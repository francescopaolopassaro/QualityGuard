using QualityGuard.Core.Analysis;

namespace QualityGuard.Core.Models;

public sealed record IssueLocation(string File, int StartLine, int StartColumn, int EndLine, int EndColumn);

public sealed class Issue
{
    public Issue(string ruleKey, string message, Severity severity, IssueKind kind, string? file = null,
        int? line = null, string? remediationEffort = null, Dictionary<string, string>? secondaryLocations = null,
        string? howToFix = null, IReadOnlyList<FlowStep>? flow = null)
    {
        RuleKey = ruleKey;
        Message = message;
        Severity = severity;
        Kind = kind;
        File = file;
        Line = line;
        RemediationEffort = remediationEffort;
        SecondaryLocations = secondaryLocations;
        HowToFix = howToFix;
        Flow = flow;
    }

    public string RuleKey { get; }

    /// <summary>Always English: what is wrong on this line.</summary>
    public string Message { get; }

    public Severity Severity { get; }
    public IssueKind Kind { get; }
    public string? File { get; }
    public int? Line { get; }

    /// <summary>Estimated effort, e.g. <c>10min</c>.</summary>
    public string? RemediationEffort { get; }

    public Dictionary<string, string>? SecondaryLocations { get; }

    /// <summary>Always English: the steps that resolve the finding.</summary>
    public string? HowToFix { get; }

    /// <summary>Source-to-sink trail when the finding comes from data-flow analysis.</summary>
    public IReadOnlyList<FlowStep>? Flow { get; }

    public override string ToString()
        => $"[{Severity}] {RuleKey}: {Message} ({File ?? "-"}{(Line is null ? "" : $":{Line}")})";
}
