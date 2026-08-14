namespace QualityGuard.Core.Models;

/// <summary>Before/after snippet pair shown with a finding.</summary>
public sealed record CodeExample(string Language, string Noncompliant, string Compliant);

/// <summary>
/// Everything a developer needs to act on a finding, in English: what was detected, why it matters and
/// the concrete steps that fix it. Every rule must provide one; wording is written for this engine,
/// aimed at being shorter and more direct than the usual analyzer prose.
/// </summary>
public sealed record RuleDescription(
    string Summary,
    string WhyIsThisAnIssue,
    string HowToFix,
    string? Impact = null,
    CodeExample? Example = null,
    string[]? References = null)
{
    /// <summary>Rendered as Markdown for SARIF help text and CLI output.</summary>
    public string ToMarkdown(string ruleKey, string ruleName)
    {
        var text = new System.Text.StringBuilder();
        text.AppendLine($"## {ruleKey} — {ruleName}").AppendLine();
        text.AppendLine(Summary).AppendLine();
        text.AppendLine("### Why is this a problem?").AppendLine().AppendLine(WhyIsThisAnIssue).AppendLine();
        if (!string.IsNullOrWhiteSpace(Impact))
            text.AppendLine("### What can go wrong").AppendLine().AppendLine(Impact).AppendLine();
        text.AppendLine("### How to fix it").AppendLine().AppendLine(HowToFix).AppendLine();
        if (Example != null)
        {
            text.AppendLine("#### Wrong").AppendLine();
            text.AppendLine($"```{Example.Language}").AppendLine(Example.Noncompliant).AppendLine("```").AppendLine();
            text.AppendLine("#### Fixed").AppendLine();
            text.AppendLine($"```{Example.Language}").AppendLine(Example.Compliant).AppendLine("```").AppendLine();
        }
        if (References is { Length: > 0 })
        {
            text.AppendLine("### References").AppendLine();
            foreach (var reference in References)
                text.AppendLine($"- {reference}");
        }
        return text.ToString();
    }
}
