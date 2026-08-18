using System.Text.RegularExpressions;
using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Rules.Catalog;
using Xunit;

namespace QualityGuard.Core.Tests;

public class RuleRegistryTests
{
    private static readonly IRule[] Rules = RuleRepository.GetBuiltInRules().ToArray();

    /// <summary>
    /// The number registry has to stay ahead of every identifier in use. Two batches generated in
    /// one sitting both read the highest number from the sources and both started from it, so the
    /// second silently reused the first one's numbers. A number is never reassigned, so the registry
    /// is the record — and a record nobody updates is worse than none.
    /// </summary>
    [Fact]
    public void The_number_registry_is_ahead_of_every_rule()
    {
        var registry = System.Text.Json.JsonDocument.Parse(
            File.ReadAllText(Path.Combine(RepositoryRoot(), "rule-ids.json")));
        var next = registry.RootElement.GetProperty("next");

        var behind = new List<string>();
        foreach (var rule in Rules)
        {
            var parts = rule.Key.Split('-');
            if (parts.Length != 4 || !int.TryParse(parts[3], out var number))
                continue;
            var family = $"{parts[1]}-{parts[2]}";
            if (!next.TryGetProperty(family, out var recorded) || recorded.GetInt32() <= number)
                behind.Add($"{rule.Key}: the registry offers {(next.TryGetProperty(family, out var r) ? r.GetInt32() : 0)} next");
        }
        Assert.Empty(behind);
    }

    /// <summary>Walks up from the test binary to the folder that holds the registry.</summary>
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "rule-ids.json")))
            directory = directory.Parent;
        return directory?.FullName ?? AppContext.BaseDirectory;
    }

    [Fact]
    public void Every_key_follows_the_proprietary_format()
    {
        var pattern = new Regex("^QG-(ALL|[A-Z][A-Z0-9]{1,3})-(BUG|SEC|SML|PRF|CNV)-[0-9]{4}$");
        var invalid = Rules.Where(r => !pattern.IsMatch(r.Key)).Select(r => r.Key).ToList();
        Assert.Empty(invalid);
    }

    [Fact]
    public void Keys_are_unique()
    {
        var duplicates = Rules.GroupBy(r => r.Key).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        Assert.Empty(duplicates);
    }

    [Fact]
    public void No_rule_borrows_a_foreign_identifier()
    {
        var foreign = new Regex(@"\bS\d{3,4}\b");
        var offenders = Rules
            .Where(r => foreign.IsMatch(r.Key) || foreign.IsMatch(r.Name)
                        || foreign.IsMatch(r.Description.WhyIsThisAnIssue))
            .Select(r => r.Key)
            .ToList();
        Assert.Empty(offenders);
    }

    [Fact]
    public void Every_rule_explains_itself_and_how_to_fix_it()
    {
        var incomplete = Rules
            .Where(r => string.IsNullOrWhiteSpace(r.Description.Summary)
                        || string.IsNullOrWhiteSpace(r.Description.WhyIsThisAnIssue)
                        || string.IsNullOrWhiteSpace(r.Description.HowToFix))
            .Select(r => r.Key)
            .ToList();
        Assert.Empty(incomplete);
    }

    [Fact]
    public void Every_user_visible_text_is_english()
    {
        var offenders = new List<string>();
        foreach (var rule in Rules)
        {
            foreach (var text in new[] { rule.Name, rule.Description.Summary, rule.Description.WhyIsThisAnIssue, rule.Description.HowToFix })
            {
                if (EnglishGuard.FindMarker(text) is { } marker)
                    offenders.Add($"{rule.Key}: '{marker}'");
            }
        }
        Assert.Empty(offenders);
    }

    [Fact]
    public void Severity_and_kind_agree_with_the_category()
    {
        var mismatched = Rules
            .Where(r => r.Key.Split('-')[2] switch
            {
                "SEC" => r.Kind != IssueKind.Vulnerability && r.Kind != IssueKind.SecurityHotspot,
                "BUG" => r.Kind != IssueKind.Bug,
                _ => r.Kind != IssueKind.CodeSmell
            })
            .Select(r => $"{r.Key} is {r.Kind}")
            .ToList();
        Assert.Empty(mismatched);
    }

    [Fact]
    public void Catalog_entries_are_loaded_and_documented()
    {
        Assert.NotEmpty(RuleCatalog.Entries);
        var undocumented = RuleCatalog.Entries
            .Where(e => string.IsNullOrWhiteSpace(e.Description.HowToFix))
            .Select(e => e.Key)
            .ToList();
        Assert.Empty(undocumented);
    }

    [Fact]
    public void Catalog_documentation_reaches_the_rules_it_targets()
    {
        var orphans = RuleCatalog.Entries
            .Where(e => e.IsDocumentationOnly && !e.IsPlanned && !e.IsSuperseded
                        && RuleRepository.Find(e.Key) == null)
            .Select(e => e.Key)
            .ToList();
        Assert.Empty(orphans);
    }
    [Fact]
    public void Every_rule_states_its_effort_as_a_duration()
    {
        // the value is written into SARIF as remediationEffort and summed into the technical debt:
        // a sentence there is read as zero minutes and quietly removes the rule from the total
        var prose = Rules
            .Where(r => QualityGuard.Core.Analysis.QualityRatings.EffortMinutes(r.RemediationEffort) <= 0)
            .Select(r => $"{r.Key}: {r.RemediationEffort}")
            .ToList();
        Assert.Empty(prose);
    }

    [Fact]
    public void Every_rule_says_how_the_finding_is_fixed()
    {
        var silent = Rules
            .Where(r => string.IsNullOrWhiteSpace(r.Description.HowToFix))
            .Select(r => r.Key)
            .ToList();
        Assert.Empty(silent);
    }

}
