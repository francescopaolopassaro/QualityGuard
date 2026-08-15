using System.Text.RegularExpressions;
using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Rules.Catalog;
using Xunit;

namespace QualityGuard.Core.Tests;

public class RuleRegistryTests
{
    private static readonly IRule[] Rules = RuleRepository.GetBuiltInRules().ToArray();

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
            .Where(e => e.IsDocumentationOnly && !e.IsPlanned && RuleRepository.Find(e.Key) == null)
            .Select(e => e.Key)
            .ToList();
        Assert.Empty(orphans);
    }
}
