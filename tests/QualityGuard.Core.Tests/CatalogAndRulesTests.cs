using QualityGuard.Core.Rules.Catalog;
using Xunit;

namespace QualityGuard.Core.Tests;

public class CatalogAndRulesTests
{
    [Fact]
    public void Yaml_reader_understands_the_catalog_shape()
    {
        var entries = RuleCatalog.Parse("""
            - key: QG-CS-SEC-9001
              name: Test rule
              languages: [cs, vb]
              category: SEC
              cwe: [89, 943]
              message: Something is wrong here.
              summary: A test entry.
              why: |
                First line.
                Second line.
              fix: |
                Do the thing.
              detect:
                - invocation: [Danger]
                  argDynamic: true
            """).ToList();

        var entry = Assert.Single(entries);
        Assert.Equal("QG-CS-SEC-9001", entry.Key);
        Assert.Equal(["cs", "vb"], entry.Languages);
        Assert.Equal([89, 943], entry.Cwe);
        Assert.Contains("Second line.", entry.Description.WhyIsThisAnIssue);
        Assert.Equal("Do the thing.", entry.Description.HowToFix.Trim());
        var spec = Assert.Single(entry.Detect);
        Assert.Equal(MatchTarget.Invocation, spec.Target);
        Assert.True(spec.ArgDynamic);
    }

    [Fact]
    public void Declarative_rules_detect_what_they_describe()
    {
        var analysis = Analyze.WithRules("Controller.cs", """
            public class C
            {
                [IgnoreAntiforgeryToken]
                public IActionResult Post(string name)
                {
                    return Ok();
                }
            }
            """, "QG-CS-SEC-0032");

        Assert.Equal([3], Analyze.LinesOf(analysis, "QG-CS-SEC-0032"));
    }

    [Fact]
    public void Structural_rules_use_the_syntax_tree()
    {
        var analysis = Analyze.WithRules("Sample.cs", """
            class A
            {
                int go(int x)
                {
                    if (x > 0) { return 1; }
                    else if (x > 0) { return 2; }
                    return 0;
                    log("done");
                }
            }
            """, "QG-ALL-BUG-0001", "QG-ALL-BUG-0002");

        Assert.NotEmpty(Analyze.LinesOf(analysis, "QG-ALL-BUG-0001"));
        Assert.NotEmpty(Analyze.LinesOf(analysis, "QG-ALL-BUG-0002"));
    }

    [Fact]
    public void Findings_carry_english_fix_guidance()
    {
        var analysis = Analyze.WithRules("Sample.cs", """
            class A { void go() { var x = 1; } }
            """, "QG-ALL-SML-0009");

        var issue = Assert.Single(analysis.Issues);
        Assert.False(string.IsNullOrWhiteSpace(issue.HowToFix));
        Assert.Null(QualityGuard.Core.Rules.EnglishGuard.FindMarker(issue.HowToFix));
        Assert.Null(QualityGuard.Core.Rules.EnglishGuard.FindMarker(issue.Message));
    }

    [Fact]
    public void Same_rule_reports_a_line_only_once()
    {
        var analysis = Analyze.WithRules("Controller.cs", """
            public class C
            {
                public void Go()
                {
                    var input = Request.Query["file"];
                    File.ReadAllText(Path.Combine("/data", input));
                }
            }
            """, "QG-CS-SEC-0018");

        var reported = Analyze.LinesOf(analysis, "QG-CS-SEC-0018");
        Assert.Equal(reported.Distinct().Count(), reported.Count);
    }
}
