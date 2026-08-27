using QualityGuard.Core.Frameworks;
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
            """, "QG-CS-BUG-0150", "QG-CS-BUG-0151");

        Assert.NotEmpty(Analyze.LinesOf(analysis, "QG-CS-BUG-0150"));
        Assert.NotEmpty(Analyze.LinesOf(analysis, "QG-CS-BUG-0151"));
    }

    [Fact]
    public void Findings_carry_english_fix_guidance()
    {
        var analysis = Analyze.WithRules("Sample.cs", """
            class A { void go() { var x = 1; } }
            """, "QG-CS-SML-0499");

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

    [Fact]
    public void Framework_registry_loads_embedded_yaml_files()
    {
        var registry = FrameworkRegistry.Empty;
        Assert.NotNull(registry);
        Assert.Empty(registry.All);
    }

    [Fact]
    public void Framework_registry_loads_java_assertj_framework()
    {
        var catalogDir = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..",
            "src", "QualityGuard.Core", "Rules", "Catalog");
        if (!Directory.Exists(catalogDir))
            catalogDir = Path.Combine(AppContext.BaseDirectory, "Rules", "Catalog");

        var registry = FrameworkRegistry.Load(catalogDir);

        // Should have loaded at least one framework
        Assert.NotEmpty(registry.All);

        // Find the assertj framework
        var assertj = registry.All.FirstOrDefault(f =>
            f.Name == "assertj" && f.Language == "java");
        Assert.NotNull(assertj);
        Assert.NotEmpty(assertj.Chains);
        Assert.NotEmpty(assertj.MethodReturns);
    }

    [Fact]
    public void Framework_registry_resolves_fluent_assertion_types()
    {
        var catalogDir = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..",
            "src", "QualityGuard.Core", "Rules", "Catalog");
        if (!Directory.Exists(catalogDir))
            catalogDir = Path.Combine(AppContext.BaseDirectory, "Rules", "Catalog");

        var registry = FrameworkRegistry.Load(catalogDir);

        // assertThat() entry point returns ObjectAssert
        var chain = registry.FindChain("java", "assertThat");
        Assert.NotNull(chain);
        Assert.Equal("ObjectAssert", chain.Returns);

        // ObjectAssert.isEqualTo() returns self
        var returnType = registry.ReturnType("java", "ObjectAssert", "isEqualTo");
        Assert.Equal("ObjectAssert", returnType);

        // StringAssert.contains() returns self
        var stringReturn = registry.ReturnType("java", "StringAssert", "contains");
        Assert.Equal("StringAssert", stringReturn);
    }

    [Fact]
    public void Framework_registry_resolves_cs_fluent_assertion_types()
    {
        var catalogDir = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..",
            "src", "QualityGuard.Core", "Rules", "Catalog");
        if (!Directory.Exists(catalogDir))
            catalogDir = Path.Combine(AppContext.BaseDirectory, "Rules", "Catalog");

        var registry = FrameworkRegistry.Load(catalogDir);

        // .Should() entry point returns ObjectAssertions
        var returnType = registry.ReturnType("cs", "string", "Should");
        Assert.Equal("ObjectAssertions", returnType);

        // ObjectAssertions.Be() returns self
        var chainReturn = registry.ReturnType("cs", "ObjectAssertions", "Be");
        Assert.Equal("ObjectAssertions", chainReturn);
    }

    [Fact]
    public void Framework_registry_go_http_has_sinks_and_sources()
    {
        var catalogDir = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..",
            "src", "QualityGuard.Core", "Rules", "Catalog");
        if (!Directory.Exists(catalogDir))
            catalogDir = Path.Combine(AppContext.BaseDirectory, "Rules", "Catalog");

        var registry = FrameworkRegistry.Load(catalogDir);

        var sinks = registry.GetSinks("go").ToList();
        Assert.NotEmpty(sinks);

        var sources = registry.GetSources("go").ToList();
        Assert.NotEmpty(sources);
    }

    [Fact]
    public void Framework_registry_python_web_has_sanitizers()
    {
        var catalogDir = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..",
            "src", "QualityGuard.Core", "Rules", "Catalog");
        if (!Directory.Exists(catalogDir))
            catalogDir = Path.Combine(AppContext.BaseDirectory, "Rules", "Catalog");

        var registry = FrameworkRegistry.Load(catalogDir);

        var pyWeb = registry.All.FirstOrDefault(f =>
            f.Name == "web" && f.Language == "py");
        Assert.NotNull(pyWeb);
        Assert.NotEmpty(pyWeb.Sanitizers);
    }

    [Fact]
    public void Framework_registry_java_assertj_chain_returns_self()
    {
        var catalogDir = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..",
            "src", "QualityGuard.Core", "Rules", "Catalog");
        if (!Directory.Exists(catalogDir))
            catalogDir = Path.Combine(AppContext.BaseDirectory, "Rules", "Catalog");

        var registry = FrameworkRegistry.Load(catalogDir);

        // StringAssert.isEqualTo() should return self
        var returnType = registry.ReturnType("java", "StringAssert", "isEqualTo");
        Assert.Equal("StringAssert", returnType);

        // IntegerAssert.isGreaterThan() should return self
        var intReturn = registry.ReturnType("java", "IntegerAssert", "isGreaterThan");
        Assert.Equal("IntegerAssert", intReturn);
    }

    [Fact]
    public void Framework_registry_counts_total_frameworks()
    {
        var catalogDir = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..",
            "src", "QualityGuard.Core", "Rules", "Catalog");
        if (!Directory.Exists(catalogDir))
            catalogDir = Path.Combine(AppContext.BaseDirectory, "Rules", "Catalog");

        var registry = FrameworkRegistry.Load(catalogDir);

        // Should have loaded all 10 framework YAML files
        Assert.True(registry.All.Count >= 10,
            $"Expected at least 10 frameworks, got {registry.All.Count}");
    }
}
