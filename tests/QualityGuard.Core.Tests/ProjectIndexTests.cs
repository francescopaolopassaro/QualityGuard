using QualityGuard.Core.Analysis;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Tokenization;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>The cross-file index is what rules about hierarchies and dead members rely on.</summary>
public class ProjectIndexTests
{
    private static IReadOnlyList<FileAnalysis> Analyze(params (string Name, string Content)[] files)
    {
        var sources = files.Select(f => new SourceFile(f.Name, f.Content,
            BuiltInLanguages.Recognizer.Recognize(f.Name)!)).ToList();
        var context = new AnalysisContext(sources, new AnalysisOptions());
        var analyses = new AnalysisEngine().Run(context).ToList();
        var rules = RuleRepository.GetBuiltInRules();
        foreach (var analysis in analyses)
            RuleEngine.Run(analysis, rules);
        return analyses;
    }

    [Fact]
    public void Types_and_their_bases_are_visible_across_files()
    {
        var analyses = Analyze(
            ("Base.cs", "public class Base { public void Run() { } }"),
            ("Middle.cs", "public class Middle : Base { }"),
            ("Leaf.cs", "public class Leaf : Middle { }"));

        var index = analyses[0].Project!;
        Assert.Equal(3, index.Types.Count);
        var leaf = index.FindType("Leaf")!;
        Assert.Equal(2, index.InheritanceDepth(leaf));
        Assert.Contains("Run", index.InheritedMembers(leaf));
    }

    [Fact]
    public void Implementing_an_interface_is_not_hiding_a_member()
    {
        var analyses = Analyze(
            ("IStore.cs", "public interface IStore { void Save(); }"),
            ("Store.cs", "public class Store : IStore { public void Save() { } }"));

        var findings = analyses.SelectMany(a => a.Issues).Where(i => i.RuleKey == "QG-ALL-BUG-0012");
        Assert.Empty(findings);
    }

    [Fact]
    public void A_member_that_hides_a_base_implementation_is_reported()
    {
        var analyses = Analyze(
            ("Base.cs", "public class Base { public void Save() { } }"),
            ("Child.cs", "public class Child : Base { public void Save() { } }"));

        var findings = analyses.SelectMany(a => a.Issues).Where(i => i.RuleKey == "QG-ALL-BUG-0012");
        Assert.Single(findings);
    }

    [Fact]
    public void Equality_without_hashing_is_reported_once()
    {
        var analyses = Analyze(("Money.cs", """
            public class Money
            {
                public override bool Equals(object other) { return true; }
            }
            """));

        var finding = Assert.Single(analyses[0].Issues.Where(i => i.RuleKey == "QG-ALL-BUG-0013"));
        Assert.Contains("hashing", finding.Message);
    }

    [Fact]
    public void A_type_declared_twice_is_reported()
    {
        var analyses = Analyze(
            ("A.cs", "namespace One; public class Report { public void Go() { } }"),
            ("B.cs", "namespace Two; public class Report { public void Go() { } }"));

        var findings = analyses.SelectMany(a => a.Issues).Where(i => i.RuleKey == "QG-ALL-SML-0033");
        Assert.Equal(2, findings.Count());
    }
}
