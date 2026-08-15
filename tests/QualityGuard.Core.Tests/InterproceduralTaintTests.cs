using QualityGuard.Core.Analysis;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>Untrusted data has to stay tracked when it crosses functions and files.</summary>
public class InterproceduralTaintTests
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
    public void A_function_returning_request_data_is_a_source_for_its_callers()
    {
        var analyses = Analyze(
            ("Input.cs", """
                public class Input
                {
                    public string ReadUserFile() { return Request.Query["file"]; }
                }
                """),
            ("Reader.cs", """
                public class Reader
                {
                    public string Load()
                    {
                        var path = ReadUserFile();
                        return File.ReadAllText(path);
                    }
                }
                """));

        var reader = analyses.Single(a => a.File.Path == "Reader.cs");
        var call = SyntaxQuery.InvocationsNamed(reader.Tree.Root, "ReadAllText").Single();
        var argument = SyntaxQuery.ArgumentAt(call, 0);
        Assert.True(reader.Taint!.IsTainted(argument));
    }

    [Fact]
    public void The_flow_names_the_file_where_the_data_enters()
    {
        var analyses = Analyze(
            ("Input.cs", """
                public class Input
                {
                    public string ReadUserFile() { return Request.Query["file"]; }
                }
                """),
            ("Reader.cs", """
                public class Reader
                {
                    public string Load() { return File.ReadAllText(ReadUserFile()); }
                }
                """));

        var reader = analyses.Single(a => a.File.Path == "Reader.cs");
        var call = SyntaxQuery.InvocationsNamed(reader.Tree.Root, "ReadAllText").Single();
        var flow = reader.Taint!.FlowTo(call);
        Assert.Contains(flow, step => step.Description.Contains("Input.cs"));
    }

    [Fact]
    public void An_argument_taints_the_parameter_of_a_callee_in_another_file()
    {
        var analyses = Analyze(
            ("Caller.cs", """
                public class Caller
                {
                    public void Handle() { Save(Request.Query["name"]); }
                }
                """),
            ("Writer.cs", """
                public class Writer
                {
                    public void Save(string content) { File.WriteAllText("out.txt", content); }
                }
                """));

        var writer = analyses.Single(a => a.File.Path == "Writer.cs");
        Assert.Contains(writer.Taint!.TaintedSymbols, s => s.Name == "content");
    }

    [Fact]
    public void A_clean_function_does_not_become_a_source()
    {
        var analyses = Analyze(
            ("Constants.cs", """
                public class Constants
                {
                    public string DefaultPath() { return "/etc/app/config"; }
                }
                """),
            ("Reader.cs", """
                public class Reader
                {
                    public string Load() { return File.ReadAllText(DefaultPath()); }
                }
                """));

        var reader = analyses.Single(a => a.File.Path == "Reader.cs");
        var call = SyntaxQuery.InvocationsNamed(reader.Tree.Root, "ReadAllText").Single();
        Assert.False(reader.Taint!.IsTainted(SyntaxQuery.ArgumentAt(call, 0)));
    }

    [Fact]
    public void An_overloaded_name_is_not_propagated_through()
    {
        var analyses = Analyze(
            ("A.cs", "public class A { public string Read() { return Request.Query[\"x\"]; } }"),
            ("B.cs", "public class B { public string Read() { return \"safe\"; } }"),
            ("C.cs", "public class C { public string Go() { return File.ReadAllText(Read()); } }"));

        var caller = analyses.Single(a => a.File.Path == "C.cs");
        var call = SyntaxQuery.InvocationsNamed(caller.Tree.Root, "ReadAllText").Single();
        // two declarations share the name, so the analysis stays silent instead of guessing
        Assert.False(caller.Taint!.IsTainted(SyntaxQuery.ArgumentAt(call, 0)));
    }
}
