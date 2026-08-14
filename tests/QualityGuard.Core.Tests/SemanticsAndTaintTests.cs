using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;
using Xunit;

namespace QualityGuard.Core.Tests;

public class SemanticsAndTaintTests
{
    [Fact]
    public void Symbols_record_declarations_and_references()
    {
        var analysis = Analyze.File("Sample.cs", """
            class A
            {
                void go()
                {
                    string greeting = "hello";
                    Console.WriteLine(greeting);
                }
            }
            """);

        var symbol = Assert.Single(analysis.Semantics.AllSymbols().Where(s => s.Name == "greeting"));
        Assert.Contains(symbol.Usages, u => u.Kind == UsageKind.Declaration);
        Assert.Contains(symbol.Usages, u => u.Kind == UsageKind.Reference);
        Assert.Equal("hello", symbol.SafeStringValue());
    }

    [Fact]
    public void A_reassigned_symbol_has_no_safe_value()
    {
        var analysis = Analyze.File("Sample.cs", """
            class A
            {
                void go(bool flag)
                {
                    string mode = "read";
                    mode = "write";
                    use(mode);
                }
            }
            """);

        var symbol = Assert.Single(analysis.Semantics.AllSymbols().Where(s => s.Name == "mode"));
        Assert.Null(symbol.SafeStringValue());
    }

    [Fact]
    public void Same_name_in_two_functions_stays_separate()
    {
        var analysis = Analyze.File("Sample.cs", """
            class A
            {
                void first(string q) { var value = Request.Query["id"]; sink(value); }
                void second() { var value = "constant"; sink(value); }
            }
            """);

        var tainted = analysis.Taint!.TaintedSymbols;
        Assert.Single(tainted.Where(s => s.Name == "value"));
        var clean = analysis.Semantics.AllSymbols().First(s => s.Name == "value" && !s.IsTainted);
        Assert.Equal("constant", clean.SafeStringValue());
    }

    [Fact]
    public void Taint_flows_from_request_data_into_a_sink()
    {
        var analysis = Analyze.File("Sample.cs", """
            class A
            {
                void go()
                {
                    var raw = Request.Query["file"];
                    var path = raw;
                    File.ReadAllText(path);
                }
            }
            """);

        var call = Assert.Single(SyntaxQuery.InvocationsNamed(analysis.Tree.Root, "ReadAllText"));
        var argument = SyntaxQuery.ArgumentAt(call, 0);
        Assert.True(analysis.Taint!.IsTainted(argument));
        Assert.NotEmpty(analysis.Taint.FlowTo(call));
    }

    [Fact]
    public void A_sanitized_value_is_no_longer_tainted()
    {
        var analysis = Analyze.File("Sample.cs", """
            class A
            {
                void go()
                {
                    var id = int.Parse(Request.Query["id"]);
                    load(id);
                }
            }
            """);

        var symbol = Assert.Single(analysis.Semantics.AllSymbols().Where(s => s.Name == "id"));
        Assert.False(symbol.IsTainted);
    }

    [Fact]
    public void Taint_propagates_into_a_function_called_with_it()
    {
        var analysis = Analyze.File("Sample.cs", """
            class A
            {
                void entry() { handle(Request.Query["q"]); }
                void handle(string value) { run(value); }
            }
            """);

        Assert.Contains(analysis.Taint!.TaintedSymbols, s => s.Name == "value");
    }
}
