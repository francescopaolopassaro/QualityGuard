using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The modern-API rules of JavaScript and Python read shapes the language outgrew; each test pins
/// the reported form next to the near-miss that must stay silent.
/// </summary>
public class JsPyModernTests
{
    private static IReadOnlyList<int> Lines(string file, string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    // ------------------------------------------------- JavaScript

    [Fact]
    public void A_reduce_without_seed_is_reported()
    {
        var code = "const total = items.reduce((a, b) => a + b);";
        Assert.Equal([1], Lines("app.js", code, "QG-JS-BUG-0084"));
    }

    [Fact]
    public void A_reduce_with_seed_is_left_alone()
    {
        var code = "const total = items.reduce((a, b) => a + b, 0);";
        Assert.Empty(Lines("app.js", code, "QG-JS-BUG-0084"));
    }

    [Fact]
    public void An_equality_findIndex_is_reported()
    {
        var code = "const at = items.findIndex(x => x === target);";
        Assert.Equal([1], Lines("app.js", code, "QG-JS-SML-0293"));
    }

    [Fact]
    public void A_predicate_findIndex_is_left_alone()
    {
        var code = "const at = items.findIndex(x => x.age > 18);";
        Assert.Empty(Lines("app.js", code, "QG-JS-SML-0293"));
    }

    [Fact]
    public void Length_minus_n_indexing_is_reported()
    {
        var code = "const last = items[items.length - 1];";
        Assert.Equal([1], Lines("app.js", code, "QG-JS-SML-0295"));
    }

    [Fact]
    public void A_plain_index_is_left_alone()
    {
        var code = "const first = items[0];";
        Assert.Empty(Lines("app.js", code, "QG-JS-SML-0295"));
    }

    [Fact]
    public void A_date_built_for_its_timestamp_is_reported()
    {
        var code = "const now = new Date().getTime();";
        Assert.Equal([1], Lines("app.js", code, "QG-JS-SML-0299"));
    }

    [Fact]
    public void Remove_child_through_parent_is_reported()
    {
        var code = "node.parentNode.removeChild(node);";
        Assert.Equal([1], Lines("app.js", code, "QG-JS-SML-0302"));
    }

    [Fact]
    public void Web_security_disabled_in_electron_is_reported()
    {
        var code = """
            const win = new BrowserWindow({ webPreferences: { webSecurity: false } });
            """;
        Assert.Equal([1], Lines("main.js", code, "QG-JS-SEC-0118"));
    }

    // ------------------------------------------------- Python

    [Fact]
    public void Indexing_the_dictionary_inside_the_loop_is_reported()
    {
        var code = """
            for key in settings:
                print(key, settings[key])
            """;
        Assert.Equal([1], Lines("s.py", code, "QG-PY-SML-0180"));
    }

    [Fact]
    public void Items_iteration_is_left_alone()
    {
        var code = """
            for key, value in settings.items():
                print(key, value)
            """;
        Assert.Empty(Lines("s.py", code, "QG-PY-SML-0180"));
    }

    [Fact]
    public void Constant_population_is_reported()
    {
        var code = """
            for name in names:
                flags[name] = False
            """;
        Assert.Equal([1], Lines("s.py", code, "QG-PY-SML-0181"));
    }

    [Fact]
    public void A_nested_loop_reusing_the_variable_is_reported()
    {
        var code = """
            for row in grid:
                for row in grid[row]:
                    touch(row)
            """;
        var lines = Analyze.LinesOf(Analyze.WithRules("n.py", code, "QG-PY-SML-0206"), "QG-PY-SML-0206");
        Assert.NotEmpty(lines);
    }

    [Fact]
    public void Range_len_indexing_is_reported()
    {
        var code = """
            for i in range(len(items)):
                print(items[i])
            """;
        Assert.Equal([1], Lines("s.py", code, "QG-PY-SML-0211"));
    }

    [Fact]
    public void Membership_on_a_number_is_reported()
    {
        var code = """
            if key in 3:
                pass
            """;
        Assert.Equal([1], Lines("s.py", code, "QG-PY-BUG-0048"));
    }

    [Fact]
    public void Blocking_sleep_inside_async_is_reported()
    {
        var code = """
            import time

            async def wait():
                time.sleep(5)
            """;
        Assert.Equal([4], Lines("w.py", code, "QG-PY-BUG-0084"));
    }

    [Fact]
    public void Async_sleep_is_left_alone()
    {
        var code = """
            import asyncio

            async def wait():
                await asyncio.sleep(5)
            """;
        Assert.Empty(Lines("w.py", code, "QG-PY-BUG-0084"));
    }

    [Fact]
    public void Inconsistent_tuple_lengths_are_reported()
    {
        var code = """
            def split(pair):
                if pair:
                    return 1, 2
                return 1, 2, 3
            """;
        Assert.Equal([1], Lines("t.py", code, "QG-PY-SML-0201"));
    }
}
