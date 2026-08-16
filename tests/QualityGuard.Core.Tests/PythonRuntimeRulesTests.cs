using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The second Python wave. Several negative cases come straight from the standard library, where
/// these were measured: a dictionary whose keys are bracket characters, a valid "rb" mode reached
/// through a computed path, an __exit__ that raises a problem of its own.
/// </summary>
public class PythonRuntimeRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "service.py")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_mutable_default_is_reported_but_none_is_not()
    {
        Assert.NotEmpty(Lines("def collect(items=[]):\n    return items\n", "QG-PY-BUG-0139"));
        Assert.NotEmpty(Lines("def collect(seen={}):\n    return seen\n", "QG-PY-BUG-0139"));
        Assert.Empty(Lines("def collect(items=None):\n    return items or []\n", "QG-PY-BUG-0139"));
        Assert.Empty(Lines("def collect(name=\"x\", limit=3):\n    return name\n", "QG-PY-BUG-0139"));
    }

    [Fact]
    public void A_mutable_default_is_found_in_a_signature_spread_over_lines()
    {
        var code = """
            def build(
                prog=None,
                parents=[],
                prefix="-",
            ):
                return prog
            """;
        Assert.NotEmpty(Lines(code, "QG-PY-BUG-0139"));
    }

    [Fact]
    public void Raising_a_string_is_reported()
    {
        Assert.NotEmpty(Lines("def go():\n    raise \"broken\"\n", "QG-PY-BUG-0140"));
        Assert.Empty(Lines("def go():\n    raise ValueError(\"broken\")\n", "QG-PY-BUG-0140"));
    }

    [Fact]
    public void A_repeated_keyword_argument_is_reported()
    {
        Assert.NotEmpty(Lines("def go():\n    return helper(mode=1, mode=2)\n", "QG-PY-BUG-0141"));
        Assert.Empty(Lines("def go():\n    return helper(mode=1, other=2)\n", "QG-PY-BUG-0141"));
    }

    [Fact]
    public void An_exit_that_reraises_its_own_argument_is_reported()
    {
        Assert.NotEmpty(Lines("class G:\n    def __exit__(self, kind, exc, tb):\n        raise exc\n",
            "QG-PY-BUG-0142"));
        // raising a problem of its own is a different thing, and the standard library does it
        Assert.Empty(Lines("class G:\n    def __exit__(self, kind, exc, tb):\n"
                           + "        raise RuntimeError(\"generator didn't stop\")\n", "QG-PY-BUG-0142"));
    }

    [Fact]
    public void A_handler_hidden_by_a_wider_one_is_reported()
    {
        var shadowed = """
            def go():
                try:
                    work()
                except Exception:
                    report()
                except ValueError:
                    report()
            """;
        Assert.NotEmpty(Lines(shadowed, "QG-PY-BUG-0143"));

        var ordered = """
            def go():
                try:
                    work()
                except ValueError:
                    report()
                except Exception:
                    report()
            """;
        Assert.Empty(Lines(ordered, "QG-PY-BUG-0143"));
    }

    [Fact]
    public void A_constant_condition_is_reported()
    {
        Assert.NotEmpty(Lines("def go():\n    if 42:\n        return 1\n    return 0\n", "QG-PY-BUG-0144"));
        Assert.Empty(Lines("def go(x):\n    if x:\n        return 1\n    return 0\n", "QG-PY-BUG-0144"));
    }

    [Fact]
    public void An_invalid_open_mode_is_reported_but_a_valid_one_is_not()
    {
        Assert.NotEmpty(Lines("def read(p):\n    return open(p, \"rz\")\n", "QG-PY-BUG-0145"));
        Assert.Empty(Lines("def read(p):\n    return open(p, \"rb\")\n", "QG-PY-BUG-0145"));
        Assert.Empty(Lines("def read(p):\n    return open(p, \"a+\")\n", "QG-PY-BUG-0145"));
        // a path fragment that lands in the mode position is not a mode
        Assert.Empty(Lines("def read(p):\n    return open(p + \".pag\", \"rb\")\n", "QG-PY-BUG-0145"));
    }

    [Fact]
    public void An_unhashable_key_is_reported_but_a_bracket_string_is_not()
    {
        Assert.NotEmpty(Lines("d = {[1, 2]: \"a\"}\n", "QG-PY-BUG-0146"));
        Assert.Empty(Lines("d = {'[': 'LSQB', ']': 'RSQB'}\n", "QG-PY-BUG-0146"));
        Assert.Empty(Lines("d = {(1, 2): \"a\"}\n", "QG-PY-BUG-0146"));
    }

    [Fact]
    public void A_comparison_against_nan_is_reported()
    {
        Assert.NotEmpty(Lines("import math\ndef go(x):\n    return x == math.nan\n", "QG-PY-BUG-0147"));
        Assert.Empty(Lines("import math\ndef go(x):\n    return math.isnan(x)\n", "QG-PY-BUG-0147"));
    }

    [Fact]
    public void A_value_returned_from_a_generator_is_reported()
    {
        Assert.NotEmpty(Lines("def gen():\n    yield 1\n    return 5\n", "QG-PY-BUG-0148"));
        Assert.Empty(Lines("def gen():\n    yield 1\n    return\n", "QG-PY-BUG-0148"));
        Assert.Empty(Lines("def plain():\n    return 5\n", "QG-PY-BUG-0148"));
    }

    [Fact]
    public void An_exception_class_without_a_base_is_reported()
    {
        Assert.NotEmpty(Lines("class LoadError:\n    pass\n", "QG-PY-SML-0249"));
        Assert.Empty(Lines("class LoadError(Exception):\n    pass\n", "QG-PY-SML-0249"));
        Assert.Empty(Lines("class Loader:\n    pass\n", "QG-PY-SML-0249"));
    }

    [Fact]
    public void A_shadowed_builtin_is_reported_only_when_the_function_calls_it()
    {
        Assert.NotEmpty(Lines("def go(items):\n    list = [1]\n    return list(items)\n", "QG-PY-SML-0250"));
        // a local called list that nobody calls hurts nobody
        Assert.Empty(Lines("def go():\n    list = [1]\n    return list\n", "QG-PY-SML-0250"));
    }

    [Fact]
    public void Parentheses_glued_to_a_keyword_are_reported()
    {
        Assert.NotEmpty(Lines("def go(a):\n    if not(a):\n        return 1\n    return 0\n",
            "QG-PY-CNV-0007"));
        Assert.Empty(Lines("def go(a, b):\n    if not (a and b):\n        return 1\n    return 0\n",
            "QG-PY-CNV-0007"));
    }
}
