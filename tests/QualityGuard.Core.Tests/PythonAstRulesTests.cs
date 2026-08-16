using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Python on the tree. Several of the negative cases here come straight from the standard library,
/// which is where these rules were measured: the filter idiom in front of a wider handler, a
/// signature spread over several lines, __new__ receiving the class.
/// </summary>
public class PythonAstRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "service.py")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_break_outside_a_loop_is_reported()
    {
        Assert.NotEmpty(Lines("def go():\n    break\n", "QG-PY-BUG-0132"));
        Assert.Empty(Lines("def go():\n    for i in range(3):\n        break\n", "QG-PY-BUG-0132"));
    }

    [Fact]
    public void An_init_that_returns_a_value_is_reported()
    {
        Assert.NotEmpty(Lines("class A:\n    def __init__(self):\n        return 1\n", "QG-PY-BUG-0133"));
        Assert.Empty(Lines("class A:\n    def __init__(self):\n        return None\n", "QG-PY-BUG-0133"));
    }

    [Fact]
    public void A_non_string_in_all_is_reported()
    {
        Assert.NotEmpty(Lines("__all__ = [\"a\", 1]\n", "QG-PY-BUG-0134"));
        Assert.Empty(Lines("__all__ = [\"a\", \"b\"]\n", "QG-PY-BUG-0134"));
    }

    [Fact]
    public void A_loop_else_without_a_break_is_reported()
    {
        var without = """
            def go(items):
                for i in items:
                    use(i)
                else:
                    done()
            """;
        Assert.NotEmpty(Lines(without, "QG-PY-BUG-0135"));

        var with_break = """
            def go(items):
                for i in items:
                    if i:
                        break
                else:
                    done()
            """;
        Assert.Empty(Lines(with_break, "QG-PY-BUG-0135"));
    }

    [Fact]
    public void A_repeated_dictionary_key_is_reported()
    {
        Assert.NotEmpty(Lines("d = {\"a\": 1, \"b\": 2, \"a\": 3}\n", "QG-PY-BUG-0136"));
        Assert.Empty(Lines("d = {\"a\": 1, \"b\": 2}\n", "QG-PY-BUG-0136"));
    }

    [Fact]
    public void A_repeated_set_element_is_reported_and_a_dictionary_is_left_to_the_other_rule()
    {
        Assert.NotEmpty(Lines("s = {1, 2, 1}\n", "QG-PY-BUG-0137"));
        Assert.Empty(Lines("d = {\"a\": 1, \"b\": 1}\n", "QG-PY-BUG-0137"));
    }

    [Fact]
    public void An_assert_on_a_tuple_is_reported()
    {
        Assert.NotEmpty(Lines("def go(x):\n    assert (x, \"must be set\")\n", "QG-PY-BUG-0138"));
        Assert.Empty(Lines("def go(x):\n    assert x, \"must be set\"\n", "QG-PY-BUG-0138"));
    }

    [Fact]
    public void A_doubled_not_is_reported()
        => Assert.NotEmpty(Lines("def go(x):\n    return not not x\n", "QG-PY-SML-0243"));

    [Fact]
    public void An_exact_type_comparison_is_reported()
    {
        Assert.NotEmpty(Lines("def go(x):\n    return type(x) == str\n", "QG-PY-SML-0244"));
        Assert.Empty(Lines("def go(x):\n    return isinstance(x, str)\n", "QG-PY-SML-0244"));
        Assert.Empty(Lines("def go(a, b):\n    return type(a) == type(b)\n", "QG-PY-SML-0244"));
    }

    [Fact]
    public void A_slice_compared_to_a_literal_is_reported()
    {
        Assert.NotEmpty(Lines("def go(name):\n    return name[:3] == \"do_\"\n", "QG-PY-SML-0245"));
        Assert.Empty(Lines("def go(name):\n    return name.startswith(\"do_\")\n", "QG-PY-SML-0245"));
    }

    [Fact]
    public void A_lambda_bound_to_a_name_is_reported()
    {
        Assert.NotEmpty(Lines("f = lambda v: v + 1\n", "QG-PY-SML-0246"));
        Assert.Empty(Lines("def f(v):\n    return v + 1\n", "QG-PY-SML-0246"));
    }

    [Fact]
    public void A_nested_conditional_expression_is_reported()
    {
        Assert.NotEmpty(Lines("def go(x):\n    return 1 if x else (2 if x else 3)\n", "QG-PY-SML-0247"));
        Assert.Empty(Lines("def go(x):\n    return 1 if x else 2\n", "QG-PY-SML-0247"));
    }

    [Fact]
    public void A_lone_handler_that_only_reraises_is_reported()
    {
        var lone = """
            def go():
                try:
                    work()
                except ValueError:
                    raise
            """;
        Assert.NotEmpty(Lines(lone, "QG-PY-SML-0248"));
    }

    [Fact]
    public void A_bare_reraise_in_front_of_a_wider_handler_is_left_alone()
    {
        var filtering = """
            def go():
                try:
                    work()
                except (SystemExit, KeyboardInterrupt):
                    raise
                except BaseException:
                    report()
            """;
        Assert.Empty(Lines(filtering, "QG-PY-SML-0248"));
    }

    [Fact]
    public void A_method_without_self_is_reported()
    {
        Assert.NotEmpty(Lines("class A:\n    def go():\n        pass\n", "QG-PY-CNV-0005"));
        Assert.NotEmpty(Lines("class A:\n    def go(this, x):\n        return x\n", "QG-PY-CNV-0005"));
        Assert.Empty(Lines("class A:\n    def go(self, x):\n        return x\n", "QG-PY-CNV-0005"));
        Assert.Empty(Lines("class A:\n    @staticmethod\n    def go(x):\n        return x\n",
            "QG-PY-CNV-0005"));
    }

    [Fact]
    public void A_signature_spread_over_several_lines_is_read_whole()
    {
        var code = """
            class A:
                def __init__(
                    self,
                    values: dict[str, int],
                ):
                    self.values = values
            """;
        Assert.Empty(Lines(code, "QG-PY-CNV-0005"));
    }

    [Fact]
    public void The_implicitly_static_methods_are_left_alone()
    {
        var code = """
            class Meta(type):
                def __new__(meta, name, bases, namespace):
                    return super().__new__(meta, name, bases, namespace)
            """;
        Assert.Empty(Lines(code, "QG-PY-CNV-0005"));
    }

    [Fact]
    public void A_class_method_that_does_not_take_cls_is_reported()
    {
        Assert.NotEmpty(Lines("class A:\n    @classmethod\n    def build(self):\n        return None\n",
            "QG-PY-CNV-0006"));
        Assert.Empty(Lines("class A:\n    @classmethod\n    def build(cls):\n        return None\n",
            "QG-PY-CNV-0006"));
    }
}
