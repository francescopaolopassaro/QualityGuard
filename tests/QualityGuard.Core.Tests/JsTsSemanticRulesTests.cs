using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The second JavaScript and TypeScript wave. The negative cases are the ones a real TypeScript
/// corpus produced while these were being built: a template literal that contains quotes, a
/// destructuring rename of a reserved property name, the === true that narrows an optional boolean.
/// </summary>
public class JsTsSemanticRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "app.js")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_label_after_a_finished_case_is_reported()
    {
        var code = """
            function go(x) {
              switch (x) {
                case 1:
                  one();
                  break;
                defualt:
                  other();
              }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-JS-BUG-0122"));
    }

    [Fact]
    public void A_bitwise_operator_in_a_condition_is_reported()
    {
        Assert.NotEmpty(Lines("function go(a, b) {\n  if (a & b) { return 1; }\n  return 0;\n}\n",
            "QG-JS-BUG-0123"));
        Assert.Empty(Lines("function go(a, b) {\n  if (a && b) { return 1; }\n  return 0;\n}\n",
            "QG-JS-BUG-0123"));
    }

    [Fact]
    public void An_assignment_to_undefined_is_reported()
        => Assert.NotEmpty(Lines("undefined = 1;\n", "QG-JS-BUG-0124"));

    [Fact]
    public void A_destructuring_rename_of_arguments_is_left_alone()
        => Assert.Empty(Lines("function go(call) {\n  const { arguments: args } = call;\n  return args;\n}\n",
            "QG-JS-BUG-0124", "app.ts"));

    [Fact]
    public void Extending_a_built_in_prototype_is_reported()
    {
        Assert.NotEmpty(Lines("Object.prototype.each = function () {};\n", "QG-JS-BUG-0125"));
        Assert.Empty(Lines("const own = {};\nown.each = function () {};\n", "QG-JS-BUG-0125"));
    }

    [Fact]
    public void A_setter_that_returns_a_value_is_reported()
    {
        var code = """
            class Box {
              set value(v) {
                this._v = v;
                return v;
              }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-JS-BUG-0126"));
    }

    [Fact]
    public void An_index_tested_for_positive_is_reported()
    {
        Assert.NotEmpty(Lines("function go(t) {\n  return t.indexOf(\"a\") > 0;\n}\n", "QG-JS-BUG-0127"));
        Assert.Empty(Lines("function go(t) {\n  return t.indexOf(\"a\") >= 0;\n}\n", "QG-JS-BUG-0127"));
    }

    [Fact]
    public void A_sort_without_a_comparator_is_reported()
    {
        Assert.NotEmpty(Lines("function go(list) {\n  return list.filter(Boolean).sort();\n}\n",
            "QG-JS-BUG-0128"));
        Assert.Empty(Lines("function go(list) {\n  return list.filter(Boolean).sort((a, b) => a - b);\n}\n",
            "QG-JS-BUG-0128"));
    }

    [Fact]
    public void A_generator_that_never_yields_is_reported()
    {
        Assert.NotEmpty(Lines("function* empty() {\n  return 1;\n}\n", "QG-JS-BUG-0129"));
        Assert.Empty(Lines("function* ok() {\n  yield 1;\n}\n", "QG-JS-BUG-0129"));
    }

    [Fact]
    public void Throwing_a_string_is_reported()
    {
        Assert.NotEmpty(Lines("function go() {\n  throw \"broken\";\n}\n", "QG-JS-BUG-0130"));
        Assert.Empty(Lines("function go() {\n  throw new Error(\"broken\");\n}\n", "QG-JS-BUG-0130"));
    }

    [Fact]
    public void A_placeholder_in_a_quoted_string_is_reported()
        => Assert.NotEmpty(Lines("function go(name) {\n  return \"hello ${name}\";\n}\n", "QG-JS-BUG-0131"));

    [Fact]
    public void A_template_literal_holding_quotes_is_left_alone()
        => Assert.Empty(Lines("function go(from, dir) {\n"
                              + "  throw new Error(`\"${from}\" is not under \"${dir}\"`);\n}\n",
            "QG-JS-BUG-0131", "app.ts"));

    [Fact]
    public void Negating_the_left_side_of_in_is_reported()
        => Assert.NotEmpty(Lines("function go(obj) {\n  if (!\"a\" in obj) { return 1; }\n  return 0;\n}\n",
            "QG-JS-BUG-0133"));

    [Fact]
    public void Calling_Symbol_with_new_is_reported()
    {
        Assert.NotEmpty(Lines("const s = new Symbol();\n", "QG-JS-BUG-0134"));
        Assert.Empty(Lines("const s = Symbol();\n", "QG-JS-BUG-0134"));
    }

    [Fact]
    public void A_strict_comparison_against_a_boolean_literal_is_reported()
    {
        Assert.NotEmpty(Lines("function go(flag) {\n  return flag === true;\n}\n", "QG-JS-SML-0361"));
        // in TypeScript this narrows a boolean | undefined and is doing real work
        Assert.Empty(Lines("function go(options) {\n  return options.flag === true;\n}\n",
            "QG-JS-SML-0361", "app.ts"));
    }

    [Fact]
    public void The_object_constructor_is_reported()
    {
        Assert.NotEmpty(Lines("const o = new Object();\n", "QG-JS-SML-0363"));
        Assert.Empty(Lines("const o = {};\n", "QG-JS-SML-0363"));
    }

    [Fact]
    public void An_alias_of_this_is_reported()
    {
        Assert.NotEmpty(Lines("function go() {\n  const self = this;\n  return self;\n}\n",
            "QG-JS-SML-0364"));
        Assert.Empty(Lines("function go() {\n  const other = this.value;\n  return other;\n}\n",
            "QG-JS-SML-0364"));
    }

    [Fact]
    public void A_regular_expression_containing_quotes_does_not_derail_the_scan()
    {
        // the tokenizer used to read the quote inside the pattern as the start of a string, which
        // left every later line inside that string
        var code = """
            function go(text) {
              const match = /"([^"]+)"/.exec(text);
              return "plain ${text}";
            }
            """;
        Assert.Equal([3], Lines(code, "QG-JS-BUG-0131", "app.ts"));
    }
}
