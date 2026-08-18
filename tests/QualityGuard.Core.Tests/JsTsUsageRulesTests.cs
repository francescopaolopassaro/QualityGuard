using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The third JavaScript and TypeScript wave. The negative cases are the ones a real TypeScript
/// corpus produced: an optional chain whose tail looks like a statement, a declaration whose
/// initializer ends in a member of the same name.
/// </summary>
public class JsTsUsageRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "app.ts")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_discarded_string_result_is_reported()
    {
        Assert.NotEmpty(Lines("function go(text) {\n  text.trim();\n}\n", "QG-JS-BUG-0166"));
        Assert.Empty(Lines("function go(text) {\n  return text.trim();\n}\n", "QG-JS-BUG-0166"));
    }

    [Fact]
    public void An_optional_chain_assigned_to_a_name_is_left_alone()
    {
        // the parser splits the chain, and its tail arrives looking like a statement of its own
        var code = """
            function go(message) {
              const justification = message.suppressions?.[0]?.justification?.trim();
              return justification;
            }
            """;
        Assert.Empty(Lines(code, "QG-JS-BUG-0166"));
    }

    [Fact]
    public void A_typeof_compared_to_an_impossible_value_is_reported()
    {
        Assert.NotEmpty(Lines("function go(x) {\n  return typeof x === \"arrray\";\n}\n",
            "QG-JS-BUG-0137"));
        Assert.Empty(Lines("function go(x) {\n  return typeof x === \"string\";\n}\n",
            "QG-JS-BUG-0137"));
    }

    [Fact]
    public void A_for_in_over_an_array_is_reported()
        => Assert.NotEmpty(Lines("function go(list) {\n  for (const i in list.map(String)) {\n"
                                 + "    use(i);\n  }\n}\n", "QG-JS-BUG-0138"));

    [Fact]
    public void A_hole_in_an_array_literal_is_reported()
    {
        Assert.NotEmpty(Lines("const holes = [1, , 3];\n", "QG-JS-BUG-0139"));
        Assert.Empty(Lines("const full = [1, 2, 3];\n", "QG-JS-BUG-0139"));
    }

    [Fact]
    public void A_self_assignment_is_reported()
    {
        Assert.NotEmpty(Lines("function go(name) {\n  name = name;\n  return name;\n}\n",
            "QG-JS-BUG-0140"));
        Assert.Empty(Lines("function go(name, other) {\n  name = other;\n  return name;\n}\n",
            "QG-JS-BUG-0140"));
    }

    [Fact]
    public void A_declaration_taking_a_member_of_the_same_name_is_left_alone()
        => Assert.Empty(Lines("function go(child) {\n  const source = (child as Root).source;\n"
                              + "  return source;\n}\n", "QG-JS-BUG-0140"));

    [Fact]
    public void A_redeclared_name_is_reported()
    {
        Assert.NotEmpty(Lines("function go() {\n  let a = 1;\n  let a = 2;\n  return a;\n}\n",
            "QG-JS-BUG-0141"));
        Assert.Empty(Lines("function go() {\n  let a = 1;\n  let b = 2;\n  return a + b;\n}\n",
            "QG-JS-BUG-0141"));
    }

    [Fact]
    public void A_repeated_union_member_is_reported()
    {
        Assert.NotEmpty(Lines("function go(v: string | number | string) {\n  return v;\n}\n",
            "QG-JS-BUG-0142"));
        Assert.Empty(Lines("function go(v: string | number) {\n  return v;\n}\n", "QG-JS-BUG-0142"));
    }

    [Fact]
    public void The_function_constructor_is_reported()
        => Assert.NotEmpty(Lines("const f = new Function(\"return 1\");\n", "QG-JS-SEC-0079"));

    [Fact]
    public void A_property_repeating_its_name_is_reported()
    {
        Assert.NotEmpty(Lines("function go(name) {\n  return { name: name, other: 2 };\n}\n",
            "QG-JS-SML-0365"));
        Assert.Empty(Lines("function go(name) {\n  return { name, other: 2 };\n}\n", "QG-JS-SML-0365"));
    }

    [Fact]
    public void A_long_concatenation_is_reported()
        => Assert.NotEmpty(Lines("function go(a, b) {\n  return \"user \" + a + \" did \" + b + \" now\";\n}\n",
            "QG-JS-SML-0366"));

    [Fact]
    public void The_arguments_object_is_reported()
    {
        Assert.NotEmpty(Lines("function go() {\n  return arguments.length;\n}\n", "QG-JS-SML-0367"));
        Assert.Empty(Lines("function go(...args) {\n  return args.length;\n}\n", "QG-JS-SML-0367"));
    }

    [Fact]
    public void A_nested_template_is_reported()
        => Assert.NotEmpty(Lines("function go(t) {\n  return `outer ${`inner ${t}`} end`;\n}\n",
            "QG-JS-SML-0368"));

    [Fact]
    public void The_any_type_is_reported_in_typescript_only()
    {
        Assert.NotEmpty(Lines("const payload: any = {};\n", "QG-JS-SML-0369"));
        Assert.Empty(Lines("const payload: any = {};\n", "QG-JS-SML-0369", "app.js"));
    }

    [Fact]
    public void Two_imports_of_one_module_are_reported()
    {
        Assert.NotEmpty(Lines("import { a } from \"./mod\";\nimport { b } from \"./mod\";\n",
            "QG-JS-SML-0370"));
        Assert.Empty(Lines("import { a } from \"./mod\";\nimport { b } from \"./other\";\n",
            "QG-JS-SML-0370"));
    }

    [Fact]
    public void A_setter_without_a_getter_is_reported()
    {
        var lone = """
            class Box {
              set value(v) {
                this._v = v;
              }
            }
            """;
        Assert.NotEmpty(Lines(lone, "QG-JS-SML-0371"));

        var paired = """
            class Box {
              get value() {
                return this._v;
              }
              set value(v) {
                this._v = v;
              }
            }
            """;
        Assert.Empty(Lines(paired, "QG-JS-SML-0371"));
    }
}
