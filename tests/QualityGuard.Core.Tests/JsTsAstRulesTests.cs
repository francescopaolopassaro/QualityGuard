using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// JavaScript and TypeScript rules on the tree. The negative cases matter more than usual here: the
/// language has idioms that look like the defect (the null comparison, an optional parameter, a
/// deliberate fallthrough) and a rule that reports them is turned off the same day.
/// </summary>
public class JsTsAstRulesTests
{
    private static IReadOnlyList<int> Lines(string file, string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void Returning_true_and_false_from_the_two_branches_is_reported()
    {
        var code = """
            function check(a, b) {
              if (a > b) {
                return true;
              } else {
                return false;
              }
            }
            """;
        Assert.Equal([2], Lines("check.js", code, "QG-JS-SML-0358"));
    }

    [Fact]
    public void Returning_different_values_is_left_alone()
    {
        var code = """
            function check(a, b) {
              if (a > b) {
                return a;
              } else {
                return b;
              }
            }
            """;
        Assert.Empty(Lines("check.js", code, "QG-JS-SML-0358"));
    }

    [Fact]
    public void A_debugger_statement_is_reported()
        => Assert.NotEmpty(Lines("app.js", "function go() {\n  debugger;\n}\n", "QG-JS-BUG-0113"));

    [Fact]
    public void A_blocking_dialog_is_reported()
        => Assert.NotEmpty(Lines("app.js", "function go() {\n  alert('hi');\n}\n", "QG-JS-SML-0359"));

    [Fact]
    public void Loose_equality_is_reported_but_the_null_comparison_is_not()
    {
        var code = """
            function go(x, y) {
              if (x == 1) { return 1; }
              if (y == null) { return 2; }
              return 3;
            }
            """;
        Assert.Equal([2], Lines("app.js", code, "QG-JS-BUG-0114"));
    }

    [Fact]
    public void The_array_constructor_and_the_primitive_wrappers_are_reported()
    {
        var code = """
            function go() {
              const a = new Array(5);
              const n = new Number(3);
              const ok = new Map();
              return [a, n, ok];
            }
            """;
        Assert.Equal([2], Lines("app.js", code, "QG-JS-BUG-0115"));
        Assert.Equal([3], Lines("app.js", code, "QG-JS-BUG-0116"));
    }

    [Fact]
    public void A_duplicated_key_in_an_object_literal_is_reported()
        => Assert.NotEmpty(Lines("app.js", "const o = { a: 1, b: 2, a: 3 };\n", "QG-JS-BUG-0117"));

    [Fact]
    public void A_duplicated_parameter_is_reported()
        => Assert.NotEmpty(Lines("app.js", "function f(x, x) { return x; }\n", "QG-JS-BUG-0118"));

    [Fact]
    public void A_destructured_signature_is_not_read_as_a_duplicate()
    {
        var code = """
            export function run(
              context,
              { allowParameterized = false }: { allowParameterized?: boolean } = {},
            ) {
              return context;
            }
            """;
        Assert.Empty(Lines("run.ts", code, "QG-JS-BUG-0118"));
        Assert.Empty(Lines("run.ts", code, "QG-JS-SML-0360"));
    }

    [Fact]
    public void A_closure_capturing_a_var_loop_variable_is_reported()
    {
        var code = """
            function go(items) {
              for (var i = 0; i < 3; i++) {
                setTimeout(function () { use(i); }, 10);
              }
            }
            """;
        Assert.NotEmpty(Lines("app.js", code, "QG-JS-BUG-0119"));
    }

    [Fact]
    public void The_same_loop_with_let_is_left_alone()
    {
        var code = """
            function go(items) {
              for (let i = 0; i < 3; i++) {
                setTimeout(function () { use(i); }, 10);
              }
            }
            """;
        Assert.Empty(Lines("app.js", code, "QG-JS-BUG-0119"));
    }

    [Fact]
    public void An_unfiltered_for_in_is_reported_and_a_guarded_one_is_not()
    {
        var open = """
            function go(obj) {
              for (const k in obj) {
                use(k);
              }
            }
            """;
        Assert.NotEmpty(Lines("app.js", open, "QG-JS-BUG-0120"));

        var guarded = """
            function go(obj) {
              for (const k in obj) {
                if (!Object.prototype.hasOwnProperty.call(obj, k)) { continue; }
                use(k);
              }
            }
            """;
        Assert.Empty(Lines("app.js", guarded, "QG-JS-BUG-0120"));
    }

    [Fact]
    public void A_required_parameter_after_a_default_is_reported()
        => Assert.NotEmpty(Lines("app.js", "function f(a = 1, b) { return a + b; }\n", "QG-JS-SML-0360"));

    [Fact]
    public void An_optional_typescript_parameter_after_a_default_is_left_alone()
    {
        var code = """
            export function f(
              a: number = 1,
              b?: string,
            ) {
              return a;
            }
            """;
        Assert.Empty(Lines("f.ts", code, "QG-JS-SML-0360"));
    }

    [Fact]
    public void A_case_that_runs_into_the_next_is_reported()
    {
        var code = """
            function go(x) {
              switch (x) {
                case 1:
                  doOne();
                case 2:
                  return 2;
              }
              return 0;
            }
            """;
        Assert.NotEmpty(Lines("app.js", code, "QG-JS-BUG-0121"));
    }

    [Fact]
    public void Cases_that_end_with_a_jump_are_left_alone()
    {
        var code = """
            function go(x) {
              switch (x) {
                case 1: {
                  doOne();
                  break;
                }
                case 2:
                case 3:
                  return 2;
              }
              return 0;
            }
            """;
        Assert.Empty(Lines("app.js", code, "QG-JS-BUG-0121"));
    }
}
