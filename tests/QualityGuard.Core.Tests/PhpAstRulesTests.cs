using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// PHP on the tree. Three shapes of the PHP dialect are pinned here because they cost time to find:
/// the parser keeps the dollar inside a name, a variable variable arrives as one token, and a call
/// does not always carry an identifier child.
/// </summary>
public class PhpAstRulesTests
{
    private static IReadOnlyList<int> Lines(string body, string rule, string file = "Sample.php")
        => Analyze.LinesOf(Analyze.WithRules(file, "<?php\n" + body, rule), rule);

    [Fact]
    public void A_variable_variable_is_reported()
    {
        Assert.NotEmpty(Lines("function go($key) {\n  return $$key;\n}\n", "QG-PP-BUG-0039"));
        Assert.Empty(Lines("function go($key) {\n  return $key;\n}\n", "QG-PP-BUG-0039"));
    }

    [Fact]
    public void A_variable_removed_from_the_language_is_reported()
        => Assert.NotEmpty(Lines("function go() {\n  return $HTTP_GET_VARS;\n}\n", "QG-PP-BUG-0040"));

    [Fact]
    public void A_php4_constructor_is_reported()
    {
        Assert.NotEmpty(Lines("class Order {\n  function Order($n) {\n    $this->n = $n;\n  }\n}\n",
            "QG-PP-BUG-0041"));
        Assert.Empty(Lines("class Order {\n  function __construct($n) {\n    $this->n = $n;\n  }\n}\n",
            "QG-PP-BUG-0041"));
    }

    [Fact]
    public void This_in_a_static_method_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  public static function build() {\n    return $this->n;\n  }\n}\n",
            "QG-PP-BUG-0042"));
        Assert.Empty(Lines("class A {\n  public function build() {\n    return $this->n;\n  }\n}\n",
            "QG-PP-BUG-0042"));
    }

    [Fact]
    public void A_catch_hidden_by_a_wider_one_is_reported()
    {
        var shadowed = """
            function go() {
              try {
                work();
              } catch (Exception $e) {
                report($e);
              } catch (RuntimeException $e) {
                report($e);
              }
            }
            """;
        Assert.NotEmpty(Lines(shadowed, "QG-PP-BUG-0043"));

        var ordered = """
            function go() {
              try {
                work();
              } catch (RuntimeException $e) {
                report($e);
              } catch (Exception $e) {
                report($e);
              }
            }
            """;
        Assert.Empty(Lines(ordered, "QG-PP-BUG-0043"));
    }

    [Fact]
    public void A_constant_condition_is_reported()
        => Assert.NotEmpty(Lines("function go() {\n  if (1) {\n    echo \"x\";\n  }\n}\n",
            "QG-PP-BUG-0044"));

    [Fact]
    public void A_variable_passed_twice_is_reported_but_two_literals_are_not()
    {
        Assert.NotEmpty(Lines("function go($a) {\n  merge($a, $a);\n}\n", "QG-PP-BUG-0045"));
        Assert.Empty(Lines("function go() {\n  merge(1, 1);\n}\n", "QG-PP-BUG-0045"));
    }

    [Fact]
    public void An_assignment_in_a_condition_is_reported()
        => Assert.NotEmpty(Lines("function go($items) {\n  if ($n = count($items)) {\n    echo $n;\n  }\n}\n",
            "QG-PP-BUG-0046"));

    [Fact]
    public void Throwing_a_string_is_reported()
    {
        Assert.NotEmpty(Lines("function go() {\n  throw \"broken\";\n}\n", "QG-PP-BUG-0047"));
        Assert.Empty(Lines("function go() {\n  throw new RuntimeException(\"broken\");\n}\n",
            "QG-PP-BUG-0047"));
    }

    [Fact]
    public void A_foreach_reference_that_is_never_released_is_reported()
    {
        var leaking = """
            function go($items) {
              foreach ($items as &$item) {
                $item = 1;
              }
              return $items;
            }
            """;
        Assert.NotEmpty(Lines(leaking, "QG-PP-BUG-0048"));

        var released = """
            function go($items) {
              foreach ($items as &$item) {
                $item = 1;
              }
              unset($item);
              return $items;
            }
            """;
        Assert.Empty(Lines(released, "QG-PP-BUG-0048"));
    }

    [Fact]
    public void A_constant_defined_twice_is_reported_but_a_method_named_define_is_not()
    {
        Assert.NotEmpty(Lines("define(\"LIMIT\", 3);\ndefine(\"LIMIT\", 4);\n", "QG-PP-BUG-0049"));
        Assert.Empty(Lines("$o->define(\"Foo\", true);\ndefine(\"Foo\", false);\n", "QG-PP-BUG-0049"));
    }

    [Fact]
    public void A_silenced_error_is_reported()
        => Assert.NotEmpty(Lines("function go($p) {\n  return @file_get_contents($p);\n}\n",
            "QG-PP-SEC-0066"));

    [Fact]
    public void The_var_keyword_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  var $name;\n}\n", "QG-PP-SML-0111"));

    [Fact]
    public void Several_properties_in_one_statement_are_reported()
        => Assert.NotEmpty(Lines("class A {\n  private $a, $b;\n}\n", "QG-PP-SML-0112"));

    [Fact]
    public void A_method_without_visibility_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  function go() {\n    return 1;\n  }\n}\n", "QG-PP-SML-0113"));
        Assert.Empty(Lines("class A {\n  public function go() {\n    return 1;\n  }\n}\n",
            "QG-PP-SML-0113"));
    }

    [Fact]
    public void A_required_parameter_after_a_default_is_reported()
        => Assert.NotEmpty(Lines("function go($a = 1, $b) {\n  return $a + $b;\n}\n", "QG-PP-SML-0114"));

    [Fact]
    public void An_exit_inside_a_function_is_reported()
    {
        Assert.NotEmpty(Lines("function go() {\n  exit(1);\n}\n", "QG-PP-SML-0115"));
        // a script that is meant to be run rather than included may legitimately stop
        Assert.Empty(Lines("exit(1);\n", "QG-PP-SML-0115"));
    }

    [Fact]
    public void An_alias_function_is_reported()
    {
        Assert.NotEmpty(Lines("function go($d) {\n  return sizeof($d);\n}\n", "QG-PP-SML-0116"));
        Assert.Empty(Lines("function go($d) {\n  return count($d);\n}\n", "QG-PP-SML-0116"));
    }
}
