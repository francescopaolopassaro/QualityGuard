using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Java on the tree. The negative cases are the ones that were actually found on a real corpus while
/// building these rules: a case that lists its constants over several lines, a static two-argument
/// helper called equalsTo, a catch that does use the exception it caught.
/// </summary>
public class JavaAstRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "Sample.java")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void An_override_of_finalize_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  protected void finalize() {\n    close();\n  }\n}\n",
            "QG-JV-BUG-0179"));

    [Fact]
    public void Comparing_two_upper_cased_strings_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  boolean f(String a, String b) {\n"
                              + "    return a.toUpperCase().equals(b.toUpperCase());\n  }\n}\n",
            "QG-JV-BUG-0180"));
        Assert.Empty(Lines("class A {\n  boolean f(String a, String b) {\n"
                           + "    return a.equalsIgnoreCase(b);\n  }\n}\n", "QG-JV-BUG-0180"));
    }

    [Fact]
    public void A_class_extending_error_is_reported()
    {
        Assert.NotEmpty(Lines("class Broken extends Error {\n  int a;\n}\n", "QG-JV-BUG-0181"));
        Assert.Empty(Lines("class Broken extends RuntimeException {\n  int a;\n}\n", "QG-JV-BUG-0181"));
    }

    [Fact]
    public void A_label_after_a_finished_case_is_reported()
    {
        var code = """
            class A {
              void f(int x) {
                switch (x) {
                  case 1:
                    go();
                    break;
                  defualt:
                    stop();
                }
              }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-JV-BUG-0182"));
    }

    [Fact]
    public void A_case_listing_its_constants_over_several_lines_is_left_alone()
    {
        var code = """
            class A {
              void f(Kind x) {
                switch (x) {
                  case PLUS,
                       MINUS,
                       TIMES:
                    go();
                    break;
                  default:
                    stop();
                }
              }
            }
            """;
        Assert.Empty(Lines(code, "QG-JV-BUG-0182"));
    }

    [Fact]
    public void A_near_miss_of_an_object_method_is_reported_but_a_helper_is_not()
    {
        Assert.NotEmpty(Lines("class A {\n  public String tostring() {\n    return \"a\";\n  }\n}\n",
            "QG-JV-BUG-0183"));
        // a static two-argument helper is not a failed override, whatever it is called
        Assert.Empty(Lines("class A {\n  static boolean equalsTo(Node a, Node b) {\n"
                           + "    return a == b;\n  }\n}\n", "QG-JV-BUG-0183"));
    }

    [Fact]
    public void A_method_named_after_its_class_is_reported()
        => Assert.NotEmpty(Lines("class Sample {\n  public String Sample() {\n    return \"a\";\n  }\n}\n",
            "QG-JV-BUG-0184"));

    [Fact]
    public void A_public_static_field_that_is_not_final_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  public static int counter = 0;\n}\n", "QG-JV-BUG-0185"));
        Assert.Empty(Lines("class A {\n  public static final int LIMIT = 10;\n}\n", "QG-JV-BUG-0185"));
    }

    [Fact]
    public void A_hasNext_that_advances_the_iterator_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  public boolean hasNext() {\n"
                                 + "    return next() != null;\n  }\n  Object next() { return null; }\n}\n",
            "QG-JV-BUG-0186"));

    [Fact]
    public void A_big_decimal_built_from_a_double_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  Object f() {\n    return new BigDecimal(0.1);\n  }\n}\n",
            "QG-JV-BUG-0187"));
        Assert.Empty(Lines("class A {\n  Object f() {\n    return new BigDecimal(\"0.1\");\n  }\n}\n",
            "QG-JV-BUG-0187"));
    }

    [Fact]
    public void A_redundant_string_conversion_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  String f(int n) {\n"
                                 + "    return \"n=\" + String.valueOf(n);\n  }\n}\n", "QG-JV-SML-0435"));

    [Fact]
    public void A_wrapper_allocated_for_a_conversion_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  String f() {\n"
                                 + "    return new Integer(3).toString();\n  }\n}\n", "QG-JV-SML-0436"));

    [Fact]
    public void A_rethrow_that_drops_the_cause_is_reported_but_a_wrapped_one_is_not()
    {
        var dropped = """
            class A {
              void f() {
                try {
                  work();
                } catch (Exception e) {
                  throw new IllegalStateException("failed");
                }
              }
            }
            """;
        Assert.NotEmpty(Lines(dropped, "QG-JV-SML-0437"));

        var wrapped = """
            class A {
              void f() {
                try {
                  work();
                } catch (Exception e) {
                  throw new IllegalStateException("failed", e);
                }
              }
            }
            """;
        Assert.Empty(Lines(wrapped, "QG-JV-SML-0437"));
    }

    [Fact]
    public void An_internal_package_import_is_reported()
    {
        Assert.NotEmpty(Lines("import sun.misc.Unsafe;\nclass A { int a; }\n", "QG-JV-SML-0438"));
        Assert.Empty(Lines("import java.util.List;\nclass A { int a; }\n", "QG-JV-SML-0438"));
    }

    [Fact]
    public void Sorting_exceptions_inside_a_catch_is_reported()
    {
        var code = """
            class A {
              void f() {
                try {
                  work();
                } catch (Exception e) {
                  if (e instanceof RuntimeException) {
                    report(e);
                  }
                }
              }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-JV-SML-0439"));
    }

    [Fact]
    public void toString_on_a_string_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  String f() {\n    return \"abc\".toString();\n  }\n}\n",
            "QG-JV-SML-0440"));

    [Fact]
    public void A_negated_comparison_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  boolean f(int a) {\n    return !(a == 3);\n  }\n}\n",
            "QG-JV-SML-0441"));
        Assert.Empty(Lines("class A {\n  boolean f(boolean a) {\n    return !a;\n  }\n}\n",
            "QG-JV-SML-0441"));
    }

    [Fact]
    public void A_main_that_declares_throws_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  public static void main(String[] a) throws Exception {\n"
                                 + "    work();\n  }\n}\n", "QG-JV-SML-0442"));

    [Fact]
    public void A_lambda_wrapping_one_expression_in_a_block_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  void f() {\n    Runnable r = () -> { go(); };\n  }\n}\n",
            "QG-JV-SML-0443"));
        Assert.Empty(Lines("class A {\n  void f() {\n    Runnable r = () -> go();\n  }\n}\n",
            "QG-JV-SML-0443"));
    }
}
