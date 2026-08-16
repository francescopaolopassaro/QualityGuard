using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Java contract rules. The negative cases are the shapes that survived the real corpus: a next that
/// does throw, a wait already inside its loop, an override that answers with a constant on purpose.
/// </summary>
public class JavaContractRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "Sample.java")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void An_iterator_next_without_the_expected_exception_is_reported()
    {
        var open = """
            class A {
              public boolean hasNext() { return true; }
              public String next() {
                return "x";
              }
            }
            """;
        Assert.NotEmpty(Lines(open, "QG-JV-BUG-0188"));

        var guarded = """
            class A {
              public boolean hasNext() { return true; }
              public String next() {
                if (!hasNext()) {
                  throw new NoSuchElementException();
                }
                return "x";
              }
            }
            """;
        Assert.Empty(Lines(guarded, "QG-JV-BUG-0188"));
    }

    [Fact]
    public void A_wait_outside_a_loop_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  void f() throws Exception {\n    wait();\n  }\n}\n",
            "QG-JV-BUG-0189"));
        Assert.Empty(Lines("class A {\n  void f() throws Exception {\n    while (!ready) {\n"
                           + "      wait();\n    }\n  }\n}\n", "QG-JV-BUG-0189"));
    }

    [Fact]
    public void Returning_null_from_a_Boolean_method_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  Boolean f(int a) {\n    if (a == 0) {\n      return null;\n"
                              + "    }\n    return true;\n  }\n}\n", "QG-JV-BUG-0190"));
        Assert.Empty(Lines("class A {\n  boolean f(int a) {\n    return a > 0;\n  }\n}\n",
            "QG-JV-BUG-0190"));
    }

    [Fact]
    public void An_index_tested_for_positive_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  boolean f(String t) {\n    return t.indexOf(\"a\") > 0;\n  }\n}\n",
            "QG-JV-BUG-0191"));

    [Fact]
    public void Starting_a_thread_in_a_constructor_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  Thread worker;\n  A() {\n    worker = new Thread();\n"
                                 + "    worker.start();\n  }\n}\n", "QG-JV-BUG-0192"));

    [Fact]
    public void An_iterator_returning_this_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  public Iterator<String> iterator() {\n    return this;\n  }\n}\n",
            "QG-JV-BUG-0193"));

    [Fact]
    public void A_jdbc_index_of_zero_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  void f(PreparedStatement ps, String t) throws Exception {\n"
                              + "    ps.setString(0, t);\n  }\n}\n", "QG-JV-BUG-0194"));
        Assert.Empty(Lines("class A {\n  void f(PreparedStatement ps, String t) throws Exception {\n"
                           + "    ps.setString(1, t);\n  }\n}\n", "QG-JV-BUG-0194"));
    }

    [Fact]
    public void A_bit_operation_that_changes_nothing_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  int f(int a) {\n    return a | 0;\n  }\n}\n", "QG-JV-BUG-0195"));
        Assert.Empty(Lines("class A {\n  int f(int a) {\n    return a | 4;\n  }\n}\n", "QG-JV-BUG-0195"));
    }

    [Fact]
    public void A_week_year_pattern_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  String p = \"YYYY-MM-dd\";\n}\n", "QG-JV-BUG-0196"));
        Assert.Empty(Lines("class A {\n  String p = \"yyyy-MM-dd\";\n}\n", "QG-JV-BUG-0196"));
    }

    [Fact]
    public void An_overloaded_compareTo_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  public int compareTo(A o) { return 0; }\n"
                                 + "  public int compareTo(Object o) { return 0; }\n}\n", "QG-JV-BUG-0197"));

    [Fact]
    public void A_class_of_static_members_is_reported()
    {
        Assert.NotEmpty(Lines("class Helpers {\n  public static int twice(int a) {\n    return a * 2;\n  }\n}\n",
            "QG-JV-SML-0444"));
        Assert.Empty(Lines("class Helpers {\n  private Helpers() { }\n"
                           + "  public static int twice(int a) { return a * 2; }\n}\n", "QG-JV-SML-0444"));
    }

    [Fact]
    public void A_field_set_to_its_default_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  private int count = 0;\n}\n", "QG-JV-SML-0445"));
        Assert.NotEmpty(Lines("class A {\n  private String name = null;\n}\n", "QG-JV-SML-0445"));
        Assert.Empty(Lines("class A {\n  private int count = 1;\n}\n", "QG-JV-SML-0445"));
        Assert.Empty(Lines("class A {\n  private final int count = 0;\n}\n", "QG-JV-SML-0445"));
    }

    [Fact]
    public void An_implied_modifier_on_an_interface_member_is_reported()
    {
        Assert.NotEmpty(Lines("interface A {\n  public abstract void go();\n}\n", "QG-JV-SML-0446"));
        Assert.Empty(Lines("class A {\n  public void go() { }\n}\n", "QG-JV-SML-0446"));
    }

    [Fact]
    public void Double_brace_initialization_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  void f() {\n"
                                 + "    List<String> l = new ArrayList<String>() {{\n      add(\"a\");\n    }};\n  }\n}\n",
            "QG-JV-SML-0447"));

    [Fact]
    public void An_override_of_clone_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  public Object clone() {\n    return null;\n  }\n}\n",
            "QG-JV-SML-0448"));

    [Fact]
    public void A_static_nested_enum_is_reported()
        => Assert.NotEmpty(Lines("class A {\n  static enum Kind { X, Y }\n}\n", "QG-JV-SML-0449"));

    [Fact]
    public void A_method_returning_a_constant_is_reported_unless_it_overrides()
    {
        Assert.NotEmpty(Lines("class A {\n  int limit() {\n    return 42;\n  }\n}\n", "QG-JV-SML-0450"));
        Assert.Empty(Lines("class A {\n  @Override\n  int limit() {\n    return 42;\n  }\n}\n",
            "QG-JV-SML-0450"));
    }

    [Fact]
    public void An_instance_method_writing_a_static_field_is_reported()
    {
        Assert.NotEmpty(Lines("class A {\n  static int shared;\n  void bump() {\n    shared = 1;\n  }\n}\n",
            "QG-JV-SML-0451"));
        Assert.Empty(Lines("class A {\n  static final int SHARED = 1;\n  void bump() { }\n}\n",
            "QG-JV-SML-0451"));
    }

    [Fact]
    public void A_stray_semicolon_is_reported_but_a_for_header_is_not()
    {
        Assert.NotEmpty(Lines("class A {\n  void f() {\n    go();;\n  }\n}\n", "QG-JV-CNV-0002"));
        Assert.Empty(Lines("class A {\n  void f() {\n    for (;;) {\n      go();\n    }\n  }\n}\n",
            "QG-JV-CNV-0002"));
    }
}
