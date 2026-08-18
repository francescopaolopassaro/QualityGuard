using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The Java rules chosen by measuring against an annotated reference corpus. Each is pinned with the
/// defect it must find and the shape it must leave alone.
/// </summary>
public class JavaMeasuredRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "Sample.java")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void An_invisible_character_in_a_literal_is_reported()
    {
        // a zero-width space sits between the two words
        var hidden = """
            package demo;

            class A {
              String s = "one​two";
            }
            """;
        Assert.NotEmpty(Lines(hidden, "QG-JV-BUG-0198"));

        var plain = """
            package demo;

            class A {
              String s = "one two";
            }
            """;
        Assert.Empty(Lines(plain, "QG-JV-BUG-0198"));
    }

    [Fact]
    public void A_charset_named_by_string_is_reported()
    {
        var named = """
            package demo;

            class A {
              void f() {
                Charset c = Charset.forName("UTF-8");
              }
            }
            """;
        Assert.NotEmpty(Lines(named, "QG-JV-SML-0452"));

        var computed = """
            package demo;

            class A {
              void f(String name) {
                Charset c = Charset.forName(name);
              }
            }
            """;
        Assert.Empty(Lines(computed, "QG-JV-SML-0452"));
    }

    [Fact]
    public void A_conversion_without_a_charset_is_reported()
    {
        var silent = """
            package demo;

            class A {
              void f(byte[] data, String t) {
                String s = new String(data);
                byte[] b = t.getBytes();
              }
            }
            """;
        Assert.NotEmpty(Lines(silent, "QG-JV-BUG-0199"));

        var stated = """
            package demo;

            class A {
              void f(String t) {
                byte[] b = t.getBytes(StandardCharsets.UTF_8);
              }
            }
            """;
        Assert.Empty(Lines(stated, "QG-JV-BUG-0199"));
    }

    [Fact]
    public void A_mathematical_call_with_a_fixed_answer_is_reported()
    {
        var constant = """
            package demo;

            class A {
              int f(int x) {
                int a = Math.abs(-5);
                return Math.max(x, x);
              }
            }
            """;
        Assert.NotEmpty(Lines(constant, "QG-JV-BUG-0200"));

        var real = """
            package demo;

            class A {
              int f(int x, int y) {
                return Math.max(x, y);
              }
            }
            """;
        Assert.Empty(Lines(real, "QG-JV-BUG-0200"));
    }

    [Fact]
    public void A_short_key_is_reported()
    {
        var weak = """
            package demo;

            class A {
              void f(KeyPairGenerator g) {
                g.initialize(1024);
              }
            }
            """;
        Assert.NotEmpty(Lines(weak, "QG-JV-SEC-0069"));

        var strong = """
            package demo;

            class A {
              void f(KeyPairGenerator g) {
                g.initialize(2048);
              }
            }
            """;
        Assert.Empty(Lines(strong, "QG-JV-SEC-0069"));
    }

    [Fact]
    public void A_compound_assignment_to_a_volatile_field_is_reported()
    {
        var shared = """
            package demo;

            class A {
              private volatile int counter;

              void bump() {
                counter++;
              }
            }
            """;
        Assert.NotEmpty(Lines(shared, "QG-JV-BUG-0201"));

        var plain = """
            package demo;

            class A {
              private int counter;

              void bump() {
                counter++;
              }
            }
            """;
        Assert.Empty(Lines(plain, "QG-JV-BUG-0201"));
    }

    [Fact]
    public void A_log_message_built_by_concatenation_is_reported()
    {
        var eager = """
            package demo;

            class A {
              void f(String t) {
                logger.debug("value " + t + " now");
              }
            }
            """;
        Assert.NotEmpty(Lines(eager, "QG-JV-SML-0453"));

        var lazy = """
            package demo;

            class A {
              void f(String t) {
                logger.debug("value {} now", t);
              }
            }
            """;
        Assert.Empty(Lines(lazy, "QG-JV-SML-0453"));
    }

    [Fact]
    public void A_loop_copying_one_array_into_another_is_reported()
    {
        var code = """
            package demo;

            class A {
              void f(int[] src, int[] dst) {
                for (int i = 0; i < src.length; i++) {
                  dst[i] = src[i];
                }
              }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-JV-SML-0454"));
    }

    [Fact]
    public void Reading_the_clock_through_a_number_is_reported()
    {
        var code = """
            package demo;

            class A {
              void f() {
                Instant t = Instant.ofEpochMilli(System.currentTimeMillis());
              }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-JV-SML-0455"));
    }

    [Fact]
    public void An_absolute_executable_path_is_reported()
    {
        var absolute = """
            package demo;

            class A {
              void f(Runtime r) throws Exception {
                r.exec("/usr/bin/ls");
              }
            }
            """;
        Assert.NotEmpty(Lines(absolute, "QG-JV-SML-0456"));

        var onPath = """
            package demo;

            class A {
              void f(Runtime r) throws Exception {
                r.exec("ls");
              }
            }
            """;
        Assert.Empty(Lines(onPath, "QG-JV-SML-0456"));
    }

    [Fact]
    public void A_regex_written_on_a_string_receiver_is_analysed()
    {
        // Java writes most of its patterns on a String, not on a Pattern
        var duplicated = """
            package demo;

            class A {
              boolean f(String s) {
                return s.matches("[aa]");
              }
            }
            """;
        Assert.NotEmpty(Lines(duplicated, "QG-JV-BUG-0228"));

        var distinct = """
            package demo;

            class A {
              boolean f(String s) {
                return s.matches("[ab]");
              }
            }
            """;
        Assert.Empty(Lines(distinct, "QG-JV-BUG-0228"));
    }

    [Fact]
    public void A_range_that_already_covers_a_character_is_reported()
    {
        var overlapping = """
            package demo;

            class A {
              boolean f(String s) {
                return s.matches("[0-99]");
              }
            }
            """;
        Assert.NotEmpty(Lines(overlapping, "QG-JV-BUG-0228"));

        var disjoint = """
            package demo;

            class A {
              boolean f(String s) {
                return s.matches("[0-9a]");
              }
            }
            """;
        Assert.Empty(Lines(disjoint, "QG-JV-BUG-0228"));
    }
    [Fact]
    public void A_format_string_missing_a_value_is_reported()
    {
        var short_ = """
            package demo;

            class A {
              String f(int count, String basket) {
                return String.format("%d items in %s", count);
              }
            }
            """;
        Assert.NotEmpty(Lines(short_, "QG-JV-BUG-0202"));

        var matched = """
            package demo;

            class A {
              String f(int count, String basket) {
                return String.format("%d items in %s", count, basket);
              }
            }
            """;
        Assert.Empty(Lines(matched, "QG-JV-BUG-0202"));
    }

    [Fact]
    public void An_argument_that_is_never_printed_is_reported()
    {
        var extra = """
            package demo;

            class A {
              String f() {
                return String.format("%d and %d", 1, 2, 3);
              }
            }
            """;
        Assert.NotEmpty(Lines(extra, "QG-JV-BUG-0202"));
    }

    [Fact]
    public void An_array_of_values_is_not_counted()
    {
        // the array holds as many values as it holds, and the engine cannot count them from here
        var code = """
            package demo;

            class A {
              String f(Object[] values) {
                return String.format("%d %d", values);
              }
            }
            """;
        Assert.Empty(Lines(code, "QG-JV-BUG-0202"));
    }

    [Fact]
    public void A_positional_format_is_left_to_itself()
    {
        var code = """
            package demo;

            class A {
              String f() {
                return String.format("%1$s and %1$s", "a");
              }
            }
            """;
        Assert.Empty(Lines(code, "QG-JV-BUG-0202"));
    }

    [Fact]
    public void An_invalid_calendar_value_is_reported()
    {
        var wrong = """
            package demo;

            class A {
              Object f() {
                return new Date(2020, 13, 5);
              }
            }
            """;
        Assert.NotEmpty(Lines(wrong, "QG-JV-BUG-0038"));

        var right = """
            package demo;

            class A {
              Object f() {
                return new Date(2020, 11, 5);
              }
            }
            """;
        Assert.Empty(Lines(right, "QG-JV-BUG-0038"));
    }

}
