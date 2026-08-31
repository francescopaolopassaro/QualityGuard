using QualityGuard.Core.Analysis;
using Xunit;
using Xunit.Abstractions;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The Java rules chosen by measuring against an annotated reference corpus. Each is pinned with the
/// defect it must find and the shape it must leave alone.
/// </summary>
public class JavaMeasuredRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "Sample.java")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    private readonly ITestOutputHelper _output;
    public JavaMeasuredRulesTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void OsCommandPath_Detects_ProcessBuilder_And_Command()
    {
        var code = """
            package demo;
            class A {
              void f() {
                ProcessBuilder pb = new ProcessBuilder();
                pb.command("make");
                Runtime.getRuntime().exec("make");
              }
            }
            """;
        var lines = Lines(code, "QG-JV-SEC-0092");
        Assert.NotEmpty(lines);
    }

    [Fact]
    public void OsCommandPath_Still_Detects_Command_After_String_Array_Patterns()
    {
        var code = """
            package demo;
            class A {
              void execArray() {
                Runtime.getRuntime().exec(new String[]{"make"});
                Runtime.getRuntime().exec(new String[]{"usr/bin/make"});
              }
              private void command() {
                ProcessBuilder builder = new ProcessBuilder();
                builder.command("make");
                Runtime.getRuntime().exec("make");
              }
            }
            """;
        var lines = Lines(code, "QG-JV-SEC-0092");
        _output.WriteLine("LINES: " + string.Join(",", lines));
        Assert.NotEmpty(lines);
    }

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
    public void ConstantMath_whole_number_forms_are_reported()
    {
        var code = """
            package demo;

            class A {
              double f(int a, double y) {
                double v1 = Math.abs((float) 0);          // int cast via float target
                double v2 = Math.ceil((double) 0L);       // long literal
                double v3 = Math.floor((float) 0);        // int literal with float cast
                double v4 = Math.round((float) 0);
                double v5 = Math.rint((double) -3);       // negative whole
                double v6 = Math.ceil((double) ' ');      // char literal
                double v7 = Math.abs((double) 'a');       // char via cast
                double v8 = Math.acos((0.0));             // pair of parentheses
                double v9 = Math.cos(0.0d);
                double v10 = Math.atan2(0.0D, y);         // atan2 with 0.0 first arg
                return v1 + v2 + v3 + v4 + v5 + v6 + v7 + v8 + v9 + v10;
              }
            }
            """;
        var expected = new[] { 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
        Assert.Equal(expected, Lines(code, "QG-JV-BUG-0200"));
    }

    [Fact]
    public void ConstantMath_does_not_report_variables_floats_or_strings()
    {
        var code = """
            package demo;

            class A {
              double f(int a, double value) {
                double v1 = Math.abs(a);                       // variable, type unknown
                double v2 = Math.ceil((double) 0.0f);          // float literal has a fraction
                double v3 = Math.ceil((double) 0.0d);
                double v4 = Math.abs((double) "a");            // string, not a character
                double v5 = Math.acos(value);                  // variable
                double v6 = Math.cos(2.0);                     // not the constant 0.0/1.0
                double v7 = Math.exp(a);                       // variable
                double v8 = Math.max(a, a + 1);                // different operands
                return v1 + v2 + v3 + v4 + v5 + v6 + v7 + v8;
              }
            }
            """;
        Assert.Empty(Lines(code, "QG-JV-BUG-0200"));
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

    [Fact]
    public void Incompatible_transactional_propagation_is_reported()
    {
        var bad = """
            package demo;
            import org.springframework.transaction.annotation.Transactional;
            class A {
              SpringIncompatibleTransactionalCheckSample other;
              @Transactional
              public void transactional() {
              }
              public void plain() {
                this.transactional(); // call to REQUIRED from NOT_TRANSACTIONAL
              }
            }
            """;
        Assert.Contains(9, Lines(bad, "QG-JV-BUG-0329"));
    }

    [Fact]
    public void Matching_or_foreign_transactional_calls_are_left_alone()
    {
        var code = """
            package demo;
            import org.springframework.transaction.annotation.Transactional;
            class A {
              A other;
              @Transactional
              public void transactional() {
                transactional(); // same REQUIRED -> fine
              }
              public void plain() {
                other.transactional(); // not on this instance
                String s = String.valueOf(1); // not a class method
              }
              @Transactional(propagation = Propagation.REQUIRED)
              public void required() {
                transactional(); // REQUIRED -> REQUIRED fine
              }
            }
            """;
        Assert.Empty(Lines(code, "QG-JV-BUG-0329"));
    }

    [Fact]
    public void Incompatible_propagation_is_reported_on_the_call()
    {
        var code = """
            package demo;
            import org.springframework.transaction.annotation.Propagation;
            import org.springframework.transaction.annotation.Transactional;
            class A {
              @Transactional(propagation = Propagation.NOT_SUPPORTED)
              public String methodA() {
                return "";
              }
              @Transactional(propagation = Propagation.REQUIRES_NEW)
              public int methodB() {
                methodA().length(); // REQUIRES_NEW calls NOT_SUPPORTED
                return 1;
              }
            }
            """;
        Assert.Contains(11, Lines(code, "QG-JV-BUG-0329"));
    }

    [Fact]
    public void A_class_level_propagation_inherits_into_plain_methods()
    {
        var code = """
            package demo;
            import org.springframework.transaction.annotation.Propagation;
            import org.springframework.transaction.annotation.Transactional;
            @Transactional(propagation = Propagation.NOT_SUPPORTED)
            class A {
              public void plain() {
                transactional();
              }
              @Transactional
              public void transactional() {
              }
            }
            """;
        Assert.Contains(7, Lines(code, "QG-JV-BUG-0329"));
    }

    [Fact]
    public void AssertJ_Contains_StartsWith_EndsWith_Simplifications()
    {
        var code = """
            package demo;
            class A {
              void f(String s) {
                assertThat(s.contains("x")).isTrue();
                assertThat(s.contains("x")).isFalse();
                assertThat(s.startsWith("x")).isTrue();
                assertThat(s.startsWith("x")).isFalse();
                assertThat(s.endsWith("x")).isTrue();
                assertThat(s.endsWith("x")).isFalse();
              }
            }
            """;
        var lines = Lines(code, "QG-JV-SML-0566");
        Assert.Equal(6, lines.Count);
    }

    [Fact]
    public void AssertJ_Index_And_ToString_Simplifications()
    {
        var code = """
            package demo;
            class A {
              void f(String s, int n) {
                assertThat(s.indexOf("x")).isEqualTo(0);
                assertThat(s.indexOf("x")).isNotEqualTo(0);
                assertThat(s.indexOf("x")).isEqualTo(-1);
                assertThat(s.indexOf("x")).isZero();
                assertThat(s.indexOf("x")).isNotZero();
                assertThat(s.toString()).isEqualTo(n);
                assertThat(s.compareTo("x")).isEqualTo(0);
                assertThat(s.compareTo("x")).isZero();
              }
            }
            """;
        var lines = Lines(code, "QG-JV-SML-0566");
        Assert.Equal(8, lines.Count);
    }

    [Fact]
    public void AssertJ_Leaves_Positive_Assertions_Alone()
    {
        var code = """
            package demo;
            class A {
              void f(String s) {
                assertThat(s).contains("x");
                assertThat(s).startsWith("x");
                assertThat(s).endsWith("x");
                assertThat(s).isEqualTo("x");
                assertThat(s).isNotNull();
              }
            }
            """;
        var lines = Lines(code, "QG-JV-SML-0566");
        Assert.Empty(lines);
    }

    [Theory]
    [InlineData("t.getBytes(\"UTF-8\");")]
    [InlineData("new String(bytes, \"UTF-8\");")]
    [InlineData("new String(bytes, 0, 4, \"UTF-8\");")]
    [InlineData("new InputStreamReader(in, \"UTF-8\");")]
    [InlineData("new OutputStreamWriter(out, \"UTF-8\");")]
    public void StandardCharsets_Literal_Chosen_By_Name_Is_Reported(string statement)
    {
        const string template = """
            package demo;
            class A {
              void f(byte[] bytes, String t, java.io.InputStream in, java.io.OutputStream out) {
                //STATEMENT
              }
            }
            """;
        var code = template.Replace("//STATEMENT", statement);
        Assert.NotEmpty(Lines(code, "QG-JV-SML-0737"));
    }

    [Fact]
    public void StandardCharsets_Constant_Forms_Are_Reported()
    {
        var code = """
            package demo;
            class A {
              void f(byte[] bytes, int offset, int length, java.io.InputStream in, java.io.OutputStream out) {
                new String(bytes, org.apache.commons.lang.CharEncoding.UTF_8);
                new String(bytes, offset, length, org.apache.commons.lang.CharEncoding.UTF_8);
                com.google.common.base.Charsets.UTF_8;
                org.apache.commons.codec.Charsets.toCharset("UTF-8");
              }
            }
            """;
        var lines = Lines(code, "QG-JV-SML-0737");
        Assert.Equal(4, lines.Count);
    }

    [Fact]
    public void StandardCharsets_Leaves_The_Standard_And_Data_Alone()
    {
        var code = """
            package demo;
            class A {
              void f(byte[] bytes, String t, String name) throws Exception {
                t.getBytes();
                new String(bytes);
                new String(bytes, StandardCharsets.UTF_8);
                new String(bytes, offset, length, StandardCharsets.UTF_8);
                Charset.forName("UTF-8");
                t.getBytes(StandardCharsets.UTF_8);
                Charsets.toCharset("UTF-8");
                new Object(data, "UTF-8");
              }
            }
            """;
        var lines = Lines(code, "QG-JV-SML-0737");
        Assert.Empty(lines);
    }

    [Fact]
    public void HardcodedMathConstant_Reports_Approximations_Of_Pi_And_E()
    {
        var code = """
            package demo;
            class A {
              double pi1 = 3.14;
              double pi2 = 3.14159;
              double e1 = 2.718;
              double e2 = 2.71828f;
              double sqrt2 = 1.41421;
              double ln2 = 0.693147;
              double leadingDot = .693;
            }
            """;
        var lines = Lines(code, "QG-JV-SML-0734");
        Assert.Equal(new[] { 3, 4, 5, 6, 7, 8, 9 }, lines);
    }

    [Fact]
    public void HardcodedMathConstant_Leaves_Standards_And_Unrelated_Values_Alone()
    {
        var code = """
            package demo;
            class A {
              double pi = Math.PI;
              double e = Math.E;
              double sqrt2 = Math.sqrt(2);
              double ln2 = Math.log(2);
              double unrelated = 3.0;
              double small = 0.001;
              double tooImprecise = 3.1;
              double outsideTolerance = 3.16;
              double sci = 3.14e0;
              double hex = 0x1.0p0;
            }
            """;
        var lines = Lines(code, "QG-JV-SML-0734");
        Assert.Empty(lines);
    }

    [Fact]
    public void HardcodedMathConstant_Reports_Negative_And_Underscored_Forms()
    {
        var code = """
            package demo;
            class A {
              double negativePi = -3.14159;
              long area(double r) { return 3.14159; }
              double und = 3.14_159;
              double dsuffix = 3.14159d;
            }
            """;
        var lines = Lines(code, "QG-JV-SML-0734");
        Assert.All(lines, l => Assert.Contains(l, new[] { 3, 4, 5, 6 }));
    }

    [Fact]
    public void BooleanOperatorLiteral_Reports_And_Or_And_Negation()
    {
        var code = """
            package demo;
            class A {
              boolean f(boolean var, boolean exp) {
                boolean b;
                b = var || true;
                b = false && exp;
                b = true || false;
                b = !true;
                b = !false;
                return b;
              }
            }
            """;
        var lines = Lines(code, "QG-JV-SML-0738");
        Assert.Equal(new[] { 5, 6, 7, 8, 9 }, lines);
    }

    [Fact]
    public void BooleanOperatorLiteral_Leaves_Meaningful_Expressions_Alone()
    {
        var code = """
            package demo;
            class A {
              boolean f(boolean var, boolean exp) {
                boolean b;
                b = var || exp;
                b = var && exp;
                b = !var;
                b = var;
                return b;
              }
            }
            """;
        var lines = Lines(code, "QG-JV-SML-0738");
        Assert.Empty(lines);
    }
}
