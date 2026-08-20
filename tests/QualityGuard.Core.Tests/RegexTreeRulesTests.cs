using QualityGuard.Core.Analysis;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The rules that read a pattern as a tree. Each case pairs the shape that must be reported with the
/// nearby shape that must not, because a rule that stays silent looks the same as clean code.
/// </summary>
public class RegexTreeRulesTests
{
    private static IReadOnlyList<int> Php(string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules("sample.php", code, rule), rule);

    private static IReadOnlyList<int> Java(string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules("Sample.java", code, rule), rule);

    private static IReadOnlyList<int> Python(string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules("sample.py", code, rule), rule);

    [Fact]
    public void A_pattern_that_cannot_be_read_produces_no_tree()
    {
        Assert.Null(RegexSyntax.Parse("(unbalanced"));
        Assert.Null(RegexSyntax.Parse("*leading"));
        Assert.NotNull(RegexSyntax.Parse("^(?:a|b)$"));
    }

    [Fact]
    public void A_quantifier_keeps_its_bounds_and_its_mode()
    {
        var tree = RegexSyntax.Parse("a{2,5}+");
        Assert.NotNull(tree);
        Assert.Equal(RegexKind.Repetition, tree!.Kind);
        Assert.Equal(2, tree.Min);
        Assert.Equal(5, tree.Max);
        Assert.Equal(RegexRepeat.Possessive, tree.RepeatMode);
    }

    [Fact]
    public void An_anchor_next_to_a_bar_is_reported_only_when_it_binds_to_one_branch()
    {
        var loose = """
            <?php
            function f($s) { return preg_match("/^a|b|c$/", $s); }
            """;
        Assert.NotEmpty(Php(loose, "QG-PP-BUG-0026"));

        var grouped = """
            <?php
            function f($s) { return preg_match("/^(?:a|b|c)$/", $s); }
            """;
        Assert.Empty(Php(grouped, "QG-PP-BUG-0026"));

        // every branch anchored the same way is deliberate, not a precedence mistake
        var each = """
            <?php
            function f($s) { return preg_match("/^a|^b/", $s); }
            """;
        Assert.Empty(Php(each, "QG-PP-BUG-0026"));
    }

    [Fact]
    public void A_possessive_quantifier_is_reported_only_when_it_starves_what_follows()
    {
        var starved = """
            class Sample {
              void f(String s) { s.matches("a++abc"); }
            }
            """;
        Assert.NotEmpty(Java(starved, "QG-JV-BUG-0132"));

        var fed = """
            class Sample {
              void f(String s) { s.matches("aa++bc"); }
            }
            """;
        Assert.Empty(Java(fed, "QG-JV-BUG-0132"));

        // a bounded count can stop early, so the element after it still has characters to read
        var bounded = """
            class Sample {
              void f(String s) { s.matches("a{2,3}+a"); }
            }
            """;
        Assert.Empty(Java(bounded, "QG-JV-BUG-0132"));
    }

    [Fact]
    public void A_look_ahead_is_reported_only_when_it_cannot_hold_with_what_follows()
    {
        var contradictory = """
            class Sample {
              void f(String s) { s.matches("(?=a)b"); }
            }
            """;
        Assert.NotEmpty(Java(contradictory, "QG-JV-BUG-0136"));

        var consistent = """
            class Sample {
              void f(String s) { s.matches("a(?=b)"); }
            }
            """;
        Assert.Empty(Java(consistent, "QG-JV-BUG-0136"));

        // the assertion and the element agree on the character, so the pattern can match
        var overlapping = """
            class Sample {
              void f(String s) { s.matches("(?=[ab])a"); }
            }
            """;
        Assert.Empty(Java(overlapping, "QG-JV-BUG-0136"));
    }

    [Fact]
    public void A_count_is_reported_only_when_a_shorter_spelling_says_the_same()
    {
        var spelled = """
            class Sample {
              void f(String s) { s.matches("x{2,2}"); }
            }
            """;
        Assert.NotEmpty(Java(spelled, "QG-JV-SML-0351"));

        var already = """
            class Sample {
              void f(String s) { s.matches("x{2}"); }
            }
            """;
        Assert.Empty(Java(already, "QG-JV-SML-0351"));

        // '[\s\S]' is how "any character, newline included" is written without the dot-all flag
        var idiom = """
            class Sample {
              void f(String s) { s.matches("[\\s\\S]"); }
            }
            """;
        Assert.Empty(Java(idiom, "QG-JV-SML-0351"));
    }

    [Fact]
    public void A_non_capturing_group_is_kept_when_it_holds_alternatives_or_a_quantifier()
    {
        var pointless = """
            class Sample {
              void f(String s) { s.matches("(?:number)\\d{2}"); }
            }
            """;
        Assert.NotEmpty(Java(pointless, "QG-JV-SML-0353"));

        var alternatives = """
            class Sample {
              void f(String s) { s.matches("(?:number|word)\\d{2}"); }
            }
            """;
        Assert.Empty(Java(alternatives, "QG-JV-SML-0353"));

        var quantified = """
            class Sample {
              void f(String s) { s.matches("(?:number)?\\d{2}"); }
            }
            """;
        Assert.Empty(Java(quantified, "QG-JV-SML-0353"));
    }

    [Fact]
    public void A_raw_python_literal_keeps_its_backslashes()
    {
        // the pattern is only visible to the rules if the raw prefix stops the escape from being eaten
        var octal = """
            import re
            re.compile(r"\101")
            """;
        Assert.NotEmpty(Python(octal, "QG-PY-SML-0112"));

        var hexadecimal = """
            import re
            re.compile(r"\x41")
            """;
        Assert.Empty(Python(hexadecimal, "QG-PY-SML-0112"));
    }

    [Fact]
    public void A_count_in_a_python_literal_is_not_read_as_a_hole()
    {
        var counted = """
            import re
            re.compile(r"(?:number)\d{2}")
            """;
        Assert.NotEmpty(Python(counted, "QG-PY-SML-0110"));
    }

    [Fact]
    public void A_named_reference_is_reported_only_when_no_group_carries_the_name()
    {
        var undefined = """
            import re
            re.compile(r"(?P<year>\d{4})-(?P=yr)")
            """;
        Assert.NotEmpty(Python(undefined, "QG-PY-SML-0091"));

        var defined = """
            import re
            re.compile(r"(?P<year>\d{4})-(?P=year)")
            """;
        Assert.Empty(Python(defined, "QG-PY-SML-0091"));
    }

    [Fact]
    public void A_replacement_is_reported_only_when_the_pattern_has_no_regex_feature()
    {
        var plain = """
            import re
            re.sub(r"Bob is", "It's", text)
            """;
        Assert.NotEmpty(Python(plain, "QG-PY-SML-0069"));

        var real = """
            import re
            re.sub(r"\s+", " ", text)
            """;
        Assert.Empty(Python(real, "QG-PY-SML-0069"));
    }

    [Fact]
    public void A_deeply_nested_pattern_is_reported_and_a_plain_one_is_not()
    {
        var nested = """
            class Sample {
              void f(String s) {
                s.matches("^(?:(?:31(\\/|-|\\.)(?:0?[13578]|1[02]))\\1|(?:(?:29|30)(\\/|-|\\.)(?:0?[13-9]|1[0-2])\\2))(?:(?:1[6-9]|[2-9]\\d)?\\d{2})$|^(?:29(\\/|-|\\.)0?2\\3(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\\d|2[0-8])(\\/|-|\\.)(?:(?:0?[1-9])|(?:1[0-2]))\\4(?:(?:1[6-9]|[2-9]\\d)?\\d{2})$");
              }
            }
            """;
        Assert.NotEmpty(Java(nested, "QG-JV-SML-0310"));

        var plain = """
            class Sample {
              void f(String s) { s.matches("^\\d{1,2}([-/.])\\d{1,2}\\1\\d{1,4}$"); }
            }
            """;
        Assert.Empty(Java(plain, "QG-JV-SML-0310"));
    }
}
