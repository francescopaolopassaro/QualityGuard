using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The regular-expression rules that read the shape of a pattern. PHP is used for most cases because
/// it writes patterns as plain calls with their own delimiters, which is the path that had to be
/// taught to the analyzer; the same rules run on every language whose patterns the engine finds.
/// </summary>
public class RegexStructureRulesTests
{
    private static IReadOnlyList<int> Php(string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules("sample.php", code, rule), rule);

    [Fact]
    public void A_php_pattern_is_analysed_at_all()
    {
        var duplicated = """
            <?php
            function f($s) {
              return preg_match("/[aa]/", $s);
            }
            """;
        Assert.NotEmpty(Php(duplicated, "QG-PP-BUG-0075"));

        var distinct = """
            <?php
            function f($s) {
              return preg_match("/[ab]/", $s);
            }
            """;
        Assert.Empty(Php(distinct, "QG-PP-BUG-0075"));
    }

    [Fact]
    public void The_replacement_argument_is_not_read_as_a_pattern()
    {
        // preg_replace takes the pattern first and the replacement second: reading the second one as
        // a regex reported on the text a match is turned into
        var code = """
            <?php
            function f($regex, $s) {
              return preg_replace($regex, '<a href="http$1://$2">$0</a>', $s);
            }
            """;
        Assert.Empty(Php(code, "QG-PP-BUG-0090"));
    }

    [Fact]
    public void A_group_that_can_match_nothing_is_reported()
    {
        var empty = """
            <?php
            function f($s) {
              return preg_match("/(x*)*/", $s);
            }
            """;
        Assert.NotEmpty(Php(empty, "QG-PP-BUG-0089"));

        var required = """
            <?php
            function f($s) {
              return preg_match("/(x+)*/", $s);
            }
            """;
        Assert.Empty(Php(required, "QG-PP-BUG-0089"));
    }

    [Fact]
    public void An_anchor_with_text_behind_it_is_reported()
    {
        var impossible = """
            <?php
            function f($s) {
              return preg_match('/$[a-z]/', $s);
            }
            """;
        Assert.NotEmpty(Php(impossible, "QG-PP-BUG-0090"));

        var fine = """
            <?php
            function f($s) {
              return preg_match('/[a-z]$/', $s);
            }
            """;
        Assert.Empty(Php(fine, "QG-PP-BUG-0090"));
    }

    [Fact]
    public void A_pattern_that_leans_on_a_flag_is_left_alone()
    {
        // under multiline the anchor holds in places it otherwise could not, and the flag sits after
        // the closing delimiter where only PHP puts it
        var multiline = """
            <?php
            function f($s) {
              return preg_match('/a$\nb/m', $s);
            }
            """;
        Assert.Empty(Php(multiline, "QG-PP-BUG-0090"));
    }

    [Fact]
    public void A_lazy_quantifier_before_its_terminator_is_reported()
    {
        var lazy = """
            <?php
            function f($s) {
              return preg_match("/<.+?>/", $s);
            }
            """;
        Assert.NotEmpty(Php(lazy, "QG-PP-SML-0166"));

        var negated = """
            <?php
            function f($s) {
              return preg_match("/<[^>]+>/", $s);
            }
            """;
        Assert.Empty(Php(negated, "QG-PP-SML-0166"));
    }

    [Fact]
    public void A_terminator_of_several_characters_is_left_alone()
    {
        // a negated class cannot express "until the three characters -->"
        var code = """
            <?php
            function f($s) {
              return preg_match("/<--.+?-->/", $s);
            }
            """;
        Assert.Empty(Php(code, "QG-PP-SML-0166"));
    }
}
