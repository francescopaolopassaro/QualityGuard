using QualityGuard.Core.Rules;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The pattern analyzer and the rules built on it. Every rule is checked on the defect and on a
/// correct pattern that must stay silent, because a regex rule that cries wolf makes people delete
/// the whole category.
/// </summary>
public class RegexRulesTests
{
    private static IReadOnlyList<int> Lines(string pattern, string rule)
    {
        var code = $$"""
            public class Check
            {
                public bool Run(string text)
                    => System.Text.RegularExpressions.Regex.IsMatch(text, "{{pattern}}");
            }
            """;
        return Analyze.LinesOf(Analyze.WithRules("Check.cs", code, rule), rule);
    }

    [Theory]
    [InlineData(@"[aab]")]
    [InlineData(@"[0-9a-fa-f]")]
    public void A_character_repeated_in_a_class_is_reported(string pattern)
        => Assert.NotEmpty(Lines(pattern, "QG-ALL-BUG-0025"));

    [Theory]
    [InlineData(@"[abc]")]
    [InlineData(@"[0-9]")]
    public void A_class_without_repetition_is_not_reported(string pattern)
        => Assert.Empty(Lines(pattern, "QG-ALL-BUG-0025"));

    [Fact]
    public void A_class_with_one_character_is_reported()
        => Assert.NotEmpty(Lines(@"ab[c]d", "QG-ALL-SML-0039"));

    [Fact]
    public void A_negated_class_with_one_character_is_left_alone()
        => Assert.Empty(Lines(@"ab[^c]d", "QG-ALL-SML-0039"));

    [Fact]
    public void An_alternation_of_single_characters_is_reported()
        => Assert.NotEmpty(Lines(@"(a|b|c)+", "QG-ALL-SML-0040"));

    [Fact]
    public void An_alternation_of_words_is_left_alone()
        => Assert.Empty(Lines(@"(cat|dog)", "QG-ALL-SML-0040"));

    [Fact]
    public void Several_spaces_in_a_row_are_reported()
        => Assert.NotEmpty(Lines(@"name:   value", "QG-ALL-SML-0041"));

    [Fact]
    public void A_single_space_is_left_alone()
        => Assert.Empty(Lines(@"name: value", "QG-ALL-SML-0041"));

    [Fact]
    public void An_empty_branch_is_reported()
        => Assert.NotEmpty(Lines(@"(cat||dog)", "QG-ALL-BUG-0026"));

    [Fact]
    public void A_repeated_branch_is_reported()
        => Assert.NotEmpty(Lines(@"(cat|dog|cat)", "QG-ALL-BUG-0027"));

    [Fact]
    public void Distinct_branches_are_left_alone()
        => Assert.Empty(Lines(@"(cat|dog|bird)", "QG-ALL-BUG-0027"));

    [Theory]
    [InlineData(@"(a+)+")]
    [InlineData(@"(\\w*)*")]
    public void A_repeating_group_that_is_itself_repeated_is_reported(string pattern)
        => Assert.NotEmpty(Lines(pattern, "QG-ALL-BUG-0028"));

    [Theory]
    [InlineData(@"(ab)+")]
    [InlineData(@"(a|b)+")]
    public void A_single_level_of_repetition_is_left_alone(string pattern)
        => Assert.Empty(Lines(pattern, "QG-ALL-BUG-0028"));

    [Fact]
    public void A_back_reference_without_a_group_is_reported()
        => Assert.NotEmpty(Lines(@"(a)(b)\\3", "QG-ALL-BUG-0029"));

    [Fact]
    public void A_back_reference_to_an_existing_group_is_left_alone()
        => Assert.Empty(Lines(@"(a)(b)\\2", "QG-ALL-BUG-0029"));

    [Fact]
    public void A_plain_string_argument_is_never_read_as_a_pattern()
    {
        var code = """
            public class Paths
            {
                public string Clean(string path) => path.Replace("[a]", "x");
            }
            """;
        Assert.Empty(Analyze.LinesOf(Analyze.WithRules("Paths.cs", code, "QG-ALL-SML-0039"), "QG-ALL-SML-0039"));
    }

    [Fact]
    public void The_analyzer_counts_capturing_groups_including_named_ones()
    {
        // (?: does not capture, (?<= is a lookbehind, (?<name> does capture
        var parsed = RegexPattern.Parse(@"(?:a)(b)(?<name>c)(?<=d)");
        Assert.Equal(2, parsed.CapturingGroups);
    }
}
