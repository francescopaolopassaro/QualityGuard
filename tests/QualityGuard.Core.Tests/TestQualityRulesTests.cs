using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>Rules that look at the tests. Each is pinned on the defect and on correct test code.</summary>
public class TestQualityRulesTests
{
    private static IReadOnlyList<int> Lines(string file, string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void An_assertion_comparing_a_value_with_itself_is_reported()
    {
        var code = """
            public class CartTest
            {
                public void Total()
                {
                    var cart = new Cart();
                    assertEquals(cart.Total(), cart.Total());
                }
            }
            """;
        Assert.Equal([6], Lines("CartTest.cs", code, "QG-ALL-BUG-0031"));
    }

    [Fact]
    public void An_assertion_comparing_two_different_values_is_left_alone()
    {
        var code = """
            public class CartTest
            {
                public void Total()
                {
                    var cart = new Cart();
                    assertEquals(10, cart.Total());
                }
            }
            """;
        Assert.Empty(Lines("CartTest.cs", code, "QG-ALL-BUG-0031"));
    }

    [Fact]
    public void The_expected_value_placed_second_is_reported()
    {
        var code = """
            public class CartTest
            {
                public void Total()
                {
                    assertEquals(cart.Total(), 10);
                }
            }
            """;
        Assert.Equal([5], Lines("CartTest.java", code, "QG-ALL-BUG-0032"));
    }

    [Fact]
    public void The_expected_value_placed_first_is_left_alone()
    {
        var code = """
            public class CartTest
            {
                public void Total()
                {
                    assertEquals(10, cart.Total());
                }
            }
            """;
        Assert.Empty(Lines("CartTest.java", code, "QG-ALL-BUG-0032"));
    }

    [Fact]
    public void An_assertion_on_two_conditions_at_once_is_reported()
    {
        var code = """
            public class CartTest
            {
                public void Total()
                {
                    assertTrue(cart.IsOpen() && cart.IsEmpty());
                }
            }
            """;
        Assert.Equal([5], Lines("CartTest.cs", code, "QG-ALL-SML-0042"));
    }

    [Fact]
    public void A_comparison_inside_assert_true_is_reported()
    {
        var code = """
            public class CartTest
            {
                public void Total()
                {
                    assertTrue(cart.Total() == 10);
                }
            }
            """;
        Assert.Equal([5], Lines("CartTest.cs", code, "QG-ALL-SML-0043"));
    }

    [Fact]
    public void A_plain_boolean_assertion_is_left_alone()
    {
        var code = """
            public class CartTest
            {
                public void Total()
                {
                    assertTrue(cart.IsEmpty());
                }
            }
            """;
        Assert.Empty(Lines("CartTest.cs", code, "QG-ALL-SML-0043"));
    }

    [Fact]
    public void A_test_class_without_a_single_test_is_reported()
    {
        var code = """
            public class CartTests
            {
                private Cart Build() { return new Cart(); }

                private void Reset() { }
            }
            """;
        Assert.Equal([1], Lines("CartTests.cs", code, "QG-ALL-SML-0044"));
    }

    [Fact]
    public void A_test_class_with_a_test_is_left_alone()
    {
        var code = """
            public class CartTests
            {
                private Cart Build() { return new Cart(); }

                [Fact]
                public void Total_is_the_sum_of_the_lines() { }
            }
            """;
        Assert.Empty(Lines("CartTests.cs", code, "QG-ALL-SML-0044"));
    }

    [Fact]
    public void A_production_class_named_like_a_test_helper_is_not_scanned_for_tests()
    {
        var code = """
            public class LatestTests
            {
                private void Build() { }
            }
            """;
        // "Latest.cs" contains "test" but is not a test file, so the rule stays out of it
        Assert.Empty(Lines("src/Domain/Latest.cs", code, "QG-ALL-SML-0044"));
    }
}
