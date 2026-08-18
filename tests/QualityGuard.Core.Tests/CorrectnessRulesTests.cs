using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Each rule is checked twice: on the defect it is meant to catch, and on the closest correct code
/// that must stay silent. The second half is what keeps the rule usable on a real codebase.
/// </summary>
public class CorrectnessRulesTests
{
    private static IReadOnlyList<int> Lines(string file, string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_loop_that_always_returns_on_the_first_pass_is_reported()
    {
        var code = """
            public class Finder
            {
                public string First(string[] names)
                {
                    foreach (var name in names)
                    {
                        return name;
                    }
                    return null;
                }
            }
            """;
        Assert.Equal([5], Lines("Finder.cs", code, "QG-CS-BUG-0165"));
    }

    [Fact]
    public void A_loop_whose_jump_is_conditional_is_not_reported()
    {
        var code = """
            public class Finder
            {
                public string First(string[] names)
                {
                    foreach (var name in names)
                    {
                        if (name != null)
                            return name;
                    }
                    return null;
                }
            }
            """;
        Assert.Empty(Lines("Finder.cs", code, "QG-CS-BUG-0165"));
    }

    [Fact]
    public void A_size_compared_with_zero_or_minus_one_is_reported()
    {
        var code = """
            public class Cart
            {
                public bool Any(System.Collections.Generic.List<int> items)
                {
                    if (items.Count >= 0)
                        return true;
                    return items.Count == -1;
                }
            }
            """;
        Assert.Equal([5, 7], Lines("Cart.cs", code, "QG-CS-BUG-0166"));
    }

    [Fact]
    public void A_size_compared_with_a_real_bound_is_not_reported()
    {
        var code = """
            public class Cart
            {
                public bool Any(System.Collections.Generic.List<int> items) => items.Count > 0;
            }
            """;
        Assert.Empty(Lines("Cart.cs", code, "QG-CS-BUG-0166"));
    }

    [Fact]
    public void A_collection_passed_to_its_own_method_is_reported()
    {
        var code = """
            public class Merge
            {
                public void Run(System.Collections.Generic.List<int> left)
                {
                    left.AddRange(left);
                }
            }
            """;
        Assert.Equal([5], Lines("Merge.cs", code, "QG-CS-BUG-0167"));
    }

    [Fact]
    public void Two_different_collections_are_not_reported()
    {
        var code = """
            public class Merge
            {
                public void Run(System.Collections.Generic.List<int> left, System.Collections.Generic.List<int> right)
                {
                    left.AddRange(right);
                }
            }
            """;
        Assert.Empty(Lines("Merge.cs", code, "QG-CS-BUG-0167"));
    }

    [Fact]
    public void A_dropped_pure_result_is_reported()
    {
        var code = """
            public class Names
            {
                public string Clean(string name)
                {
                    name.Trim();
                    return name;
                }
            }
            """;
        Assert.Equal([5], Lines("Names.cs", code, "QG-CS-BUG-0168"));
    }

    [Fact]
    public void A_used_pure_result_is_not_reported()
    {
        var code = """
            public class Names
            {
                public string Clean(string name) => name.Trim();
            }
            """;
        Assert.Empty(Lines("Names.cs", code, "QG-CS-BUG-0168"));
    }

    [Fact]
    public void A_doubled_negation_is_reported()
    {
        var code = """
            public class Flags
            {
                public bool Check(bool ready) => !!ready;
            }
            """;
        Assert.Equal([3], Lines("Flags.cs", code, "QG-CS-BUG-0169"));
    }

    [Fact]
    public void A_shift_by_zero_and_a_shift_wider_than_the_type_are_reported()
    {
        var code = """
            public class Bits
            {
                public int Zero(int value) => value << 0;
                public int Wide(int value) => value << 70;
                public int Fine(int value) => value << 3;
            }
            """;
        Assert.Equal([3, 4], Lines("Bits.cs", code, "QG-CS-BUG-0170"));
    }

    [Fact]
    public void A_counter_moving_away_from_its_bound_is_reported()
    {
        var code = """
            public class Walk
            {
                public void Run(int n)
                {
                    for (int i = 0; i < n; i--)
                    {
                        System.Console.WriteLine(i);
                    }
                }
            }
            """;
        Assert.Equal([5], Lines("Walk.cs", code, "QG-CS-BUG-0171"));
    }

    [Fact]
    public void A_counter_moving_towards_its_bound_is_not_reported()
    {
        var code = """
            public class Walk
            {
                public void Run(int n)
                {
                    for (int i = n; i > 0; i--)
                    {
                        System.Console.WriteLine(i);
                    }
                }
            }
            """;
        Assert.Empty(Lines("Walk.cs", code, "QG-CS-BUG-0171"));
    }

    [Fact]
    public void An_always_true_loop_without_an_exit_is_reported()
    {
        var code = """
            public class Pump
            {
                public void Run()
                {
                    while (true)
                    {
                        Work();
                    }
                }

                private void Work() { }
            }
            """;
        Assert.Equal([5], Lines("Pump.cs", code, "QG-CS-BUG-0172"));
    }

    [Fact]
    public void An_always_true_loop_with_a_break_is_not_reported()
    {
        var code = """
            public class Pump
            {
                public void Run()
                {
                    while (true)
                    {
                        if (Done())
                            break;
                    }
                }

                private bool Done() => true;
            }
            """;
        Assert.Empty(Lines("Pump.cs", code, "QG-CS-BUG-0172"));
    }

    [Fact]
    public void A_comparison_between_two_declared_types_that_cannot_match_is_reported()
    {
        var code = """
            public class Money { }

            public class Till
            {
                public bool Check(string label)
                {
                    Money amount = new Money();
                    return label == amount;
                }
            }
            """;
        Assert.Equal([8], Lines("Till.cs", code, "QG-CS-BUG-0164"));
    }

    [Fact]
    public void A_comparison_whose_types_the_resolver_only_guessed_stays_silent()
    {
        // both sides come from calls the index cannot resolve: two unknowns prove nothing
        var code = """
            public class Till
            {
                public bool Check()
                {
                    var left = External.Read();
                    var right = Other.Fetch();
                    return left == right;
                }
            }
            """;
        Assert.Empty(Lines("Till.cs", code, "QG-CS-BUG-0164"));
    }

    [Fact]
    public void An_increment_inside_a_return_is_reported()
    {
        var code = """
            public class Counter
            {
                public int Next()
                {
                    int value = Read();
                    return value++;
                }

                private int Read() => 1;
            }
            """;
        Assert.Equal([6], Lines("Counter.cs", code, "QG-CS-BUG-0173"));
    }

    [Fact]
    public void A_prefix_increment_inside_a_return_is_not_reported()
    {
        var code = """
            public class Counter
            {
                public int Next()
                {
                    int value = Read();
                    return ++value;
                }

                private int Read() => 1;
            }
            """;
        Assert.Empty(Lines("Counter.cs", code, "QG-CS-BUG-0173"));
    }
}
