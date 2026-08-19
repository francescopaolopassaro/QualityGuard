using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Checks written once and given an identifier per language. Each case below is the shape the rule
/// must keep quiet about — a version number that looks like an address, a loop whose body moves the
/// counter, a loop that says "forever" on purpose.
/// </summary>
public class SharedChecksTests
{
    private static IReadOnlyList<int> Lines(string file, string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void An_address_written_into_the_source_is_reported()
    {
        var code = """
            public class Net
            {
                private const string Server = "10.0.0.8";
                private const string Endpoint = "http://192.168.1.50:8080/health";
            }
            """;
        Assert.Equal(2, Lines("Net.cs", code, "QG-CS-SML-0106").Count);
    }

    [Fact]
    public void Loopback_documentation_and_prose_are_not_addresses()
    {
        var code = """
            public class Net
            {
                private const string Local = "127.0.0.1";
                private const string Doc = "192.0.2.15";
                private const string Broadcast = "255.255.255.255";
                private const string Version = "1.02.3.4";
                private const string Sentence = "Retry 3 times after 2.5 seconds";
                private const string Oid = "2.5.4.3";
            }
            """;
        Assert.Empty(Lines("Net.cs", code, "QG-CS-SML-0106"));
    }

    [Fact]
    public void A_loop_that_steps_a_different_name_is_reported()
    {
        var code = """
            public class Counter
            {
                public void Run(int limit)
                {
                    for (int i = 0; i < limit; j++) { Work(); }
                }
            }
            """;
        Assert.NotEmpty(Lines("Counter.cs", code, "QG-CS-SML-0122"));
    }

    [Fact]
    public void A_loop_whose_body_moves_the_counter_is_left_alone()
    {
        var code = """
            public class Counter
            {
                public void Run(int limit)
                {
                    for (int i = 0; i < limit; j++)
                    {
                        i = Next(i);
                    }
                }
            }
            """;
        Assert.Empty(Lines("Counter.cs", code, "QG-CS-SML-0122"));
    }

    [Fact]
    public void A_for_with_only_a_condition_is_reported_and_forever_is_not()
    {
        var code = """
            public class Counter
            {
                public void Run(int limit)
                {
                    for (; limit > 0;) { Work(); }
                    for (;;) { Work(); }
                    for (int i = 0; i < limit; i++) { Work(); }
                }
            }
            """;
        Assert.Single(Lines("Counter.cs", code, "QG-CS-SML-0101"));
    }
    [Fact]
    public void Equality_that_casts_without_asking_is_reported()
    {
        var code = """
            class Point(val x: Int, val y: Int) {
                override fun equals(other: Any?): Boolean {
                    val o = other as Point
                    return x == o.x && y == o.y
                }
            }
            """;
        Assert.NotEmpty(Lines("Point.kt", code, "QG-KT-BUG-0014"));
    }

    [Fact]
    public void Equality_that_tests_the_type_is_left_alone()
    {
        var code = """
            class Safe(val x: Int) {
                override fun equals(other: Any?): Boolean {
                    if (other !is Safe) return false
                    return x == other.x
                }
            }
            """;
        Assert.Empty(Lines("Safe.kt", code, "QG-KT-BUG-0014"));
    }

    [Fact]
    public void Equality_that_hands_the_question_to_another_function_is_left_alone()
    {
        // a multiplatform library writes every equality this way, and the test lives in the callee
        var code = """
            class Path(val value: String) {
                override fun equals(other: Any?): Boolean = commonEquals(other)
            }
            """;
        Assert.Empty(Lines("Path.kt", code, "QG-KT-BUG-0014"));
    }
}
