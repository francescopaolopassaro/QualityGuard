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
    [Fact]
    public void A_method_that_promises_a_collection_and_answers_with_nothing_is_reported()
    {
        var code = """
            public class Repo
            {
                public List<string> Names(bool any)
                {
                    if (!any)
                        return null;
                    return new List<string> { "a" };
                }

                public List<string>? Optional(bool any)
                {
                    if (!any)
                        return null;
                    return new List<string> { "a" };
                }
            }
            """;
        // the signature that admits it may answer with nothing has told every caller already
        Assert.Single(Lines("Repo.cs", code, "QG-CS-SML-0095"));
    }

    [Fact]
    public void A_constructor_calling_a_replaceable_method_is_reported()
    {
        var code = """
            public class Repo
            {
                public Repo()
                {
                    Load();
                    Prepare();
                }

                public virtual void Load() { }

                private void Prepare() { }
            }
            """;
        Assert.Single(Lines("Repo.cs", code, "QG-CS-SML-0115"));
    }

    [Fact]
    public void A_sealed_type_cannot_be_surprised_by_a_subclass()
    {
        var code = """
            public sealed class Repo
            {
                public Repo()
                {
                    Load();
                }

                public virtual void Load() { }
            }
            """;
        Assert.Empty(Lines("Repo.cs", code, "QG-CS-SML-0115"));
    }

    [Fact]
    public void A_database_opened_without_a_password_is_reported()
    {
        var code = """
            <?php
            $config = ['password' => ''];
            $other = ['password' => getenv('DB_PASSWORD')];
            """;
        Assert.Single(Lines("db.php", code, "QG-PP-SEC-0036"));
    }

    [Fact]
    public void Certificate_checking_turned_off_is_reported_and_left_on_is_not()
    {
        var code = """
            <?php
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            """;
        Assert.Single(Lines("client.php", code, "QG-PP-SEC-0055"));
    }
    [Fact]
    public void Two_methods_with_the_same_body_are_reported()
    {
        var code = """
            public class Order
            {
                public int Total(IEnumerable<int> values)
                {
                    var sum = 0;
                    foreach (var value in values)
                        sum += value;
                    return sum;
                }

                public int Count(IEnumerable<int> values)
                {
                    var sum = 0;
                    foreach (var value in values)
                        sum += value;
                    return sum;
                }
            }
            """;
        Assert.Single(Lines("Order.cs", code, "QG-CS-SML-0291"));
    }

    [Fact]
    public void Extension_points_that_all_return_the_default_are_left_alone()
    {
        // a base class of hooks looks identical on purpose: that shape is the contract
        var code = """
            public class Proxy
            {
                public virtual bool TryConvert(object instance, out object? result)
                {
                    result = null;
                    return false;
                }

                public virtual bool TryCreate(object instance, out object? result)
                {
                    result = null;
                    return false;
                }
            }
            """;
        Assert.Empty(Lines("Proxy.cs", code, "QG-CS-SML-0291"));
    }

    [Fact]
    public void A_negated_comparison_is_reported()
    {
        var code = """
            def check(a, b):
                if not (a == b):
                    return False
                return True
            """;
        Assert.NotEmpty(Lines("check.py", code, "QG-PY-SML-0050"));
    }

    [Fact]
    public void A_hash_built_from_a_field_that_can_change_is_reported()
    {
        var code = """
            public class Order
            {
                private int _quantity;
                private readonly string _code = "x";

                public override int GetHashCode()
                {
                    return _quantity.GetHashCode() ^ _code.GetHashCode();
                }
            }
            """;
        Assert.NotEmpty(Lines("Order.cs", code, "QG-CS-BUG-0047"));
    }

    [Fact]
    public void A_hash_built_only_from_values_that_cannot_change_is_left_alone()
    {
        var code = """
            public class Order
            {
                private readonly string _code = "x";

                public override int GetHashCode()
                {
                    return _code.GetHashCode();
                }
            }
            """;
        Assert.Empty(Lines("Order.cs", code, "QG-CS-BUG-0047"));
    }
    [Fact]
    public void A_parameter_replaced_before_it_is_read_is_reported()
    {
        var code = """
            def normalise(path, mode):
                path = "/tmp"
                mode = mode.strip()
                return path + mode
            """;
        // 'mode' is derived from itself, which is a normalisation and not a loss
        Assert.Single(Lines("paths.py", code, "QG-PY-BUG-0026"));
    }

    [Fact]
    public void The_same_entry_written_twice_is_reported_and_an_append_is_not()
    {
        var written = """
            def fill(data, key):
                data[key] = 1
                data[key] = 2
                return data
            """;
        var accumulated = """
            def accumulate(counts, key):
                counts[key] = 0
                counts[key] = counts[key] + 1
                return counts
            """;
        Assert.Single(Lines("fill.py", written, "QG-PY-BUG-0044"));
        Assert.Empty(Lines("fill.py", accumulated, "QG-PY-BUG-0044"));
    }

    [Fact]
    public void A_function_that_always_answers_the_same_literal_is_reported()
    {
        var code = """
            def always(flag):
                if flag:
                    return 42
                return 42
            """;
        Assert.NotEmpty(Lines("always.py", code, "QG-PY-SML-0062"));
    }

    [Fact]
    public void The_same_variable_returned_from_two_branches_is_left_alone()
    {
        // the variable holds whatever its branch computed: reading the text as the value reported
        // every function written this way
        var code = """
            def decide(flag):
                result = 0
                if flag:
                    result = compute()
                    return result
                result = fallback()
                return result
            """;
        Assert.Empty(Lines("decide.py", code, "QG-PY-SML-0062"));
    }
}
