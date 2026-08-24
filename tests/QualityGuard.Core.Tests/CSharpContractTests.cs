using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The C# contract rules read declarations and call shapes; each test pins the reported form and
/// the near-miss beside it that must stay silent.
/// </summary>
public class CSharpContractTests
{
    private static IReadOnlyList<int> Lines(string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules("Sample.cs", code, rule), rule);

    [Fact]
    public void An_is_test_on_this_is_reported()
    {
        var code = """
            public class W
            {
                public bool Same(object o)
                {
                    if (this is W) { return true; }
                    return false;
                }
            }
            """;
        Assert.Equal([5], Lines(code, "QG-CS-SML-0169"));
    }

    [Fact]
    public void A_comparison_starting_from_this_is_left_alone()
    {
        // this == other is an ordinary comparison; only the type-test operator is dead here
        var code = """
            public class W
            {
                public bool Same(W other)
                {
                    return this == other;
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0169"));
    }

    [Fact]
    public void An_instance_method_writing_a_static_field_is_reported()
    {
        var code = """
            public class Counter
            {
                private static int total;

                public void Add(int value)
                {
                    total += value;
                }
            }
            """;
        Assert.Equal([6], Lines(code, "QG-CS-SML-0158"));
    }

    [Fact]
    public void A_static_method_writing_a_static_field_is_left_alone()
    {
        var code = """
            public class Counter
            {
                private static int total;

                public static void Add(int value)
                {
                    total += value;
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0158"));
    }

    [Fact]
    public void Unsubscribing_with_an_inline_lambda_is_reported()
    {
        var code = """
            public class Bus
            {
                public event System.Action Tick;

                public void Detach()
                {
                    Tick -= () => { };
                }
            }
            """;
        Assert.Equal([7], Lines(code, "QG-CS-BUG-0063"));
    }

    [Fact]
    public void Reading_a_freshly_created_empty_collection_is_reported()
    {
        var code = """
            public class Reader
            {
                public int Count()
                {
                    return new System.Collections.Generic.List<string>().Count();
                }
            }
            """;
        Assert.Equal([5], Lines(code, "QG-CS-BUG-0085"));
    }

    [Fact]
    public void Adding_to_a_freshly_created_collection_is_left_alone()
    {
        // filling an empty literal is exactly what it is for
        var code = """
            public class Builder
            {
                public System.Collections.Generic.List<string> Build()
                {
                    var list = new System.Collections.Generic.List<string>();
                    return list;
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-BUG-0085"));
    }

    [Fact]
    public void A_raw_tab_inside_a_literal_is_reported()
    {
        var code = "public class T { public string Label() { return \"a\tb\"; } }";
        Assert.Equal([1], Lines(code, "QG-CS-SML-0156"));
    }

    [Fact]
    public void An_empty_namespace_is_reported()
    {
        var code = """
            namespace Dead.Space
            {
            }
            """;
        Assert.Equal([1], Lines(code, "QG-CS-SML-0191"));
    }

    [Fact]
    public void A_format_hole_without_an_argument_is_reported()
    {
        var code = """
            public class Fmt
            {
                public string Render(int a)
                {
                    return string.Format("{0} and {1}", a);
                }
            }
            """;
        Assert.Equal([5], Lines(code, "QG-CS-SML-0215"));
    }

    [Fact]
    public void A_well_numbered_format_is_left_alone()
    {
        var code = """
            public class Fmt
            {
                public string Render(int a, int b)
                {
                    return string.Format("{0} and {1}", a, b);
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0215"));
    }

    [Fact]
    public void Gettype_on_a_type_instance_is_reported()
    {
        var code = """
            public class Probe
            {
                public string Name(System.Type t)
                {
                    return t.GetType().Name;
                }
            }
            """;
        Assert.Equal([5], Lines(code, "QG-CS-SML-0209"));
    }

    [Fact]
    public void A_constant_copied_in_a_static_constructor_is_reported()
    {
        var code = """
            public class Config
            {
                private static string Key;

                static Config()
                {
                    Key = "k";
                }
            }
            """;
        Assert.Equal([7], Lines(code, "QG-CS-SML-0245"));
    }

    [Fact]
    public void Real_work_in_a_static_constructor_is_left_alone()
    {
        // reading a file cannot move onto the declaration line
        var code = """
            public class Config
            {
                private static string Text;

                static Config()
                {
                    Text = System.IO.File.ReadAllText("c.txt");
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0245"));
    }

    [Fact]
    public void An_attribute_class_without_usage_is_reported()
    {
        var code = """
            public class MarkAttribute : System.Attribute
            {
            }
            """;
        Assert.Equal([1], Lines(code, "QG-CS-SML-0253"));
    }

    [Fact]
    public void An_attribute_class_with_usage_is_left_alone()
    {
        var code = """
            [System.AttributeUsage(System.AttributeTargets.Class)]
            public class MarkAttribute : System.Attribute
            {
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0253"));
    }

    [Fact]
    public void Ordering_before_filtering_is_reported()
    {
        var code = """
            public class Query
            {
                public var Run(System.Collections.Generic.IList<int> items)
                {
                    return items.OrderBy(x => x).Where(x => x > 0);
                }
            }
            """;
        Assert.Equal([5], Lines(code, "QG-CS-SML-0326"));
    }

    [Fact]
    public void Filtering_before_ordering_is_left_alone()
    {
        var code = """
            public class Query
            {
                public var Run(System.Collections.Generic.IList<int> items)
                {
                    return items.Where(x => x > 0).OrderBy(x => x);
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0326"));
    }

    [Fact]
    public void A_logger_category_mismatching_the_type_is_reported()
    {
        var code = """
            public class Orders
            {
                public Orders(Microsoft.Extensions.Logging.ILogger<Billing> log)
                {
                }
            }
            """;
        Assert.Equal([3], Lines(code, "QG-CS-SML-0336"));
    }

    [Fact]
    public void A_matching_logger_category_is_left_alone()
    {
        var code = """
            public class Orders
            {
                public Orders(Microsoft.Extensions.Logging.ILogger<Orders> log)
                {
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0336"));
    }

    [Fact]
    public void A_duplicated_log_placeholder_is_reported()
    {
        var code = """
            public class Pay
            {
                public void Go(Microsoft.Extensions.Logging.ILogger log)
                {
                    log.LogInformation("{a} then {a}", 1, 2);
                }
            }
            """;
        Assert.Equal([5], Lines(code, "QG-CS-BUG-0095"));
    }

    [Fact]
    public void Distinct_placeholders_are_left_alone()
    {
        var code = """
            public class Pay
            {
                public void Go(Microsoft.Extensions.Logging.ILogger log)
                {
                    log.LogInformation("{a} then {b}", 1, 2);
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-BUG-0095"));
    }

    [Fact]
    public void A_lowercase_log_placeholder_is_reported()
    {
        var code = """
            public class Pay
            {
                public void Go(Microsoft.Extensions.Logging.ILogger log)
                {
                    log.LogInformation("{amount}", 1);
                }
            }
            """;
        Assert.Equal([5], Lines(code, "QG-CS-SML-0338"));
    }

    [Fact]
    public void Blocking_in_an_async_azure_function_is_reported()
    {
        var code = """
            using Microsoft.Azure.WebJobs;

            public class Greeter
            {
                [FunctionName("Ping")]
                public async void Ping(string input)
                {
                    var task = System.Threading.Tasks.Task.Delay(1);
                    task.Wait();
                }
            }
            """;
        Assert.Equal([9], Lines(code, "QG-CS-SML-0311"));
    }

    [Fact]
    public void The_blocking_rules_stay_silent_outside_functions_code()
    {
        // no FunctionName attribute anywhere: this is ordinary hosting-free code
        var code = """
            public class Worker
            {
                public async void Run()
                {
                    var task = System.Threading.Tasks.Task.Delay(1);
                    task.Wait();
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0311"));
    }

    [Fact]
    public void A_comparable_without_equals_override_is_reported()
    {
        var code = """
            public class Price : System.IComparable<Price>
            {
                public int CompareTo(Price other) => 0;
            }
            """;
        Assert.Equal([1], Lines(code, "QG-CS-SML-0098"));
    }

    [Fact]
    public void A_comparable_that_overrides_equals_is_left_alone()
    {
        var code = """
            public class Price : System.IComparable<Price>
            {
                public int CompareTo(Price other) => 0;

                public override bool Equals(object other) => true;
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0098"));
    }

    [Fact]
    public void A_public_dllimport_is_reported()
    {
        var code = """
            using System.Runtime.InteropServices;

            public class Native
            {
                [DllImport("user32.dll")]
                public static extern int Beep(uint tone, uint ms);
            }
            """;
        Assert.Equal([5], Lines(code, "QG-CS-SML-0292"));
    }
}
