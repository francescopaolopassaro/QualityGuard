using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// C# precision. Each case was a false positive on a real C# codebase: a licence header read as
/// commented-out code, a constructor forwarding with an empty body, and a null-dereference rule that
/// marked a name for the whole file and never noticed the check three lines later.
/// </summary>
public class CSharpPrecisionTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "Sample.cs")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_licence_header_is_not_commented_out_code()
    {
        var header = """
            /*
             * Product for .NET
             * Copyright (C) Acme
             *
             * but WITHOUT ANY WARRANTY; without even the implied warranty of
             * along with this program; if not, see https://acme.example/license
             */
            namespace Demo;

            public class A
            {
                private int _a;
            }
            """;
        // QG-CS-SML-0023 was retired: the shared analyzer answers the same question
        Assert.Empty(Lines(header, "QG-ALL-SML-0030"));
    }

    [Fact]
    public void A_commented_statement_is_still_reported()
        => Assert.NotEmpty(Lines("namespace Demo;\npublic class A\n{\n"
                                 + "    // var total = items.Count();\n    private int _a;\n}\n",
            "QG-ALL-SML-0030"));

    [Fact]
    public void A_constructor_forwarding_with_an_empty_body_is_left_alone()
    {
        var forwarding = """
            namespace Demo;

            public class A
            {
                public A(Context context, Diagnostic diagnostic)
                    : this(diagnostic, context.Report, context.Tree) { }
            }
            """;
        Assert.Empty(Lines(forwarding, "QG-ALL-SML-0002"));
    }

    [Fact]
    public void An_empty_nested_block_is_still_reported()
        => Assert.NotEmpty(Lines("namespace Demo;\npublic class A\n{\n    void F(int a)\n    {\n"
                                 + "        if (a > 0) { }\n    }\n}\n", "QG-ALL-SML-0002"));

    [Fact]
    public void A_value_that_may_be_null_is_reported_only_when_nothing_checked_it()
    {
        var unchecked_ = """
            namespace Demo;

            public class A
            {
                public string Go(List<string> items)
                {
                    var first = items.FirstOrDefault();
                    return first.Trim();
                }
            }
            """;
        Assert.NotEmpty(Lines(unchecked_, "QG-CS-BUG-0003"));

        var guarded = """
            namespace Demo;

            public class A
            {
                public string Go(List<string> items)
                {
                    var first = items.FirstOrDefault();
                    if (first == null) { return ""; }
                    return first.Trim();
                }
            }
            """;
        Assert.Empty(Lines(guarded, "QG-CS-BUG-0003"));
    }

    [Fact]
    public void A_coalescing_assignment_is_not_a_null_dereference()
    {
        // the rule used to mark the name for the whole file and report every later member access
        var code = """
            namespace Demo;

            public class A
            {
                public int Go(string[] locations)
                {
                    locations ??= [];
                    return locations.Length;
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-BUG-0003"));
    }
}
