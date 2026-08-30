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
        Assert.Empty(Lines(header, "QG-CS-SML-0524"));
    }

    [Fact]
    public void A_commented_statement_is_still_reported()
        => Assert.NotEmpty(Lines("namespace Demo;\npublic class A\n{\n"
                                 + "    // var total = items.Count();\n    private int _a;\n}\n",
            "QG-CS-SML-0524"));

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
        Assert.Empty(Lines(forwarding, "QG-CS-SML-0504"));
    }

    [Fact]
    public void An_empty_nested_block_is_still_reported()
        => Assert.NotEmpty(Lines("namespace Demo;\npublic class A\n{\n    void F(int a)\n    {\n"
                                 + "        if (a > 0) { }\n    }\n}\n", "QG-CS-SML-0504"));

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
    [Fact]
    public void A_directive_is_not_code()
    {
        // '#if false' used to open a branch that swallowed the declarations under it, and '#endif'
        // turned the line after it into a field named 'public'
        var code = """
            public class C
            {
            #if false
                [Test]
                public void Old() { }
            #endif

                public override string ToString() => "c";
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0012"));
    }

    [Fact]
    public void A_blank_line_inside_a_licence_header_is_not_an_empty_comment()
    {
        var code = """
            // Copyright (c) someone
            //
            // Permission is hereby granted, free of charge, to any person
            public class C
            {
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0075"));
    }

    [Fact]
    public void A_marker_standing_on_its_own_is_an_empty_comment()
    {
        var code = """
            public class C
            {
                public void M()
                {
                    //
                    var x = 1;
                }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-CS-SML-0075"));
    }

    [Fact]
    public void A_default_written_last_is_where_it_belongs()
    {
        var code = """
            public class C
            {
                public int M(int v)
                {
                    switch (v)
                    {
                        case 1:
                            return 1;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0063"));
        Assert.Empty(Lines(code, "QG-CS-SML-0064"));
    }

    [Fact]
    public void A_default_between_two_cases_is_reported()
    {
        var code = """
            public class C
            {
                public int M(int v)
                {
                    switch (v)
                    {
                        case 1:
                            return 1;
                        default:
                            return 0;
                        case 2:
                            return 2;
                    }
                }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-CS-SML-0063"));
    }

    [Fact]
    public void A_serialised_example_pasted_in_a_comment_is_not_commented_out_code()
    {
        var code = """
            public class C
            {
                public void M()
                {
                    Write(o);
                    // {
                    //   "$id": "1",
                    //   "Name": "My Documents"
                    // }
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0524"));
    }

    [Fact]
    public void A_block_of_commented_out_statements_is_reported_once()
    {
        var code = """
            public class C
            {
                public void M()
                {
                    // var reader = new JsonReader(input);
                    // reader.Read();
                    // reader.Close();
                    var x = 1;
                }
            }
            """;
        Assert.Single(Lines(code, "QG-CS-SML-0524"));
    }

    [Fact]
    public void A_stream_that_only_lives_in_memory_is_not_asked_to_be_disposed()
    {
        var code = """
            public class C
            {
                public byte[] M(string s)
                {
                    MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(s));
                    return ms.ToArray();
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0020"));
    }
    [Fact]
    public void An_italian_comment_is_not_an_unfinished_task()
    {
        // "metodo" contains "todo", and matching the marker as a substring turned every
        // documentation comment on an Italian code base into a task left open
        var code = """
            public class C
            {
                /// <summary>
                /// Metodo per pulire le variabili globali
                /// </summary>
                public void M()
                {
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0503"));
    }

    [Fact]
    public void A_marker_written_as_a_word_is_still_reported()
    {
        var code = """
            public class C
            {
                public void M()
                {
                    // TODO: handle the empty case
                    var x = 1;
                }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-CS-SML-0503"));
    }

    [Fact]
    public void A_generated_file_is_not_scanned_at_all()
    {
        // the anchor rewrite corrupted every glob with a '*', so '*.designer.cs' matched nothing and
        // the default exclusions were silently off
        var pattern = QualityGuard.Core.Analysis.SourceScanner.GlobToRegex("*.designer.cs");
        Assert.Matches("^" + pattern[1..], "Page.aspx.designer.cs");
    }
    [Fact]
    public void Two_arguments_swapped_against_the_declaration_are_reported()
    {
        var code = """
            namespace Demo
            {
                public class Geometry
                {
                    public double Area(double width, double height) => width * height;

                    public void Use()
                    {
                        double width = 3, height = 4;
                        var wrong = Area(height, width);
                    }
                }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-CS-SML-0133"));
    }

    [Fact]
    public void Arguments_in_the_declared_order_are_left_alone()
    {
        var code = """
            namespace Demo
            {
                public class Geometry
                {
                    public double Area(double width, double height) => width * height;

                    public void Use()
                    {
                        double width = 3, height = 4;
                        var right = Area(width, height);
                        var computed = Area(width * 2, height);
                    }
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-0133"));
    }

    [Fact]
    public void A_redundant_boolean_literal_in_a_logical_expression_is_reported()
    {
        var code = """
            public class A
            {
                public bool F(bool condition)
                {
                    return condition && false;
                }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-CS-SML-1082"));
    }

    [Fact]
    public void A_nullable_boolean_compared_with_a_literal_is_not_reported()
    {
        var code = """
            public class A
            {
                public bool F(bool? condition)
                {
                    return condition == true;
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-1082"));
    }

    [Fact]
    public void FirstOrDefault_on_a_list_is_reported()
    {
        var code = """
            using System.Collections.Generic;
            using System.Linq;
            public class A
            {
                public bool F(List<int> data) => data.FirstOrDefault(x => x > 0) != null;
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-CS-SML-1083"));
    }

    [Fact]
    public void FirstOrDefault_with_a_default_value_is_not_reported()
    {
        var code = """
            using System.Collections.Generic;
            using System.Linq;
            public class A
            {
                public int F(List<int> data) => data.FirstOrDefault(default(int));
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-1083"));
    }

    [Fact]
    public void FirstOrDefault_on_an_unresolved_receiver_is_not_reported()
    {
        var code = """
            using System.Linq;
            public class A
            {
                public bool F(object data) => data.FirstOrDefault(x => x != null) != null;
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-1083"));
    }

    [Fact]
    public void All_on_a_list_is_reported()
    {
        var code = """
            using System.Collections.Generic;
            using System.Linq;
            public class A
            {
                public bool F(List<int> data) => data.All(x => x > 0);
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-CS-SML-1085"));
    }

    [Fact]
    public void All_on_an_unresolved_receiver_is_not_reported()
    {
        var code = """
            using System.Linq;
            public class A
            {
                public bool F(object data) => data.All(x => x != null);
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-1085"));
    }

    [Fact]
    public void First_on_a_list_is_reported()
    {
        var code = """
            using System.Collections.Generic;
            using System.Linq;
            public class A
            {
                public int F(List<int> data) => data.First();
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-CS-SML-1086"));
    }

    [Fact]
    public void First_with_a_predicate_is_not_reported()
    {
        var code = """
            using System.Collections.Generic;
            using System.Linq;
            public class A
            {
                public int F(List<int> data) => data.First(x => x > 0);
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-1086"));
    }

    [Fact]
    public void First_on_an_unresolved_receiver_is_not_reported()
    {
        var code = """
            using System.Linq;
            public class A
            {
                public int F(object data) => data.First();
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-1086"));
    }

    [Fact]
    public void First_on_a_lambda_parameter_typed_by_a_Func_is_reported()
    {
        var code = """
            using System;
            using System.Collections.Generic;
            using System.Linq;
            public class A
            {
                public void F()
                {
                    Func<List<int>, int> func = l => l.First();
                }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-CS-SML-1086"));
    }

    [Fact]
    public void First_on_the_return_of_a_local_function_is_reported()
    {
        var code = """
            using System.Collections.Generic;
            using System.Linq;
            public class A
            {
                public void F()
                {
                    List<int> DoWork() => null;
                    DoWork().First();
                }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-CS-SML-1086"));
    }

    [Fact]
    public void All_on_the_return_of_a_local_function_is_reported()
    {
        var code = """
            using System.Collections.Generic;
            using System.Linq;
            public class A
            {
                public void F()
                {
                    List<int> DoWork() => null;
                    bool any = DoWork().All(x => x > 0);
                }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-CS-SML-1085"));
    }

    [Fact]
    public void First_on_a_type_without_a_declared_return_is_not_reported()
    {
        var code = """
            using System.Linq;
            public class A
            {
                public void F()
                {
                    DoWork().First();
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-SML-1086"));
    }
}