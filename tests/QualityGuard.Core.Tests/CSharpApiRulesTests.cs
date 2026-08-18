using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// C# rules about the shape of a type. The negative cases come from the corpus these were measured
/// on: a constructor that looks empty but forwards to its base, an Obsolete attribute that does
/// carry a message, a protected member that overrides one.
/// </summary>
public class CSharpApiRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "Sample.cs")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_public_field_is_reported_but_a_constant_is_not()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    public int Counter;\n}\n",
            "QG-CS-SML-0464"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n    public const int Limit = 3;\n}\n",
            "QG-CS-SML-0464"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n    private int _counter;\n}\n",
            "QG-CS-SML-0464"));
    }

    [Fact]
    public void A_class_of_static_members_is_reported()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    public static int F() => 1;\n}\n",
            "QG-CS-SML-0465"));
        Assert.Empty(Lines("namespace N;\npublic static class A\n{\n    public static int F() => 1;\n}\n",
            "QG-CS-SML-0465"));
    }

    [Fact]
    public void Throwing_a_general_exception_is_reported()
    {
        // QG-CS-SML-0466 and QG-CS-SML-0005 were retired: one defect, one finding
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    void F() { throw new Exception(\"x\"); }\n}\n",
            "QG-CS-SML-0520"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n    void F() { throw new ArgumentNullException(\"x\"); }\n}\n",
            "QG-CS-SML-0520"));
    }

    [Fact]
    public void An_obsolete_attribute_without_a_message_is_reported()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    [Obsolete]\n    public void F() { }\n}\n",
            "QG-CS-SML-0467"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n    [Obsolete(\"Use G\")]\n    public void F() { }\n}\n",
            "QG-CS-SML-0467"));
    }

    [Fact]
    public void A_property_that_only_wraps_a_field_is_reported()
    {
        var wrapping = """
            namespace N;
            public class A
            {
                private string _name;
                public string Name
                {
                    get { return _name; }
                    set { _name = value; }
                }
            }
            """;
        Assert.NotEmpty(Lines(wrapping, "QG-CS-SML-0469"));

        var doing_something = """
            namespace N;
            public class A
            {
                private string _name;
                public string Name
                {
                    get { return _name ?? "none"; }
                    set { _name = value; }
                }
            }
            """;
        Assert.Empty(Lines(doing_something, "QG-CS-SML-0469"));
    }

    [Fact]
    public void A_write_only_property_is_reported()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    private string _v;\n"
                              + "    public string Token { set { _v = value; } }\n}\n", "QG-CS-SML-0471"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n    public string Token { get; set; }\n}\n",
            "QG-CS-SML-0471"));
    }

    [Fact]
    public void An_empty_constructor_is_reported_but_one_that_forwards_is_not()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    public A()\n    {\n    }\n}\n",
            "QG-CS-SML-0472"));
        Assert.Empty(Lines("namespace N;\npublic class A : B\n{\n    public A() : base(\"x\") { }\n}\n",
            "QG-CS-SML-0472"));
    }

    [Fact]
    public void A_method_that_always_returns_a_literal_is_reported()
        => Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    public int Limit()\n    {\n"
                                 + "        return 42;\n    }\n}\n", "QG-CS-SML-0473"));

    [Fact]
    public void An_empty_finalizer_is_reported()
        => Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    ~A()\n    {\n    }\n}\n",
            "QG-CS-SML-0474"));

    [Fact]
    public void A_type_outside_a_namespace_is_reported()
    {
        Assert.NotEmpty(Lines("public class A\n{\n    private int _a;\n}\n", "QG-CS-SML-0475"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n    private int _a;\n}\n", "QG-CS-SML-0475"));
    }

    [Fact]
    public void A_negated_comparison_is_reported()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    bool F(int a) => !(a == 3);\n}\n",
            "QG-CS-SML-0476"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n    bool F(bool a) => !a;\n}\n",
            "QG-CS-SML-0476"));
    }

    [Fact]
    public void A_remainder_compared_to_one_is_reported_but_zero_is_not()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    bool F(int a) => a % 2 == 1;\n}\n",
            "QG-CS-BUG-0141"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n    bool F(int a) => a % 2 == 0;\n}\n",
            "QG-CS-BUG-0141"));
    }

    [Fact]
    public void An_index_tested_for_positive_is_reported()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    bool F(string s) => s.IndexOf(\"a\") > 0;\n}\n",
            "QG-CS-BUG-0142"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n    bool F(string s) => s.IndexOf(\"a\") >= 0;\n}\n",
            "QG-CS-BUG-0142"));
    }

    [Fact]
    public void A_getter_that_throws_is_reported_unless_the_exception_is_one_a_getter_may_use()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n"
                              + "    public string V { get { throw new ArgumentException(\"x\"); } }\n}\n",
            "QG-CS-BUG-0143"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n"
                           + "    public string V { get { throw new InvalidOperationException(\"x\"); } }\n}\n",
            "QG-CS-BUG-0143"));
    }

    [Fact]
    public void A_protected_member_of_a_sealed_class_is_reported_unless_it_overrides()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic sealed class A\n{\n    protected int _v;\n}\n",
            "QG-CS-BUG-0144"));
        Assert.Empty(Lines("namespace N;\npublic sealed class A : B\n{\n"
                           + "    protected override void F() { }\n}\n", "QG-CS-BUG-0144"));
    }

    [Fact]
    public void A_new_guid_is_reported()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    object F() => new Guid();\n}\n",
            "QG-CS-BUG-0145"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n    object F() => Guid.NewGuid();\n}\n",
            "QG-CS-BUG-0145"));
    }

    [Fact]
    public void Throwing_from_ToString_is_reported_but_not_implemented_is_not()
    {
        Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    public override string ToString()\n"
                              + "    {\n        throw new InvalidOperationException(\"x\");\n    }\n}\n",
            "QG-CS-BUG-0146"));
        Assert.Empty(Lines("namespace N;\npublic class A\n{\n    public override string ToString()\n"
                           + "    {\n        throw new NotImplementedException();\n    }\n}\n",
            "QG-CS-BUG-0146"));
    }

    [Fact]
    public void A_parameter_named_after_its_method_is_reported()
        => Assert.NotEmpty(Lines("namespace N;\npublic class A\n{\n    void Save(string save) { }\n}\n",
            "QG-CS-CNV-0009"));
}
