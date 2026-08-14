using QualityGuard.Core.Syntax;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>Guards the C# grammar coverage: every case here was a real source of wrong results.</summary>
public class CSharpParserTests
{
    private static SyntaxNode Parse(string code) => Analyze.File("Sample.cs", code).Tree.Root;

    [Fact]
    public void Members_are_classified_by_kind()
    {
        var root = Parse("""
            namespace App;

            public sealed class Service : Base
            {
                private const int Limit = 10;
                private readonly string _name = "x";

                public string Name { get; init; }
                public int Count => _items.Count;

                public Service(string name) { _name = name; }

                public async Task<int> LoadAsync(int id, CancellationToken token = default)
                {
                    return await _repository.GetAsync(id, token);
                }
            }
            """);

        Assert.Single(root.OfKind(NodeKind.PackageDeclaration));
        var type = Assert.Single(root.OfKind(NodeKind.ClassDeclaration));
        Assert.Equal("Service", type.Text);
        Assert.Equal(2, type.OfKind(NodeKind.FieldDeclaration).Count());
        Assert.Equal(2, type.OfKind(NodeKind.PropertyDeclaration).Count());
        Assert.Single(type.OfKind(NodeKind.ConstructorDeclaration));

        var method = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        Assert.Equal("LoadAsync", method.Text);
        Assert.Equal(2, SyntaxQuery.Parameters(method).Count());
        Assert.Contains(method.ChildrenOf(NodeKind.Modifier), m => m.Text == "async");
    }

    [Fact]
    public void Property_accessors_are_not_statements()
    {
        var root = Parse("class A { public string Name { get; set; } }");

        var property = Assert.Single(root.OfKind(NodeKind.PropertyDeclaration));
        Assert.Equal(2, property.OfKind(NodeKind.Accessor).Count());
        Assert.Empty(root.OfKind(NodeKind.ExpressionStatement));
    }

    [Fact]
    public void A_brace_inside_a_string_does_not_close_a_block()
    {
        var root = Parse("""
            class A
            {
                bool Check(string text) { return text == "}" || text == "{"; }
                void After() { }
            }
            """);

        Assert.Equal(2, root.OfKind(NodeKind.FunctionDeclaration).Count());
        Assert.Empty(root.OfKind(NodeKind.Unknown));
    }

    [Fact]
    public void Patterns_do_not_swallow_their_combinators()
    {
        var root = Parse("""
            class A
            {
                bool Check(object value)
                {
                    return value is int or string;
                }
            }
            """);

        var pattern = Assert.Single(root.OfKind(NodeKind.Pattern));
        Assert.Equal("int", pattern.Text);
        Assert.Empty(root.OfKind(NodeKind.Unknown));
    }

    [Fact]
    public void Switch_expressions_are_parsed_as_expressions()
    {
        var root = Parse("""
            class A
            {
                int Rate(int value) => value switch
                {
                    0 => 1,
                    1 => 2,
                    _ => 3
                };
            }
            """);

        var switchExpression = Assert.Single(root.OfKind(NodeKind.SwitchExpression));
        Assert.Equal(3, switchExpression.OfKind(NodeKind.SwitchSection).Count());
        Assert.Empty(root.OfKind(NodeKind.Match));
    }

    [Fact]
    public void Else_branches_belong_to_their_if()
    {
        var root = Parse("""
            class A
            {
                int Go(int x)
                {
                    if (x > 0) { return 1; }
                    else if (x < 0) { return -1; }
                    else { return 0; }
                }
            }
            """);

        var head = root.OfKind(NodeKind.If).First();
        var elseBranch = Assert.Single(head.ChildrenOf(NodeKind.Else));
        Assert.Single(elseBranch.OfKind(NodeKind.If));
    }

    [Fact]
    public void Interpolated_holes_are_parsed_as_expressions()
    {
        var root = Parse("""
            class A
            {
                string Query(string name) => $"SELECT * FROM t WHERE n = '{name}'";
            }
            """);

        var interpolated = Assert.Single(root.OfKind(NodeKind.InterpolatedString));
        var hole = Assert.Single(interpolated.OfKind(NodeKind.Interpolation));
        Assert.Contains(hole.OfKind(NodeKind.Identifier), i => i.Text == "name");
    }

    [Fact]
    public void Lambdas_and_initializers_keep_their_shape()
    {
        var root = Parse("""
            class A
            {
                void Go()
                {
                    var options = new CookieOptions { HttpOnly = true, Secure = true };
                    var names = items.Where(i => i.Length > 0).Select(i => i.Trim());
                }
            }
            """);

        Assert.Single(root.OfKind(NodeKind.ObjectInitializer));
        Assert.Equal(2, root.OfKind(NodeKind.Lambda).Count());
        Assert.Empty(root.OfKind(NodeKind.Unknown));
    }

    [Fact]
    public void For_loops_expose_initializer_condition_and_update()
    {
        var root = Parse("""
            class A
            {
                void Go(int n)
                {
                    for (var i = 0; i < n; i++) { Use(i); }
                }
            }
            """);

        var loop = Assert.Single(root.OfKind(NodeKind.Loop));
        Assert.Equal("for", loop.Text);
        Assert.Single(loop.ChildrenOf(NodeKind.VariableDeclaration));
        Assert.Contains(loop.ChildrenOf(NodeKind.Binary), b => b.Text == "<");
        Assert.Contains(loop.ChildrenOf(NodeKind.Unary), u => u.Text == "++");
    }
}
