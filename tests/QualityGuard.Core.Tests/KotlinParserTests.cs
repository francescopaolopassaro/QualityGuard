using QualityGuard.Core.Syntax;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The Kotlin dialect of the C-family parser. Kotlin names a thing before its type and ends a
/// statement at the line break, so these tests pin the two places where it parts company with Java:
/// the shape of a declaration, and where one statement stops.
/// </summary>
public class KotlinParserTests
{
    private static SyntaxNode Parse(string code) => Analyze.File("Sample.kt", code).Tree.Root;

    [Fact]
    public void A_file_has_a_real_tree()
    {
        var tree = Analyze.File("Sample.kt", "fun main() {}").Tree;
        Assert.True(tree.HasDedicatedParser);
    }

    [Fact]
    public void A_function_declares_its_parameters_and_its_type()
    {
        var root = Parse("""
            fun greet(name: String, times: Int): String {
                return name
            }
            """);

        var function = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        Assert.Equal("greet", function.Text);
        var parameters = SyntaxQuery.Parameters(function).ToList();
        Assert.Equal(2, parameters.Count);
        Assert.Equal("name", parameters[0].Text);
        Assert.Equal("String", parameters[0].FirstChild(NodeKind.TypeReference)?.Text);
    }

    [Fact]
    public void An_extension_function_is_named_after_the_dot()
    {
        var root = Parse("""
            fun String.shout(): String {
                return this.uppercase()
            }
            """);

        var function = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        Assert.Equal("shout", function.Text);
    }

    [Fact]
    public void An_expression_body_is_the_body_of_the_function()
    {
        var root = Parse("fun twice(n: Int) = n * 2\n");

        var function = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        Assert.NotNull(SyntaxQuery.Body(function));
        Assert.NotEmpty(function.OfKind(NodeKind.Binary));
    }

    [Fact]
    public void A_primary_constructor_declares_the_properties_of_the_class()
    {
        var root = Parse("""
            class Greeter(private val name: String, val times: Int) {
                fun greet() = name
            }
            """);

        var type = Assert.Single(root.OfKind(NodeKind.ClassDeclaration));
        var parameters = type.FirstChild(NodeKind.ParameterList);
        Assert.NotNull(parameters);
        Assert.Equal(2, parameters!.Children.Count);
    }

    [Fact]
    public void A_property_of_a_type_is_a_field_and_a_local_is_not()
    {
        var root = Parse("""
            class Counter {
                private var count = 0

                fun bump() {
                    val step = 1
                    count += step
                }
            }
            """);

        Assert.Single(root.OfKind(NodeKind.FieldDeclaration));
        Assert.Single(root.OfKind(NodeKind.VariableDeclaration));
    }

    [Fact]
    public void When_is_a_multi_way_branch_in_both_positions()
    {
        var statement = Parse("""
            fun label(n: Int) {
                when (n) {
                    0 -> print("zero")
                    else -> print("many")
                }
            }
            """);
        Assert.Single(statement.OfKind(NodeKind.Match));

        var expression = Parse("""
            fun label(n: Int) = when (n) {
                0 -> "zero"
                else -> "many"
            }
            """);
        var match = Assert.Single(expression.OfKind(NodeKind.Match));
        Assert.Equal(2, match.OfKind(NodeKind.SwitchSection).Count());
    }

    [Fact]
    public void A_statement_ends_at_the_line_break()
    {
        var root = Parse("""
            fun f(a: Int, b: Int): Int {
                val x = a
                val y = b
                return x + y
            }
            """);

        var body = SyntaxQuery.Body(Assert.Single(root.OfKind(NodeKind.FunctionDeclaration)));
        Assert.NotNull(body);
        Assert.Equal(3, body!.Children.Count);
    }

    [Fact]
    public void A_call_split_over_lines_stays_one_statement()
    {
        var root = Parse("""
            fun f(items: List<Int>): Int {
                return items
                    .filter { it > 0 }
                    .sum()
            }
            """);

        var body = SyntaxQuery.Body(Assert.Single(root.OfKind(NodeKind.FunctionDeclaration)));
        Assert.NotNull(body);
        Assert.Single(body!.Children);
    }

    [Fact]
    public void An_init_block_and_a_secondary_constructor_are_constructors()
    {
        var root = Parse("""
            class A(val n: Int) {
                init {
                    check(n > 0)
                }

                constructor() : this(1) {
                }
            }
            """);

        Assert.Equal(2, root.OfKind(NodeKind.ConstructorDeclaration).Count());
    }

    [Fact]
    public void An_object_and_a_data_class_are_types()
    {
        var root = Parse("""
            data class Point(val x: Int, val y: Int)

            object Registry {
                fun size() = 0
            }
            """);

        Assert.Equal(2, root.OfKind(NodeKind.ClassDeclaration).Count());
    }
}
