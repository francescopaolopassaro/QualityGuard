using QualityGuard.Core.Syntax;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Regression tests for the parser fixes of the security lot: each one was a real misread that
/// detached declarations from their meaning.
/// </summary>
public class JavaModernParserTests
{
    private static SyntaxNode ParseJava(string code)
    {
        var language = QualityGuard.Core.Tokenization.BuiltInLanguages.Recognizer.Recognize("Sample.java")!;
        var tokens = new QualityGuard.Core.Tokenization.SourceTokenizer(code, language).Tokenize();
        return SyntaxTree.Build(tokens, language).Root;
    }

    private static void AssertParses(params string[] lines)
    {
        var code = string.Join('\n', lines.Prepend("class Sample {").Append("}"));
        Assert.NotEmpty(ParseJava(code).Descendants());
    }

    [Fact]
    public void A_record_keeps_its_components()
    {
        var root = ParseJava("""
            record Point(int x, int y) { }
            """);
        var point = Assert.IsType<SyntaxNode>(root.Descendants().First(n => n.Text == "Point"));
        Assert.Equal(NodeKind.ClassDeclaration, point.Kind);
        Assert.Contains(point.Children, c => c is { Kind: NodeKind.Modifier, Text: "record" });
        Assert.NotNull(point.FirstChild(NodeKind.ParameterList));
        Assert.Contains(point.OfKind(NodeKind.Parameter), p => p.Text == "x");
        Assert.Contains(point.OfKind(NodeKind.Parameter), p => p.Text == "y");
    }

    [Fact]
    public void Permits_opens_the_supertype_list_without_joining_it()
    {
        var root = ParseJava("""
            sealed class Shape permits Circle, Square { }
            """);
        var shape = root.Descendants().First(n => n.Kind == NodeKind.ClassDeclaration);
        var bases = shape.Children.Where(c => c.Kind == NodeKind.TypeReference).Select(c => c.Text);
        Assert.Equal(["Circle", "Square"], bases);
        Assert.DoesNotContain(shape.Children, c => c.Text == "permits");
    }

    [Fact]
    public void A_text_block_is_one_multiline_literal()
    {
        var root = ParseJava(""""
            class T {
                String s = """
                hello
                """;
            }
            """");
        var literal = root.Descendants().First(n => n.Kind == NodeKind.StringLiteral);
        // the whole block arrives as one literal whose content spans lines - no stray statements
        Assert.Contains('\n', literal.Text);
        Assert.Contains("hello", literal.Text);
    }

    [Fact]
    public void An_arrow_switch_expression_carries_its_subject_and_sections()
    {
        var root = ParseJava("""
            class S {
                int size(Circle c) {
                    return switch (c.kind()) {
                        case SMALL -> 1;
                        default -> 2;
                    };
                }
            }
            """);
        var expression = root.Descendants().First(n => n.Kind == NodeKind.SwitchExpression);
        Assert.Contains(expression.Children, c => c.Kind == NodeKind.Invocation); // the subject
        Assert.Equal(2, expression.Children.Count(c => c.Kind == NodeKind.SwitchSection));
    }

    [Fact]
    public void An_assert_statement_keeps_condition_and_message_together()
    {
        var root = ParseJava("""
            class C {
                void go(int n) {
                    assert n > 0 : "size";
                }
            }
            """);
        var assertion = root.Descendants().First(n =>
            n.Kind == NodeKind.Jump && n.Text == "assert");
        Assert.Equal(2, assertion.Children.Count); // condition + message
    }
}
