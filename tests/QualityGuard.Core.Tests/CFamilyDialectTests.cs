using QualityGuard.Core.Syntax;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>Grammar coverage for the Java and Go dialects of the C-family parser.</summary>
public class CFamilyDialectTests
{
    private static SyntaxNode Java(string code) => Analyze.File("Sample.java", code).Tree.Root;

    private static SyntaxNode Go(string code) => Analyze.File("sample.go", code).Tree.Root;

    [Fact]
    public void Java_types_annotations_and_bases_are_understood()
    {
        var root = Java("""
            package app;

            import java.util.List;

            @Component
            public class Service extends Base implements Runnable {
                private final List<Map<String, Integer>> cache = new ArrayList<>();

                @Override
                public void run() throws IOException {
                    if (cache instanceof List<?> list) {
                        process(list);
                    }
                }
            }
            """);

        Assert.Single(root.OfKind(NodeKind.PackageDeclaration));
        var type = Assert.Single(root.OfKind(NodeKind.ClassDeclaration));
        Assert.Equal("Service", type.Text);
        Assert.Contains(type.OfKind(NodeKind.Attribute), a => a.Text == "Component");
        Assert.Single(type.OfKind(NodeKind.FieldDeclaration));
        var method = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        Assert.Equal("run", method.Text);
        Assert.Single(method.OfKind(NodeKind.If));
        Assert.Empty(root.OfKind(NodeKind.Unknown));
    }

    [Fact]
    public void Go_declarations_are_understood()
    {
        var root = Go("""
            package main

            import (
                "fmt"
                "os"
            )

            type Config struct {
                Name  string
                Ports []int
            }

            func (c *Config) Describe(prefix string) (string, error) {
                var parts []string
                for _, port := range c.Ports {
                    parts = append(parts, fmt.Sprintf("%s:%d", prefix, port))
                }
                if len(parts) == 0 {
                    return "", os.ErrInvalid
                }
                return parts[0], nil
            }
            """);

        Assert.Single(root.OfKind(NodeKind.PackageDeclaration));
        Assert.Equal(2, root.OfKind(NodeKind.ImportDeclaration).Count(i => i.Text.Length > 0 && i.Text != "imports"));

        var type = Assert.Single(root.OfKind(NodeKind.ClassDeclaration));
        Assert.Equal("Config", type.Text);
        Assert.Equal(2, type.OfKind(NodeKind.FieldDeclaration).Count());

        var function = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        Assert.Equal("Describe", function.Text);
        var parameter = Assert.Single(SyntaxQuery.Parameters(function));
        Assert.Equal("prefix", parameter.Text);
        Assert.Single(root.OfKind(NodeKind.Loop));
        Assert.Single(root.OfKind(NodeKind.If));
    }

    [Fact]
    public void Go_composite_literals_do_not_open_blocks()
    {
        var root = Go("""
            package main

            func build(items []Item) Result {
                result := Result{
                    Name:  "x",
                    Items: items,
                }
                if len(items) > 0 {
                    return result
                }
                return Result{}
            }
            """);

        Assert.Equal(2, root.OfKind(NodeKind.ObjectCreation).Count());
        Assert.Single(root.OfKind(NodeKind.If));
        var function = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        Assert.Equal(2, function.OfKind(NodeKind.Jump).Count());
    }

    [Fact]
    public void Go_multi_value_returns_stay_in_the_jump()
    {
        var root = Go("""
            package main

            func load() (Value, error) {
                if broken {
                    return nil, errors.New("broken")
                }
                return value, nil
            }
            """);

        var block = root.OfKind(NodeKind.Block).Last();
        Assert.All(block.Children, child => Assert.True(child.Kind is NodeKind.If or NodeKind.Jump));
    }

    [Fact]
    public void Go_type_assertions_are_expressions()
    {
        var root = Go("""
            package main

            func check(node ast.Node) {
                spec, ok := node.(*ast.TypeSpec)
                if !ok {
                    return
                }
                use(spec)
            }
            """);

        Assert.Single(root.OfKind(NodeKind.Cast));
        Assert.Empty(root.OfKind(NodeKind.Unknown));
    }
}
