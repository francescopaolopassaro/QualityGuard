using QualityGuard.Core.Syntax;
using Xunit;

namespace QualityGuard.Core.Tests;

public class SyntaxTests
{
    [Fact]
    public void Braces_parser_finds_types_functions_and_branches()
    {
        var analysis = Analyze.File("Sample.cs", """
            class Service
            {
                public string Run(string input, int retries)
                {
                    if (retries > 0)
                    {
                        return client.Send(input);
                    }
                    return "";
                }
            }
            """);

        var root = analysis.Tree.Root;
        Assert.Single(root.OfKind(NodeKind.ClassDeclaration));
        var function = Assert.Single(SyntaxQuery.Functions(root));
        Assert.Equal("Run", function.Text);
        Assert.Equal(2, SyntaxQuery.Parameters(function).Count());
        Assert.Single(root.OfKind(NodeKind.If));
        Assert.Equal(2, root.OfKind(NodeKind.Jump).Count());
    }

    [Fact]
    public void Invocations_expose_receiver_and_arguments()
    {
        var analysis = Analyze.File("Sample.java", """
            class A {
              void go() {
                connection.prepareStatement("SELECT 1", flag);
              }
            }
            """);

        var call = Assert.Single(SyntaxQuery.InvocationsNamed(analysis.Tree.Root, "prepareStatement"));
        Assert.Equal("connection.prepareStatement", SyntaxQuery.InvokedDottedName(call));
        Assert.Equal("connection", SyntaxQuery.Receiver(call));
        Assert.Equal(2, SyntaxQuery.Arguments(call).Count);
        Assert.Equal("SELECT 1", SyntaxQuery.ConstantString(SyntaxQuery.ArgumentAt(call, 0)));
    }

    [Fact]
    public void Indentation_parser_nests_python_blocks()
    {
        var analysis = Analyze.File("sample.py", """
            def handler(request):
                if request:
                    for item in request:
                        process(item)
                return None
            """);

        var function = Assert.Single(SyntaxQuery.Functions(analysis.Tree.Root));
        Assert.Equal("handler", function.Text);
        var loop = Assert.Single(analysis.Tree.Root.OfKind(NodeKind.Loop));
        Assert.Equal(2, SyntaxQuery.NestingDepth(loop.Descendants().First(d => d.Kind == NodeKind.Block)));
    }

    [Fact]
    public void Concatenated_queries_are_recognised_as_dynamic()
    {
        var analysis = Analyze.File("Sample.cs", """
            class A { void go(string name) { run("SELECT * FROM t WHERE n = '" + name + "'"); } }
            """);

        var call = Assert.Single(SyntaxQuery.InvocationsNamed(analysis.Tree.Root, "run"));
        var argument = SyntaxQuery.ArgumentAt(call, 0);
        Assert.True(SyntaxQuery.IsDynamicallyBuilt(argument));
        Assert.Null(SyntaxQuery.ConstantString(argument));
    }

    [Fact]
    public void Parser_survives_unbalanced_input()
    {
        var analysis = Analyze.File("Sample.cs", "class A { void go( { if (");
        Assert.NotNull(analysis.Tree.Root);
    }
}
