using QualityGuard.Core.Syntax;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>Grammar coverage for the indentation-driven Python parser.</summary>
public class PythonParserTests
{
    private static SyntaxNode Parse(string code) => Analyze.File("sample.py", code).Tree.Root;

    [Fact]
    public void Modules_classes_and_functions_are_recognised()
    {
        var root = Parse("""
            import os
            from typing import Optional

            class Service:
                def __init__(self, name):
                    self.name = name

                def load(self, key: str) -> Optional[str]:
                    if key in self.cache:
                        return self.cache[key]
                    return None
            """);

        Assert.Equal(2, root.OfKind(NodeKind.ImportDeclaration).Count());
        var type = Assert.Single(root.OfKind(NodeKind.ClassDeclaration));
        Assert.Equal("Service", type.Text);
        Assert.Equal(2, type.OfKind(NodeKind.FunctionDeclaration).Count());

        var load = root.OfKind(NodeKind.FunctionDeclaration).Last();
        Assert.Equal("load", load.Text);
        Assert.Equal(["key"], SyntaxQuery.Parameters(load).Select(p => p.Text).ToArray());
        Assert.Single(load.OfKind(NodeKind.If));
        Assert.Equal(2, load.OfKind(NodeKind.Jump).Count());
    }

    [Fact]
    public void Indentation_defines_the_nesting()
    {
        var root = Parse("""
            def handler(request):
                for item in request:
                    if item:
                        process(item)
                return None
            """);

        var function = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        var loop = Assert.Single(function.OfKind(NodeKind.Loop));
        var branch = Assert.Single(loop.OfKind(NodeKind.If));
        Assert.Single(branch.OfKind(NodeKind.Invocation));
        // the return belongs to the function, not to the loop
        Assert.Contains(function.FirstChild(NodeKind.Block)!.Children, c => c.Kind == NodeKind.Jump);
    }

    [Fact]
    public void Branch_chains_stay_together()
    {
        var root = Parse("""
            def pick(value):
                if value > 10:
                    return "high"
                elif value > 5:
                    return "medium"
                else:
                    return "low"
            """);

        var head = root.OfKind(NodeKind.If).First();
        Assert.Contains(head.Children, c => c.Kind == NodeKind.If);
        Assert.Contains(head.OfKind(NodeKind.Else), _ => true);
    }

    [Fact]
    public void Decorators_belong_to_the_declaration_below()
    {
        var root = Parse("""
            @app.route("/users")
            @login_required
            def users():
                return render()
            """);

        var function = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        Assert.Equal(2, function.ChildrenOf(NodeKind.Attribute).Count());
    }

    [Fact]
    public void Formatted_strings_expose_their_holes()
    {
        var root = Parse("""
            def query(name):
                cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
            """);

        var interpolated = Assert.Single(root.OfKind(NodeKind.InterpolatedString));
        var hole = Assert.Single(interpolated.OfKind(NodeKind.Interpolation));
        Assert.Contains(hole.OfKind(NodeKind.Identifier), i => i.Text == "name");
    }

    [Fact]
    public void Keyword_arguments_are_not_assignments()
    {
        var root = Parse("""
            def run(command):
                subprocess.run(command, shell=True, check=False)
            """);

        Assert.Empty(root.OfKind(NodeKind.Assignment));
        Assert.Equal(2, root.OfKind(NodeKind.NamedArgument).Count());
    }

    [Fact]
    public void Try_blocks_keep_their_handlers()
    {
        var root = Parse("""
            def load(path):
                try:
                    return open(path).read()
                except OSError as error:
                    log(error)
                finally:
                    cleanup()
            """);

        var attempt = Assert.Single(root.OfKind(NodeKind.Try));
        Assert.Single(attempt.OfKind(NodeKind.Catch));
        Assert.Single(attempt.OfKind(NodeKind.Finally));
    }
}
