using QualityGuard.Core.Syntax;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// PHP goes through the C-family parser with its own dialect, which is what gives it a real tree and
/// with it every shared structural rule. Each case here was a shape that used to break the parse.
/// </summary>
public class PhpParserTests
{
    private static SyntaxNode Parse(string code) => Analyze.File("Sample.php", code).Tree.Root;

    [Fact]
    public void A_class_with_properties_and_methods_is_read_as_declarations()
    {
        var root = Parse("""
            <?php
            namespace App;

            class UserService
            {
                private $repo;
                private ?Logger $logger = null;

                public function __construct(Repo $repo)
                {
                    $this->repo = $repo;
                }

                public function find(int $id): ?User
                {
                    return $this->repo->byId($id);
                }
            }
            """);

        var type = Assert.Single(root.OfKind(NodeKind.ClassDeclaration));
        Assert.Equal("UserService", type.Text);
        Assert.Equal(2, type.OfKind(NodeKind.FieldDeclaration).Count());
        Assert.Single(type.OfKind(NodeKind.ConstructorDeclaration));

        var method = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        Assert.Equal("find", method.Text);
        // the nullable return type used to detach the body from its method
        Assert.NotNull(SyntaxQuery.Body(method));
        Assert.Single(SyntaxQuery.Parameters(method));
    }

    [Fact]
    public void The_open_marker_does_not_swallow_the_first_declaration()
    {
        var root = Parse("""
            <?php
            namespace App;

            class Thing {}
            """);

        Assert.Single(root.OfKind(NodeKind.PackageDeclaration));
        Assert.Single(root.OfKind(NodeKind.ClassDeclaration));
        Assert.Empty(root.OfKind(NodeKind.Unknown));
    }

    [Fact]
    public void An_import_is_one_statement()
    {
        var root = Parse("""
            <?php
            use Drupal\Core\Form;
            require_once 'Zend/Mail.php';

            $value = 1;
            """);

        Assert.Equal(2, root.OfKind(NodeKind.ImportDeclaration).Count());
        // the import used to break into several nodes, which read as several statements on one line;
        // PHP has no declaration keyword, so the assignment below is the only statement left
        Assert.Single(root.OfKind(NodeKind.ExpressionStatement));
    }

    [Fact]
    public void A_static_member_access_is_one_expression()
    {
        var root = Parse("""
            <?php
            class Mail
            {
                public static function reset()
                {
                    self::$transport = null;
                }
            }
            """);

        var body = SyntaxQuery.Body(root.OfKind(NodeKind.FunctionDeclaration).First())!;
        Assert.Single(body.Children);
        Assert.Contains(body.OfKind(NodeKind.MemberSelect), m => m.Text.Contains("transport"));
    }

    [Fact]
    public void A_foreach_keeps_its_body()
    {
        var root = Parse("""
            <?php
            function total(array $rows): int
            {
                $sum = 0;
                foreach ($rows as $key => $row) {
                    $sum += $row->amount;
                }
                return $sum;
            }
            """);

        var loop = Assert.Single(root.OfKind(NodeKind.Loop));
        Assert.Equal("foreach", loop.Text);
        Assert.NotNull(loop.FirstChild(NodeKind.Block));
    }

    [Fact]
    public void A_file_that_repeats_one_sequence_thousands_of_times_still_finishes()
    {
        // a real project ships a file with six thousand concatenations in one statement; comparing
        // every pair of occurrences used to make the scan quadratic and the run never ended
        var expression = string.Join(".", Enumerable.Range(0, 2000).Select(_ => "\"1\""));
        var watch = System.Diagnostics.Stopwatch.StartNew();

        var analysis = Analyze.File("big.php", "<?php\n$a = " + expression + ";\n");

        Assert.True(watch.ElapsedMilliseconds < 5000,
            $"analysis took {watch.ElapsedMilliseconds} ms");
        Assert.NotNull(analysis.Tree);
    }
}
