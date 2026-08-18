using QualityGuard.Core.Syntax;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Java precision. Every case here was a false positive on a real Java codebase, and each covers a
/// shape the language uses everywhere: an anonymous class, a statement lambda, a local initialised
/// from a method of the same name, an abstract declaration.
/// </summary>
public class JavaPrecisionTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "Sample.java")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void An_anonymous_class_body_is_parsed_as_a_type_body()
    {
        var code = """
            package demo;

            public class Anon {
              public static final Wrapper NOOP = new Wrapper(null) {
                @Override
                public void addUnique(String text) {
                  log(text);
                }
              };
            }
            """;
        var tree = SyntaxTree.Build(
            new Core.Tokenization.SourceTokenizer(code, Core.Tokenization.BuiltInLanguages.Java).Tokenize(),
            Core.Tokenization.BuiltInLanguages.Java);

        var declared = tree.Root.OfKind(NodeKind.FunctionDeclaration).ToList();
        Assert.Contains(declared, m => m.Text == "addUnique");
    }

    [Fact]
    public void An_object_initializer_is_still_an_initializer()
    {
        var tree = SyntaxTree.Build(
            new Core.Tokenization.SourceTokenizer(
                "class A { void f() { var p = new Point { X = 1, Y = 2 }; } }\n",
                Core.Tokenization.BuiltInLanguages.CSharp).Tokenize(),
            Core.Tokenization.BuiltInLanguages.CSharp);

        Assert.NotEmpty(tree.Root.OfKind(NodeKind.ObjectInitializer));
    }

    [Fact]
    public void A_statement_lambda_over_a_void_call_is_left_alone()
    {
        var code = """
            package demo;

            public class A {
              void go(Scanner s) {
                s.forEach((i, r) -> simpleScan(i, r));
              }

              void simpleScan(int i, int r) {
                log(i);
              }
            }
            """;
        Assert.Empty(Lines(code, "QG-JV-BUG-0239"));
    }

    [Fact]
    public void A_local_initialised_from_a_method_of_the_same_name_is_not_a_self_assignment()
    {
        var code = """
            package demo;

            public class A {
              void visit(Tree tree) {
                boolean isSubscribed = isSubscribed(tree);
                use(isSubscribed);
              }
            }
            """;
        Assert.Empty(Lines(code, "QG-JV-BUG-0207"));

        var real = """
            package demo;

            public class A {
              void go(int bound) {
                bound = bound;
              }
            }
            """;
        Assert.NotEmpty(Lines(real, "QG-JV-BUG-0207"));
    }

    [Fact]
    public void A_parameter_of_a_declaration_without_a_body_is_not_unused()
    {
        // an abstract method has nothing to use its parameters in, and a default hook is written
        // empty on purpose — both declare a contract for subclasses
        Assert.Empty(Lines("package demo;\npublic abstract class A {\n"
                           + "  protected abstract boolean matches(ModifiersTree modifier);\n}\n",
            "QG-JV-SML-0458"));
        Assert.Empty(Lines("package demo;\npublic class A {\n"
                           + "  public void visitNode(Tree tree) {\n  }\n}\n", "QG-JV-SML-0458"));
        Assert.NotEmpty(Lines("package demo;\npublic class A {\n"
                              + "  public void go(Tree tree) {\n    log(\"x\");\n  }\n}\n",
            "QG-JV-SML-0458"));
    }
    [Fact]
    public void Only_a_private_method_is_asked_to_become_static()
    {
        // an override or an interface implementation is somebody's contract, not a local choice
        var contract = """
            package demo;

            class A {
              @Override
              public String toString() {
                return "a";
              }

              protected void hook() {
                helper();
              }

              static void helper() {}
            }
            """;
        Assert.Empty(Lines(contract, "QG-JV-SML-0492"));

        var local = """
            package demo;

            class A {
              private int twice(int n) {
                return n * 2;
              }
            }
            """;
        Assert.NotEmpty(Lines(local, "QG-JV-SML-0492"));
    }

    [Fact]
    public void An_empty_body_that_explains_itself_is_left_alone()
    {
        var documented = """
            package demo;

            class A {
              void onEvent() {
                // nothing to do: the framework only needs the hook to exist
              }
            }
            """;
        Assert.Empty(Lines(documented, "QG-JV-SML-0462"));

        var silent = """
            package demo;

            class A {
              void onEvent() {
              }
            }
            """;
        Assert.NotEmpty(Lines(silent, "QG-JV-SML-0462"));
    }

    [Fact]
    public void An_empty_constructor_is_not_a_finding()
    {
        var code = """
            package demo;

            class A {
              A() {}
            }
            """;
        Assert.Empty(Lines(code, "QG-JV-SML-0462"));
    }

}
