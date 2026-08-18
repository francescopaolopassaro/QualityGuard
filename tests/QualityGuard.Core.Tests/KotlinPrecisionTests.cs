using QualityGuard.Core.Syntax;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Kotlin precision. Every case here was a false positive found on a real Kotlin codebase, and each
/// one covers a shape the language uses constantly — an extension function, a composable, a trailing
/// lambda, a lexer token that is not a credential.
/// </summary>
public class KotlinPrecisionTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "Sample.kt")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_declaration_behind_modifiers_is_recognised()
    {
        var tree = SyntaxTree.Build(
            new Core.Tokenization.SourceTokenizer(
                "private const val HASH = \"MD5\"\n",
                Core.Tokenization.BuiltInLanguages.Kotlin).Tokenize(),
            Core.Tokenization.BuiltInLanguages.Kotlin);

        var declared = tree.Root.OfKind(NodeKind.VariableDeclaration).ToList();
        Assert.Single(declared);
        Assert.Equal("HASH", declared[0].Text);
    }

    [Fact]
    public void A_class_literal_is_not_read_as_a_class_declaration()
    {
        var tree = SyntaxTree.Build(
            new Core.Tokenization.SourceTokenizer(
                "val logger = Loggers.get(ContentHashCache::class.java)\n",
                Core.Tokenization.BuiltInLanguages.Kotlin).Tokenize(),
            Core.Tokenization.BuiltInLanguages.Kotlin);

        Assert.Empty(tree.Root.OfKind(NodeKind.ClassDeclaration));
    }

    [Fact]
    public void An_extension_function_is_not_reported_for_its_receiver_type()
    {
        // the name is what follows the dot; the receiver is a type and is upper case on purpose
        Assert.Empty(Lines("fun KotlinFileContext.reportIssue(range: TextRange) {\n    log(range)\n}\n",
            "QG-KT-CNV-0003"));
        Assert.NotEmpty(Lines("fun ReportIssue(range: TextRange) {\n    log(range)\n}\n",
            "QG-KT-CNV-0003"));
    }

    [Fact]
    public void A_composable_keeps_its_upper_camel_case_name()
    {
        var code = """
            @Composable
            fun OutlinedTextField(state: TextFieldState) {
                render(state)
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-CNV-0003"));
    }

    [Fact]
    public void A_test_name_written_as_a_sentence_is_left_alone()
        => Assert.Empty(Lines("fun `reports the issue once`() {\n    check()\n}\n", "QG-KT-CNV-0003"));

    [Fact]
    public void A_trailing_lambda_after_return_is_not_unreachable_code()
    {
        var code = """
            fun getParentCall(): String? {
                return withSession { resolve() }
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-BUG-0031"));

        var real = """
            fun go(): Int {
                return 1
                log("never")
            }
            """;
        Assert.NotEmpty(Lines(real, "QG-KT-BUG-0031"));
    }

    [Fact]
    public void A_lexer_token_is_not_a_credential()
    {
        // 'token' in a parser is a piece of syntax, and this comparison protects nothing
        Assert.Empty(Lines("fun go(operationToken: Int) {\n    if (operationToken == PLUS) log()\n}\n",
            "QG-KT-SEC-0026"));
        Assert.NotEmpty(Lines("fun go(password: String) {\n    if (password == expected) grant()\n}\n",
            "QG-KT-SEC-0026"));
    }
}
