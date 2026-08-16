using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules;

public static class BuiltInRuleRegistrar
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new TodosAndFixmesRule(),
        new TrailingCommasRule(),
        new EmptyBlockRule(),
        new TabCharacterRule(),
        new LineTooLongRule(),
        ..Languages.JavaRuleSet.All,
        ..Languages.KotlinRuleSet.All,
        ..Languages.SwiftRuleSet.All,
        ..Languages.JavaAstRuleSet.All,
        ..Languages.JavaContractRuleSet.All,
        ..Languages.JsTsRuleSet.All,
        ..Languages.JsTsAstRuleSet.All,
        ..Languages.JsTsSemanticRuleSet.All,
        ..Languages.JsTsUsageRuleSet.All,
        ..Languages.PythonRuleSet.All,
        ..Languages.PythonAstRuleSet.All,
        ..Languages.PythonRuntimeRuleSet.All,
        ..Languages.RubyRuleSet.All,
        ..Languages.GoRuleSet.All,
        ..Languages.PhpRuleSet.All,
        ..Languages.PhpAstRuleSet.All,
        ..Languages.CSharpRuleSet.All,
        ..Languages.CSharpAstRuleSet.All,
        ..Languages.CSharpApiRuleSet.All,
        ..Languages.TerraformRuleSet.All,
        ..Languages.DockerRuleSet.All,
        ..Languages.KubernetesRuleSet.All,
        ..Languages.CCRuleSet.All,
        ..Languages.ShellRuleSet.All,
        ..Languages.CssRuleSet.All,
        ..Languages.StyleSheetRuleSet.All,
        ..Languages.SqlRuleSet.All,
        ..Languages.MarkupRuleSet.All,
        ..Languages.MarkupDocumentRuleSet.All,
        ..Languages.MarkupAccessibilityRuleSet.All,
        ..Languages.RustRuleSet.All,
        ..Languages.DartRuleSet.All,
        ..Languages.JsonRuleSet.All,
        ..Languages.InfrastructureRuleSet.All,
        ..Languages.DockerfileRuleSet.All,
        ..StructuralRuleSet.All,
        ..CorrectnessRuleSet.All,
        ..RegexRuleSet.All,
        ..SecretRuleSet.All,
        ..TestQualityRuleSet.All,
        ..ApiUsageRuleSet.All,
        ..ExceptionRuleSet.All,
        ..Catalog.RuleCatalog.Rules
    ];
}

public abstract class TextualRuleBase : RuleBase
{
    protected static IEnumerable<Token> CommentsBetween(IRuleContext context)
        => context.Tokens.Where(t => t.Kind == TokenKind.Comment);
}

public sealed class TodosAndFixmesRule : TextualRuleBase
{
    public override string Key => "QG-ALL-SML-0001";
    public override string Name => "Track uses of TODO and FIXME tags";
    public override Severity Severity => Severity.Info;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages =>
    [
        "cs", "java", "js", "ts", "py", "go", "rb", "kt", "php", "c", "cpp", "sh", "rs"
    ];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in CommentsBetween(context)
                     .Where(t => t.Text.Contains("TODO", StringComparison.OrdinalIgnoreCase)
                              || t.Text.Contains("FIXME", StringComparison.OrdinalIgnoreCase)))
        {
            context.Report("Take the required action to fix the issue indicated by this comment.", token.Line);
        }
    }
}

public sealed class TrailingCommasRule : TextualRuleBase
{
    public override string Key => "QG-ALL-CNV-0001";
    public override string Name => "Trailing commas should not be used";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["cs", "java", "pb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 1; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Text != "," || tokens[i + 1].Kind != TokenKind.Symbol)
                continue;
            var next = tokens[i + 1].Text;
            if (next is ")" or "]" or "}")
                context.Report("Avoid using trailing commas in collections and arguments.", tokens[i].Line);
        }
    }
}

public sealed class EmptyBlockRule : TextualRuleBase
{
    public override string Key => "QG-ALL-SML-0002";
    public override string Name => "Nested blocks of code should not be left empty";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages =>
    [
        "cs", "java", "js", "ts", "py", "rb", "kt", "php", "c", "cpp", "rs"
    ];

    /// <summary>Keywords whose block is nested inside a body rather than being one.</summary>
    private static readonly string[] NestingKeywords =
    [
        "if", "else", "for", "foreach", "while", "do", "switch", "try", "catch", "finally",
        "using", "lock", "synchronized", "unless", "elsif", "elif"
    ];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 1; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Text != "{" || tokens[i + 1].Text != "}")
                continue;
            // exclude an object literal or an initializer
            if (tokens[i - 1].Text is "=" or ":" or "return" or "(" or ",")
                continue;
            // The rule is about a block nested inside a body, and only a control keyword opens one.
            // The body of a method or a constructor is a different question, answered on the tree by
            // the empty-body rule — and 'ReportingContext(...) : this(...) { }' is how C# forwards a
            // constructor, which is neither.
            if (!OpensNestedBlock(tokens, i))
                continue;

            context.Report("Either remove or fill this block of code.", tokens[i].Line);
        }
    }

    private static bool OpensNestedBlock(IReadOnlyList<Token> tokens, int brace)
    {
        var previous = tokens[brace - 1];
        if (NestingKeywords.Contains(previous.Text, StringComparer.OrdinalIgnoreCase))
            return true;
        if (previous.Text != ")")
            return false;

        // walk back to the parenthesis this one closes and look at the word in front of it
        var depth = 0;
        for (var i = brace - 1; i >= 0 && brace - i < 512; i--)
        {
            var text = tokens[i].Text;
            if (text == ")")
                depth++;
            else if (text == "(")
            {
                depth--;
                if (depth != 0)
                    continue;
                return i > 0 && NestingKeywords.Contains(tokens[i - 1].Text, StringComparer.OrdinalIgnoreCase);
            }
        }
        return false;
    }
}

public sealed class TabCharacterRule : TextualRuleBase
{
    public override string Key => "QG-ALL-CNV-0002";
    public override string Name => "Replace all tab characters in this file by sequences of white-spaces";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages =>
    [
        "cs", "java", "js", "ts", "py", "rb", "kt", "php", "c", "cpp", "sh", "rs"
    ];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (lines[i].Contains('\t'))
                context.Report("Replace all tab characters in this file by sequences of white-spaces.", i + 1);
        }
    }
}

public sealed class LineTooLongRule : TextualRuleBase
{
    public override string Key => "QG-ALL-CNV-0003";
    public override string Name => "Lines should not be too long";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => [];
    private const int MaxLength = 200;

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (lines[i].Length > MaxLength)
                context.Report($"Split this {lines[i].Length} characters long line (which is greater than {MaxLength} authorized).", i + 1);
        }
    }
}