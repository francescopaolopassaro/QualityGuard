using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules;

public static class BuiltInRuleRegistrar
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new TodosAndFixmesRuleCs(),
        new TodosAndFixmesRuleJava(),
        new TodosAndFixmesRuleKotlin(),
        new TodosAndFixmesRuleJs(),
        new TodosAndFixmesRulePython(),
        new TodosAndFixmesRulePhp(),
        new TodosAndFixmesRuleGo(),
        new TodosAndFixmesRuleHtml(),
        new TodosAndFixmesRuleXml(),
        new TodosAndFixmesRuleCss(),
        new TodosAndFixmesRuleTerraform(),
        new TodosAndFixmesRuleDockerfile(),
        new TodosAndFixmesRuleKubernetes(),
        new TodosAndFixmesRuleCloudFormation(),
        new TodosAndFixmesRuleJson(),
        new TodosAndFixmesRuleDart(),
        new TodosAndFixmesRuleSwift(),
        new TrailingCommasRuleCs(),
        new TrailingCommasRuleJava(),
        new EmptyBlockRuleCs(),
        new EmptyBlockRuleJava(),
        new EmptyBlockRuleKotlin(),
        new EmptyBlockRuleJs(),
        new EmptyBlockRulePython(),
        new EmptyBlockRulePhp(),
        new TabCharacterRuleCs(),
        new TabCharacterRuleKotlin(),
        new TabCharacterRuleJs(),
        new TabCharacterRulePython(),
        new TabCharacterRulePhp(),
        new LineTooLongRuleJava(),
        new LineTooLongRuleJs(),
        new LineTooLongRuleDart(),
        ..Languages.JavaRuleSet.All,
        ..Languages.KotlinRuleSet.All,
        ..Languages.SwiftRuleSet.All,
        ..Languages.JavaAstRuleSet.All,
        ..Languages.JavaContractRuleSet.All,
        ..Languages.JavaMeasuredRuleSet.All,
        ..Languages.JavaTestRuleSet.All,
        ..Languages.JsTsRuleSet.All,
        ..Languages.JsTsAstRuleSet.All,
        ..Languages.JsTsSemanticRuleSet.All,
        ..Languages.JsTsUsageRuleSet.All,
        ..Languages.JsTsMeasuredRuleSet.All,
        ..Languages.JsTsModernRuleSet.All,
        ..Languages.KotlinMeasuredRuleSet.All,
        ..Languages.OrmRuleSet.All,
        ..Languages.PythonRuleSet.All,
        ..Languages.PythonClassRuleSet.All,
        ..Languages.PythonAstRuleSet.All,
        ..Languages.PythonRuntimeRuleSet.All,
        ..Languages.PythonMeasuredRuleSet.All,
        ..Languages.RubyRuleSet.All,
        ..Languages.GoRuleSet.All,
        ..Languages.PhpRuleSet.All,
        ..Languages.PhpAstRuleSet.All,
        ..Languages.CSharpRuleSet.All,
        ..Languages.CSharpAstRuleSet.All,
        ..Languages.CSharpApiRuleSet.All,
        ..Languages.CSharpGapRuleSet.All,
        ..Languages.TerraformRuleSet.All,
        ..Languages.DockerRuleSet.All,
        ..Languages.KubernetesRuleSet.All,
        ..Languages.ClusterRuleSet.All,
        ..Languages.CloudRuleSet.All,
        ..Languages.CloudSecurityRuleSet.All,
        ..Languages.PhpPlatformRuleSet.All,
        ..Languages.XmlPlatformRuleSet.All,
        ..Languages.KotlinAndroidRuleSet.All,
        ..Languages.PythonCloudRuleSet.All,
        ..Languages.ClusterSecurityRuleSet.All,
        ..Languages.CloudFormationSecurityRuleSet.All,
        ..Languages.CloudStorageRuleSet.All,
        ..Languages.JsTsPackRuleSet.All,
        ..Languages.BlazorRuleSet.All,
        ..Languages.AspNetRuleSet.All,
        ..Languages.XamlRuleSet.All,
        ..Languages.DotNetFrameworkRuleSet.All,
        ..SharedCheckSet.All,
        ..SecurityCheckSet.All,
        ..Languages.CCRuleSet.All,
        ..Languages.ShellRuleSet.All,
        ..Languages.CssRuleSet.All,
        ..Languages.StyleSheetRuleSet.All,
        ..Languages.SqlRuleSet.All,
        ..Languages.MarkupRuleSet.All,
        ..Languages.MarkupDocumentRuleSet.All,
        ..Languages.MarkupAccessibilityRuleSet.All,
        ..Languages.RustRuleSet.All,
        ..Languages.RustTreeRuleSet.All,
        ..Languages.CSharpVbGapRuleSet.All,
        ..Languages.JavaGapRuleSet.All,
        ..Languages.PhpGapRuleSet.All,
        ..Languages.PythonGapRuleSet.All,
        ..Languages.PythonGapRuleSet2.All,
        ..Languages.CssGapRuleSet.All,
        ..Languages.VbNetGapRuleSet.All,
        ..Languages.HtmlAriaRuleSet.All,
        ..Languages.PythonTypeGapRuleSet.All,
        ..Languages.ScalaRuleSet.All,
        ..Languages.DartRuleSet.All,
        ..Languages.JsonRuleSet.All,
        ..Languages.InfrastructureRuleSet.All,
        ..Languages.InfrastructureGapRuleSet.All,
        ..Languages.XmlDescriptorRuleSet.All,
        ..Languages.DockerfileRuleSet.All,
        ..Languages.DockerSecurityRuleSet.All,
        ..StructuralRuleSet.All,
        ..CorrectnessRuleSet.All,
        ..RegexRuleSet.All,
        ..RegexStructureRuleSet.All,
        ..RegexTreeRuleSet.All,
        ..SecretRuleSet.All,
        ..Languages.SecretGapRuleSet.All,
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

public abstract class TodosAndFixmesRule : TextualRuleBase
{
    public override string Name => "Track uses of TODO and FIXME tags";
    public override Severity Severity => Severity.Info;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages =>
    [
        "cs", "java", "js", "ts", "py", "go", "rb", "kt", "php", "c", "cpp", "sh", "rs",
        // a marker left in a template or a deployment file is the same promise to come back
        "html", "xml", "css", "tf", "dk", "k8", "cf", "json", "dart", "swift"
    ];

    /// <summary>
    /// The marker has to stand as a word, and in the spelling a marker is written in. Matched as a
    /// substring without case, 'TODO' is inside the Italian 'metodo' and the Spanish 'todo', so every
    /// documentation comment on a real code base counted as an unfinished task.
    /// </summary>
    private static readonly System.Text.RegularExpressions.Regex Marker =
        new(@"\b(TODO|FIXME|HACK|XXX)\b|\b(todo|fixme|hack)\s*[:(]",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    public override void Execute(IRuleContext context)
    {
        foreach (var token in CommentsBetween(context).Where(t => Marker.IsMatch(t.Text)))
        {
            context.Report("Take the required action to fix the issue indicated by this comment.", token.Line);
        }
    }
}

public sealed class TodosAndFixmesRuleRuby : TodosAndFixmesRule
{
    public override string Key => "QG-ALL-SML-0001";
    public override string[] Languages => ["rb"];
}

public sealed class TodosAndFixmesRuleCs : TodosAndFixmesRule
{
    public override string Key => "QG-CS-SML-0503";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class TodosAndFixmesRuleJava : TodosAndFixmesRule
{
    public override string Key => "QG-JV-SML-0464";
    public override string[] Languages => ["java"];
}

public sealed class TodosAndFixmesRuleKotlin : TodosAndFixmesRule
{
    public override string Key => "QG-KT-SML-0086";
    public override string[] Languages => ["kt"];
}

public sealed class TodosAndFixmesRuleJs : TodosAndFixmesRule
{
    public override string Key => "QG-JS-SML-0380";
    public override string[] Languages => ["js", "ts"];
}

public sealed class TodosAndFixmesRulePython : TodosAndFixmesRule
{
    public override string Key => "QG-PY-SML-0259";
    public override string[] Languages => ["py"];
}

public sealed class TodosAndFixmesRulePhp : TodosAndFixmesRule
{
    public override string Key => "QG-PP-SML-0124";
    public override string[] Languages => ["php"];
}

public sealed class TodosAndFixmesRuleGo : TodosAndFixmesRule
{
    public override string Key => "QG-GO-SML-0038";
    public override string[] Languages => ["go"];
}

public sealed class TodosAndFixmesRuleHtml : TodosAndFixmesRule
{
    public override string Key => "QG-HTML-SML-0147";
    public override string[] Languages => ["html"];
}

public sealed class TodosAndFixmesRuleXml : TodosAndFixmesRule
{
    public override string Key => "QG-XML-SML-0062";
    public override string[] Languages => ["xml"];
}

public sealed class TodosAndFixmesRuleCss : TodosAndFixmesRule
{
    public override string Key => "QG-CSS-SML-0075";
    public override string[] Languages => ["css"];
}

public sealed class TodosAndFixmesRuleTerraform : TodosAndFixmesRule
{
    public override string Key => "QG-TF-SML-0054";
    public override string[] Languages => ["tf"];
}

public sealed class TodosAndFixmesRuleDockerfile : TodosAndFixmesRule
{
    public override string Key => "QG-DK-SML-0068";
    public override string[] Languages => ["dk"];
}

public sealed class TodosAndFixmesRuleKubernetes : TodosAndFixmesRule
{
    public override string Key => "QG-K8-SML-0062";
    public override string[] Languages => ["k8"];
}

public sealed class TodosAndFixmesRuleCloudFormation : TodosAndFixmesRule
{
    public override string Key => "QG-CF-SML-0055";
    public override string[] Languages => ["cf"];
}

public sealed class TodosAndFixmesRuleJson : TodosAndFixmesRule
{
    public override string Key => "QG-JSON-SML-0050";
    public override string[] Languages => ["json"];
}

public sealed class TodosAndFixmesRuleDart : TodosAndFixmesRule
{
    public override string Key => "QG-DART-SML-0054";
    public override string[] Languages => ["dart"];
}

public sealed class TodosAndFixmesRuleSwift : TodosAndFixmesRule
{
    public override string Key => "QG-SW-SML-0054";
    public override string[] Languages => ["swift"];
}


public abstract class TrailingCommasRule : TextualRuleBase
{
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

public sealed class TrailingCommasRuleCs : TrailingCommasRule
{
    public override string Key => "QG-CS-CNV-0012";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class TrailingCommasRuleJava : TrailingCommasRule
{
    public override string Key => "QG-JV-CNV-0004";
    public override string[] Languages => ["java"];
}







public abstract class EmptyBlockRule : TextualRuleBase
{
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
        // 'catch' is deliberately absent: an ignored exception is a defect of its own, and the rule
        // about it says more than "this block is empty"
        "if", "else", "for", "foreach", "while", "do", "switch", "try", "finally",
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
            // the empty-body rule â€” and 'ReportingContext(...) : this(...) { }' is how C# forwards a
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

public sealed class EmptyBlockRuleCs : EmptyBlockRule
{
    public override string Key => "QG-CS-SML-0504";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class EmptyBlockRuleJava : EmptyBlockRule
{
    public override string Key => "QG-JV-SML-0465";
    public override string[] Languages => ["java"];
}

public sealed class EmptyBlockRuleKotlin : EmptyBlockRule
{
    public override string Key => "QG-KT-SML-0087";
    public override string[] Languages => ["kt"];
}

public sealed class EmptyBlockRuleJs : EmptyBlockRule
{
    public override string Key => "QG-JS-SML-0381";
    public override string[] Languages => ["js", "ts"];
}

public sealed class EmptyBlockRulePython : EmptyBlockRule
{
    public override string Key => "QG-PY-SML-0260";
    public override string[] Languages => ["py"];
}

public sealed class EmptyBlockRulePhp : EmptyBlockRule
{
    public override string Key => "QG-PP-SML-0125";
    public override string[] Languages => ["php"];
}



public abstract class TabCharacterRule : TextualRuleBase
{
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

public sealed class TabCharacterRuleCs : TabCharacterRule
{
    public override string Key => "QG-CS-CNV-0013";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class TabCharacterRuleJava : TabCharacterRule
{
    public override string Key => "QG-JV-CNV-0005";
    public override string[] Languages => ["java"];
}

public sealed class TabCharacterRuleKotlin : TabCharacterRule
{
    public override string Key => "QG-KT-CNV-0007";
    public override string[] Languages => ["kt"];
}

public sealed class TabCharacterRuleJs : TabCharacterRule
{
    public override string Key => "QG-JS-CNV-0005";
    public override string[] Languages => ["js", "ts"];
}

public sealed class TabCharacterRulePython : TabCharacterRule
{
    public override string Key => "QG-PY-CNV-0012";
    public override string[] Languages => ["py"];
}

public sealed class TabCharacterRulePhp : TabCharacterRule
{
    public override string Key => "QG-PP-CNV-0003";
    public override string[] Languages => ["php"];
}



public abstract class LineTooLongRule : TextualRuleBase
{
    public override string Name => "Lines should not be too long";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => [];
    private const int MaxLength = 200;

    /// <summary>
    /// Formats where a long line is not a choice anyone made. A data file holds one record per line,
    /// a stylesheet is minified by a tool, a query is generated: nobody is going to split them, and a
    /// rule that asks for it buries the findings that matter under the ones that do not.
    /// </summary>
    private static readonly string[] NotProse =
        ["json", "csv", "xml", "yaml", "yml", "css", "scss", "sass", "less", "html", "htm", "svg",
         "sql", "md", "txt", "resx", "config", "props", "targets", "raz", "razor", "cshtml", "vbhtml",
         "xaml", "aspx", "ascx", "jsp", "vue"];

    public override void Execute(IRuleContext context)
    {
        if (NotProse.Contains(context.Language.LanguageKey, StringComparer.OrdinalIgnoreCase))
            return;

        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (lines[i].Length > MaxLength)
                context.Report($"Split this {lines[i].Length} characters long line (which is greater than {MaxLength} authorized).", i + 1);
        }
    }
}

public sealed class LineTooLongRuleCs : LineTooLongRule
{
    public override string Key => "QG-CS-CNV-0014";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class LineTooLongRuleJava : LineTooLongRule
{
    public override string Key => "QG-JV-CNV-0006";
    public override string[] Languages => ["java"];
}

public sealed class LineTooLongRuleKotlin : LineTooLongRule
{
    public override string Key => "QG-KT-CNV-0008";
    public override string[] Languages => ["kt"];
}

public sealed class LineTooLongRuleJs : LineTooLongRule
{
    public override string Key => "QG-JS-CNV-0006";
    public override string[] Languages => ["js", "ts"];
}

public sealed class LineTooLongRulePython : LineTooLongRule
{
    public override string Key => "QG-PY-CNV-0013";
    public override string[] Languages => ["py"];
}

public sealed class LineTooLongRulePhp : LineTooLongRule
{
    public override string Key => "QG-PP-CNV-0004";
    public override string[] Languages => ["php"];
}

public sealed class LineTooLongRuleGo : LineTooLongRule
{
    public override string Key => "QG-GO-CNV-0005";
    public override string[] Languages => ["go"];
}

public sealed class LineTooLongRuleDart : LineTooLongRule
{
    public override string Key => "QG-DART-CNV-0004";
    public override string[] Languages => ["dart"];
}
