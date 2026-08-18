using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Constructs that are legal, common, and mean something different from what they look like: a number
/// that is not the number it spells, a call that ends the process from inside a library, a value that
/// was never produced. They cross every language, so they live here rather than in a language set.
/// </summary>
public static class ApiUsageRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new OctalLiteralRuleCs(),
        new OctalLiteralRuleJava(),
        new OctalLiteralRuleKotlin(),
        new OctalLiteralRuleJs(),
        new OctalLiteralRulePython(),
        new OctalLiteralRulePhp(),
        new OctalLiteralRuleGo(),
        new OctalLiteralRuleDart(),
        new OctalLiteralRuleRuby(),
        new OctalLiteralRuleSwift(),
        new OctalLiteralRuleCss(),
        new OctalLiteralRuleHtml(),
        new OctalLiteralRuleXml(),
        new OctalLiteralRuleTerraform(),
        new OctalLiteralRuleDockerfile(),
        new OctalLiteralRuleKubernetes(),
        new OctalLiteralRuleCloudFormation(),
        new OctalLiteralRuleJson(),
        new ProcessExitInLibraryRuleCs(),
        new ProcessExitInLibraryRuleJava(),
        new ProcessExitInLibraryRuleKotlin(),
        new ProcessExitInLibraryRuleJs(),
        new ProcessExitInLibraryRulePython(),
        new ProcessExitInLibraryRulePhp(),
        new ProcessExitInLibraryRuleGo(),
        new ProcessExitInLibraryRuleDart(),
        new ProcessExitInLibraryRuleRuby(),
        new ProcessExitInLibraryRuleSwift(),
        new ProcessExitInLibraryRuleCss(),
        new ProcessExitInLibraryRuleHtml(),
        new ProcessExitInLibraryRuleXml(),
        new ProcessExitInLibraryRuleTerraform(),
        new ProcessExitInLibraryRuleDockerfile(),
        new ProcessExitInLibraryRuleKubernetes(),
        new ProcessExitInLibraryRuleCloudFormation(),
        new ProcessExitInLibraryRuleJson(),
        new CsStandardOutputForLoggingRule(),
        new JsStandardOutputForLoggingRule(),
        new JavaStandardOutputForLoggingRule(),
        new GoStandardOutputForLoggingRule(),
        new StandardOutputForLoggingRuleRuby(),
        new StandardOutputForLoggingRuleSwift(),
        new StandardOutputForLoggingRuleCss(),
        new StandardOutputForLoggingRuleHtml(),
        new StandardOutputForLoggingRuleXml(),
        new StandardOutputForLoggingRuleTerraform(),
        new StandardOutputForLoggingRuleDockerfile(),
        new StandardOutputForLoggingRuleKubernetes(),
        new StandardOutputForLoggingRuleCloudFormation(),
        new StandardOutputForLoggingRuleJson(),
        new StandardOutputForLoggingRuleDart(),
        new WildcardImportRuleCs(),
        new WildcardImportRuleJava(),
        new WildcardImportRuleKotlin(),
        new WildcardImportRuleJs(),
        new WildcardImportRulePython(),
        new WildcardImportRulePhp(),
        new WildcardImportRuleGo(),
        new WildcardImportRuleDart(),
        new WildcardImportRuleRuby(),
        new WildcardImportRuleSwift(),
        new WildcardImportRuleCss(),
        new WildcardImportRuleHtml(),
        new WildcardImportRuleXml(),
        new WildcardImportRuleTerraform(),
        new WildcardImportRuleDockerfile(),
        new WildcardImportRuleKubernetes(),
        new WildcardImportRuleCloudFormation(),
        new WildcardImportRuleJson(),
        new SideEffectInsideExpressionRuleCs(),
        new SideEffectInsideExpressionRuleJava(),
        new SideEffectInsideExpressionRuleKotlin(),
        new SideEffectInsideExpressionRuleJs(),
        new SideEffectInsideExpressionRulePython(),
        new SideEffectInsideExpressionRulePhp(),
        new SideEffectInsideExpressionRuleGo(),
        new SideEffectInsideExpressionRuleDart(),
        new SideEffectInsideExpressionRuleRuby(),
        new SideEffectInsideExpressionRuleSwift(),
        new SideEffectInsideExpressionRuleCss(),
        new SideEffectInsideExpressionRuleHtml(),
        new SideEffectInsideExpressionRuleXml(),
        new SideEffectInsideExpressionRuleTerraform(),
        new SideEffectInsideExpressionRuleDockerfile(),
        new SideEffectInsideExpressionRuleKubernetes(),
        new SideEffectInsideExpressionRuleCloudFormation(),
        new SideEffectInsideExpressionRuleJson(),
        new LoopBoundCheckedWithInequalityRuleCs(),
        new LoopBoundCheckedWithInequalityRuleJava(),
        new LoopBoundCheckedWithInequalityRuleKotlin(),
        new LoopBoundCheckedWithInequalityRuleJs(),
        new LoopBoundCheckedWithInequalityRulePython(),
        new LoopBoundCheckedWithInequalityRulePhp(),
        new LoopBoundCheckedWithInequalityRuleGo(),
        new LoopBoundCheckedWithInequalityRuleDart(),
        new LoopBoundCheckedWithInequalityRuleRuby(),
        new LoopBoundCheckedWithInequalityRuleSwift(),
        new LoopBoundCheckedWithInequalityRuleCss(),
        new LoopBoundCheckedWithInequalityRuleHtml(),
        new LoopBoundCheckedWithInequalityRuleXml(),
        new LoopBoundCheckedWithInequalityRuleTerraform(),
        new LoopBoundCheckedWithInequalityRuleDockerfile(),
        new LoopBoundCheckedWithInequalityRuleKubernetes(),
        new LoopBoundCheckedWithInequalityRuleCloudFormation(),
        new LoopBoundCheckedWithInequalityRuleJson(),
        new ResultOfVoidCallUsedRuleCs(),
        new ResultOfVoidCallUsedRuleRuby(),
        new ResultOfVoidCallUsedRuleSwift(),
        new ResultOfVoidCallUsedRuleCss(),
        new ResultOfVoidCallUsedRuleHtml(),
        new ResultOfVoidCallUsedRuleXml(),
        new ResultOfVoidCallUsedRuleTerraform(),
        new ResultOfVoidCallUsedRuleDockerfile(),
        new ResultOfVoidCallUsedRuleKubernetes(),
        new ResultOfVoidCallUsedRuleCloudFormation(),
        new ResultOfVoidCallUsedRuleJson(),
        new ResultOfVoidCallUsedRuleJava(),
        new ResultOfVoidCallUsedRuleKotlin(),
        new ResultOfVoidCallUsedRuleJs(),
        new ResultOfVoidCallUsedRulePython(),
        new ResultOfVoidCallUsedRulePhp(),
        new ResultOfVoidCallUsedRuleGo(),
        new ResultOfVoidCallUsedRuleDart()
    ];
}

public abstract class ApiRuleBase : RuleBase
{
    public override string[] Languages => [];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "10min";

    protected static bool HasPreciseTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>
    /// True when the file is the entry point of a program. Writing to the console and ending the
    /// process are what an entry point is for; the same calls inside a library are the problem.
    /// </summary>
    protected static bool IsEntryPoint(IRuleContext context)
    {
        if (context.File.Content.Contains("__main__", StringComparison.Ordinal))
            return true;
        var stem = System.IO.Path.GetFileNameWithoutExtension(context.File.FileName);
        if (stem is "Program" or "Main" or "main" or "cli" or "Cli" or "__main__")
            return true;
        return SyntaxQuery.Functions(context.Root).Any(f => f.Text is "main" or "Main");
    }
}

public abstract class OctalLiteralRule : ApiRuleBase
{
    public override string Name => "A number should not be written in octal by accident";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        // Python and Rust require an explicit 0o prefix, so a leading zero cannot surprise anyone
        if (!HasPreciseTree(context) || context.Language.LanguageKey is "py" or "rs")
            return;

        foreach (var number in context.Root.OfKind(NodeKind.NumberLiteral))
        {
            var text = number.Text;
            if (text.Length < 2 || text[0] != '0')
                continue;
            if (!text.Skip(1).All(char.IsAsciiDigit))
                continue;
            if (text.Skip(1).Any(c => c is '8' or '9'))
                continue; // not a valid octal number: the compiler rejects it, no rule needed
            // A Unix permission mask is written in octal on purpose, in every language that has a
            // file API: 0755 means rwxr-xr-x to the reader, and 493 means nothing to anyone.
            if (IsPermissionMask(text))
                continue;

            context.Report(number, $"'{text}' starts with a zero, so the compiler reads it in base 8: "
                                   + $"its value is {Convert.ToInt64(text, 8)}, not {text.TrimStart('0')}. "
                                   + "Drop the leading zero, or write the octal prefix the language "
                                   + "provides so the intent is visible.");
        }
    }

    /// <summary>Whether the literal is a Unix permission mask, which is meant to be read in octal.</summary>
    private static bool IsPermissionMask(string text)
    {
        var digits = text[1..];
        if (digits.Length is < 3 or > 4)
            return false;
        return digits.All(c => c is >= '0' and <= '7');
    }
}

public sealed class OctalLiteralRuleCs : OctalLiteralRule
{
    public override string Key => "QG-CS-BUG-0182";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class OctalLiteralRuleJava : OctalLiteralRule
{
    public override string Key => "QG-JV-BUG-0236";
    public override string[] Languages => ["java"];
}

public sealed class OctalLiteralRuleKotlin : OctalLiteralRule
{
    public override string Key => "QG-KT-BUG-0063";
    public override string[] Languages => ["kt"];
}

public sealed class OctalLiteralRuleJs : OctalLiteralRule
{
    public override string Key => "QG-JS-BUG-0180";
    public override string[] Languages => ["js", "ts"];
}

public sealed class OctalLiteralRulePython : OctalLiteralRule
{
    public override string Key => "QG-PY-BUG-0186";
    public override string[] Languages => ["py"];
}

public sealed class OctalLiteralRulePhp : OctalLiteralRule
{
    public override string Key => "QG-PP-BUG-0083";
    public override string[] Languages => ["php"];
}

public sealed class OctalLiteralRuleGo : OctalLiteralRule
{
    public override string Key => "QG-GO-BUG-0039";
    public override string[] Languages => ["go"];
}

public sealed class OctalLiteralRuleDart : OctalLiteralRule
{
    public override string Key => "QG-DART-BUG-0037";
    public override string[] Languages => ["dart"];
}

public sealed class OctalLiteralRuleRuby : OctalLiteralRule
{
    public override string Key => "QG-RB-BUG-0002";
    public override string[] Languages => ["rb"];
}

public sealed class OctalLiteralRuleSwift : OctalLiteralRule
{
    public override string Key => "QG-SW-BUG-0006";
    public override string[] Languages => ["swift"];
}

public sealed class OctalLiteralRuleCss : OctalLiteralRule
{
    public override string Key => "QG-CSS-BUG-0031";
    public override string[] Languages => ["css"];
}

public sealed class OctalLiteralRuleHtml : OctalLiteralRule
{
    public override string Key => "QG-HTML-BUG-0031";
    public override string[] Languages => ["html"];
}

public sealed class OctalLiteralRuleXml : OctalLiteralRule
{
    public override string Key => "QG-XML-BUG-0006";
    public override string[] Languages => ["xml"];
}

public sealed class OctalLiteralRuleTerraform : OctalLiteralRule
{
    public override string Key => "QG-TF-BUG-0001";
    public override string[] Languages => ["tf"];
}

public sealed class OctalLiteralRuleDockerfile : OctalLiteralRule
{
    public override string Key => "QG-DK-BUG-0008";
    public override string[] Languages => ["dk"];
}

public sealed class OctalLiteralRuleKubernetes : OctalLiteralRule
{
    public override string Key => "QG-K8-BUG-0001";
    public override string[] Languages => ["k8"];
}

public sealed class OctalLiteralRuleCloudFormation : OctalLiteralRule
{
    public override string Key => "QG-CF-BUG-0001";
    public override string[] Languages => ["cf"];
}

public sealed class OctalLiteralRuleJson : OctalLiteralRule
{
    public override string Key => "QG-JSON-BUG-0002";
    public override string[] Languages => ["json"];
}

public abstract class ProcessExitInLibraryRule : ApiRuleBase
{
    private static readonly string[] ExitCalls =
        ["exit", "Exit", "_exit", "abort", "halt", "die"];

    private static readonly string[] ExitOwners =
        ["System", "Environment", "os", "sys", "process", "Runtime", "Process"];
    public override string Name => "A library should not end the process";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || IsEntryPoint(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!ExitCalls.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;
            var owner = SyntaxQuery.Receiver(call);
            if (!ExitOwners.Contains(owner, StringComparer.Ordinal))
                continue;

            context.Report(call, $"'{owner}.{SyntaxQuery.InvokedName(call)}' ends the whole process from "
                                 + "inside a component that does not own it: buffers are not flushed, "
                                 + "callers cannot recover, and a test that reaches this line kills the "
                                 + "runner. Return an error and let the entry point decide.");
        }
    }
}

public sealed class ProcessExitInLibraryRuleCs : ProcessExitInLibraryRule
{
    public override string Key => "QG-CS-SML-0539";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class ProcessExitInLibraryRuleJava : ProcessExitInLibraryRule
{
    public override string Key => "QG-JV-SML-0500";
    public override string[] Languages => ["java"];
}

public sealed class ProcessExitInLibraryRuleKotlin : ProcessExitInLibraryRule
{
    public override string Key => "QG-KT-SML-0122";
    public override string[] Languages => ["kt"];
}

public sealed class ProcessExitInLibraryRuleJs : ProcessExitInLibraryRule
{
    public override string Key => "QG-JS-SML-0416";
    public override string[] Languages => ["js", "ts"];
}

public sealed class ProcessExitInLibraryRulePython : ProcessExitInLibraryRule
{
    public override string Key => "QG-PY-SML-0295";
    public override string[] Languages => ["py"];
}

public sealed class ProcessExitInLibraryRulePhp : ProcessExitInLibraryRule
{
    public override string Key => "QG-PP-SML-0160";
    public override string[] Languages => ["php"];
}

public sealed class ProcessExitInLibraryRuleGo : ProcessExitInLibraryRule
{
    public override string Key => "QG-GO-SML-0074";
    public override string[] Languages => ["go"];
}

public sealed class ProcessExitInLibraryRuleDart : ProcessExitInLibraryRule
{
    public override string Key => "QG-DART-SML-0039";
    public override string[] Languages => ["dart"];
}

public sealed class ProcessExitInLibraryRuleRuby : ProcessExitInLibraryRule
{
    public override string Key => "QG-RB-SML-0021";
    public override string[] Languages => ["rb"];
}

public sealed class ProcessExitInLibraryRuleSwift : ProcessExitInLibraryRule
{
    public override string Key => "QG-SW-SML-0005";
    public override string[] Languages => ["swift"];
}

public sealed class ProcessExitInLibraryRuleCss : ProcessExitInLibraryRule
{
    public override string Key => "QG-CSS-SML-0026";
    public override string[] Languages => ["css"];
}

public sealed class ProcessExitInLibraryRuleHtml : ProcessExitInLibraryRule
{
    public override string Key => "QG-HTML-SML-0098";
    public override string[] Languages => ["html"];
}

public sealed class ProcessExitInLibraryRuleXml : ProcessExitInLibraryRule
{
    public override string Key => "QG-XML-SML-0013";
    public override string[] Languages => ["xml"];
}

public sealed class ProcessExitInLibraryRuleTerraform : ProcessExitInLibraryRule
{
    public override string Key => "QG-TF-SML-0005";
    public override string[] Languages => ["tf"];
}

public sealed class ProcessExitInLibraryRuleDockerfile : ProcessExitInLibraryRule
{
    public override string Key => "QG-DK-SML-0019";
    public override string[] Languages => ["dk"];
}

public sealed class ProcessExitInLibraryRuleKubernetes : ProcessExitInLibraryRule
{
    public override string Key => "QG-K8-SML-0013";
    public override string[] Languages => ["k8"];
}

public sealed class ProcessExitInLibraryRuleCloudFormation : ProcessExitInLibraryRule
{
    public override string Key => "QG-CF-SML-0006";
    public override string[] Languages => ["cf"];
}

public sealed class ProcessExitInLibraryRuleJson : ProcessExitInLibraryRule
{
    public override string Key => "QG-JSON-SML-0001";
    public override string[] Languages => ["json"];
}

/// <summary>
/// Diagnostics written straight to the console. The check reads the same on every language, but the
/// rule does not: each one carries its own id, so a codebase can silence it where its conventions
/// differ without losing the check everywhere else.
/// </summary>
public abstract class StandardOutputForLoggingRule : ApiRuleBase
{
    private static readonly string[] ConsoleWrites =
        ["println", "print", "printf", "WriteLine", "Write", "log", "warn", "error", "puts"];

    private static readonly string[] ConsoleOwners =
    [
        "System.out", "System.err", "Console", "console", "out", "err", "STDOUT", "STDERR",
        // .NET writes its diagnostics through these two, and they reach the same place
        "Debug", "Trace", "System.Console", "System.Diagnostics.Debug", "System.Diagnostics.Trace"
    ];

    public override string Name => "Logging should not go straight to the console";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || IsEntryPoint(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!ConsoleWrites.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;
            var owner = SyntaxQuery.Receiver(call);
            if (!ConsoleOwners.Contains(owner, StringComparer.Ordinal))
                continue;

            context.Report(call, "This writes straight to the console, so the message has no level, no "
                                 + "timestamp and no way of being switched off in production. Send it "
                                 + "through the logger the application already configures.");
        }

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "printStackTrace"))
        {
            context.Report(call, "The stack trace goes to the console with nothing around it: no level, "
                                 + "no timestamp, and no record of what the program was doing. Log the "
                                 + "exception through the logger, which keeps the trace and the context "
                                 + "together.");
        }
    }
}

public sealed class CsStandardOutputForLoggingRule : StandardOutputForLoggingRule
{
    public override string Key => "QG-CS-SML-0071";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class JsStandardOutputForLoggingRule : StandardOutputForLoggingRule
{
    public override string Key => "QG-JS-SML-0008";
    public override string[] Languages => ["js", "ts"];
}

public sealed class JavaStandardOutputForLoggingRule : StandardOutputForLoggingRule
{
    public override string Key => "QG-JV-SML-0025";
    public override string[] Languages => ["java", "kt"];
}

public sealed class GoStandardOutputForLoggingRule : StandardOutputForLoggingRule
{
    public override string Key => "QG-GO-SML-0030";
    public override string[] Languages => ["go"];
}

public sealed class StandardOutputForLoggingRuleRuby : StandardOutputForLoggingRule
{
    public override string Key => "QG-RB-SML-0022";
    public override string[] Languages => ["rb"];
}

public sealed class StandardOutputForLoggingRuleSwift : StandardOutputForLoggingRule
{
    public override string Key => "QG-SW-SML-0006";
    public override string[] Languages => ["swift"];
}

public sealed class StandardOutputForLoggingRuleCss : StandardOutputForLoggingRule
{
    public override string Key => "QG-CSS-SML-0027";
    public override string[] Languages => ["css"];
}

public sealed class StandardOutputForLoggingRuleHtml : StandardOutputForLoggingRule
{
    public override string Key => "QG-HTML-SML-0099";
    public override string[] Languages => ["html"];
}

public sealed class StandardOutputForLoggingRuleXml : StandardOutputForLoggingRule
{
    public override string Key => "QG-XML-SML-0014";
    public override string[] Languages => ["xml"];
}

public sealed class StandardOutputForLoggingRuleTerraform : StandardOutputForLoggingRule
{
    public override string Key => "QG-TF-SML-0006";
    public override string[] Languages => ["tf"];
}

public sealed class StandardOutputForLoggingRuleDockerfile : StandardOutputForLoggingRule
{
    public override string Key => "QG-DK-SML-0020";
    public override string[] Languages => ["dk"];
}

public sealed class StandardOutputForLoggingRuleKubernetes : StandardOutputForLoggingRule
{
    public override string Key => "QG-K8-SML-0014";
    public override string[] Languages => ["k8"];
}

public sealed class StandardOutputForLoggingRuleCloudFormation : StandardOutputForLoggingRule
{
    public override string Key => "QG-CF-SML-0007";
    public override string[] Languages => ["cf"];
}

public sealed class StandardOutputForLoggingRuleJson : StandardOutputForLoggingRule
{
    public override string Key => "QG-JSON-SML-0002";
    public override string[] Languages => ["json"];
}

public sealed class StandardOutputForLoggingRuleDart : StandardOutputForLoggingRule
{
    public override string Key => "QG-DART-SML-0046";
    public override string[] Languages => ["dart"];
}

public abstract class WildcardImportRule : ApiRuleBase
{
    public override string Name => "Imports should name what they bring in";

    public override void Execute(IRuleContext context)
    {
        foreach (var import in context.Root.OfKind(NodeKind.ImportDeclaration))
        {
            var text = import.Text;
            if (!text.EndsWith(".*", StringComparison.Ordinal)
                && !text.EndsWith("import *", StringComparison.Ordinal)
                && !text.Contains("import *", StringComparison.Ordinal))
                continue;

            context.Report(import, "This import brings in every name of the module at once. A name added "
                                   + "upstream can then shadow one of yours without a single line changing "
                                   + "here, and no reader can tell where a symbol comes from. Import the "
                                   + "names you use.");
        }
    }
}

public sealed class WildcardImportRuleCs : WildcardImportRule
{
    public override string Key => "QG-CS-SML-0540";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class WildcardImportRuleJava : WildcardImportRule
{
    public override string Key => "QG-JV-SML-0501";
    public override string[] Languages => ["java"];
}

public sealed class WildcardImportRuleKotlin : WildcardImportRule
{
    public override string Key => "QG-KT-SML-0123";
    public override string[] Languages => ["kt"];
}

public sealed class WildcardImportRuleJs : WildcardImportRule
{
    public override string Key => "QG-JS-SML-0417";
    public override string[] Languages => ["js", "ts"];
}

public sealed class WildcardImportRulePython : WildcardImportRule
{
    public override string Key => "QG-PY-SML-0296";
    public override string[] Languages => ["py"];
}

public sealed class WildcardImportRulePhp : WildcardImportRule
{
    public override string Key => "QG-PP-SML-0161";
    public override string[] Languages => ["php"];
}

public sealed class WildcardImportRuleGo : WildcardImportRule
{
    public override string Key => "QG-GO-SML-0075";
    public override string[] Languages => ["go"];
}

public sealed class WildcardImportRuleDart : WildcardImportRule
{
    public override string Key => "QG-DART-SML-0040";
    public override string[] Languages => ["dart"];
}

public sealed class WildcardImportRuleRuby : WildcardImportRule
{
    public override string Key => "QG-RB-SML-0023";
    public override string[] Languages => ["rb"];
}

public sealed class WildcardImportRuleSwift : WildcardImportRule
{
    public override string Key => "QG-SW-SML-0007";
    public override string[] Languages => ["swift"];
}

public sealed class WildcardImportRuleCss : WildcardImportRule
{
    public override string Key => "QG-CSS-SML-0028";
    public override string[] Languages => ["css"];
}

public sealed class WildcardImportRuleHtml : WildcardImportRule
{
    public override string Key => "QG-HTML-SML-0100";
    public override string[] Languages => ["html"];
}

public sealed class WildcardImportRuleXml : WildcardImportRule
{
    public override string Key => "QG-XML-SML-0015";
    public override string[] Languages => ["xml"];
}

public sealed class WildcardImportRuleTerraform : WildcardImportRule
{
    public override string Key => "QG-TF-SML-0007";
    public override string[] Languages => ["tf"];
}

public sealed class WildcardImportRuleDockerfile : WildcardImportRule
{
    public override string Key => "QG-DK-SML-0021";
    public override string[] Languages => ["dk"];
}

public sealed class WildcardImportRuleKubernetes : WildcardImportRule
{
    public override string Key => "QG-K8-SML-0015";
    public override string[] Languages => ["k8"];
}

public sealed class WildcardImportRuleCloudFormation : WildcardImportRule
{
    public override string Key => "QG-CF-SML-0008";
    public override string[] Languages => ["cf"];
}

public sealed class WildcardImportRuleJson : WildcardImportRule
{
    public override string Key => "QG-JSON-SML-0003";
    public override string[] Languages => ["json"];
}

public abstract class SideEffectInsideExpressionRule : ApiRuleBase
{
    public override string Name => "A variable changed inside an expression should not be read twice in it";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        // `arr[i++]` and `guard++ < 10` are ordinary: the variable is read once and the order is
        // fixed. The defect is reading the same variable again in the same expression, where the
        // result depends on when the compiler applies the change.
        foreach (var statement in context.Root.OfKind(NodeKind.ExpressionStatement, NodeKind.VariableDeclaration))
        {
            foreach (var unary in statement.OfKind(NodeKind.Unary))
            {
                if (unary.Text is not ("++" or "--"))
                    continue;
                var name = SyntaxQuery.DottedName(unary.ChildAt(0));
                if (name.Length == 0)
                    continue;
                var reads = statement.OfKind(NodeKind.Identifier).Count(i => i.Text == name);
                if (reads < 2)
                    continue;

                context.Report(unary, $"'{name}' is changed by '{unary.Text}' and read again in the same "
                                      + "expression, so the value each read sees depends on the order the "
                                      + "compiler chooses. Change it in its own statement first.");
                break;
            }
        }
    }
}

public sealed class SideEffectInsideExpressionRuleCs : SideEffectInsideExpressionRule
{
    public override string Key => "QG-CS-BUG-0183";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class SideEffectInsideExpressionRuleJava : SideEffectInsideExpressionRule
{
    public override string Key => "QG-JV-BUG-0237";
    public override string[] Languages => ["java"];
}

public sealed class SideEffectInsideExpressionRuleKotlin : SideEffectInsideExpressionRule
{
    public override string Key => "QG-KT-BUG-0064";
    public override string[] Languages => ["kt"];
}

public sealed class SideEffectInsideExpressionRuleJs : SideEffectInsideExpressionRule
{
    public override string Key => "QG-JS-BUG-0181";
    public override string[] Languages => ["js", "ts"];
}

public sealed class SideEffectInsideExpressionRulePython : SideEffectInsideExpressionRule
{
    public override string Key => "QG-PY-BUG-0187";
    public override string[] Languages => ["py"];
}

public sealed class SideEffectInsideExpressionRulePhp : SideEffectInsideExpressionRule
{
    public override string Key => "QG-PP-BUG-0084";
    public override string[] Languages => ["php"];
}

public sealed class SideEffectInsideExpressionRuleGo : SideEffectInsideExpressionRule
{
    public override string Key => "QG-GO-BUG-0040";
    public override string[] Languages => ["go"];
}

public sealed class SideEffectInsideExpressionRuleDart : SideEffectInsideExpressionRule
{
    public override string Key => "QG-DART-BUG-0038";
    public override string[] Languages => ["dart"];
}

public sealed class SideEffectInsideExpressionRuleRuby : SideEffectInsideExpressionRule
{
    public override string Key => "QG-RB-BUG-0003";
    public override string[] Languages => ["rb"];
}

public sealed class SideEffectInsideExpressionRuleSwift : SideEffectInsideExpressionRule
{
    public override string Key => "QG-SW-BUG-0007";
    public override string[] Languages => ["swift"];
}

public sealed class SideEffectInsideExpressionRuleCss : SideEffectInsideExpressionRule
{
    public override string Key => "QG-CSS-BUG-0032";
    public override string[] Languages => ["css"];
}

public sealed class SideEffectInsideExpressionRuleHtml : SideEffectInsideExpressionRule
{
    public override string Key => "QG-HTML-BUG-0032";
    public override string[] Languages => ["html"];
}

public sealed class SideEffectInsideExpressionRuleXml : SideEffectInsideExpressionRule
{
    public override string Key => "QG-XML-BUG-0007";
    public override string[] Languages => ["xml"];
}

public sealed class SideEffectInsideExpressionRuleTerraform : SideEffectInsideExpressionRule
{
    public override string Key => "QG-TF-BUG-0002";
    public override string[] Languages => ["tf"];
}

public sealed class SideEffectInsideExpressionRuleDockerfile : SideEffectInsideExpressionRule
{
    public override string Key => "QG-DK-BUG-0009";
    public override string[] Languages => ["dk"];
}

public sealed class SideEffectInsideExpressionRuleKubernetes : SideEffectInsideExpressionRule
{
    public override string Key => "QG-K8-BUG-0002";
    public override string[] Languages => ["k8"];
}

public sealed class SideEffectInsideExpressionRuleCloudFormation : SideEffectInsideExpressionRule
{
    public override string Key => "QG-CF-BUG-0002";
    public override string[] Languages => ["cf"];
}

public sealed class SideEffectInsideExpressionRuleJson : SideEffectInsideExpressionRule
{
    public override string Key => "QG-JSON-BUG-0003";
    public override string[] Languages => ["json"];
}

public abstract class LoopBoundCheckedWithInequalityRule : ApiRuleBase
{
    public override string Name => "A counting loop should stop with a comparison, not an inequality";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            var condition = loop.Children.FirstOrDefault(c => c.Kind == NodeKind.Binary && c.Text == "!=");
            if (condition == null)
                continue;
            var counter = SyntaxQuery.DottedName(condition.ChildAt(0));
            if (counter.Length == 0)
                continue;
            // only a loop that counts: an iterator compared with an end marker is a different idiom
            var counts = loop.Children.Any(c => c.Kind == NodeKind.Unary && c.Text is "++" or "--"
                                                && SyntaxQuery.DottedName(c.ChildAt(0)) == counter);
            if (!counts)
                continue;

            context.Report(loop, $"The loop ends only when '{counter}' is exactly equal to the bound. If "
                                 + "anything makes it step over the value — a change of increment, a "
                                 + "modification inside the body — the loop runs past the end. Use < or > "
                                 + "so the bound cannot be missed.");
        }
    }
}

public sealed class LoopBoundCheckedWithInequalityRuleCs : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-CS-BUG-0184";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class LoopBoundCheckedWithInequalityRuleJava : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-JV-BUG-0238";
    public override string[] Languages => ["java"];
}

public sealed class LoopBoundCheckedWithInequalityRuleKotlin : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-KT-BUG-0065";
    public override string[] Languages => ["kt"];
}

public sealed class LoopBoundCheckedWithInequalityRuleJs : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-JS-BUG-0182";
    public override string[] Languages => ["js", "ts"];
}

public sealed class LoopBoundCheckedWithInequalityRulePython : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-PY-BUG-0188";
    public override string[] Languages => ["py"];
}

public sealed class LoopBoundCheckedWithInequalityRulePhp : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-PP-BUG-0085";
    public override string[] Languages => ["php"];
}

public sealed class LoopBoundCheckedWithInequalityRuleGo : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-GO-BUG-0041";
    public override string[] Languages => ["go"];
}

public sealed class LoopBoundCheckedWithInequalityRuleDart : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-DART-BUG-0039";
    public override string[] Languages => ["dart"];
}

public sealed class LoopBoundCheckedWithInequalityRuleRuby : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-RB-BUG-0004";
    public override string[] Languages => ["rb"];
}

public sealed class LoopBoundCheckedWithInequalityRuleSwift : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-SW-BUG-0008";
    public override string[] Languages => ["swift"];
}

public sealed class LoopBoundCheckedWithInequalityRuleCss : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-CSS-BUG-0033";
    public override string[] Languages => ["css"];
}

public sealed class LoopBoundCheckedWithInequalityRuleHtml : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-HTML-BUG-0033";
    public override string[] Languages => ["html"];
}

public sealed class LoopBoundCheckedWithInequalityRuleXml : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-XML-BUG-0008";
    public override string[] Languages => ["xml"];
}

public sealed class LoopBoundCheckedWithInequalityRuleTerraform : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-TF-BUG-0003";
    public override string[] Languages => ["tf"];
}

public sealed class LoopBoundCheckedWithInequalityRuleDockerfile : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-DK-BUG-0010";
    public override string[] Languages => ["dk"];
}

public sealed class LoopBoundCheckedWithInequalityRuleKubernetes : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-K8-BUG-0003";
    public override string[] Languages => ["k8"];
}

public sealed class LoopBoundCheckedWithInequalityRuleCloudFormation : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-CF-BUG-0003";
    public override string[] Languages => ["cf"];
}

public sealed class LoopBoundCheckedWithInequalityRuleJson : LoopBoundCheckedWithInequalityRule
{
    public override string Key => "QG-JSON-BUG-0004";
    public override string[] Languages => ["json"];
}

public abstract class ResultOfVoidCallUsedRule : ApiRuleBase
{
    public override string Name => "A call that returns nothing should not be used as a value";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Project.Types.Count == 0)
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var parent = call.Parent;
            if (parent == null || parent.Kind is NodeKind.ExpressionStatement or NodeKind.Block)
                continue;
            // an expression-bodied lambda over a void call is a statement lambda, which is what
            // every Consumer and Runnable in the language is written as
            if (parent.Kind is NodeKind.Lambda)
                continue;
            var name = SyntaxQuery.InvokedName(call);
            if (name.Length == 0)
                continue;
            // the method has to be the one the receiver's type declares: a name-only lookup confuses
            // every same-named method in the scan, starting with Add on the platform collections
            var callee = call.ChildAt(0);
            var ownerType = callee is { Kind: NodeKind.MemberSelect }
                ? context.Types.TypeOf(callee.ChildAt(0))
                : SyntaxQuery.EnclosingType(call)?.Text;
            if (ownerType == null || context.Project.FindType(ownerType) == null)
                continue;
            if (context.Project.MemberType(ownerType, name) is not ("void" or "Unit"))
                continue;
            // `return DoSomething();` inside a void function is a legitimate early exit in C-family code
            if (parent.Kind == NodeKind.Jump && parent.Text.StartsWith("return", StringComparison.Ordinal))
                continue;

            context.Report(call, $"'{name}' returns nothing, so this expression has no value to work with. "
                                 + "Call it as a statement and use the value it produced elsewhere.");
        }
    }
}

public sealed class ResultOfVoidCallUsedRuleCs : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-CS-BUG-0185";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class ResultOfVoidCallUsedRuleJava : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-JV-BUG-0239";
    public override string[] Languages => ["java"];
}

public sealed class ResultOfVoidCallUsedRuleKotlin : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-KT-BUG-0066";
    public override string[] Languages => ["kt"];
}

public sealed class ResultOfVoidCallUsedRuleJs : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-JS-BUG-0183";
    public override string[] Languages => ["js", "ts"];
}

public sealed class ResultOfVoidCallUsedRulePython : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-PY-BUG-0189";
    public override string[] Languages => ["py"];
}

public sealed class ResultOfVoidCallUsedRulePhp : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-PP-BUG-0086";
    public override string[] Languages => ["php"];
}

public sealed class ResultOfVoidCallUsedRuleGo : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-GO-BUG-0042";
    public override string[] Languages => ["go"];
}

public sealed class ResultOfVoidCallUsedRuleDart : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-DART-BUG-0040";
    public override string[] Languages => ["dart"];
}

public sealed class ResultOfVoidCallUsedRuleRuby : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-RB-BUG-0005";
    public override string[] Languages => ["rb"];
}

public sealed class ResultOfVoidCallUsedRuleSwift : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-SW-BUG-0009";
    public override string[] Languages => ["swift"];
}

public sealed class ResultOfVoidCallUsedRuleCss : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-CSS-BUG-0034";
    public override string[] Languages => ["css"];
}

public sealed class ResultOfVoidCallUsedRuleHtml : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-HTML-BUG-0034";
    public override string[] Languages => ["html"];
}

public sealed class ResultOfVoidCallUsedRuleXml : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-XML-BUG-0009";
    public override string[] Languages => ["xml"];
}

public sealed class ResultOfVoidCallUsedRuleTerraform : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-TF-BUG-0004";
    public override string[] Languages => ["tf"];
}

public sealed class ResultOfVoidCallUsedRuleDockerfile : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-DK-BUG-0011";
    public override string[] Languages => ["dk"];
}

public sealed class ResultOfVoidCallUsedRuleKubernetes : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-K8-BUG-0004";
    public override string[] Languages => ["k8"];
}

public sealed class ResultOfVoidCallUsedRuleCloudFormation : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-CF-BUG-0004";
    public override string[] Languages => ["cf"];
}

public sealed class ResultOfVoidCallUsedRuleJson : ResultOfVoidCallUsedRule
{
    public override string Key => "QG-JSON-BUG-0005";
    public override string[] Languages => ["json"];
}
