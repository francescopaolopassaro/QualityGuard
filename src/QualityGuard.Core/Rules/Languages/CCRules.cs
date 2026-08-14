using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class CCRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CcCommandExecutionRule(),
        new CcUnsafeStringFunctionRule(),
        new CcGetsRule(),
        new CcFormatStringRule(),
        new CcHardcodedCredentialsRule(),
        new CcWeakCryptoRule(),
        new CcInsecureRandomRule(),
        new CcInsecureTempRule(),
        new CcWorldWritableRule(),
        new CcFormatNumberRule(),
        new CcAssignmentConditionRule(),
        new CcDebugOutputRule(),
        new CcGotoRule(),
        new CcVoidMainRule(),
        new CcUsingNamespaceRule(),
        new CcStrlenLoopRule()
    ];

    internal static readonly string[] CredentialNames =
        ["password", "passwd", "secret", "token", "apikey", "api_key", "credential", "key"];

    internal static string[] LinesOf(IRuleContext context) => context.File.Content.Split('\n');

    internal static bool HasAny(string text, string[] fragments)
        => fragments.Any(f => text.Contains(f, StringComparison.OrdinalIgnoreCase));

    internal static bool IsWord(Token token, string[] names, bool caseInsensitive = false)
        => (token.Kind is TokenKind.Identifier or TokenKind.Keyword)
           && RuleMatchers.Contains(token.Text, names, caseInsensitive);

    internal static bool IsWord(Token token, string name, bool caseInsensitive = false)
        => (token.Kind is TokenKind.Identifier or TokenKind.Keyword)
           && (caseInsensitive
               ? string.Equals(token.Text, name, StringComparison.OrdinalIgnoreCase)
               : token.Text == name);

    internal static int FindIndex(IReadOnlyList<Token> tokens, Token target)
    {
        for (var i = 0; i < tokens.Count; i++)
            if (tokens[i].Line == target.Line && tokens[i].Text == target.Text)
                return i;
        return -1;
    }
}

public sealed class CcCommandExecutionRule : PatternRuleBase
{
    public override string Key => "QG-CC-SEC-0001";
    public override string Name => "Unsafe OS command execution";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not build OS commands from external input; use a whitelist or escape arguments.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens,
                     ["system", "popen", "execl", "execle", "execlp", "execv", "execve", "execvp", "posix_spawn"]))
        {
            if (!RuleMatchers.NextNonParenIsString(context.Tokens, CCRuleSet.FindIndex(context.Tokens, token))
                || context.IsTaintedLine(token.Line))
                context.Report("Make sure this OS command is not built from user input.", token.Line);
        }
    }
}

public sealed class CcUnsafeStringFunctionRule : PatternRuleBase
{
    public override string Key => "QG-CC-SEC-0002";
    public override string Name => "Unsafe string functions";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Replace unbounded string functions with bounds-checked variants.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["strcpy", "strcat", "sprintf", "scanf", "vsprintf"]))
            context.Report("This function can overflow the destination buffer.", token.Line);
    }
}

public sealed class CcGetsRule : PatternRuleBase
{
    public override string Key => "QG-CC-SEC-0003";
    public override string Name => "Use of gets";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "gets cannot bound the input buffer; use fgets instead.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["gets"]))
            context.Report("gets cannot bound the input buffer and can overflow it.", token.Line);
    }
}

public sealed class CcFormatStringRule : PatternRuleBase
{
    public override string Key => "QG-CC-SEC-0004";
    public override string Name => "Format string built from user input";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Always pass a static format string; pass user input only as arguments.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var arg = tokens[i].Text switch
            {
                "printf" => 1,
                "fprintf" => 2,
                "sprintf" => 2,
                "snprintf" => 3,
                _ => -1
            };
            if (arg < 0) continue;
            var format = NthArgument(tokens, i, arg);
            if (format == null || !RuleMatchers.IsString(format))
                context.Report("Make sure the format string is not built from user input.", tokens[i].Line);
        }
    }

    private static Token? NthArgument(IReadOnlyList<Token> tokens, int index, int argNumber)
    {
        var depth = 0;
        var arg = 0;
        for (var j = index + 1; j < tokens.Count; j++)
        {
            var t = tokens[j];
            if (t.Text == "(")
            {
                depth++;
                continue;
            }
            if (t.Text == ")")
            {
                if (depth == 1) break;
                depth--;
                continue;
            }
            if (depth == 1)
            {
                if (t.Text == ",") { arg++; continue; }
                if (arg == argNumber - 1) return t;
            }
        }
        return null;
    }
}

public sealed class CcHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-CC-SEC-0005";
    public override string Name => "Hardcoded credentials";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Load credentials from a secure secret store or environment variable.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!CCRuleSet.IsWord(tokens[i], CCRuleSet.CredentialNames, true)) continue;
            for (var j = i + 1; j < tokens.Count && j < i + 6; j++)
            {
                if (tokens[j].Text == "=")
                {
                    if (j + 1 < tokens.Count && RuleMatchers.IsString(tokens[j + 1]))
                        context.Report("Hardcoded credentials must not be committed.", tokens[i].Line);
                    break;
                }
                if (tokens[j].Text is ";" or "(" or ")" or "{" or "}")
                    break;
            }
        }
        var lines = CCRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!RuleMatchers.LineContains(lines[i], "#define")) continue;
            if (!CCRuleSet.HasAny(lines[i], ["password", "secret", "token", "api_key"])) continue;
            if (!lines[i].Contains('=')) continue;
            context.Report("Hardcoded credentials must not be committed.", i + 1);
        }
    }
}

public sealed class CcWeakCryptoRule : PatternRuleBase
{
    public override string Key => "QG-CC-SEC-0006";
    public override string Name => "Use of weak cryptographic primitives";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Replace MD5/SHA-1/DES/RC4 and ECB mode with modern algorithms.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens,
                     ["MD5", "SHA1", "EVP_md5", "EVP_sha1", "DES", "RC4", "AES_encrypt"], caseInsensitive: true))
            context.Report("Replace weak cryptographic primitives with modern algorithms.", token.Line);
        foreach (var token in RuleMatchers.StringsContaining(context.Tokens, "ecb"))
            context.Report("Do not use ECB mode or other insecure block modes.", token.Line);
    }
}

public sealed class CcInsecureRandomRule : PatternRuleBase
{
    public override string Key => "QG-CC-SEC-0007";
    public override string Name => "Use of non-cryptographic random generator";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use a cryptographically secure random generator for sensitive values.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["rand", "random", "srand", "drand48"]))
            context.Report("This random generator is not cryptographically secure.", token.Line);
    }
}

public sealed class CcInsecureTempRule : PatternRuleBase
{
    public override string Key => "QG-CC-SEC-0008";
    public override string Name => "Insecure temporary file creation";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use mkstemp or similar safe APIs instead of tmpnam/tempnam/mktemp.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["tmpnam", "tempnam", "mktemp"]))
            context.Report("This temporary file API is insecure; use mkstemp instead.", token.Line);
    }
}

public sealed class CcWorldWritableRule : PatternRuleBase
{
    public override string Key => "QG-CC-SEC-0009";
    public override string Name => "World-writable permissions";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Restrict permissions; world-writable files and directories expose data.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        var lines = CCRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "chmod")
                && (RuleMatchers.LineContains(lines[i], "0777") || RuleMatchers.LineContains(lines[i], "777")))
                context.Report("Avoid world-writable permissions.", i + 1);
        }
    }
}

public sealed class CcFormatNumberRule : PatternRuleBase
{
    public override string Key => "QG-CC-SEC-0010";
    public override string Name => "Use of %n in format strings";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Remove %n from format strings; it writes to memory and is exploitable.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.StringsContaining(context.Tokens, "%n"))
            context.Report("Do not use %n in format strings; it can overwrite memory.", token.Line);
    }
}

public sealed class CcAssignmentConditionRule : PatternRuleBase
{
    public override string Key => "QG-CC-BUG-0001";
    public override string Name => "Assignment used as a condition";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "Use == to compare values in conditions instead of a single =.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!CCRuleSet.IsWord(tokens[i], ["if", "while"])) continue;
            var depth = 0;
            var parenSeen = false;
            var hasAssignment = false;
            for (var j = i + 1; j < tokens.Count; j++)
            {
                var t = tokens[j];
                if (t.Text == "(")
                {
                    parenSeen = true;
                    depth++;
                    continue;
                }
                if (t.Text == ")")
                {
                    if (!parenSeen) break;
                    depth--;
                    if (depth == 0) break;
                    continue;
                }
                if (depth == 1 && t.Text == "=")
                    hasAssignment = true;
            }
            if (parenSeen && hasAssignment)
                context.Report("Assignment used as a condition; use == to compare.", tokens[i].Line);
        }
    }
}

public sealed class CcDebugOutputRule : PatternRuleBase
{
    public override string Key => "QG-CC-SML-0001";
    public override string Name => "Debug output left in production code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Remove debug prints and console output before shipping.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["printf", "fprintf"]))
            context.Report("Remove this debug or console output before production.", token.Line);
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (CCRuleSet.IsWord(tokens[i], "cout") && tokens[i + 1].Text == "<<")
                context.Report("Remove this debug or console output before production.", tokens[i].Line);
        }
    }
}

public sealed class CcGotoRule : PatternRuleBase
{
    public override string Key => "QG-CC-SML-0002";
    public override string Name => "Goto statements";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Refactor to structured control flow.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => CCRuleSet.IsWord(t, "goto")))
            context.Report("Refactor to structured control flow.", token.Line);
    }
}

public sealed class CcVoidMainRule : PatternRuleBase
{
    public override string Key => "QG-CC-CNV-0001";
    public override string Name => "main declared with void return type";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Declare main with an int return type.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        var lines = CCRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "void main"))
                context.Report("Declare main with an int return type.", i + 1);
        }
    }
}

public sealed class CcUsingNamespaceRule : PatternRuleBase
{
    public override string Key => "QG-CC-CNV-0002";
    public override string Name => "Using-directives in headers";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Avoid using namespace directives; pollutes the global scope.";
    public override string[] Languages => ["cpp"];

    public override void Execute(IRuleContext context)
    {
        var lines = CCRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "using namespace std"))
                context.Report("Avoid using namespace directives; pollutes the global scope.", i + 1);
        }
    }
}

public sealed class CcStrlenLoopRule : PatternRuleBase
{
    public override string Key => "QG-CC-PRF-0001";
    public override string Name => "strlen recomputed in a loop condition";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Cache the string length before the loop instead of calling strlen each iteration.";
    public override string[] Languages => ["c", "cpp"];

    public override void Execute(IRuleContext context)
    {
        var lines = CCRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!RuleMatchers.LineContains(lines[i], "strlen(")) continue;
            if (!CCRuleSet.HasAny(lines[i], ["for (", "for(", "while (", "while("])) continue;
            context.Report("strlen in a loop condition is recomputed each iteration; cache the length.", i + 1);
        }
    }
}
