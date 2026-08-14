using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class VbRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new VbShellExecutionRule(),
        new VbSqlInjectionRule(),
        new VbHardcodedCredentialsRule(),
        new VbDeclareFunctionRule(),
        new VbWeakCryptoRule(),
        new VbMsgBoxRule(),
        new VbOnErrorRule(),
        new VbEmptyCatchRule(),
        new VbInfiniteDoLoopRule(),
        new VbOptionStrictRule()
    ];

    internal static string[] LinesOf(IRuleContext context) => context.File.Content.Split('\n');

    internal static bool IsWord(Token token, string name)
        => (token.Kind is TokenKind.Identifier or TokenKind.Keyword) &&
           string.Equals(token.Text, name, StringComparison.OrdinalIgnoreCase);

    internal static bool IsWord(Token token, string[] names)
        => (token.Kind is TokenKind.Identifier or TokenKind.Keyword)
           && RuleMatchers.Contains(token.Text, names, true);

    internal static bool HasAny(string text, string[] fragments)
        => fragments.Any(f => text.Contains(f, StringComparison.OrdinalIgnoreCase));

    internal static bool IsMemberAccess(IReadOnlyList<Token> tokens, int index, string baseName, string member)
        => index >= 2
           && IsWord(tokens[index - 2], baseName)
           && tokens[index - 1].Text == "."
           && IsWord(tokens[index], member);
}

public sealed class VbShellExecutionRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0012";
    public override string Name => "Execution of externally-influenced OS commands";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate and allow list the command and its arguments.";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i + 1].Text != "(") continue;
            if (!VbRuleSet.IsWord(tokens[i], "Shell")) continue;
            if (!RuleMatchers.NextNonParenIsString(tokens, i) || context.IsTaintedLine(tokens[i].Line))
                context.Report("Sanitize the arguments passed to Shell.", tokens[i].Line);
        }
    }
}

public sealed class VbSqlInjectionRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0013";
    public override string Name => "SQL injection via concatenated queries";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use parameterized queries to prevent SQL injection.";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = VbRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!VbRuleSet.HasAny(line, ["ExecuteNonQuery", "ExecuteScalar", "ExecuteReader", "SqlCommand", "OleDbCommand", "CommandText"]))
                continue;
            if (!VbRuleSet.HasAny(line, ["select", "insert", "update", "delete", "drop"]))
                continue;
            if (!line.Contains('&')) continue;
            context.Report("Use parameterized queries to prevent SQL injection.", i + 1);
        }
    }
}

public sealed class VbHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0014";
    public override string Name => "Hardcoded credentials";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Load credentials from a secure secret store.";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!VbRuleSet.IsWord(tokens[i], ["password", "pass", "pwd", "secret", "token", "apikey", "credential"]))
                continue;
            for (var j = i + 1; j < tokens.Count && j < i + 6; j++)
            {
                if (tokens[j].Text == "=")
                {
                    if (j + 1 < tokens.Count && tokens[j + 1].Kind == TokenKind.String)
                        context.Report("Hardcoded credentials must not be committed.", tokens[i].Line);
                    break;
                }
                if (tokens[j].Text is "(" or ")" or "{")
                    break;
            }
        }
    }
}

public sealed class VbDeclareFunctionRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0015";
    public override string Name => "Unsafe P/Invoke declarations";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use safe marshaling with explicit CharSet and CallingConvention.";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (VbRuleSet.IsWord(tokens[i], "Declare")
                && VbRuleSet.IsWord(tokens[i + 1], ["Function", "Sub"]))
                context.Report("Validate marshaling of native entry points.", tokens[i].Line);
        }
    }
}

public sealed class VbWeakCryptoRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0016";
    public override string Name => "Use of weak cryptographic primitives";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Replace DES/TripleDES/RC2/MD5/SHA1 with modern algorithms.";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => VbRuleSet.IsWord(t, ["DES", "TripleDES", "RC2", "MD5", "SHA1"])))
            context.Report("Replace weak cryptographic primitives with modern algorithms.", token.Line);
    }
}

public sealed class VbMsgBoxRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0009";
    public override string Name => "MsgBox and Debug output left in production code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Remove MsgBox and Debug.Print before shipping.";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i + 1].Text != "(") continue;
            if (VbRuleSet.IsWord(tokens[i], "MsgBox")
                || VbRuleSet.IsMemberAccess(tokens, i, "Debug", "Print"))
                context.Report("Remove MsgBox or debug output before production.", tokens[i].Line);
        }
    }
}

public sealed class VbOnErrorRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0010";
    public override string Name => "On Error Resume Next swallows errors";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Use structured exception handling (Try/Catch) instead of On Error.";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (!VbRuleSet.IsWord(tokens[i], "On")) continue;
            if (VbRuleSet.IsWord(tokens[i + 1], "Error"))
                context.Report("Handle errors explicitly instead of using On Error.", tokens[i].Line);
        }
    }
}

public sealed class VbEmptyCatchRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0011";
    public override string Name => "Empty catch block";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Handle or log the exception instead of swallowing it.";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!VbRuleSet.IsWord(tokens[i], "Catch")) continue;
            var j = i + 1;
            while (j < tokens.Count && (tokens[j].Kind == TokenKind.Identifier
                                        || tokens[j].Kind == TokenKind.Comment
                                        || tokens[j].Text is "As" or "(" or ")" or ","))
                j++;
            if (j < tokens.Count && VbRuleSet.IsWord(tokens[j], "End"))
                context.Report("Either handle or log the exception.", tokens[i].Line);
        }
    }
}

public sealed class VbInfiniteDoLoopRule : PatternRuleBase
{
    public override string Key => "QG-CS-BUG-0002";
    public override string Name => "Do loop without an exit condition";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "Add a While/Until condition or an Exit Do statement.";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var firstBareDo = -1;
        var hasExitDo = false;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (VbRuleSet.IsWord(tokens[i], "Exit")
                && i + 1 < tokens.Count && VbRuleSet.IsWord(tokens[i + 1], "Do"))
            {
                hasExitDo = true;
            }
            else if (VbRuleSet.IsWord(tokens[i], "Do"))
            {
                var next = i + 1 < tokens.Count ? tokens[i + 1] : null;
                if (next is { } t && (VbRuleSet.IsWord(t, "While") || VbRuleSet.IsWord(t, "Until")))
                    continue;
                if (firstBareDo < 0) firstBareDo = tokens[i].Line;
            }
        }
        if (firstBareDo >= 0 && !hasExitDo)
            context.Report("Ensure this Do loop has an exit condition.", firstBareDo);
    }
}

public sealed class VbOptionStrictRule : PatternRuleBase
{
    public override string Key => "QG-CS-CNV-0001";
    public override string Name => "Option Strict and Option Explicit should be enabled";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Add Option Strict On and Option Explicit On at the top of the file.";
    public override string[] Languages => ["vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = VbRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('\'')) continue;
            if (VbRuleSet.HasAny(trimmed, ["Option Strict", "Option Explicit"])) return;
            context.Report("Add Option Strict and Option Explicit to enforce strict typing.", i + 1);
            return;
        }
    }
}
