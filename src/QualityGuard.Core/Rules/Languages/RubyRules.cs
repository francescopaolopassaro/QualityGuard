using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class RubyRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new RubyDynamicCommandRule(),
        new RubyPopenRule(),
        new RubyUnsafeDeserializationRule(),
        new RubySqlInjectionRule(),
        new RubyWeakCryptoRule(),
        new RubyHardcodedCredentialsRule(),
        new RubyRandomRule(),
        new RubyCleartextHttpRule(),
        new RubyDynamicSendRule(),
        new RubyPrintRule(),
        new RubyDebuggerRule(),
        new RubyEmptyRescueRule(),
        new RubyLoopRule(),
        new RubySsrfRule(),
        new RubyPathTraversalRule(),
        new RubyErbInjectionRule(),
        new RubyNilComparisonRule(),
        new RubyDoubleQuoteRule()
    ];

    internal static readonly string[] CredentialNames =
        ["password", "passwd", "secret", "token", "api_key", "apikey", "credential", "credentials", "client_secret"];

    internal static string[] Lines(IRuleContext context)
        => context.File.Content.Split('\n');

    internal static IEnumerable<int> QualifiedCall(IReadOnlyList<Token> tokens, string[] modules, string[] names)
    {
        for (var i = 0; i < tokens.Count; i++)
        {
            if (i >= 2 && tokens[i - 1].Kind == TokenKind.Symbol && tokens[i - 1].Text == "."
                && RuleMatchers.Contains(tokens[i - 2].Text, modules)
                && RuleMatchers.Contains(tokens[i].Text, names))
                yield return i;
        }
    }

    internal static bool HasSqlKeyword(string line)
        => new[] { "select", "insert", "update", "delete", "drop" }
            .Any(kw => RuleMatchers.LineContains(line, kw));
}

public sealed class RubyDynamicCommandRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0001";
    public override string Name => "Shell command built from dynamic input";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Avoid interpolating untrusted values into commands and never build commands from dynamic input.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "system")
                && !RuleMatchers.IsName(tokens[i], "exec")
                && !RuleMatchers.IsName(tokens[i], "spawn"))
                continue;

            if (!RuleMatchers.NextNonParenIsString(tokens, i))
            {
                context.Report("Do not invoke shell commands with dynamic arguments.", tokens[i].Line);
                continue;
            }
            var j = i + 1;
            while (j < tokens.Count && tokens[j].Text == "(")
                j++;
            if (j < tokens.Count && RuleMatchers.IsString(tokens[j]) && tokens[j].Text.Contains("#{"))
                context.Report("Shell command strings should not interpolate untrusted values.", tokens[i].Line);
        }
        foreach (var t in tokens)
        {
            if (t.Kind == TokenKind.Symbol && t.Text == "`")
                context.Report("Command substitution should not be used for untrusted input.", t.Line);
        }
    }
}

public sealed class RubyPopenRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0002";
    public override string Name => "Popen and Open3 shell execution";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Avoid IO.popen and Open3 command execution or validate input strictly.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var i in RubyRuleSet.QualifiedCall(context.Tokens, ["IO", "Open3"],
                     ["popen", "popen3", "capture", "capture2", "capture2e", "capture3"]))
            context.Report("Shell execution via IO.popen/Open3 should be avoided.", context.Tokens[i].Line);
    }
}

public sealed class RubyUnsafeDeserializationRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0003";
    public override string Name => "Unsafe deserialization endpoint";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Deserialize only trusted data; use YAML.safe_load and avoid Marshal.load.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var i in RubyRuleSet.QualifiedCall(context.Tokens, ["Marshal", "YAML"],
                     ["load", "load_file", "restore"]))
            context.Report("Unsafe deserialization may allow remote code execution.", context.Tokens[i].Line);
    }
}

public sealed class RubySqlInjectionRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0004";
    public override string Name => "SQL query built by string concatenation";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use parameterized queries or ActiveRecord bind values instead of interpolation.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var lines = RubyRuleSet.Lines(context);
        foreach (var t in RuleMatchers.Names(context.Tokens, ["execute", "exec_query"]))
        {
            var line = lines[t.Line - 1];
            if (!RubyRuleSet.HasSqlKeyword(line))
                continue;
            if (RuleMatchers.LineContains(line, "#{") || RuleMatchers.LineContains(line, "+"))
                context.Report("Use parameterized queries to prevent SQL injection.", t.Line);
        }
    }
}

public sealed class RubyWeakCryptoRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0005";
    public override string Name => "Weak cryptographic algorithms";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Replace MD5/SHA-1/DES/RC4 with strong modern algorithms.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var lines = RubyRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "Digest::MD5") || RuleMatchers.LineContains(lines[i], "Digest::SHA1"))
                context.Report("Weak cryptographic hashing function is used.", i + 1);
        }
        foreach (var t in RuleMatchers.StringsContaining(context.Tokens, "DES-"))
            context.Report("Weak cipher DES is used.", t.Line);
        foreach (var t in RuleMatchers.StringsContaining(context.Tokens, "RC4"))
            context.Report("Weak cipher RC4 is used.", t.Line);
    }
}

public sealed class RubyHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0006";
    public override string Name => "Hard-coded credentials";
    public override Severity Severity => Severity.Blocker;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Store secrets in environment variables or a secret manager instead of source code.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsIdentifier(tokens[i])
                || !RuleMatchers.Contains(tokens[i].Text, RubyRuleSet.CredentialNames, true))
                continue;
            if (tokens[i + 1].Text is "=" or "==" && RuleMatchers.IsString(tokens[i + 2]))
                context.Report("Do not hard-code credentials.", tokens[i].Line);
        }
    }
}

public sealed class RubyRandomRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0007";
    public override string Name => "Pseudo-random number generator used for security";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use SecureRandom instead of Kernel#rand for security-sensitive values.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var t in RuleMatchers.Names(context.Tokens, ["rand"]))
            context.Report("Use SecureRandom instead of rand for security-sensitive values.", t.Line);
    }
}

public sealed class RubyCleartextHttpRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0008";
    public override string Name => "Cleartext HTTP communication";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use HTTPS to encrypt data in transit.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var t in RuleMatchers.StringsContaining(context.Tokens, "http://"))
            context.Report("Replace cleartext HTTP with HTTPS.", t.Line);
    }
}

public sealed class RubyDynamicSendRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0009";
    public override string Name => "Dynamic method invocation via send";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Avoid send with dynamic arguments; dispatch on an allow-list instead.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "send"))
                continue;
            if (!RuleMatchers.NextNonParenIsString(tokens, i))
                context.Report("Dynamic method invocation may call unintended methods.", tokens[i].Line);
        }
    }
}

public sealed class RubyPrintRule : PatternRuleBase
{
    public override string Key => "QG-RB-SML-0001";
    public override string Name => "Debug print statements";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Use a logger and remove leftover puts/print statements.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var t in RuleMatchers.Names(context.Tokens, ["puts", "print"]))
            context.Report("Remove this debug print statement.", t.Line);
    }
}

public sealed class RubyDebuggerRule : PatternRuleBase
{
    public override string Key => "QG-RB-SML-0002";
    public override string Name => "Debugger statements left in code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Remove debugging hooks such as binding.pry, byebug and debugger.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var lines = RubyRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "binding.pry")
                || RuleMatchers.LineContains(lines[i], "byebug")
                || RuleMatchers.LineContains(lines[i], "debugger"))
                context.Report("Debugger call left in production code.", i + 1);
        }
    }
}

public sealed class RubyEmptyRescueRule : PatternRuleBase
{
    public override string Key => "QG-RB-SML-0003";
    public override string Name => "Empty rescue block";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Handle the error or re-raise it instead of silently swallowing it.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var lines = RubyRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.StartsWith("rescue", StringComparison.Ordinal)
                && (line == "rescue" || line.EndsWith("end", StringComparison.Ordinal)))
                context.Report("Empty rescue block silently swallows errors.", i + 1);
        }
    }
}

public sealed class RubyLoopRule : PatternRuleBase
{
    public override string Key => "QG-RB-SML-0004";
    public override string Name => "Infinite loop without exit condition";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Ensure the loop has a guaranteed break/return to avoid hanging the process.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var lines = RubyRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "while true")
                || RuleMatchers.LineContains(lines[i], "loop do"))
                context.Report("Unconditional loop may never terminate.", i + 1);
        }
    }
}

public sealed class RubySsrfRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0010";
    public override string Name => "Server-side request forgery via dynamic URL";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Fetch only trusted URLs and restrict the set of allowed outbound targets.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        foreach (var i in RubyRuleSet.QualifiedCall(tokens, ["URI", "Net", "HTTP"], ["open", "get"]))
            CheckUrl(context, tokens, i);
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "open"))
                continue;
            if (i >= 2 && tokens[i - 1].Text == ".")
                continue;
            CheckUrl(context, tokens, i);
        }
    }

    private static void CheckUrl(IRuleContext context, IReadOnlyList<Token> tokens, int i)
    {
        if (!RuleMatchers.NextNonParenIsString(tokens, i) || context.IsTaintedLine(tokens[i].Line))
            context.Report("Do not open URLs derived from untrusted input.", tokens[i].Line);
    }
}

public sealed class RubyPathTraversalRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0011";
    public override string Name => "File path built from untrusted input";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate and canonicalize file paths and restrict access to a safe base directory.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        foreach (var i in RubyRuleSet.QualifiedCall(tokens, ["File", "Pathname"], ["read", "open", "expand_path"]))
        {
            if (!RuleMatchers.NextNonParenIsString(tokens, i) || context.IsTaintedLine(tokens[i].Line))
                context.Report("Do not open files or build paths from untrusted input.", tokens[i].Line);
        }
    }
}

public sealed class RubyErbInjectionRule : PatternRuleBase
{
    public override string Key => "QG-RB-SEC-0012";
    public override string Name => "Server-side template injection via ERB";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Never render ERB templates built from user input; use static templates with a sandboxed renderer.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var lines = RubyRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "ERB.new("))
                context.Report("ERB templates must not be built from untrusted input.", i + 1);
        }
    }
}

public sealed class RubyNilComparisonRule : PatternRuleBase
{
    public override string Key => "QG-RB-SML-0005";
    public override string Name => "Comparison against nil";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Use the nil? predicate instead of comparing with == nil.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var lines = RubyRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "== nil"))
                context.Report("Use the nil? predicate instead of comparing with == nil.", i + 1);
        }
    }
}

public sealed class RubyDoubleQuoteRule : PatternRuleBase
{
    public override string Key => "QG-RB-CNV-0001";
    public override string Name => "Double quotes used without interpolation";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Use single quotes for strings that contain no interpolation or escape sequences.";
    public override string[] Languages => ["rb"];

    public override void Execute(IRuleContext context)
    {
        var lines = RubyRuleSet.Lines(context);
        foreach (var t in context.Tokens)
        {
            if (t.Kind != TokenKind.String || t.Text.Length == 0)
                continue;
            var line = lines[t.Line - 1];
            var start = t.Column - 1;
            if (start >= line.Length || line[start] != '"')
                continue;
            var end = line.IndexOf('"', start + 1);
            if (end < 0)
                continue;
            var inner = line.Substring(start + 1, end - start - 1);
            if (inner.Contains('\\') || inner.Contains("#{"))
                continue;
            context.Report("Prefer single quotes for strings without interpolation.", t.Line);
        }
    }
}