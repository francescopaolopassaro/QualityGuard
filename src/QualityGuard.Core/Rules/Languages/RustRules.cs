using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class RustRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new RustCommandExecutionRule(),
        new RustSqlInjectionRule(),
        new RustWeakCryptoRule(),
        new RustHardcodedCredentialsRule(),
        new RustInsecureRandomRule(),
        new RustUnsafeDeserializationRule(),
        new RustCleartextHttpRule(),
        new RustPathTraversalRule(),
        new RustSsrfRule(),
        new RustUnsafePointerOpsRule(),
        new RustInsecureTlsRule(),
        new RustShellCommandRule(),
        new RustWeakUuidRule(),
        new RustSensitiveLoggingRule(),
        new RustWorldWritablePermissionsRule(),
        new RustUnwrapExpectRule(),
        new RustDebugPrintRule(),
        new RustUndocumentedUnsafeRule(),
        new RustPanicMacroRule(),
        new RustLongFunctionRule(),
        new RustVariableShadowingRule(),
        new RustDuplicatedLiteralsRule(),
        new RustBooleanLiteralComparisonRule(),
        new RustInfiniteLoopRule(),
        new RustRedundantElseRule(),
        new RustDivisionByZeroRule(),
        new RustFloatEqualityRule(),
        new RustIntegerOverflowRule(),
        new RustMemForgetRule(),
        new RustRawPointerDerefRule(),
        new RustAllocationInLoopRule(),
        new RustFunctionNamingRule(),
        new RustConstNamingRule(),
        new RustTypeNamingRule(),
        new RustUnusedMutRule()
    ];

    internal static string[] Lines(IRuleContext context) => context.File.Content.Split('\n');

    internal static (int Open, int End) Block(IReadOnlyList<Token> tokens, int braceIndex)
    {
        var depth = 0;
        for (var j = braceIndex; j < tokens.Count; j++)
        {
            if (tokens[j].Text == "{")
                depth++;
            else if (tokens[j].Text == "}")
            {
                depth--;
                if (depth == 0)
                    return (braceIndex, j);
            }
        }
        return (braceIndex, -1);
    }

    internal static bool IsInsideUnsafe(IReadOnlyList<Token> tokens, int index)
    {
        var frames = new Stack<bool>();
        for (var i = 0; i < index; i++)
        {
            if (tokens[i].Text == "{")
            {
                var isUnsafe = i > 0 && tokens[i - 1].Kind == TokenKind.Keyword && tokens[i - 1].Text == "unsafe";
                frames.Push(isUnsafe);
            }
            else if (tokens[i].Text == "}")
            {
                if (frames.Count > 0)
                    frames.Pop();
            }
        }
        return frames.Any(f => f);
    }
}

public sealed class RustCommandExecutionRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0001";
    public override string Name => "OS command executed with dynamic arguments";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Do not pass dynamic input to Command; execute a fixed program with a static argument list.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 3 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "Command") || tokens[i + 1].Text != "::"
                || !RuleMatchers.IsName(tokens[i + 2], "new") || tokens[i + 3].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i + 2))
                continue;
            context.Report("Do not build OS commands from dynamic input.", tokens[i].Line);
        }
    }
}

public sealed class RustSqlInjectionRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0002";
    public override string Name => "SQL query built by string interpolation";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use parameterized queries (rusqlite params!, sqlx bind) instead of interpolating input into SQL.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var stripped = LanguageRuleSupport.StripStrings(lines[i]);
            if (!stripped.Contains("query(") && !stripped.Contains("execute(")
                && !stripped.Contains("sql_query(") && !stripped.Contains("fetch(")
                && !stripped.Contains("query_as("))
                continue;
            if (!stripped.Contains("format!") && !stripped.Contains("+"))
                continue;
            if (!LanguageRuleSupport.ContainsSqlKeyword(lines[i]))
                continue;
            context.Report("Use parameterized queries to prevent SQL injection.", i + 1);
        }
    }
}

public sealed class RustWeakCryptoRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0003";
    public override string Name => "Weak cryptographic algorithm is used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Replace MD5/SHA-1/DES/RC4 and AES-ECB with strong algorithms such as AES-GCM or SHA-256.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        string[] algorithms = ["md5", "sha1", "sha-1", "des", "3des", "desede", "rc4", "aes-ecb", "aes/ecb"];
        for (var i = 0; i < lines.Length; i++)
        {
            foreach (var algorithm in algorithms)
            {
                if (!LanguageRuleSupport.ContainsWord(lines[i], algorithm))
                    continue;
                context.Report($"Replace this weak cryptographic algorithm '{algorithm}' with a strong one.", i + 1);
                break;
            }
        }
    }
}

public sealed class RustHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0004";
    public override string Name => "Hard-coded credentials";
    public override Severity Severity => Severity.Blocker;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Read secrets from environment variables or a secret manager instead of source code.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsIdentifier(tokens[i]) || !LanguageRuleSupport.IsCredentialName(tokens[i].Text))
                continue;
            if (tokens[i + 1].Text is "=" or ":" && RuleMatchers.IsString(tokens[i + 2]))
                context.Report("Do not hard-code credentials.", tokens[i].Line);
        }
    }
}

public sealed class RustInsecureRandomRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0005";
    public override string Name => "Pseudo-random number generator used for security";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use a cryptographically secure source (getrandom, OsRng) for security-sensitive values.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "thread_rng")
                || RuleMatchers.LineContains(lines[i], "rand::random")
                || RuleMatchers.LineContains(lines[i], "rand::rng")
                || RuleMatchers.LineContains(lines[i], "SmallRng"))
                context.Report("rand is not cryptographically secure.", i + 1);
        }
    }
}

public sealed class RustUnsafeDeserializationRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0006";
    public override string Name => "Unsafe deserialization of untrusted input";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and authenticate input before deserializing with bincode/rmp_serde/serde_json.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (tokens[i + 1].Text != "::" || !RuleMatchers.Contains(tokens[i + 2].Text, ["from_str", "from_slice", "from_reader", "deserialize"], true))
                continue;
            if (!RuleMatchers.Contains(tokens[i].Text, ["serde_json", "bincode", "rmp_serde", "serde_yaml"]))
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i + 2) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Do not deserialize untrusted data without validation.", tokens[i].Line);
        }
    }
}

public sealed class RustCleartextHttpRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0007";
    public override string Name => "Cleartext HTTP communication";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use HTTPS to encrypt data in transit.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        foreach (var t in RuleMatchers.StringsContaining(context.Tokens, "http://"))
            context.Report("Replace cleartext HTTP with HTTPS.", t.Line);
    }
}

public sealed class RustPathTraversalRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0008";
    public override string Name => "Path traversal via user-controlled file path";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and sanitize file paths against a base directory allow list.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (tokens[i + 1].Text != "::")
                continue;
            if (!RuleMatchers.Contains(tokens[i].Text, ["fs", "File", "PathBuf", "Path"]))
                continue;
            if (!RuleMatchers.Contains(tokens[i + 2].Text, ["open", "read", "read_to_string", "write", "from"]))
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i + 2) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Validate file paths passed to file access calls.", tokens[i].Line);
        }
    }
}

public sealed class RustSsrfRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0009";
    public override string Name => "Server-Side Request Forgery via HTTP client";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and allow list destination URLs and prevent access to internal hosts.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            var sink = -1;
            if (RuleMatchers.IsName(tokens[i], "reqwest") && tokens[i + 1].Text == "::"
                && RuleMatchers.Contains(tokens[i + 2].Text, ["get", "post", "put", "delete"]))
                sink = i + 2;
            else if (tokens[i].Text == "." && RuleMatchers.Contains(tokens[i + 1].Text, ["get", "post", "put", "delete"]))
                sink = i + 1;
            if (sink < 0)
                continue;
            if (sink + 1 >= tokens.Count || tokens[sink + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, sink) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Validate and allow list URLs passed to the HTTP client.", tokens[i].Line);
        }
    }
}

public sealed class RustUnsafePointerOpsRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0010";
    public override string Name => "Unsafe pointer operations used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Avoid transmute, mem::uninitialized, from_raw_parts and set_len unless invariants are guaranteed.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "transmute")
                || RuleMatchers.LineContains(lines[i], "uninitialized")
                || RuleMatchers.LineContains(lines[i], "from_raw_parts")
                || RuleMatchers.LineContains(lines[i], "set_len"))
                context.Report("Unsafe pointer operation can lead to memory unsafety.", i + 1);
        }
    }
}

public sealed class RustInsecureTlsRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0011";
    public override string Name => "TLS certificate verification disabled";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Keep certificate and hostname verification enabled to protect against MITM attacks.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "danger_accept_invalid_certs")
                || RuleMatchers.LineContains(lines[i], "danger_accept_invalid_hostnames")
                || RuleMatchers.LineContains(lines[i], "danger_allow_invalid_certs"))
                context.Report("TLS certificate verification is disabled.", i + 1);
        }
    }
}

public sealed class RustShellCommandRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0012";
    public override string Name => "Shell interpreter invoked via Command";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Avoid launching sh/bash/cmd; execute the intended program directly with static arguments.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!RuleMatchers.LineContains(lines[i], "Command"))
                continue;
            if (!RuleMatchers.LineContains(lines[i], "\"sh\"")
                && !RuleMatchers.LineContains(lines[i], "\"bash\"")
                && !RuleMatchers.LineContains(lines[i], "\"cmd\"")
                && !RuleMatchers.LineContains(lines[i], "\"powershell\"")
                && !RuleMatchers.LineContains(lines[i], "\"pwsh\"")
                && !RuleMatchers.LineContains(lines[i], "\"zsh\"")
                && !RuleMatchers.LineContains(lines[i], "\"dash\""))
                continue;
            context.Report("Shell invocation may allow command injection.", i + 1);
        }
    }
}

public sealed class RustWeakUuidRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0013";
    public override string Name => "Weak randomness used for UUID generation";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use a cryptographically secure RNG (getrandom/OsRng) when UUIDs are security-sensitive.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "Uuid::new_v1"))
            {
                context.Report("Uuid::new_v1 is timestamp-based and not unpredictable.", i + 1);
                continue;
            }
            if (RuleMatchers.LineContains(lines[i], "new_v4")
                && (RuleMatchers.LineContains(lines[i], "rand") || RuleMatchers.LineContains(lines[i], "thread_rng")))
                context.Report("UUID generated from a weak random source.", i + 1);
        }
    }
}

public sealed class RustSensitiveLoggingRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0014";
    public override string Name => "Sensitive data is logged";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Do not log credentials or other secrets; redact sensitive values.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!RuleMatchers.LineContains(lines[i], "println!")
                && !RuleMatchers.LineContains(lines[i], "dbg!")
                && !RuleMatchers.LineContains(lines[i], "log::info!")
                && !RuleMatchers.LineContains(lines[i], "tracing::info!"))
                continue;
            if (LanguageRuleSupport.HasCredentialSubstring(lines[i]))
                context.Report("Sensitive information should not be logged.", i + 1);
        }
    }
}

public sealed class RustWorldWritablePermissionsRule : PatternRuleBase
{
    public override string Key => "QG-RS-SEC-0015";
    public override string Name => "World-writable file permissions";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Restrict file permissions to the least privilege required.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "0o777") || RuleMatchers.LineContains(lines[i], "0o666"))
                context.Report("Do not create world-writable files.", i + 1);
        }
    }
}

public sealed class RustUnwrapExpectRule : PatternRuleBase
{
    public override string Key => "QG-RS-SML-0001";
    public override string Name => "unwrap or expect used on a Result/Option";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Propagate errors with ? and handle the None/Err cases explicitly.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 1; i < tokens.Count - 1; i++)
        {
            if (tokens[i - 1].Text != ".")
                continue;
            if (!RuleMatchers.Contains(tokens[i].Text, ["unwrap", "expect"]))
                continue;
            if (tokens[i + 1].Text != "(")
                continue;
            context.Report("unwrap/expect panics if the value is Err or None; handle the failure case.", tokens[i].Line);
        }
    }
}

public sealed class RustDebugPrintRule : PatternRuleBase
{
    public override string Key => "QG-RS-SML-0002";
    public override string Name => "Debug output statements";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Remove leftover print/dbg! statements or route them through a logger.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (!RuleMatchers.Contains(tokens[i].Text, ["println", "print", "eprintln", "eprint", "dbg"]))
                continue;
            if (tokens[i + 1].Text != "!")
                continue;
            context.Report("Remove this debug output statement.", tokens[i].Line);
        }
    }
}

public sealed class RustUndocumentedUnsafeRule : PatternRuleBase
{
    public override string Key => "QG-RS-SML-0003";
    public override string Name => "Unsafe block without safety documentation";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Document why this unsafe block is safe with a SAFETY comment or # Safety doc section.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!RuleMatchers.LineContains(lines[i], "unsafe") || !lines[i].Contains('{'))
                continue;
            var documented = false;
            for (var j = Math.Max(0, i - 2); j < i; j++)
            {
                if (RuleMatchers.LineContains(lines[j], "SAFETY") || RuleMatchers.LineContains(lines[j], "# Safety"))
                {
                    documented = true;
                    break;
                }
            }
            if (!documented)
                context.Report("Document why this unsafe block is safe.", i + 1);
        }
    }
}

public sealed class RustPanicMacroRule : PatternRuleBase
{
    public override string Key => "QG-RS-SML-0004";
    public override string Name => "todo!/unimplemented!/unreachable! should not be left";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Replace placeholders with real implementations or handle the unreachable case gracefully.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (!RuleMatchers.Contains(tokens[i].Text, ["todo", "unimplemented", "unreachable"]))
                continue;
            if (tokens[i + 1].Text != "!")
                continue;
            context.Report("Replace this placeholder macro with a real implementation.", tokens[i].Line);
        }
    }
}

public sealed class RustLongFunctionRule : PatternRuleBase
{
    public override string Key => "QG-RS-SML-0005";
    public override string Name => "Function is too long";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Split this function into smaller, focused pieces.";
    public override string[] Languages => ["rs"];
    private const int MaxLines = 80;

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        var fnLines = context.Tokens.Where(t => t.Kind == TokenKind.Keyword && t.Text == "fn")
            .Select(t => t.Line).Distinct().ToArray();
        foreach (var start in fnLines)
        {
            var depth = 0;
            var end = start - 1;
            for (var i = start - 1; i < lines.Length; i++)
            {
                var stripped = LanguageRuleSupport.StripStrings(lines[i]);
                depth += stripped.Count(c => c == '{') - stripped.Count(c => c == '}');
                if (depth <= 0)
                {
                    end = i;
                    break;
                }
            }
            var length = end - start + 1;
            if (length > MaxLines)
                context.Report($"Split this {length}-line function into smaller pieces.", start);
        }
    }
}

public sealed class RustVariableShadowingRule : PatternRuleBase
{
    public override string Key => "QG-RS-SML-0006";
    public override string Name => "Variable should not shadow an earlier binding";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename the inner variable so it does not shadow the outer one.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var seen = new HashSet<string>();
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Kind == TokenKind.Keyword && tokens[i].Text == "fn")
            {
                seen.Clear();
                continue;
            }
            if (tokens[i].Kind != TokenKind.Keyword || tokens[i].Text != "let")
                continue;
            var j = i + 1;
            if (j < tokens.Count && RuleMatchers.IsName(tokens[j], "mut"))
                j++;
            if (j >= tokens.Count || !RuleMatchers.IsIdentifier(tokens[j]))
                continue;
            if (!seen.Add(tokens[j].Text))
                context.Report("Rename this variable; it shadows an earlier binding.", tokens[j].Line);
        }
    }
}

public sealed class RustDuplicatedLiteralsRule : PatternRuleBase
{
    public override string Key => "QG-RS-SML-0007";
    public override string Name => "String literals should not be duplicated";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Define a named constant for this repeated literal.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var groups = context.Tokens.Where(t => RuleMatchers.IsString(t) && t.Text.Length >= 6)
            .GroupBy(t => t.Text)
            .Where(g => g.Count() > 1);
        foreach (var group in groups)
        {
            var first = group.OrderBy(t => t.Line).First();
            context.Report($"Define a constant instead of duplicating this literal {group.Count()} times.", first.Line);
        }
    }
}

public sealed class RustBooleanLiteralComparisonRule : PatternRuleBase
{
    public override string Key => "QG-RS-SML-0008";
    public override string Name => "Boolean values should not be compared to true or false";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use the boolean directly instead of comparing it to a literal.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var stripped = LanguageRuleSupport.StripStrings(lines[i]);
            if (RuleMatchers.LineContains(stripped, "== true") || RuleMatchers.LineContains(stripped, "== false")
                || RuleMatchers.LineContains(stripped, "!= true") || RuleMatchers.LineContains(stripped, "!= false"))
                context.Report("Remove the comparison to the boolean literal.", i + 1);
        }
    }
}

public sealed class RustInfiniteLoopRule : PatternRuleBase
{
    public override string Key => "QG-RS-SML-0009";
    public override string Name => "Infinite loop without exit condition";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Ensure the loop has a guaranteed break/return to avoid hanging the process.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Keyword || tokens[i].Text != "loop")
                continue;
            var open = i + 1;
            if (open >= tokens.Count || tokens[open].Text != "{")
                continue;
            var (_, end) = RustRuleSet.Block(tokens, open);
            if (end < 0)
                continue;
            var exits = tokens.Skip(open + 1).Take(end - open - 1)
                .Any(t => t.Kind == TokenKind.Keyword && (t.Text == "break" || t.Text == "return"));
            if (!exits)
                context.Report("This loop has no exit condition and may never terminate.", tokens[i].Line);
        }
    }
}

public sealed class RustRedundantElseRule : PatternRuleBase
{
    public override string Key => "QG-RS-SML-0010";
    public override string Name => "Unnecessary else after return/break";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Remove the else block and return directly to reduce nesting.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!RuleMatchers.LineContains(lines[i], "else"))
                continue;
            var exitsEarly = false;
            for (var j = Math.Max(0, i - 6); j < i; j++)
            {
                if (RuleMatchers.LineContains(lines[j], "return")
                    || RuleMatchers.LineContains(lines[j], "break")
                    || RuleMatchers.LineContains(lines[j], "continue"))
                {
                    exitsEarly = true;
                    break;
                }
            }
            if (exitsEarly)
                context.Report("Unnecessary else after return.", i + 1);
        }
    }
}

public sealed class RustDivisionByZeroRule : PatternRuleBase
{
    public override string Key => "QG-RS-BUG-0001";
    public override string Name => "Division by zero";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Guard against zero divisors before performing the division.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Text != "/" && tokens[i].Text != "%")
                continue;
            if (tokens[i + 1].Kind == TokenKind.Number && tokens[i + 1].Text == "0")
                context.Report("Division by zero may panic at runtime.", tokens[i].Line);
        }
    }
}

public sealed class RustFloatEqualityRule : PatternRuleBase
{
    public override string Key => "QG-RS-BUG-0002";
    public override string Name => "Floating point values should not be compared with ==";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use an epsilon-based comparison or compare against a tolerance.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var lines = RustRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!RuleMatchers.LineContains(lines[i], "=="))
                continue;
            if (RuleMatchers.LineContains(lines[i], "f64") || RuleMatchers.LineContains(lines[i], "f32"))
                context.Report("Equality checks on floating point values are unreliable.", i + 1);
        }
    }
}

public sealed class RustIntegerOverflowRule : PatternRuleBase
{
    public override string Key => "QG-RS-BUG-0003";
    public override string Name => "Integer arithmetic may overflow in release builds";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use checked/saturating arithmetic or ensure values stay within bounds.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Number || tokens[i + 2].Kind != TokenKind.Number)
                continue;
            var op = tokens[i + 1].Text;
            if (op is not ("+" or "-" or "*"))
                continue;
            if (!long.TryParse(tokens[i].Text.Replace("_", ""), out var a)
                || !long.TryParse(tokens[i + 2].Text.Replace("_", ""), out var b))
                continue;
            var result = op switch
            {
                "+" => a + b,
                "-" => a - b,
                _ => a * b
            };
            if (result is > int.MaxValue or < int.MinValue)
                context.Report("This arithmetic may overflow in release builds.", tokens[i].Line);
        }
    }
}

public sealed class RustMemForgetRule : PatternRuleBase
{
    public override string Key => "QG-RS-BUG-0004";
    public override string Name => "mem::forget used on a resource";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Avoid mem::forget; leaking resources may exhaust system limits.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "mem") && tokens[i + 1].Text == "::"
                && RuleMatchers.IsName(tokens[i + 2], "forget"))
                context.Report("mem::forget intentionally leaks the value.", tokens[i].Line);
        }
    }
}

public sealed class RustRawPointerDerefRule : PatternRuleBase
{
    public override string Key => "QG-RS-BUG-0005";
    public override string Name => "Raw pointer dereferenced without null check";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Check the pointer for null before dereferencing it in unsafe code.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Text != "*" || !RuleMatchers.IsIdentifier(tokens[i + 1]))
                continue;
            var prev = i == 0 ? tokens[i] : tokens[i - 1];
            if (prev.Kind == TokenKind.Number || prev.Text is ")" or "]" or ">" or "\"" or "'")
                continue;
            if (!RustRuleSet.IsInsideUnsafe(tokens, i))
                continue;
            context.Report("Dereference this raw pointer only after a null check.", tokens[i].Line);
        }
    }
}

public sealed class RustAllocationInLoopRule : PatternRuleBase
{
    public override string Key => "QG-RS-BUG-0006";
    public override string Name => "Unnecessary allocation inside a loop";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Hoist the allocation outside the loop and reuse the buffer.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Keyword || tokens[i].Text is not ("for" or "while" or "loop"))
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 1, "{");
            if (open < 0)
                continue;
            var (_, end) = RustRuleSet.Block(tokens, open);
            if (end < 0)
                continue;
            for (var j = open + 1; j < end; j++)
            {
                var alloc = false;
                if (RuleMatchers.IsIdentifier(tokens[j])
                    && RuleMatchers.Contains(tokens[j].Text, ["to_string", "to_owned", "clone"])
                    && j + 1 < tokens.Count && tokens[j + 1].Text == "(")
                    alloc = true;
                else if (j + 2 < end && RuleMatchers.IsName(tokens[j], "String") && tokens[j + 1].Text == "::"
                    && RuleMatchers.IsName(tokens[j + 2], "from"))
                    alloc = true;
                else if (RuleMatchers.IsName(tokens[j], "format") && j + 1 < tokens.Count && tokens[j + 1].Text == "!")
                    alloc = true;
                if (alloc)
                    context.Report("Avoid allocating inside the loop; hoist it outside.", tokens[j].Line);
            }
        }
    }
}

public sealed class RustFunctionNamingRule : PatternRuleBase
{
    public override string Key => "QG-RS-CNV-0001";
    public override string Name => "Function names should comply with snake_case";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename this function to follow the snake_case convention.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Keyword || tokens[i].Text != "fn")
                continue;
            var name = tokens[i + 1];
            if (!RuleMatchers.IsIdentifier(name))
                continue;
            if (name.Text.Any(char.IsUpper))
                context.Report("Rename this function to follow the snake_case convention.", name.Line);
        }
    }
}

public sealed class RustConstNamingRule : PatternRuleBase
{
    public override string Key => "QG-RS-CNV-0002";
    public override string Name => "Const names should comply with UPPER_SNAKE_CASE";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename this const to follow the UPPER_SNAKE_CASE convention.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Keyword || tokens[i].Text != "const")
                continue;
            var name = tokens[i + 1];
            if (!RuleMatchers.IsIdentifier(name))
                continue;
            if (name.Text.Any(char.IsLower))
                context.Report("Rename this const to follow the UPPER_SNAKE_CASE convention.", name.Line);
        }
    }
}

public sealed class RustTypeNamingRule : PatternRuleBase
{
    public override string Key => "QG-RS-CNV-0003";
    public override string Name => "Type names should comply with UpperCamelCase";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename this type to follow the UpperCamelCase convention.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Keyword)
                continue;
            if (tokens[i].Text is not ("struct" or "enum" or "trait" or "union" or "type"))
                continue;
            var name = tokens[i + 1];
            if (RuleMatchers.IsIdentifier(name) && char.IsLower(name.Text[0]))
                context.Report("Rename this type to follow the UpperCamelCase convention.", name.Line);
        }
    }
}

public sealed class RustUnusedMutRule : PatternRuleBase
{
    public override string Key => "QG-RS-CNV-0004";
    public override string Name => "Binding declared mut is never reassigned";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Remove the unnecessary mut modifier.";
    public override string[] Languages => ["rs"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var muts = new List<(string Name, int Line, int Index)>();
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Keyword || tokens[i].Text != "let")
                continue;
            var j = i + 1;
            if (j < tokens.Count && RuleMatchers.IsName(tokens[j], "mut"))
                j++;
            else
                continue;
            if (j >= tokens.Count || !RuleMatchers.IsIdentifier(tokens[j]))
                continue;
            muts.Add((tokens[j].Text, tokens[j].Line, j));
        }
        string[] assignOps = ["=", "+=", "-=", "*=", "/=", "&=", "|=", "^=", "<<=", ">>="];
        foreach (var (name, line, idx) in muts)
        {
            var reassigned = false;
            for (var i = 0; i + 1 < tokens.Count; i++)
            {
                if (i == idx || tokens[i].Kind != TokenKind.Identifier || tokens[i].Text != name)
                    continue;
                if (tokens[i].Line < line)
                    continue;
                if (RuleMatchers.Contains(tokens[i + 1].Text, assignOps))
                {
                    reassigned = true;
                    break;
                }
            }
            if (!reassigned)
                context.Report("This mut is never reassigned; remove it.", line);
        }
    }
}
