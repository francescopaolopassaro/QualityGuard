using QualityGuard.Core.Frameworks;
using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Security rules generated from YAML framework definitions. Each rule checks for a specific
/// sink kind (sql, command, xss, etc.) and reports when tainted data reaches that sink.
/// The rules are language-specific, driven by the sinks defined in each framework YAML.
/// </summary>
public static class FrameworkSecurityRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new FrameworkSqlInjectionRule(),
        new FrameworkCommandInjectionRule(),
        new FrameworkXssRule(),
        new FrameworkPathTraversalRule(),
        new FrameworkOpenRedirectRule(),
        new FrameworkNetworkRequestRule(),
        new FrameworkFileWriteRule(),
        new FrameworkCryptoAlgorithmRule(),
    ];
}

/// <summary>
/// Detects SQL injection: tainted data reaching SQL sinks defined in framework YAML.
/// </summary>
public sealed class FrameworkSqlInjectionRule : RuleBase
{
    public override string Key => "QG-ALL-SEC-0025";
    public override string Name => "SQL injection via tainted input in framework sinks";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use parameterized queries or ORM methods that handle escaping.";
    public override string[] Languages => [];

    public override void Execute(IRuleContext context)
    {
        var lang = context.Language.LanguageKey;
        var sqlSinks = context.Frameworks.GetSinks(lang)
            .Where(s => s.Kind == "sql")
            .ToList();
        if (sqlSinks.Count == 0) return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = sqlSinks.FirstOrDefault(s =>
                RuleMatchers.IsName(tokens[i], s.Method));
            if (sink == null) continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(") continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i)) continue;
            if (!context.IsTaintedLine(tokens[i].Line)) continue;
            context.Report($"This SQL method '{sink.Method}' receives tainted data; use a parameterized query.", tokens[i].Line);
        }
    }
}

/// <summary>
/// Detects command injection: tainted data reaching command sinks defined in framework YAML.
/// </summary>
public sealed class FrameworkCommandInjectionRule : RuleBase
{
    public override string Key => "QG-ALL-SEC-0026";
    public override string Name => "OS command injection via tainted input in framework sinks";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use a fixed command list and validate arguments separately.";
    public override string[] Languages => [];

    public override void Execute(IRuleContext context)
    {
        var lang = context.Language.LanguageKey;
        var cmdSinks = context.Frameworks.GetSinks(lang)
            .Where(s => s.Kind == "command")
            .ToList();
        if (cmdSinks.Count == 0) return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = cmdSinks.FirstOrDefault(s =>
                RuleMatchers.IsName(tokens[i], s.Method));
            if (sink == null) continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(") continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i)) continue;
            if (!context.IsTaintedLine(tokens[i].Line)) continue;
            context.Report($"This command method '{sink.Method}' receives tainted data; validate and sanitize the input.", tokens[i].Line);
        }
    }
}

/// <summary>
/// Detects XSS: tainted data reaching output sinks (render, json, send, etc.) defined in framework YAML.
/// </summary>
public sealed class FrameworkXssRule : RuleBase
{
    public override string Key => "QG-ALL-SEC-0027";
    public override string Name => "Cross-site scripting via tainted input in framework output sinks";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Encode output and escape user-controlled data before rendering.";
    public override string[] Languages => [];

    public override void Execute(IRuleContext context)
    {
        var lang = context.Language.LanguageKey;
        var xssSinks = context.Frameworks.GetSinks(lang)
            .Where(s => s.Kind == "xss")
            .ToList();
        if (xssSinks.Count == 0) return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = xssSinks.FirstOrDefault(s =>
                RuleMatchers.IsName(tokens[i], s.Method));
            if (sink == null) continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(") continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i)) continue;
            if (!context.IsTaintedLine(tokens[i].Line)) continue;
            context.Report($"This output method '{sink.Method}' may render tainted data; escape or encode the output.", tokens[i].Line);
        }
    }
}

/// <summary>
/// Detects path traversal: tainted data reaching file operation sinks defined in framework YAML.
/// </summary>
public sealed class FrameworkPathTraversalRule : RuleBase
{
    public override string Key => "QG-ALL-SEC-0028";
    public override string Name => "Path traversal via tainted input in file operation sinks";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and canonicalize file paths; reject user-controlled paths.";
    public override string[] Languages => [];

    public override void Execute(IRuleContext context)
    {
        var lang = context.Language.LanguageKey;
        var pathSinks = context.Frameworks.GetSinks(lang)
            .Where(s => s.Kind is "path_traversal" or "file_read" or "file_write")
            .ToList();
        if (pathSinks.Count == 0) return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = pathSinks.FirstOrDefault(s =>
                RuleMatchers.IsName(tokens[i], s.Method));
            if (sink == null) continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(") continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i)) continue;
            if (!context.IsTaintedLine(tokens[i].Line)) continue;
            context.Report($"This file operation '{sink.Method}' receives a tainted path; validate and sanitize it.", tokens[i].Line);
        }
    }
}

/// <summary>
/// Detects open redirect: tainted data reaching redirect sinks defined in framework YAML.
/// </summary>
public sealed class FrameworkOpenRedirectRule : RuleBase
{
    public override string Key => "QG-ALL-SEC-0029";
    public override string Name => "Open redirect via tainted input in redirect sinks";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "15min";
    public override string FixAdvice => "Validate redirect URLs against a whitelist of allowed destinations.";
    public override string[] Languages => [];

    public override void Execute(IRuleContext context)
    {
        var lang = context.Language.LanguageKey;
        var redirectSinks = context.Frameworks.GetSinks(lang)
            .Where(s => s.Kind == "open_redirect")
            .ToList();
        if (redirectSinks.Count == 0) return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = redirectSinks.FirstOrDefault(s =>
                RuleMatchers.IsName(tokens[i], s.Method));
            if (sink == null) continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(") continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i)) continue;
            if (!context.IsTaintedLine(tokens[i].Line)) continue;
            context.Report($"This redirect '{sink.Method}' may use a tainted URL; validate the destination.", tokens[i].Line);
        }
    }
}

/// <summary>
/// Detects SSRF: tainted data reaching network request sinks defined in framework YAML.
/// </summary>
public sealed class FrameworkNetworkRequestRule : RuleBase
{
    public override string Key => "QG-ALL-SEC-0030";
    public override string Name => "Server-side request forgery via tainted input in network sinks";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and whitelist destination URLs before making requests.";
    public override string[] Languages => [];

    public override void Execute(IRuleContext context)
    {
        var lang = context.Language.LanguageKey;
        var netSinks = context.Frameworks.GetSinks(lang)
            .Where(s => s.Kind is "network_request" or "network_connection")
            .ToList();
        if (netSinks.Count == 0) return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = netSinks.FirstOrDefault(s =>
                RuleMatchers.IsName(tokens[i], s.Method));
            if (sink == null) continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(") continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i)) continue;
            if (!context.IsTaintedLine(tokens[i].Line)) continue;
            context.Report($"This network request '{sink.Method}' uses a tainted URL; validate the destination.", tokens[i].Line);
        }
    }
}

/// <summary>
/// Detects insecure file writes: tainted data reaching file write sinks defined in framework YAML.
/// </summary>
public sealed class FrameworkFileWriteRule : RuleBase
{
    public override string Key => "QG-ALL-SEC-0031";
    public override string Name => "Insecure file write via tainted data in framework sinks";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate file paths and content before writing.";
    public override string[] Languages => [];

    public override void Execute(IRuleContext context)
    {
        var lang = context.Language.LanguageKey;
        var writeSinks = context.Frameworks.GetSinks(lang)
            .Where(s => s.Kind is "file_write" or "cache_write")
            .ToList();
        if (writeSinks.Count == 0) return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = writeSinks.FirstOrDefault(s =>
                RuleMatchers.IsName(tokens[i], s.Method));
            if (sink == null) continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(") continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i)) continue;
            if (!context.IsTaintedLine(tokens[i].Line)) continue;
            context.Report($"This write operation '{sink.Method}' uses tainted data; validate before writing.", tokens[i].Line);
        }
    }
}

/// <summary>
/// Detects weak crypto algorithm usage: calls to crypto sinks with known-weak algorithms.
/// </summary>
public sealed class FrameworkCryptoAlgorithmRule : RuleBase
{
    public override string Key => "QG-ALL-SEC-0032";
    public override string Name => "Use of weak cryptographic algorithm in framework crypto sinks";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use modern algorithms like AES-GCM, SHA-256, or Ed25519.";
    public override string[] Languages => [];

    private static readonly HashSet<string> WeakAlgorithms = new(StringComparer.OrdinalIgnoreCase)
    {
        "MD5", "SHA1", "DES", "3DES", "RC4", "Blowfish", "ECB",
        "RSA/ECB", "RSA/NONE", "AES/ECB"
    };

    public override void Execute(IRuleContext context)
    {
        var lang = context.Language.LanguageKey;
        var cryptoSinks = context.Frameworks.GetSinks(lang)
            .Where(s => s.Kind == "crypto_algorithm")
            .ToList();
        if (cryptoSinks.Count == 0) return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = cryptoSinks.FirstOrDefault(s =>
                RuleMatchers.IsName(tokens[i], s.Method));
            if (sink == null) continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(") continue;
            // Check if the argument is a string literal containing a weak algorithm
            for (var j = i + 2; j < Math.Min(i + 10, tokens.Count); j++)
            {
                if (tokens[j].Text == ")") break;
                if (tokens[j].Kind == TokenKind.String && WeakAlgorithms.Contains(tokens[j].Text.Trim('"', '\'')))
                {
                    context.Report($"Weak cryptographic algorithm '{tokens[j].Text.Trim('"', '\'')}' should not be used; use a modern algorithm instead.", tokens[i].Line);
                    break;
                }
            }
        }
    }
}
