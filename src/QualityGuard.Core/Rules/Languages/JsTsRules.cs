using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class JsTsRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JsChainedComparisonRule(),
        new JsEvalRule(),
        new JsCommandExecutionRule(),
        new JsTemplateInjectionRule(),
        new JsSqlInjectionRule(),
        new JsHardcodedCredentialsRule(),
        new JsStorageRule(),
        new JsInsecureCookieRule(),
        new JsWeakCryptoRule(),
        new JsMathRandomRule(),
        new JsCleartextHttpRule(),
        new JsOpenRedirectRule(),
        new JsPrototypePollutionRule(),
        new JsXssSinkRule(),
        new JsPostMessageRule(),
        new JsSsrRule(),
        new JsPathTraversalRule(),
        new JsSstiRule(),
        new JsHeaderInjectionRule(),
        new JsZipSlipRule(),
        new TsEnvSecretsRule(),
        new TsTlsVerificationRule(),
        new TsDynamicModuleRule(),
        new TsCorsWildcardRule(),
        new TsAnyAssertionRule(),
        new JsConsoleLogRule(),
        new JsDebuggerRule(),
        new JsBlockingDialogsRule(),
        new JsEmptyCatchRule(),
        new JsSwitchDefaultRule(),
        new JsInfiniteLoopRule(),
        new JsParseIntRadixRule(),
        new JsVarRule(),
        new JsStrictEqualityRule(),
        new JsSetTimeoutStringRule(),
        new TsSuppressionRule()
    ];

    internal static string[] Lines(IRuleContext context) => context.File.Content.Split('\n');

    internal static IEnumerable<Token> CallArguments(IReadOnlyList<Token> tokens, int callIndex)
    {
        var i = callIndex + 1;
        if (i >= tokens.Count || tokens[i].Text != "(")
            yield break;
        var depth = 0;
        for (; i < tokens.Count; i++)
        {
            if (tokens[i].Text == "(")
            {
                depth++;
            }
            else if (tokens[i].Text == ")")
            {
                depth--;
                if (depth == 0)
                    yield break;
            }
            else if (depth > 0)
            {
                yield return tokens[i];
            }
        }
    }
}

public sealed class JsEvalRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0001";
    public override string Name => "Arbitrary code execution via eval";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Avoid eval(); use a JSON parser or a safe evaluator.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        foreach (var token in RuleMatchers.Names(tokens, ["eval"]))
            context.Report("Do not evaluate arbitrary code with eval.", token.Line);
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "Function") && tokens[i + 1].Text == "(")
                context.Report("Do not build dynamic code with the Function constructor.", tokens[i].Line);
        }
    }
}

public sealed class JsCommandExecutionRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0002";
    public override string Name => "Command execution with a dynamic argument";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use a fixed command line and pass arguments through spawn's options instead of shell concatenation.";
    public override string[] Languages => ["js", "ts"];

    private static readonly string[] Names = ["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.Contains(tokens[i].Text, Names))
                continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (i > 0 && tokens[i - 1].Text == "function")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i))
                continue;
            context.Report("Do not execute operating system commands built from a dynamic argument.", tokens[i].Line);
        }
    }
}

public sealed class JsTemplateInjectionRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0003";
    public override string Name => "Command injection through string template";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not interpolate untrusted data into shell commands; use spawn with an argument array.";
    public override string[] Languages => ["js", "ts"];

    private static readonly string[] Names = ["exec", "execSync", "execFile", "spawn", "spawnSync", "fork"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.Contains(tokens[i].Text, Names) || i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (JsTsRuleSet.CallArguments(tokens, i).Any(t => RuleMatchers.IsString(t) && t.Text.Contains("${", StringComparison.Ordinal)))
                context.Report("Do not build shell commands through string interpolation.", tokens[i].Line);
        }
    }
}

public sealed class JsSqlInjectionRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0004";
    public override string Name => "SQL query built by string concatenation";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use parameterized queries or an ORM that binds user input as parameters.";
    public override string[] Languages => ["js", "ts"];

    private static readonly string[] SqlKeywords = ["select", "insert", "update", "delete", "drop", "alter", "create", "truncate"];
    private static readonly string[] MethodNames = ["query", "executeQuery", "execute", "raw", "prepare", "createQuery"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.Contains(tokens[i].Text, MethodNames) || i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            var args = JsTsRuleSet.CallArguments(tokens, i).ToList();
            var hasSql = args.Any(t => RuleMatchers.IsString(t) && SqlKeywords.Any(k =>
                t.Text.Contains(k, StringComparison.OrdinalIgnoreCase)));
            if (!hasSql)
                continue;
            var hasConcat = args.Any(t => t.Text == "+")
                || args.Any(t => RuleMatchers.IsString(t) && t.Text.Contains("${", StringComparison.Ordinal));
            if (hasConcat)
                context.Report("Do not concatenate user-controlled values into SQL statements.", tokens[i].Line);
        }
    }
}

public sealed class JsHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0005";
    public override string Name => "Hardcoded credential";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Store secrets in a vault or environment variables and load them at runtime.";
    public override string[] Languages => ["js", "ts"];

    private static readonly string[] CredentialNames =
    [
        "password", "passwd", "pwd", "secret", "apikey", "api_key", "api-key", "access_token",
        "auth_token", "authkey", "client_secret", "consumer_secret", "private_key", "privatekey",
        "credential", "credentials", "token", "token_secret", "signing_secret", "session_secret"
    ];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            if (!RuleMatchers.Contains(tokens[i].Text, CredentialNames, caseInsensitive: true))
                continue;
            if (!RuleMatchers.IsSymbol(tokens[i + 1], "=") && !RuleMatchers.IsSymbol(tokens[i + 1], ":"))
                continue;
            if (RuleMatchers.IsString(tokens[i + 2]))
                context.Report($"Do not hardcode the credential '{tokens[i].Text}' in source code.", tokens[i].Line);
        }
    }
}

public sealed class JsStorageRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0006";
    public override string Name => "Sensitive data stored in web storage";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not store sensitive data in localStorage or sessionStorage; use a safe server-side session.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "localStorage") && !RuleMatchers.IsName(tokens[i], "sessionStorage"))
                continue;
            if (tokens[i + 1].Text == "." && RuleMatchers.IsName(tokens[i + 2], "setItem"))
                context.Report("Sensitive data written to web storage is readable from any script.", tokens[i].Line);
        }
    }
}

public sealed class JsInsecureCookieRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0007";
    public override string Name => "Cookie written without Secure and HttpOnly flags";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set cookies with the Secure and HttpOnly flags unless the cookie is intentionally client-accessible.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var lines = JsTsRuleSet.Lines(context);
        for (var i = 0; i < tokens.Count - 3; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "document") || tokens[i + 1].Text != "."
                || !RuleMatchers.IsName(tokens[i + 2], "cookie") || tokens[i + 3].Text != "=")
                continue;
            var line = lines[tokens[i].Line - 1];
            if (!RuleMatchers.LineContains(line, "Secure") || !RuleMatchers.LineContains(line, "HttpOnly"))
                context.Report("Write cookies with the Secure and HttpOnly attributes.", tokens[i].Line);
        }
    }
}

public sealed class JsWeakCryptoRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0008";
    public override string Name => "Use of a weak hashing algorithm";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use a strong, modern algorithm such as SHA-256 or a dedicated password hashing function.";
    public override string[] Languages => ["js", "ts"];

    private static readonly string[] WeakAlgorithms = ["md5", "sha1", "sha-1"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "createHash") || i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (JsTsRuleSet.CallArguments(tokens, i).Any(t => RuleMatchers.IsString(t) && WeakAlgorithms.Any(a =>
                t.Text.Contains(a, StringComparison.OrdinalIgnoreCase))))
                context.Report("This hashing algorithm is considered weak and broken.", tokens[i].Line);
        }
    }
}

public sealed class JsMathRandomRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0009";
    public override string Name => "Insecure random number generator";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use a cryptographically secure generator such as crypto.getRandomValues.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "Math") && tokens[i + 1].Text == "."
                && RuleMatchers.IsName(tokens[i + 2], "random") && tokens[i + 2].Text == "random")
                context.Report("Math.random is not suitable for security-sensitive values.", tokens[i].Line);
        }
    }
}

public sealed class JsCleartextHttpRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0010";
    public override string Name => "Cleartext HTTP usage";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Communicate only over HTTPS endpoints.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.StringsContaining(context.Tokens, "http://"))
            context.Report("Communicating over cleartext HTTP may expose data.", token.Line);
    }
}

public sealed class JsOpenRedirectRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0011";
    public override string Name => "Open redirect via location assignment";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate and whitelist the redirect target before assigning location.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 3; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "location"))
                continue;
            if (tokens[i + 1].Text == "." && RuleMatchers.IsName(tokens[i + 2], "href") && tokens[i + 3].Text == "=")
            {
                context.Report("Redirecting to an unvalidated location enables open redirect attacks.", tokens[i].Line);
                continue;
            }
            if (i > 0 && tokens[i - 1].Text == "." && tokens[i + 1].Text == "=")
                context.Report("Redirecting to an unvalidated location enables open redirect attacks.", tokens[i].Line);
        }
    }
}

public sealed class JsPrototypePollutionRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0012";
    public override string Name => "Prototype pollution vector";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Never merge untrusted objects into prototypes; reject keys named __proto__ or constructor.prototype.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Text == "__proto__"))
            context.Report("Accessing __proto__ can lead to prototype pollution.", token.Line);
    }
}

public sealed class JsXssSinkRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0013";
    public override string Name => "Cross-site scripting sink";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Never write untrusted data to HTML sinks; use textContent or a sanitization library.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (RuleMatchers.Contains(tokens[i].Text, ["innerHTML", "outerHTML", "insertAdjacentHTML"]))
            {
                context.Report($"Writing dynamic content to {tokens[i].Text} can lead to XSS.", tokens[i].Line);
                continue;
            }
            if (i >= 2 && RuleMatchers.IsName(tokens[i], "write") && tokens[i - 1].Text == "."
                && RuleMatchers.IsName(tokens[i - 2], "document"))
                context.Report("document.write can be an XSS sink for untrusted content.", tokens[i].Line);
        }
    }
}

public sealed class JsPostMessageRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0014";
    public override string Name => "postMessage to a wildcard target origin";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Pass a specific target origin instead of '*' to avoid leaking messages.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "postMessage") || i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (JsTsRuleSet.CallArguments(tokens, i).Any(t => RuleMatchers.IsString(t) && t.Text == "*"))
                context.Report("postMessage should not use '*' as the target origin.", tokens[i].Line);
        }
    }
}

public sealed class TsEnvSecretsRule : PatternRuleBase
{
    public override string Key => "QG-TS-SEC-0001";
    public override string Name => "Secret read from environment";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not place secrets in code or logs; load them from a secure secret store.";
    public override string[] Languages => ["ts"];

    private static readonly string[] SecretNames =
    [
        "secret", "password", "passwd", "pwd", "apikey", "api_key", "api-key", "access_token",
        "auth_token", "authkey", "auth_key", "client_secret", "client_id", "consumer_key",
        "consumer_secret", "private_key", "privatekey", "credential", "credentials", "token",
        "token_secret", "session_secret", "jwt_secret", "signing_secret"
    ];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 2; i < tokens.Count; i++)
        {
            if (tokens[i - 1].Text != "." || !RuleMatchers.IsName(tokens[i - 2], "env"))
                continue;
            if (SecretNames.Contains(tokens[i].Text, StringComparer.OrdinalIgnoreCase))
                context.Report($"Environment variable '{tokens[i].Text}' holds a secret; protect it from exposure.", tokens[i].Line);
        }
    }
}

public sealed class TsTlsVerificationRule : PatternRuleBase
{
    public override string Key => "QG-TS-SEC-0002";
    public override string Name => "Disabling TLS certificate verification";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Keep TLS certificate validation enabled; fix the certificate issue instead of disabling checks.";
    public override string[] Languages => ["ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "NODE_TLS_REJECT_UNAUTHORIZED", caseInsensitive: true)
                || tokens[i + 1].Text != "=")
                continue;
            if (tokens[i + 2].Text is "0" or "false")
                context.Report("Disabling TLS certificate validation exposes connections to man-in-the-middle attacks.", tokens[i].Line);
        }
    }
}

public sealed class TsDynamicModuleRule : PatternRuleBase
{
    public override string Key => "QG-TS-SEC-0003";
    public override string Name => "Dynamic module loading";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use static imports or validate that the resolved path is under an allowed directory.";
    public override string[] Languages => ["ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "require" && tokens[i].Text != "import")
                continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i))
                continue;
            context.Report("Do not load modules from a dynamically constructed path.", tokens[i].Line);
        }
    }
}

public sealed class JsConsoleLogRule : PatternRuleBase
{
    public override string Key => "QG-JS-SML-0001";
    public override string Name => "Logging statements left in production code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Remove or gate debugging statements behind a logging configuration.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "console") && tokens[i + 1].Text == "."
                && RuleMatchers.Contains(tokens[i + 2].Text, ["log", "debug", "info"]))
                context.Report("Remove this logging statement from production code.", tokens[i].Line);
        }
    }
}

public sealed class JsDebuggerRule : PatternRuleBase
{
    public override string Key => "QG-JS-SML-0002";
    public override string Name => "Debugger statement left in production code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Remove the debugger statement before shipping.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Text == "debugger"))
            context.Report("Remove the debugger statement before shipping.", token.Line);
    }
}

public sealed class JsBlockingDialogsRule : PatternRuleBase
{
    public override string Key => "QG-JS-SML-0003";
    public override string Name => "Blocking dialog in production code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Replace blocking dialogs with non-blocking UI elements.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (RuleMatchers.Contains(tokens[i].Text, ["alert", "confirm", "prompt"]) && tokens[i + 1].Text == "(")
                context.Report("Blocking dialogs should not be used in production code.", tokens[i].Line);
        }
    }
}

public sealed class JsEmptyCatchRule : PatternRuleBase
{
    public override string Key => "QG-JS-SML-0004";
    public override string Name => "Empty catch block swallows errors";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Handle or at least log the exception inside the catch block.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "catch")
                continue;
            var j = i + 1;
            if (j < tokens.Count && tokens[j].Text == "(")
            {
                while (j < tokens.Count && tokens[j].Text != ")")
                    j++;
                j++;
            }
            if (j + 1 < tokens.Count && tokens[j].Text == "{" && tokens[j + 1].Text == "}")
                context.Report("Either handle this exception or remove the empty catch block.", tokens[i].Line);
        }
    }
}

public sealed class JsSwitchDefaultRule : PatternRuleBase
{
    public override string Key => "QG-JS-SML-0005";
    public override string Name => "Switch without a default clause";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Add a default clause to handle the unexpected values explicitly.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var switches = context.Tokens.Where(t => t.Text == "switch").ToList();
        if (switches.Count == 0)
            return;
        if (context.Tokens.All(t => t.Text != "default"))
        {
            foreach (var sw in switches)
                context.Report("Add a default case to this switch statement.", sw.Line);
        }
    }
}

public sealed class JsInfiniteLoopRule : PatternRuleBase
{
    public override string Key => "QG-JS-SML-0006";
    public override string Name => "Infinite loop with a literal true condition";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Guarantee a break condition or use an exit flag for the loop.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            if (tokens[i].Text == "while" && tokens[i + 1].Text == "(" && tokens[i + 2].Text == "true")
                context.Report("This loop condition is always true; make sure a break is reachable.", tokens[i].Line);
        }
    }
}

public sealed class JsVarRule : PatternRuleBase
{
    public override string Key => "QG-JS-CNV-0001";
    public override string Name => "Use of var instead of const or let";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Use const for never-reassigned bindings and let otherwise.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Text == "var"))
            context.Report("Use const or let instead of var.", token.Line);
    }
}

public sealed class JsStrictEqualityRule : PatternRuleBase
{
    public override string Key => "QG-JS-BUG-0001";
    public override string Name => "Loose equality operators";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "Use === and !== to avoid implicit type coercion.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "==" && tokens[i].Text != "!=")
                continue;
            // comparing with null covers undefined as well and is the accepted idiom
            var neighbour = i + 1 < tokens.Count ? tokens[i + 1].Text : string.Empty;
            var previous = i > 0 ? tokens[i - 1].Text : string.Empty;
            if (neighbour is "null" or "undefined" || previous is "null" or "undefined")
                continue;
            context.Report("Use strict equality (===/!==) to avoid type coercion bugs.", tokens[i].Line);
        }
    }
}

public sealed class TsSuppressionRule : PatternRuleBase
{
    public override string Key => "QG-TS-SML-0001";
    public override string Name => "Type checking suppressed";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Resolve the underlying type error instead of suppressing the compiler.";
    public override string[] Languages => ["ts"];

    public override void Execute(IRuleContext context)
    {
        var lines = JsTsRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "@ts-ignore")
                || RuleMatchers.LineContains(lines[i], "@ts-nocheck")
                || RuleMatchers.LineContains(lines[i], "@ts-expect-error"))
                context.Report("A comment is suppressing TypeScript type checking.", i + 1);
        }
    }
}

public sealed class JsSsrRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0015";
    public override string Name => "Server-side request forgery";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate and whitelist the request target; never forward user input to internal services.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "fetch") && !RuleMatchers.IsName(tokens[i], "request"))
                continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Do not fetch a URL built from untrusted input.", tokens[i].Line);
        }
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "get" && tokens[i].Text != "post")
                continue;
            if (i < 2 || tokens[i - 1].Text != "." || (!RuleMatchers.IsName(tokens[i - 2], "axios")
                && !RuleMatchers.IsName(tokens[i - 2], "http")))
                continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Do not build the request URL from untrusted input.", tokens[i].Line);
        }
    }
}

public sealed class JsPathTraversalRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0016";
    public override string Name => "Path traversal in file access";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Resolve and validate the path stays inside an allowed directory; reject traversal sequences.";
    public override string[] Languages => ["js", "ts"];

    private static readonly string[] FileMethods = ["readFile", "readFileSync", "writeFile", "writeFileSync", "createReadStream"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.Contains(tokens[i].Text, FileMethods))
                continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Do not access a file whose path is built from untrusted input.", tokens[i].Line);
        }
    }
}

public sealed class JsSstiRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0017";
    public override string Name => "Server-side template injection";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Never pass user input into a template renderer; pass it as structured data after escaping.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "render") && !RuleMatchers.IsName(tokens[i], "compile"))
                continue;
            if (i >= 2 && tokens[i - 1].Text == "."
                && (RuleMatchers.IsName(tokens[i - 2], "ejs") || RuleMatchers.IsName(tokens[i - 2], "nunjucks")
                    || RuleMatchers.IsName(tokens[i - 2], "handlebars")))
            {
                if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                    continue;
                if (RuleMatchers.NextNonParenIsString(tokens, i))
                    continue;
                context.Report("Do not render a template built from untrusted input.", tokens[i].Line);
            }
        }
    }
}

public sealed class JsHeaderInjectionRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0018";
    public override string Name => "HTTP response header injection";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Never write user input directly into response headers; validate and encode values.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "setHeader") || i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            var args = JsTsRuleSet.CallArguments(tokens, i).ToList();
            if (args.Any(t => t.Kind == TokenKind.Identifier) && !context.IsTaintedLine(tokens[i].Line)
                && args.All(t => t.Text != "\\r" && t.Text != "\\n"))
                context.Report("Do not write untrusted values into response headers.", tokens[i].Line);
        }
    }
}

public sealed class JsZipSlipRule : PatternRuleBase
{
    public override string Key => "QG-JS-SEC-0019";
    public override string Name => "Unsafe archive extraction destination";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate entry names and ensure extracted files stay inside the target directory.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "extractAllTo") && !RuleMatchers.IsName(tokens[i], "extract"))
                continue;
            if (RuleMatchers.IsName(tokens[i], "extract") && (i < 1 || tokens[i - 1].Text != "."))
                continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i))
                continue;
            context.Report("Do not extract archives to a path built from untrusted input.", tokens[i].Line);
        }
    }
}

public sealed class JsParseIntRadixRule : PatternRuleBase
{
    public override string Key => "QG-JS-SML-0007";
    public override string Name => "parseInt called without a radix";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Pass the radix as the second argument to parseInt to avoid ambiguity across environments.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "parseInt") || i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            var args = JsTsRuleSet.CallArguments(tokens, i).ToList();
            if (args.Count > 0 && args.All(t => t.Text != ","))
                context.Report("Provide the radix argument to parseInt.", tokens[i].Line);
        }
    }
}

public sealed class JsSetTimeoutStringRule : PatternRuleBase
{
    public override string Key => "QG-JS-BUG-0002";
    public override string Name => "setTimeout or setInterval with a string callback";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "Pass a function reference instead of a string; string callbacks execute in global scope.";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "setTimeout") && !RuleMatchers.IsName(tokens[i], "setInterval"))
                continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i))
                context.Report("Pass a function instead of a string to setTimeout/setInterval.", tokens[i].Line);
        }
    }
}

public sealed class TsCorsWildcardRule : PatternRuleBase
{
    public override string Key => "QG-TS-SEC-0004";
    public override string Name => "CORS header set to a wildcard origin";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Restrict Access-Control-Allow-Origin to trusted origins instead of '*'.";
    public override string[] Languages => ["ts"];

    public override void Execute(IRuleContext context)
    {
        var lines = JsTsRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "Access-Control-Allow-Origin")
                && RuleMatchers.LineContains(lines[i], "*"))
                context.Report("Access-Control-Allow-Origin should not be set to a wildcard.", i + 1);
        }
    }
}

public sealed class TsAnyAssertionRule : PatternRuleBase
{
    public override string Key => "QG-TS-SML-0002";
    public override string Name => "Type assertion to any";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Avoid 'as any'; narrow the type explicitly instead of erasing type safety.";
    public override string[] Languages => ["ts"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "as") && RuleMatchers.IsName(tokens[i + 1], "any"))
                context.Report("Casting to any bypasses TypeScript type checking.", tokens[i].Line);
        }
    }
}


/// <summary>
/// Chained comparisons compile in JavaScript but compare a boolean with the next operand, so the tree
/// is what tells the difference between a range check and a mistake.
/// </summary>
public sealed class JsChainedComparisonRule : PatternRuleBase
{
    private static readonly string[] Comparisons = ["<", ">", "<=", ">="];

    public override string Key => "QG-JS-BUG-0010";
    public override string Name => "Comparisons should not be chained";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["js", "ts"];

    public override void Execute(IRuleContext context)
    {
        foreach (var comparison in context.Root.OfKind(QualityGuard.Core.Syntax.NodeKind.Binary))
        {
            if (!Comparisons.Contains(comparison.Text, StringComparer.Ordinal))
                continue;
            var nested = comparison.Children.FirstOrDefault(c =>
                c.Kind == QualityGuard.Core.Syntax.NodeKind.Binary
                && Comparisons.Contains(c.Text, StringComparer.Ordinal));
            if (nested == null)
                continue;
            context.Report(comparison, "This compares the result of another comparison; "
                                       + "split the range check into two conditions.");
        }
    }
}
