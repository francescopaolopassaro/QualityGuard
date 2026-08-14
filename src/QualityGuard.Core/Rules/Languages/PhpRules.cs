using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class PhpRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PhpEvalRule(),
        new PhpDynamicCodeRule(),
        new PhpSystemCallsRule(),
        new PhpSqlInjectionRule(),
        new PhpHardcodedCredentialsRule(),
        new PhpXssRule(),
        new PhpDynamicIncludeRule(),
        new PhpCleartextHttpRule(),
        new PhpWeakCryptoRule(),
        new PhpUnsafeDeserializationRule(),
        new PhpOpenRedirectRule(),
        new PhpUnrestrictedUploadRule(),
        new PhpInsecureCookieRule(),
        new PhpSsrfRule(),
        new PhpExtractSuperglobalRule(),
        new PhpDebugOutputRule(),
        new PhpErrorSuppressionRule(),
        new PhpGotoRule(),
        new PhpEmptyCatchRule(),
        new PhpDeprecatedMysqlFunctionsRule(),
        new PhpInfiniteLoopRule(),
        new PhpDeprecatedMcryptRule(),
        new PhpSsrfClientRule(),
        new PhpPathTraversalRule(),
        new PhpHeaderInjectionRule(),
        new PhpLdapInjectionRule(),
        new PhpGlobalsUsageRule(),
        new PhpLooseComparisonRule()
    ];

    internal static string[] LinesOf(IRuleContext context) => context.File.Content.Split('\n');

    internal static string LineAt(IRuleContext context, int line)
    {
        var lines = LinesOf(context);
        return line >= 1 && line <= lines.Length ? lines[line - 1] : "";
    }

    internal static bool IsWord(Token token, string name, bool caseInsensitive = false)
        => (token.Kind is TokenKind.Identifier or TokenKind.Keyword) &&
           (caseInsensitive
               ? string.Equals(token.Text, name, StringComparison.OrdinalIgnoreCase)
               : token.Text == name);

    internal static bool IsWord(Token token, string[] names, bool caseInsensitive = false)
        => (token.Kind is TokenKind.Identifier or TokenKind.Keyword)
           && RuleMatchers.Contains(token.Text, names, caseInsensitive);

    internal static bool IsWord(string text, string[] names, bool caseInsensitive = false)
        => RuleMatchers.Contains(text, names, caseInsensitive);

    internal static bool HasAny(string text, string[] fragments)
        => fragments.Any(f => text.Contains(f, StringComparison.OrdinalIgnoreCase));

    internal static bool IsSuperglobal(string line)
        => HasAny(line, ["$_GET", "$_POST", "$_REQUEST"]);

    internal static bool IsCredentialName(Token token)
    {
        if (token.Kind is not (TokenKind.Identifier or TokenKind.Keyword)) return false;
        var name = token.Text.TrimStart('$');
        return name.Length > 0
            && IsWord(name, ["password", "pass", "pwd", "secret", "token", "credential", "apikey", "api_key"], true);
    }

    internal static bool IsEmptyCatch(IReadOnlyList<Token> tokens, int index)
    {
        var k = index + 1;
        if (k < tokens.Count && tokens[k].Text == "(")
        {
            var depth = 0;
            for (; k < tokens.Count; k++)
            {
                if (tokens[k].Text == "(") depth++;
                else if (tokens[k].Text == ")")
                {
                    depth--;
                    if (depth == 0) { k++; break; }
                }
            }
        }
        while (k < tokens.Count && tokens[k].Text != "{" && tokens[k].Text != ";")
            k++;
        return k + 1 < tokens.Count && tokens[k].Text == "{" && tokens[k + 1].Text == "}";
    }
}

public sealed class PhpEvalRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0001";
    public override string Name => "Arbitrary code execution via eval";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not use eval(); parse and validate input instead.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => PhpRuleSet.IsWord(t, "eval", true)))
            context.Report("Do not evaluate arbitrary code.", token.Line);
    }
}

public sealed class PhpDynamicCodeRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0002";
    public override string Name => "Arbitrary code execution via assert and string-based callbacks";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Avoid assert and callback-based code generation; validate input strictly.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (PhpRuleSet.IsWord(token, "assert", true) || PhpRuleSet.IsWord(token, "create_function", true))
                context.Report("Do not evaluate code built from strings.", token.Line);
            else if (PhpRuleSet.IsWord(token, "preg_replace", true)
                     && PhpRuleSet.LineAt(context, token.Line).Contains("/e", StringComparison.Ordinal))
                context.Report("The /e modifier in preg_replace executes code.", token.Line);
        }
    }
}

public sealed class PhpSystemCallsRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0003";
    public override string Name => "Execution of OS commands";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Replace system calls with safe APIs and validate all input.";
    public override string[] Languages => ["php"];
    private static readonly string[] Calls = ["exec", "system", "shell_exec", "passthru", "proc_open", "popen"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (PhpRuleSet.IsWord(tokens[i], Calls, true) && !RuleMatchers.NextNonParenIsString(tokens, i))
                context.Report("Sanitize arguments passed to OS command execution.", tokens[i].Line);
        }
        var lines = PhpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (lines[i].Contains('`'))
                context.Report("Backtick command substitution executes shell commands.", i + 1);
        }
    }
}

public sealed class PhpSqlInjectionRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0004";
    public override string Name => "SQL injection via concatenated queries";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use prepared statements with bound parameters.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var lines = PhpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!PhpRuleSet.HasAny(line, ["mysqli_query", "mysql_query", "pg_query", "sqlsrv_query", "oci_parse", "->query", "->exec", "::exec"]))
                continue;
            if (!PhpRuleSet.HasAny(line, ["select", "insert", "update", "delete", "drop"]))
                continue;
            if (!(line.Contains(".$") || PhpRuleSet.HasAny(line, ["sprintf", "$_GET", "$_POST", "$_REQUEST"])))
                continue;
            context.Report("Sanitize values interpolated into SQL queries.", i + 1);
        }
    }
}

public sealed class PhpHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0005";
    public override string Name => "Hardcoded credentials";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Load credentials from a secure secret store.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!PhpRuleSet.IsCredentialName(tokens[i])) continue;
            for (var j = i + 1; j < tokens.Count && j < i + 6; j++)
            {
                if (tokens[j].Text is "=" or "=>")
                {
                    if (j + 1 < tokens.Count && tokens[j + 1].Kind == TokenKind.String)
                        context.Report("Hardcoded credentials must not be committed.", tokens[i].Line);
                    break;
                }
                if (tokens[j].Text is ";" or "(" or ")" or "{" or "}")
                    break;
            }
        }
    }
}

public sealed class PhpXssRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0006";
    public override string Name => "Reflected XSS without output escaping";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Escape request data before writing it to output.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var lines = PhpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!PhpRuleSet.IsSuperglobal(line)) continue;
            if (!PhpRuleSet.HasAny(line, ["echo", "print"]) || line.Contains("print_r", StringComparison.OrdinalIgnoreCase))
                continue;
            context.Report("Escape output that contains request data.", i + 1);
        }
    }
}

public sealed class PhpDynamicIncludeRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0007";
    public override string Name => "Dynamic file inclusion";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Resolve file paths used with include/require to a safe allow list.";
    public override string[] Languages => ["php"];
    private static readonly string[] Forms = ["include", "include_once", "require", "require_once"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (PhpRuleSet.IsWord(tokens[i], Forms, true) && !RuleMatchers.NextNonParenIsString(tokens, i))
                context.Report("Resolve file paths used with include/require to a safe allow list.", tokens[i].Line);
        }
    }
}

public sealed class PhpCleartextHttpRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0008";
    public override string Name => "Cleartext HTTP";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use HTTPS instead of cleartext HTTP.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.StringsContaining(context.Tokens, "http://"))
            context.Report("Use HTTPS instead of cleartext HTTP.", token.Line);
    }
}

public sealed class PhpWeakCryptoRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0009";
    public override string Name => "Use of weak cryptographic primitives";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Replace MD5/SHA1 and legacy ciphers with modern algorithms (AES-256-GCM, sha2).";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => PhpRuleSet.IsWord(t, ["md5", "sha1", "crypt"], true)))
            context.Report("Replace weak cryptographic primitives with modern algorithms.", token.Line);
        foreach (var token in RuleMatchers.StringsContaining(context.Tokens, "des-")
                     .Concat(RuleMatchers.StringsContaining(context.Tokens, "rc4"))
                     .Concat(RuleMatchers.StringsContaining(context.Tokens, "ecb")))
            context.Report("Weak cipher suites or modes must not be used.", token.Line);
    }
}

public sealed class PhpUnsafeDeserializationRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0010";
    public override string Name => "Unsafe deserialization";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Avoid unserialize() on untrusted data; use JSON with schema validation.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => PhpRuleSet.IsWord(t, "unserialize", true)))
            context.Report("Unsafe deserialization can lead to code execution.", token.Line);
    }
}

public sealed class PhpOpenRedirectRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0011";
    public override string Name => "Open redirect via Location header";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate redirect targets against an allow list.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var lines = PhpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!PhpRuleSet.HasAny(line, ["header("])) continue;
            if (!PhpRuleSet.HasAny(line, ["Location", "location"])) continue;
            if (PhpRuleSet.IsSuperglobal(line))
                context.Report("Validate Location header values to prevent open redirects.", i + 1);
        }
    }
}

public sealed class PhpUnrestrictedUploadRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0012";
    public override string Name => "Unrestricted file upload";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate uploaded file type, size and content before storing.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => PhpRuleSet.IsWord(t, "move_uploaded_file", true)))
            context.Report("Validate uploaded file type and content before storing.", token.Line);
    }
}

public sealed class PhpInsecureCookieRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0013";
    public override string Name => "Insecure cookie configuration";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set the Secure and HttpOnly flags on cookies.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var lines = PhpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!PhpRuleSet.HasAny(lines[i], ["setcookie"])) continue;
            if (PhpRuleSet.HasAny(lines[i], ["httponly", "secure"])) continue;
            context.Report("Set the Secure and HttpOnly flags on cookies.", i + 1);
        }
    }
}

public sealed class PhpSsrfRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0014";
    public override string Name => "Server-Side Request Forgery via remote resource";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate and allow list URLs passed to remote resource access.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => PhpRuleSet.IsWord(t, ["file_get_contents", "fopen"], true)))
        {
            if (PhpRuleSet.LineAt(context, token.Line).Contains("http", StringComparison.OrdinalIgnoreCase))
                context.Report("Validate URLs passed to remote resource access.", token.Line);
        }
    }
}

public sealed class PhpExtractSuperglobalRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0015";
    public override string Name => "Variable injection via extract";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not extract request data into local variables.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => PhpRuleSet.IsWord(t, "extract", true)))
        {
            if (PhpRuleSet.IsSuperglobal(PhpRuleSet.LineAt(context, token.Line)))
                context.Report("Do not extract request data into local variables.", token.Line);
        }
    }
}

public sealed class PhpDebugOutputRule : PatternRuleBase
{
    public override string Key => "QG-PP-SML-0001";
    public override string Name => "Debug output left in production code";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Remove var_dump and print_r calls before shipping.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => PhpRuleSet.IsWord(t, ["var_dump", "print_r"], true)))
            context.Report("Remove debug output before production.", token.Line);
    }
}

public sealed class PhpErrorSuppressionRule : PatternRuleBase
{
    public override string Key => "QG-PP-SML-0002";
    public override string Name => "Error suppression operator";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Handle errors explicitly instead of suppressing them.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (RuleMatchers.IsSymbol(tokens[i], "@")
                && (tokens[i + 1].Kind is TokenKind.Identifier or TokenKind.Keyword))
                context.Report("Avoid the error suppression operator.", tokens[i].Line);
        }
    }
}

public sealed class PhpGotoRule : PatternRuleBase
{
    public override string Key => "QG-PP-SML-0003";
    public override string Name => "Goto statements";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Refactor to structured control flow.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => PhpRuleSet.IsWord(t, "goto", true)))
            context.Report("Refactor to structured control flow.", token.Line);
    }
}

public sealed class PhpEmptyCatchRule : PatternRuleBase
{
    public override string Key => "QG-PP-SML-0004";
    public override string Name => "Empty catch block";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Handle or log the exception instead of swallowing it.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (PhpRuleSet.IsWord(tokens[i], "catch", true) && PhpRuleSet.IsEmptyCatch(tokens, i))
                context.Report("Either handle or log the exception.", tokens[i].Line);
        }
    }
}

public sealed class PhpDeprecatedMysqlFunctionsRule : PatternRuleBase
{
    public override string Key => "QG-PP-SML-0005";
    public override string Name => "Deprecated mysql_* functions";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Migrate to mysqli or PDO.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.Identifier
                                                         && t.Text.StartsWith("mysql_", StringComparison.OrdinalIgnoreCase)))
            context.Report("The mysql_* extension is deprecated; use mysqli or PDO.", token.Line);
    }
}

public sealed class PhpInfiniteLoopRule : PatternRuleBase
{
    public override string Key => "QG-PP-SML-0006";
    public override string Name => "Unconditional infinite loop";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Introduce an explicit exit condition.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var lines = PhpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (PhpRuleSet.HasAny(lines[i], ["while"]) && PhpRuleSet.HasAny(lines[i], ["true"])
                && !PhpRuleSet.HasAny(lines[i], ["false"]))
                context.Report("Avoid unconditional infinite loops.", i + 1);
        }
    }
}

public sealed class PhpDeprecatedMcryptRule : PatternRuleBase
{
    public override string Key => "QG-PP-SML-0007";
    public override string Name => "Deprecated mcrypt_* functions";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Use OpenSSL or sodium instead of mcrypt.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.Identifier
                                                         && t.Text.StartsWith("mcrypt_", StringComparison.OrdinalIgnoreCase)))
            context.Report("The mcrypt extension is deprecated; use OpenSSL.", token.Line);
    }
}

public sealed class PhpSsrfClientRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0016";
    public override string Name => "Server-Side Request Forgery via HTTP clients";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate and allow list URLs passed to HTTP clients such as cURL.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!PhpRuleSet.IsWord(tokens[i], ["curl_exec", "curl_setopt", "fopen"], true))
                continue;
            var line = PhpRuleSet.LineAt(context, tokens[i].Line);
            if (!RuleMatchers.NextNonParenIsString(tokens, i)
                || PhpRuleSet.IsSuperglobal(line)
                || context.IsTaintedLine(tokens[i].Line))
                context.Report("Validate URLs passed to HTTP clients to prevent SSRF.", tokens[i].Line);
        }
    }
}

public sealed class PhpPathTraversalRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0017";
    public override string Name => "Path traversal via user-controlled file path";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate file paths against a base directory allow list.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!PhpRuleSet.IsWord(tokens[i], ["file_get_contents", "readfile", "file"], true))
                continue;
            if (!RuleMatchers.NextNonParenIsString(tokens, i)
                || PhpRuleSet.IsSuperglobal(PhpRuleSet.LineAt(context, tokens[i].Line))
                || context.IsTaintedLine(tokens[i].Line))
                context.Report("Validate file paths passed to file access calls.", tokens[i].Line);
        }
    }
}

public sealed class PhpHeaderInjectionRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0018";
    public override string Name => "HTTP header injection";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Strip CR/LF characters and validate header values before sending.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var lines = PhpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (PhpRuleSet.HasAny(lines[i], ["header("])
                && PhpRuleSet.HasAny(lines[i], ["\\r", "%0d", "%0a"]))
                context.Report("Header values must not contain CR/LF injection.", i + 1);
        }
    }
}

public sealed class PhpLdapInjectionRule : PatternRuleBase
{
    public override string Key => "QG-PP-SEC-0019";
    public override string Name => "LDAP injection via dynamic filter";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Escape LDAP special characters and use allow lists in filters.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!PhpRuleSet.IsWord(tokens[i], ["ldap_search", "ldap_list", "ldap_read"], true))
                continue;
            if (!RuleMatchers.NextNonParenIsString(tokens, i)
                || PhpRuleSet.IsSuperglobal(PhpRuleSet.LineAt(context, tokens[i].Line))
                || context.IsTaintedLine(tokens[i].Line))
                context.Report("Sanitize LDAP filters built from user input.", tokens[i].Line);
        }
    }
}

public sealed class PhpGlobalsUsageRule : PatternRuleBase
{
    public override string Key => "QG-PP-SML-0008";
    public override string Name => "Direct use of the $GLOBALS superglobal";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Avoid the $GLOBALS superglobal; pass dependencies explicitly.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var lines = PhpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (PhpRuleSet.HasAny(lines[i], ["$GLOBALS"]))
                context.Report("Avoid direct use of the $GLOBALS superglobal.", i + 1);
        }
    }
}

public sealed class PhpLooseComparisonRule : PatternRuleBase
{
    public override string Key => "QG-PP-BUG-0001";
    public override string Name => "Loose comparison operator";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "Use strict comparison === to avoid type coercion bugs.";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsSymbol(tokens[i], "=="))
                continue;
            if (i > 0 && RuleMatchers.IsSymbol(tokens[i - 1], "!"))
                continue;
            if (i + 1 < tokens.Count && RuleMatchers.IsSymbol(tokens[i + 1], "="))
                continue;
            context.Report("Use strict comparison === to avoid type coercion.", tokens[i].Line);
        }
    }
}