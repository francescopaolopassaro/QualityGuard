using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class JavaRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JavaInsecureRandomRule(),
        new JavaOptionalGetRule(),
        new JavaUnsafeCommandExecutionRule(),
        new JavaWeakCryptoRule(),
        new JavaSqlInjectionRule(),
        new JavaHardcodedCredentialsRule(),
        new JavaUnsafeDynamicCodeRule(),
        new JavaInsecureDeserializationRule(),
        new JavaHttpCleartextRule(),
        new JavaInsecureCookieRule(),
        new JavaXmlExternalEntityRule(),
        new JavaWeakTlsRule(),
        new JavaSensitiveLoggingRule(),
        new JavaLocaleIndependentCaseRule(),
        new JavaSwitchDefaultRule(),
        new JavaEmptyCatchRule(),
        new JavaConsoleLoggingRule(),
        new JavaThreadControlRule(),
        new JavaDeprecatedDateRule(),
        new JavaSystemExitRule(),
        new JavaInfiniteLoopRule(),
        new JavaTypeNameConventionRule(),
        new JavaServerSideRequestForgeryRule(),
        new JavaPathTraversalRule(),
        new JavaLdapInjectionRule(),
        new JavaHeaderInjectionRule(),
        new JavaCorsWildcardRule(),
        new JavaSystemGcRule(),
        new JavaDirectThreadRunRule()
    ];
}

internal static class LanguageRuleSupport
{
    internal static string[] Lines(IRuleContext context) => context.File.Content.Split('\n');

    internal static bool IsCredentialName(string name)
    {
        var lower = name.ToLowerInvariant();
        return lower.Contains("password") || lower.Contains("passwd") || lower.Contains("secret")
            || lower.Contains("token") || lower.Contains("apikey") || lower.Contains("api_key")
            || lower.Contains("credential");
    }

    internal static bool HasCredentialSubstring(string line)
    {
        var lower = line.ToLowerInvariant();
        return lower.Contains("password") || lower.Contains("passwd") || lower.Contains("secret")
            || lower.Contains("token") || lower.Contains("apikey") || lower.Contains("api_key")
            || lower.Contains("credential");
    }

    internal static bool ContainsWord(string text, string word)
    {
        var idx = 0;
        while ((idx = text.IndexOf(word, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            var leftOk = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
            var end = idx + word.Length;
            var rightOk = end >= text.Length || !char.IsLetterOrDigit(text[end]);
            if (leftOk && rightOk)
                return true;
            idx += word.Length;
        }
        return false;
    }

    internal static bool ContainsSqlKeyword(string text)
        => ContainsWord(text, "select") || ContainsWord(text, "insert")
        || ContainsWord(text, "update") || ContainsWord(text, "delete")
        || ContainsWord(text, "drop");

    internal static string StripStrings(string line)
    {
        var sb = new System.Text.StringBuilder(line.Length);
        var quote = '\0';
        foreach (var c in line)
        {
            if (quote != '\0')
            {
                if (c == quote)
                    quote = '\0';
                continue;
            }
            if (c == '"' || c == '\'')
            {
                quote = c;
                continue;
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    internal static int NextIndex(IReadOnlyList<Token> tokens, int start, string text)
    {
        for (var i = start; i < tokens.Count; i++)
        {
            if (tokens[i].Text == text)
                return i;
        }
        return -1;
    }
}

public sealed class JavaInsecureRandomRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0001";
    public override string Name => "Use cryptographically strong random numbers";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Replace java.util.Random and ThreadLocalRandom with java.security.SecureRandom.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["Random", "ThreadLocalRandom"]))
            context.Report("Random values must not be used for security-sensitive operations.", token.Line);
    }
}

public sealed class JavaUnsafeCommandExecutionRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0002";
    public override string Name => "Make sure no OS command is executed with untrusted input";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not concatenate user input into OS commands; use a fixed list of allowed commands and arguments.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "exec") && !RuleMatchers.IsName(tokens[i], "ProcessBuilder"))
                continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i))
                continue;
            context.Report("Make sure the arguments passed to this OS command are not user-controlled.", tokens[i].Line);
        }
    }
}

public sealed class JavaWeakCryptoRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0003";
    public override string Name => "Use of weak cryptographic algorithm";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use a strong, modern algorithm such as AES-GCM or SHA-256.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        string[] algorithms = ["MD5", "SHA-1", "DES", "DESede", "RC4", "AES/ECB"];
        foreach (var algorithm in algorithms)
        {
            foreach (var token in RuleMatchers.StringsContaining(context.Tokens, algorithm))
            {
                if (token.Line > lines.Length || !RuleMatchers.LineContains(lines[token.Line - 1], "getInstance"))
                    continue;
                context.Report($"Replace this weak cryptographic algorithm '{algorithm}' with a strong one.", token.Line);
            }
        }
    }
}

public sealed class JavaSqlInjectionRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0004";
    public override string Name => "Make sure using this dynamic SQL is safe";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use parameterized queries (PreparedStatement) instead of concatenating input into SQL.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var stripped = LanguageRuleSupport.StripStrings(lines[i]);
            if (!stripped.Contains('+') && !RuleMatchers.LineContains(stripped, "String.format")
                && !RuleMatchers.LineContains(stripped, ".append("))
                continue;
            if (context.Tokens.Any(t => t.Line == i + 1 && RuleMatchers.IsString(t)
                && LanguageRuleSupport.ContainsSqlKeyword(t.Text)))
                context.Report("Make sure this SQL query is not vulnerable to SQL injection.", i + 1);
        }
    }
}

public sealed class JavaHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0005";
    public override string Name => "Password or other credentials should not be hardcoded";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Store secrets in environment variables or a secure configuration store.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsIdentifier(tokens[i]) || !LanguageRuleSupport.IsCredentialName(tokens[i].Text))
                continue;
            if (tokens[i + 1].Text != "=" || !RuleMatchers.IsString(tokens[i + 2]))
                continue;
            context.Report("Define this credential through configuration or an environment variable.", tokens[i].Line);
        }
    }
}

public sealed class JavaUnsafeDynamicCodeRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0006";
    public override string Name => "Make sure the dynamic code executed is safe";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Avoid eval() and scripting engines; validate and restrict the executed code.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["eval", "ScriptEngineManager"]))
            context.Report("Do not evaluate or execute dynamic code supplied at runtime.", token.Line);
    }
}

public sealed class JavaInsecureDeserializationRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0007";
    public override string Name => "Make sure deserializing this object is safe";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Restrict the deserialized object types, prefer safe data formats, and use them only with trusted input.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["readObject", "XMLDecoder", "SerializationUtils"]))
            context.Report("Deserializing untrusted data can lead to remote code execution.", token.Line);
    }
}

public sealed class JavaHttpCleartextRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0008";
    public override string Name => "Using http:// URLs is insecure";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use https:// to prevent eavesdropping and man-in-the-middle attacks.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.StringsContaining(context.Tokens, "http://"))
            context.Report("Using http:// URLs is insecure; use https:// instead.", token.Line);
    }
}

public sealed class JavaInsecureCookieRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0009";
    public override string Name => "Cookies should be created with the Secure and HttpOnly flags";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set the cookie HttpOnly and Secure properties when it is created.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!RuleMatchers.LineContains(line, "addCookie(") && !RuleMatchers.LineContains(line, "setCookie("))
                continue;
            if (RuleMatchers.LineContains(line, "HttpOnly") || RuleMatchers.LineContains(line, "Secure"))
                continue;
            context.Report("Make sure this cookie is built with the Secure and HttpOnly flags.", i + 1);
        }
    }
}

public sealed class JavaXmlExternalEntityRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0010";
    public override string Name => "XML parsers should not be vulnerable to XXE attacks";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.SecurityHotspot;
    public override string RemediationEffort => "Configure the factory to disable external entities (setFeature and setExpandEntityReferences).";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens,
                     ["DocumentBuilderFactory", "SAXParserFactory", "XMLReader", "TransformerFactory"]))
            context.Report("Make sure XML processing is configured securely against XXE attacks.", token.Line);
    }
}

public sealed class JavaWeakTlsRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0011";
    public override string Name => "Old TLS and SSL protocols are insecure";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Only use TLSv1.2 or TLSv1.3 for the transport layer.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        foreach (var token in context.Tokens)
        {
            if (token.Kind != TokenKind.String)
                continue;
            if (RuleMatchers.LineContains(token.Text, "TLSv1.2") || RuleMatchers.LineContains(token.Text, "TLSv1.3"))
                continue;
            if (!RuleMatchers.LineContains(token.Text, "TLS") && !RuleMatchers.LineContains(token.Text, "SSL"))
                continue;
            if (token.Line > lines.Length
                || (!RuleMatchers.LineContains(lines[token.Line - 1], "SSLContext")
                    && !RuleMatchers.LineContains(lines[token.Line - 1], "SSLParameters")))
                continue;
            context.Report("Only use TLSv1.2 or TLSv1.3 with a proper configuration.", token.Line);
        }
    }
}

public sealed class JavaSensitiveLoggingRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0012";
    public override string Name => "Sensitive data should not be logged";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Remove sensitive data from log lines; log references that do not expose the value.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        string[] levels = [".info(", ".debug(", ".warn(", ".error(", ".trace("];
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var isLogCall = false;
            for (var k = 0; k < levels.Length; k++)
            {
                if (RuleMatchers.LineContains(line, levels[k]))
                {
                    isLogCall = true;
                    break;
                }
            }
            if (!isLogCall || !LanguageRuleSupport.HasCredentialSubstring(line))
                continue;
            context.Report("Do not log passwords, tokens or other sensitive data.", i + 1);
        }
    }
}

public sealed class JavaLocaleIndependentCaseRule : PatternRuleBase
{
    public override string Key => "QG-JV-BUG-0001";
    public override string Name => "String case-shifting methods should be called with an explicit Locale";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "Call toLowerCase() or toUpperCase() with a Locale argument.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["toLowerCase", "toUpperCase"]))
            context.Report("Use Locale when calling toLowerCase() or toUpperCase().", token.Line);
    }
}

public sealed class JavaSwitchDefaultRule : PatternRuleBase
{
    public override string Key => "QG-JV-SML-0001";
    public override string Name => "Switch statements should end with a default clause";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Add a default clause to cover the unhandled cases.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "switch")
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 1, "{");
            if (open < 0)
                continue;
            var depth = 0;
            var hasCase = false;
            var hasDefault = false;
            for (var j = open; j < tokens.Count; j++)
            {
                if (tokens[j].Text == "{")
                    depth++;
                else if (tokens[j].Text == "}")
                {
                    depth--;
                    if (depth == 0)
                        break;
                }
                if (tokens[j].Text == "case")
                    hasCase = true;
                if (tokens[j].Text == "default")
                    hasDefault = true;
            }
            if (hasCase && !hasDefault)
                context.Report("Add a default clause to this switch statement.", tokens[i].Line);
        }
    }
}

public sealed class JavaEmptyCatchRule : PatternRuleBase
{
    public override string Key => "QG-JV-SML-0002";
    public override string Name => "Empty catch blocks should not be left";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Log the exception or rethrow it; never swallow it silently.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "catch")
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 1, "{");
            if (open < 0)
                continue;
            var j = open + 1;
            while (j < tokens.Count && tokens[j].Kind == TokenKind.Comment)
                j++;
            if (j < tokens.Count && tokens[j].Text == "}")
                context.Report("Either log or rethrow this exception, or remove the empty catch block.", tokens[i].Line);
        }
    }
}

public sealed class JavaConsoleLoggingRule : PatternRuleBase
{
    public override string Key => "QG-JV-SML-0003";
    public override string Name => "System.out calls and printStackTrace should not remain in production code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Replace console output with a logger such as Log4j or SLF4J.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 4 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "System") || tokens[i + 1].Text != "."
                || !RuleMatchers.IsName(tokens[i + 2], "out") || tokens[i + 3].Text != "."
                || !RuleMatchers.Contains(tokens[i + 4].Text, ["println", "print", "printf"]))
                continue;
            context.Report("Replace this console output with a proper logger.", tokens[i].Line);
        }
        foreach (var token in RuleMatchers.Names(context.Tokens, ["printStackTrace"]))
            context.Report("Replace this printStackTrace() call with a logger.", token.Line);
    }
}

public sealed class JavaThreadControlRule : PatternRuleBase
{
    public override string Key => "QG-JV-SML-0004";
    public override string Name => "Thread.stop/suspend/resume should not be used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Use interruption and synchronization primitives to control threads.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "Thread") || tokens[i + 1].Text != "."
                || !RuleMatchers.Contains(tokens[i + 2].Text, ["stop", "suspend", "resume"]))
                continue;
            context.Report("Thread.stop/suspend/resume are unsafe and deprecated.", tokens[i].Line);
        }
    }
}

public sealed class JavaDeprecatedDateRule : PatternRuleBase
{
    public override string Key => "QG-JV-SML-0005";
    public override string Name => "java.util.Date and Calendar are deprecated";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Use the java.time API (Instant, LocalDate, LocalDateTime).";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "Date") && !RuleMatchers.IsName(tokens[i], "Calendar"))
                continue;
            var isCreation = (i > 0 && tokens[i - 1].Text == "new")
                || (i + 1 < tokens.Count && tokens[i + 1].Text == "(")
                || (i + 2 < tokens.Count && tokens[i + 1].Text == "."
                    && RuleMatchers.IsName(tokens[i + 2], "getInstance"));
            if (isCreation)
                context.Report("Prefer the java.time API over java.util.Date and Calendar.", tokens[i].Line);
        }
    }
}

public sealed class JavaSystemExitRule : PatternRuleBase
{
    public override string Key => "QG-JV-SML-0006";
    public override string Name => "System.exit should not be called in application code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Return an error status instead of terminating the whole JVM.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "System") && tokens[i + 1].Text == "."
                && RuleMatchers.IsName(tokens[i + 2], "exit"))
                context.Report("Avoid calling System.exit(); this halts the whole JVM.", tokens[i].Line);
        }
    }
}

public sealed class JavaInfiniteLoopRule : PatternRuleBase
{
    public override string Key => "QG-JV-SML-0007";
    public override string Name => "while(true) loops should provide a break condition";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Use a boolean or counter condition that terminates the loop.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "while")
                continue;
            var close = -1;
            for (var j = i + 1; j < tokens.Count && j < i + 20; j++)
            {
                if (tokens[j].Text == ")")
                {
                    close = j;
                    break;
                }
                if (tokens[j].Text == "{")
                    break;
            }
            if (close < 0)
                continue;
            var hasTrue = false;
            for (var j = i + 1; j < close; j++)
            {
                if (tokens[j].Text == "true")
                {
                    hasTrue = true;
                    break;
                }
            }
            if (hasTrue)
                context.Report("Replace this while(true) loop with a clear break condition.", tokens[i].Line);
        }
    }
}

public sealed class JavaTypeNameConventionRule : PatternRuleBase
{
    public override string Key => "QG-JV-CNV-0001";
    public override string Name => "Type names should comply with a naming convention";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Rename this type using UpperCamelCase.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Keyword)
                continue;
            if (tokens[i].Text is not ("class" or "record" or "enum" or "interface"))
                continue;
            var name = tokens[i + 1];
            if (RuleMatchers.IsIdentifier(name) && char.IsLower(name.Text[0]))
                context.Report("Rename this type to follow the UpperCamelCase convention.", name.Line);
        }
    }
}

/// <summary>
/// An optional unwrapped without a check. The receiver has to be typed before reporting: `.get()`
/// belongs to Map, List and half the standard library too, and matching the text alone turned every
/// lookup in a file that merely mentions Optional into a finding.
/// </summary>
public sealed class JavaOptionalGetRule : RuleBase
{
    public override string Key => "QG-JV-SML-0011";
    public override string Name => "Optional values should not be dereferenced without a check";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";
    public override string[] Languages => ["java", "kt"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "get"))
        {
            if (SyntaxQuery.Arguments(call).Count > 0)
                continue;
            var receiver = call.ChildAt(0)?.ChildAt(0);
            var type = context.Types.TypeOf(receiver);
            if (type is not ("Optional" or "OptionalInt" or "OptionalLong" or "OptionalDouble"))
                continue;
            context.Report(call, "This optional is unwrapped without checking that it holds a value, so "
                                 + "the call throws on the absent case; use orElse, orElseGet or "
                                 + "orElseThrow with a message that names the missing value.");
        }
    }
}

public sealed class JavaServerSideRequestForgeryRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0013";
    public override string Name => "Server-side requests should not be made to user-controlled URLs";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate and whitelist destination URLs before opening connections.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = -1;
            if (RuleMatchers.IsName(tokens[i], "openConnection"))
                sink = i;
            else if (RuleMatchers.IsName(tokens[i], "HttpClient") && i + 2 < tokens.Count
                && tokens[i + 1].Text == "."
                && RuleMatchers.Contains(tokens[i + 2].Text, ["send", "newHttpRequest"]))
                sink = i + 2;
            if (sink < 0)
                continue;
            if (sink + 1 >= tokens.Count || tokens[sink + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, sink) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Make sure the URL of this server-side request is not user-controlled.", tokens[i].Line);
        }
    }
}

public sealed class JavaPathTraversalRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0014";
    public override string Name => "File operations should not use user-controlled paths";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate and canonicalize file paths; never build them from raw user input.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = -1;
            if (RuleMatchers.IsName(tokens[i], "FileInputStream"))
                sink = i;
            else if (RuleMatchers.IsName(tokens[i], "File") && i > 0 && tokens[i - 1].Text == "new")
                sink = i;
            else if (RuleMatchers.IsName(tokens[i], "Paths") && i + 2 < tokens.Count
                && tokens[i + 1].Text == "." && RuleMatchers.IsName(tokens[i + 2], "get"))
                sink = i + 2;
            else if (RuleMatchers.IsName(tokens[i], "Files") && i + 2 < tokens.Count
                && tokens[i + 1].Text == "." && RuleMatchers.IsName(tokens[i + 2], "readAllBytes"))
                sink = i + 2;
            if (sink < 0)
                continue;
            if (sink + 1 >= tokens.Count || tokens[sink + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, sink) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Make sure the file path used here is not user-controlled.", tokens[i].Line);
        }
    }
}

public sealed class JavaLdapInjectionRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0015";
    public override string Name => "Make sure using this LDAP filter is safe";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Sanitize and parameterize LDAP filters; never concatenate user input into them.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "InitialDirContext")
                && !RuleMatchers.IsName(tokens[i], "search"))
                continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Make sure this LDAP filter or context cannot be manipulated by user input.", tokens[i].Line);
        }
    }
}

public sealed class JavaHeaderInjectionRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0016";
    public override string Name => "Response headers should not be set with user-controlled values";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate header values and never embed user input directly into response headers.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "addHeader")
                && !RuleMatchers.IsName(tokens[i], "setHeader")
                && !RuleMatchers.IsName(tokens[i], "addCookie"))
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 1, "(");
            if (open < 0)
                continue;
            var comma = LanguageRuleSupport.NextIndex(tokens, open + 1, ",");
            if (comma < 0)
                continue;
            var value = comma + 1;
            while (value < tokens.Count && tokens[value].Kind == TokenKind.Comment)
                value++;
            if (value < tokens.Count && RuleMatchers.IsString(tokens[value])
                && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Make sure this response header value is not user-controlled.", tokens[i].Line);
        }
    }
}

public sealed class JavaCorsWildcardRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0017";
    public override string Name => "Wildcard origins should not be allowed in CORS headers";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Restrict Access-Control-Allow-Origin to a fixed set of trusted origins.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!RuleMatchers.LineContains(line, "Access-Control-Allow-Origin")
                || !RuleMatchers.LineContains(line, "*"))
                continue;
            context.Report("Do not use a wildcard origin for CORS.", i + 1);
        }
    }
}

public sealed class JavaSystemGcRule : PatternRuleBase
{
    public override string Key => "QG-JV-SML-0008";
    public override string Name => "System.gc() calls should not be used";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Let the JVM manage garbage collection; avoid calling System.gc().";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "System") && tokens[i + 1].Text == "."
                && RuleMatchers.IsName(tokens[i + 2], "gc"))
                context.Report("Avoid calling System.gc() explicitly.", tokens[i].Line);
        }
    }
}

public sealed class JavaDirectThreadRunRule : PatternRuleBase
{
    public override string Key => "QG-JV-BUG-0002";
    public override string Name => "Thread.run() should not be called directly";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "Call start() instead of run() to execute the thread asynchronously.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "Thread") && tokens[i + 1].Text == "."
                && RuleMatchers.IsName(tokens[i + 2], "run"))
                context.Report("Calling run() directly runs on the current thread; use start() instead.", tokens[i].Line);
        }
    }
}