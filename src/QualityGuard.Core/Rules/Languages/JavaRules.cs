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
        new JavaDirectThreadRunRule(),
        new JavaPrintfMisuseRule(),
        new JavaOsCommandPathRule(),
        new JavaAssertJChainRule()
    ];
}

internal static class LanguageRuleSupport
{
    internal static string[] Lines(IRuleContext context) => context.File.Content.Split('\n');

    /// <summary>
    /// True when the file is a test. Kept here rather than in one rule family because several of
    /// them need it, and a second copy of this judgement would drift from the first.
    /// </summary>
    /// <summary>
    /// Whether a literal is an address someone will actually call, rather than a scheme being
    /// assembled. "http://" and "http://%s" are parsing material; "http://api.example.com" is a call.
    /// </summary>
    internal static bool IsPlainAddress(string literal)
    {
        var index = literal.IndexOf("http://", StringComparison.OrdinalIgnoreCase);
        if (index < 0)
            return false;
        var host = literal[(index + "http://".Length)..];
        var end = host.IndexOfAny([' ', '"', '\'', '/', '?', ')', '\\']);
        if (end >= 0)
            host = host[..end];
        // a host needs a dot or a port to be a host, and a placeholder is not one
        return host.Length > 3 && (host.Contains('.') || host.Contains(':'))
               && !host.Contains('%') && !host.Contains('{') && !host.Contains('$');
    }

    internal static bool IsTestFile(string path, string fileName)
    {
        var normalized = path.Replace('\\', '/');
        // A file under test resources is data the tests read, not a test. An analyzer corpus keeps
        // its deliberately defective samples in src/test/resources, and reading those as tests made
        // every one of them "a test that verifies nothing".
        if (normalized.Contains("/resources/", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("/fixtures/", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("/testdata/", StringComparison.OrdinalIgnoreCase))
            return false;
        if (normalized.Contains("/test/", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("/tests/", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("/spec/", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("/__tests__/", StringComparison.OrdinalIgnoreCase))
            return true;
        // a multiplatform project names the source set after the target it tests: commonTest,
        // jvmTest, nativeTest. Those directories hold nothing but tests, and reading them as
        // production code made every deliberate empty catch in them a finding.
        foreach (var segment in normalized.Split('/'))
        {
            // A source set named after what it tests — commonTest, jvmTest — and the .NET convention
            // of a whole project called 'Something.Tests'. Requiring the segment to be a single word
            // left every file of a .NET test project reading as production code.
            if (segment.Length > 4
                && (segment.EndsWith("Test", StringComparison.Ordinal)
                    || segment.EndsWith("Tests", StringComparison.Ordinal)
                    || segment.EndsWith(".Test", StringComparison.OrdinalIgnoreCase)
                    || segment.EndsWith(".Tests", StringComparison.OrdinalIgnoreCase)))
                return true;
        }

        // the word has to stand at one end of the name: "Latest" and "Contest" contain "test" and
        // have nothing to do with testing, so the camel-case suffixes are matched exactly
        var stem = System.IO.Path.GetFileNameWithoutExtension(fileName);
        foreach (var suffix in new[] { "Test", "Tests", "Spec", "Specs" })
        {
            if (stem.EndsWith(suffix, StringComparison.Ordinal))
                return true;
        }
        foreach (var suffix in new[] { "_test", "_tests", "_spec", ".test", ".spec" })
        {
            if (stem.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return stem.StartsWith("Test", StringComparison.Ordinal)
               || stem.StartsWith("test_", StringComparison.OrdinalIgnoreCase);
    }

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
        var escaped = false;
        foreach (var c in line)
        {
            if (quote != '\0')
            {
                // A quote written inside the string does not end it. Without this, an f-string
                // carrying a shell command closed at its first escaped quote, and everything after
                // it was read as code — semicolons and all.
                if (escaped)
                {
                    escaped = false;
                    continue;
                }
                if (c == '\\')
                {
                    escaped = true;
                    continue;
                }
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
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Replace java.util.Random and ThreadLocalRandom with java.security.SecureRandom.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["Random", "ThreadLocalRandom"]))
        {
            if (context.Taint != null)
            {
                // skip SecureRandom — it is the secure alternative
                if (token.Line > 0)
                {
                    var lines = LanguageRuleSupport.Lines(context);
                    if (token.Line <= lines.Length && lines[token.Line - 1].Contains("SecureRandom"))
                        continue;
                }
                // argument-level: only flag if the random value feeds into a tainted expression
                var lineTainted = context.Tokens.Any(t => t.Line == token.Line
                    && RuleMatchers.IsIdentifier(t) && t.Text != "Random" && t.Text != "ThreadLocalRandom"
                    && context.IsTainted(t.Text));
                if (!lineTainted)
                    continue;
            }
            context.Report("Random values must not be used for security-sensitive operations.", token.Line);
        }
    }
}

public sealed class JavaUnsafeCommandExecutionRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0002";
    public override string Name => "Make sure no OS command is executed with untrusted input";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Do not concatenate user input into OS commands; use a fixed list of allowed commands and arguments.";
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
            if (context.Taint is { } taint && taint.Sources.Count > 0)
            {
                // argument-level: check identifiers in ( ... ) for taint
                var parenEnd = LanguageRuleSupport.NextIndex(tokens, i + 1, ")");
                var hasTaintedArg = false;
                for (var j = i + 2; j < parenEnd && j < tokens.Count; j++)
                {
                    if (RuleMatchers.IsIdentifier(tokens[j]) && taint.IsTainted(tokens[j].Text))
                    {
                        hasTaintedArg = true;
                        break;
                    }
                }
                if (!hasTaintedArg)
                    continue;
            }
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
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use a strong, modern algorithm such as AES-GCM or SHA-256.";
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
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use parameterized queries (PreparedStatement) instead of concatenating input into SQL.";
    public override string[] Languages => ["java"];

    private static readonly string[] SqlSinkMethods =
    [
        "executeQuery", "executeUpdate", "execute", "executeBatch",
        "prepareStatement", "prepareCall",
        "createQuery", "createNativeQuery", "createNamedQuery",
        "queryForObject", "queryForList", "queryForMap", "query",
        "update", "batchUpdate"
    ];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var stripped = LanguageRuleSupport.StripStrings(lines[i]);
            var hasConcat = stripped.Contains('+') || RuleMatchers.LineContains(stripped, "String.format")
                || RuleMatchers.LineContains(stripped, ".append(");
            var hasSink = SqlSinkMethods.Any(m => RuleMatchers.LineContains(lines[i], m + "("));
            if (!hasConcat && !hasSink)
                continue;
            if (!hasConcat)
                continue;
            if (context.Taint != null)
            {
                var lineHasTaintedIdentifier = context.Tokens.Any(t => t.Line == i + 1
                    && RuleMatchers.IsIdentifier(t) && context.IsTainted(t.Text));
                if (!lineHasTaintedIdentifier)
                    continue;
            }
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
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Store secrets in environment variables or a secure configuration store.";
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
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Avoid eval() and scripting engines; validate and restrict the executed code.";
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
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Restrict the deserialized object types, prefer safe data formats, and use them only with trusted input.";
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use https:// to prevent eavesdropping and man-in-the-middle attacks.";
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Set the cookie HttpOnly and Secure properties when it is created.";
    public override string[] Languages => ["java"];

    private static readonly string[] SetterFalseMethods =
        ["setHttpOnly", "withHttpOnly", "httpOnly", "setSecure", "withSecure", "secure"];

    private static readonly string[] CookieCtors =
        ["Cookie", "HttpCookie", "NewCookie", "SimpleCookie", "ResponseCookie", "SavedCookie"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Symbol || tokens[i].Text != ".")
                continue;
            var methodName = i + 1 < tokens.Count ? tokens[i + 1].Text : "";
            if (!SetterFalseMethods.Contains(methodName, StringComparer.Ordinal))
                continue;
            if (i + 2 >= tokens.Count || tokens[i + 2].Text != "(")
                continue;
            var argIdx = i + 3;
            if (argIdx >= tokens.Count)
                continue;
            var arg = tokens[argIdx].Text;
            if (arg != "false" && arg != "FALSE" && arg != "FALSE_CONSTANT")
                continue;
            if (IsXsrfReceiver(tokens, i))
                continue;
            var isHttpOnly = methodName.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase)
                          || methodName == "httpOnly";
            var isSecure = methodName.Contains("Secure", StringComparison.OrdinalIgnoreCase)
                        || methodName == "secure";
            if (isHttpOnly)
                context.Report("Set this cookie's HttpOnly flag to true instead of false.", tokens[i + 1].Line);
            else if (isSecure)
                context.Report("Set this cookie's Secure flag to true instead of false.", tokens[i + 1].Line);
        }
    }

    private static bool IsXsrfReceiver(IReadOnlyList<Token> tokens, int dotIndex)
    {
        for (var j = dotIndex - 1; j >= 0 && j >= dotIndex - 30; j--)
        {
            if (tokens[j].Kind == TokenKind.String
                && (tokens[j].Text.Contains("csrf", StringComparison.OrdinalIgnoreCase)
                 || tokens[j].Text.Contains("xsrf", StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
    }
}

public sealed class JavaXmlExternalEntityRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0010";
    public override string Name => "XML parsers should not be vulnerable to XXE attacks";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.SecurityHotspot;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Configure the factory to disable external entities (setFeature and setExpandEntityReferences).";
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Only use TLSv1.2 or TLSv1.3 for the transport layer.";
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Remove sensitive data from log lines; log references that do not expose the value.";
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Call toLowerCase() or toUpperCase() with a Locale argument.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            // the defect is the missing locale, not the call: reading the tokens alone reported on
            // 'toLowerCase(Locale.ENGLISH)' too, which is the fixed form
            if (SyntaxQuery.InvokedName(call) is not ("toLowerCase" or "toUpperCase")
                || SyntaxQuery.Arguments(call).Count > 0)
                continue;
            context.Report(call, "This call folds case with whatever locale the machine happens to "
                                 + "have, so the same input gives different results in Turkish. Pass "
                                 + "the locale the text belongs to, or Locale.ROOT.");
        }
    }
}

public sealed class JavaThreadControlRule : PatternRuleBase
{
    public override string Key => "QG-JV-SML-0004";
    public override string Name => "Thread.stop/suspend/resume should not be used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use interruption and synchronization primitives to control threads.";
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
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use the java.time API (Instant, LocalDate, LocalDateTime).";
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
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Return an error status instead of terminating the whole JVM.";
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
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use a boolean or counter condition that terminates the loop.";
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
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename this type using UpperCamelCase.";
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and whitelist destination URLs before opening connections.";
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and canonicalize file paths; never build them from raw user input.";
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
            if (RuleMatchers.NextNonParenIsString(tokens, sink))
                continue;
            if (context.Taint != null)
            {
                // argument-level: check identifiers between ( and ) for taint
                var parenEnd = LanguageRuleSupport.NextIndex(tokens, sink + 1, ")");
                var hasTaintedArg = false;
                for (var j = sink + 2; j < parenEnd && j < tokens.Count; j++)
                {
                    if (RuleMatchers.IsIdentifier(tokens[j]) && context.IsTainted(tokens[j].Text))
                    {
                        hasTaintedArg = true;
                        break;
                    }
                }
                if (!hasTaintedArg)
                    continue;
            }
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Sanitize and parameterize LDAP filters; never concatenate user input into them.";
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate header values and never embed user input directly into response headers.";
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
            if (context.Taint != null && !context.IsTaintedLine(tokens[i].Line))
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Restrict Access-Control-Allow-Origin to a fixed set of trusted origins.";
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
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Let the JVM manage garbage collection; avoid calling System.gc().";
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Call start() instead of run() to execute the thread asynchronously.";
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

public sealed class JavaPrintfMisuseRule : PatternRuleBase
{
    public override string Key => "QG-JV-BUG-0280";
    public override string Name => "Format strings should use correct argument counts";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";
    public override string FixAdvice => "Ensure the number of format specifiers matches the number of arguments.";
    public override string[] Languages => ["java"];

    private static readonly string[] LogMethods = ["debug", "error", "info", "trace", "warn", "fatal"];
    private static readonly string[] PrintfMethods = ["format", "printf"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Identifier)
                continue;
            var name = tokens[i].Text;

            // String.format("fmt", args) or String.formatted("fmt")
            if (name == "String" && i + 2 < tokens.Count && tokens[i + 1].Text == "."
                && PrintfMethods.Contains(tokens[i + 2].Text, StringComparer.Ordinal)
                && i + 3 < tokens.Count && tokens[i + 3].Text == "(")
            {
                var formatIdx = i + 4;
                var formatStr = ResolveFormatString(tokens, formatIdx);
                if (formatStr != null)
                    CheckFormatString(tokens, formatIdx, formatStr, context);
            }

            // log.info("fmt", args) / log.debug("fmt", args) — SLF4J and java.util.logging
            if (LogMethods.Contains(name, StringComparer.Ordinal)
                && i + 2 < tokens.Count && tokens[i + 1].Text == "."
                && i + 3 < tokens.Count && tokens[i + 3].Text == "(")
            {
                var argIdx = i + 4;
                var formatStr = ResolveFormatString(tokens, argIdx);
                if (formatStr != null)
                {
                    if (formatStr.Contains("{}"))
                    {
                        var placeholders = CountChar(formatStr, '{');
                        var argCount = CountArguments(tokens, argIdx);
                        if (argCount > 0 && placeholders != argCount)
                            ReportFormatMismatch(placeholders, argCount, "placeholders", tokens[i].Line, context);
                    }
                    else
                    {
                        var specifiers = CountPrintfSpecifiers(formatStr);
                        if (specifiers > 0)
                        {
                            var argCount = CountArguments(tokens, argIdx);
                            if (argCount > 0)
                                ReportFormatMismatch(specifiers, argCount, "specifiers", tokens[i].Line, context);
                        }
                    }
                }
            }
        }
    }

    private static string? ResolveFormatString(IReadOnlyList<Token> tokens, int idx)
    {
        if (idx >= tokens.Count) return null;
        if (tokens[idx].Kind == TokenKind.String)
            return StripQuotes(tokens[idx].Text);
        if (tokens[idx].Kind == TokenKind.Identifier)
            return ResolveVariable(tokens, idx);
        return null;
    }

    private static string? ResolveVariable(IReadOnlyList<Token> tokens, int varIdx)
    {
        var name = tokens[varIdx].Text;
        for (var j = varIdx - 1; j >= 0 && j >= varIdx - 50; j--)
        {
            if (tokens[j].Kind != TokenKind.Identifier || tokens[j].Text != name)
                continue;
            if (j + 2 < tokens.Count && tokens[j + 1].Text == "=" && tokens[j + 1].Kind == TokenKind.Symbol)
            {
                var valIdx = j + 2;
                if (valIdx < tokens.Count && tokens[valIdx].Kind == TokenKind.String)
                    return StripQuotes(tokens[valIdx].Text);
            }
        }
        return null;
    }

    private void CheckFormatString(IReadOnlyList<Token> tokens, int formatIdx, string formatStr, IRuleContext context)
    {
        if (formatStr.Contains("{}"))
        {
            var placeholders = CountChar(formatStr, '{');
            var argCount = CountArguments(tokens, formatIdx + 1);
            if (argCount > 0 && placeholders != argCount)
                ReportFormatMismatch(placeholders, argCount, "placeholders", tokens[formatIdx].Line, context);
        }
        else
        {
            var specifiers = CountPrintfSpecifiers(formatStr);
            var argCount = CountArguments(tokens, formatIdx + 1);
            if (argCount <= 0) return;
            if (specifiers == 0 && argCount > 0)
                context.Report("This format string has no specifiers but " + argCount + " arguments were provided.", tokens[formatIdx].Line);
            else
                ReportFormatMismatch(specifiers, argCount, "specifiers", tokens[formatIdx].Line, context);
        }
    }

    private static void ReportFormatMismatch(int expected, int actual, string kind, int line, IRuleContext context)
    {
        if (actual > expected)
            context.Report("This format string expects " + expected + " " + kind + " but " + actual + " were provided.", line);
        else
            context.Report("This format string expects " + expected + " " + kind + " but only " + actual + " were provided.", line);
    }

    private static int CountPrintfSpecifiers(string format)
    {
        var count = 0;
        for (var i = 0; i < format.Length; i++)
        {
            if (format[i] == '%' && i + 1 < format.Length && format[i + 1] != '%')
            {
                count++;
                i++;
                while (i < format.Length && char.IsDigit(format[i])) i++;
                if (i < format.Length && format[i] == '$') i++;
                while (i < format.Length && "-+# 0".Contains(format[i])) i++;
                while (i < format.Length && char.IsDigit(format[i])) i++;
                if (i < format.Length && format[i] == '.') { i++; while (i < format.Length && char.IsDigit(format[i])) i++; }
                if (i < format.Length) i++;
            }
        }
        return count;
    }

    private static int CountChar(string s, char c)
    {
        var count = 0;
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] == c && i + 1 < s.Length && s[i + 1] == '}')
                count++;
        }
        return count;
    }

    private static int CountArguments(IReadOnlyList<Token> tokens, int startIdx)
    {
        var depth = 0;
        var count = 0;
        var hasArg = false;
        for (var j = startIdx; j < tokens.Count; j++)
        {
            var t = tokens[j].Text;
            if (t == "(") depth++;
            else if (t == ")")
            {
                if (depth == 0) break;
                depth--;
            }
            else if (t == "," && depth == 0)
            {
                if (hasArg) count++;
                hasArg = false;
            }
            else if (depth == 0 && t != " " && t != "\n" && t != "\r")
                hasArg = true;
        }
        if (hasArg) count++;
        return count;
    }

    private static string StripQuotes(string text)
    {
        if (text.Length >= 2 && text[0] == '"' && text[^1] == '"')
            return text[1..^1];
        return text;
    }
}

public sealed class JavaOsCommandPathRule : PatternRuleBase
{
    public override string Key => "QG-JV-SEC-0092";
    public override string Name => "OS command paths should be absolute";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use absolute paths for OS commands to prevent PATH manipulation attacks.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 4 < tokens.Count; i++)
        {
            // Runtime.getRuntime().exec(...)
            if (RuleMatchers.IsName(tokens[i], "Runtime") && tokens[i + 1].Text == "."
                && RuleMatchers.IsName(tokens[i + 2], "getRuntime") && tokens[i + 3].Text == "."
                && RuleMatchers.IsName(tokens[i + 4], "exec"))
            {
                if (i + 5 < tokens.Count && tokens[i + 5].Text == "(")
                    CheckCommandArg(tokens, i + 6, context);
            }

            // new ProcessBuilder("cmd") or new ProcessBuilder(Arrays.asList("cmd"))
            if (tokens[i].Text == "new" && i + 1 < tokens.Count && RuleMatchers.IsName(tokens[i + 1], "ProcessBuilder"))
            {
                if (i + 2 < tokens.Count && tokens[i + 2].Text == "(")
                    CheckCommandArg(tokens, i + 3, context);
            }

            // ProcessBuilder.command("cmd")
            if (RuleMatchers.IsName(tokens[i], "ProcessBuilder") && tokens[i + 1].Text == "."
                && RuleMatchers.IsName(tokens[i + 2], "command") && tokens[i + 3].Text == "(")
                CheckCommandArg(tokens, i + 4, context);
        }
    }

    private static void CheckCommandArg(IReadOnlyList<Token> tokens, int argIdx, IRuleContext context)
    {
        while (argIdx < tokens.Count && tokens[argIdx].Text == "(")
            argIdx++;
        if (argIdx < tokens.Count && tokens[argIdx].Kind == TokenKind.String)
        {
            var cmd = StripQuotes(tokens[argIdx].Text);
            if (!IsAbsoluteCommand(cmd) && cmd.Length > 0)
                context.Report("Use an absolute path for this command to prevent PATH manipulation.", tokens[argIdx].Line);
        }
    }

    private static bool IsAbsoluteCommand(string cmd)
    {
        if (string.IsNullOrEmpty(cmd)) return true;
        if (cmd.StartsWith('/') || cmd.StartsWith("./") || cmd.StartsWith("../") || cmd.StartsWith("~/"))
            return true;
        if (cmd.StartsWith('\\') || cmd.StartsWith(".\\") || cmd.StartsWith("..\\"))
            return true;
        if (cmd.Length >= 3 && char.IsLetter(cmd[0]) && cmd[1] == ':' && (cmd[2] == '\\' || cmd[2] == '/'))
            return true;
        return false;
    }

    private static string StripQuotes(string text)
    {
        if (text.Length >= 2 && text[0] == '"' && text[^1] == '"')
            return text[1..^1];
        return text;
    }
}

public sealed class JavaAssertJChainRule : PatternRuleBase
{
    public override string Key => "QG-JV-SML-0566";
    public override string Name => "AssertJ chains should use specific assertions";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string FixAdvice => "Replace with a more specific AssertJ assertion.";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 3 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "assertThat"))
                continue;
            if (tokens[i + 1].Text != "(")
                continue;

            // find closing paren
            var depth = 1;
            var j = i + 2;
            while (j < tokens.Count && depth > 0)
            {
                if (tokens[j].Text == "(") depth++;
                else if (tokens[j].Text == ")") depth--;
                j++;
            }
            if (depth != 0 || j >= tokens.Count) continue;
            if (tokens[j].Text != ".") continue;

            var innerStart = i + 2;
            var innerEnd = j - 1;
            var methodIdx = j + 1;
            if (methodIdx >= tokens.Count) continue;
            var method = tokens[methodIdx].Text;

            // assertThat(expr).isTrue() / assertThat(expr).isFalse()
            if (method is "isTrue" or "isFalse")
            {
                var inner = GetInnerExpression(tokens, innerStart, innerEnd);
                if (inner != null)
                    context.Report(DescribeSimplification(inner, method), tokens[i].Line);
                continue;
            }

            // assertThat(expr).isEqualTo(null)
            if (method == "isEqualTo" && methodIdx + 1 < tokens.Count && tokens[methodIdx + 1].Text == "(")
            {
                var argIdx = methodIdx + 2;
                if (argIdx < tokens.Count && tokens[argIdx].Text == "null")
                    context.Report("Use isNull() instead of isEqualTo(null).", tokens[i].Line);
            }

            // assertThat(expr).isNotEqualTo(null)
            if (method == "isNotEqualTo" && methodIdx + 1 < tokens.Count && tokens[methodIdx + 1].Text == "(")
            {
                var argIdx = methodIdx + 2;
                if (argIdx < tokens.Count && tokens[argIdx].Text == "null")
                    context.Report("Use isNotNull() instead of isNotEqualTo(null).", tokens[i].Line);
            }

            // assertThat(expr).isEqualTo(true) / isEqualTo(false)
            if (method == "isEqualTo" && methodIdx + 1 < tokens.Count && tokens[methodIdx + 1].Text == "(")
            {
                var argIdx = methodIdx + 2;
                if (argIdx < tokens.Count && tokens[argIdx].Text is "true" or "false")
                    context.Report("Use " + (tokens[argIdx].Text == "true" ? "isTrue()" : "isFalse()") + " instead of isEqualTo(" + tokens[argIdx].Text + ").", tokens[i].Line);
            }
        }
    }

    private static string? GetInnerExpression(IReadOnlyList<Token> tokens, int start, int end)
    {
        if (start >= end) return null;
        // look for == or .equals( inside the inner expression
        for (var k = start; k <= end; k++)
        {
            if (tokens[k].Text == "==" && k > start && k < end)
                return "equality";
            if (tokens[k].Text == ".equals" && k + 1 <= end && tokens[k + 1].Text == "(")
                return "equals";
            if (tokens[k].Text == ".compareTo" && k + 1 <= end && tokens[k + 1].Text == "(")
                return "compareTo";
        }
        return null;
    }

    private static string DescribeSimplification(string inner, string method)
    {
        var isTrue = method == "isTrue";
        return inner switch
        {
            "equality" => isTrue
                ? "Use isSameAs() or isEqualTo() instead of == comparison with isTrue()."
                : "Use isNotSameAs() or isNotEqualTo() instead of == comparison with isFalse().",
            "equals" => isTrue
                ? "Use isEqualTo() instead of equals() with isTrue()."
                : "Use isNotEqualTo() instead of equals() with isFalse().",
            "compareTo" => isTrue
                ? "Use isZero() or isNotZero() instead of compareTo() with isTrue()."
                : "Use isZero() or isNotZero() instead of compareTo() with isFalse().",
            _ => "Replace with a more specific AssertJ assertion."
        };
    }
}