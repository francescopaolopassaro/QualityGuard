using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class KotlinRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new KotlinInsecureRandomRule(),
        new KotlinUnsafeCommandExecutionRule(),
        new KotlinWeakCryptoRule(),
        new KotlinSqlInjectionRule(),
        new KotlinHardcodedCredentialsRule(),
        new KotlinUnsafeDynamicCodeRule(),
        new KotlinInsecureDeserializationRule(),
        new KotlinHttpCleartextRule(),
        new KotlinInsecureCookieRule(),
        new KotlinXmlExternalEntityRule(),
        new KotlinWeakTlsRule(),
        new KotlinSensitiveLoggingRule(),
        new KotlinLocaleIndependentCaseRule(),
        new KotlinPrintlnRule(),
        new KotlinInfiniteLoopRule(),
        new KotlinEmptyCatchRule(),
        new KotlinRunBlockingRule(),
        new KotlinSystemExitRule(),
        new KotlinThreadControlRule(),
        new KotlinTypeNameConventionRule(),
        new KotlinServerSideRequestForgeryRule(),
        new KotlinQueryInjectionRule(),
        new KotlinHeaderInjectionRule(),
        new KotlinCorsWildcardRule(),
        new KotlinSystemGcRule(),
        new KotlinDirectThreadRunRule(),
        new KotlinLdapInjectionRule(),
        new KotlinOpenRedirectRule(),
        new KotlinTrustAllCertificatesRule(),
        new KotlinReflectionInjectionRule(),
        new KotlinUnsafeWebViewRule(),
        new KotlinWorldReadableFileRule(),
        new KotlinZipSlipRule(),
        new KotlinReDosRule(),
        new KotlinTimingAttackRule(),
        new KotlinSharedPreferencesSecretRule(),
        new KotlinLogInjectionRule(),
        new KotlinMutablePendingIntentRule(),
        new KotlinWebViewPasswordSaveRule(),
        new KotlinStringBuilderInLoopRule(),
        new KotlinExplicitNullCheckRule(),
        new KotlinCompanionMutableStateRule(),
        new KotlinDataClassEqualsRule(),
        new KotlinLongFunctionRule(),
        new KotlinNestedStringTemplateRule(),
        new KotlinSizeEmptyCheckRule(),
        new KotlinRangeLoopRule(),
        new KotlinBooleanComparisonRule(),
        new KotlinThreadSleepInCoroutineRule(),
        new KotlinGlobalScopeRule(),
        new KotlinDoubleComparisonRule(),
        new KotlinCollectionModificationRule(),
        new KotlinIgnoredCancellationRule(),
        new KotlinFunctionNameConventionRule(),
        new KotlinConstantNameConventionRule(),
        new KotlinPackageNameConventionRule()
    ];
}

public sealed class KotlinInsecureRandomRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0001";
    public override string Name => "Use cryptographically strong random numbers";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use java.security.SecureRandom instead of Random for security-sensitive operations.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["Random", "ThreadLocalRandom"]))
            context.Report("Random values must not be used for security-sensitive operations.", token.Line);
    }
}

public sealed class KotlinUnsafeCommandExecutionRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0002";
    public override string Name => "Make sure no OS command is executed with untrusted input";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Do not concatenate user input into OS commands; keep the executed commands fixed.";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinWeakCryptoRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0003";
    public override string Name => "Use of weak cryptographic algorithm";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use a strong, modern algorithm such as AES-GCM or SHA-256.";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinSqlInjectionRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0004";
    public override string Name => "Make sure using this dynamic SQL is safe";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use parameterized queries instead of concatenating input into SQL strings or templates.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var sqlTokens = context.Tokens.Where(t => t.Line == i + 1 && RuleMatchers.IsString(t)
                && LanguageRuleSupport.ContainsSqlKeyword(t.Text)).ToList();
            if (sqlTokens.Count == 0)
                continue;
            if (sqlTokens.Any(t => t.Text.Contains('$')))
            {
                context.Report("Make sure this SQL query template is not vulnerable to SQL injection.", i + 1);
                continue;
            }
            var stripped = LanguageRuleSupport.StripStrings(line);
            if (!stripped.Contains('+') && !RuleMatchers.LineContains(stripped, "String.format")
                && !RuleMatchers.LineContains(stripped, ".append("))
                continue;
            context.Report("Make sure this SQL query is not vulnerable to SQL injection.", i + 1);
        }
    }
}

public sealed class KotlinHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0005";
    public override string Name => "Password or other credentials should not be hardcoded";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Store secrets in environment variables or a secure configuration store.";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinUnsafeDynamicCodeRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0006";
    public override string Name => "Make sure the dynamic code executed is safe";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Avoid eval() and scripting engines; validate and restrict the executed code.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["eval", "ScriptEngineManager", "ScriptEngine"]))
            context.Report("Do not evaluate or execute dynamic code supplied at runtime.", token.Line);
    }
}

public sealed class KotlinInsecureDeserializationRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0007";
    public override string Name => "Make sure deserializing this object is safe";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Restrict the deserialized object types, prefer safe formats such as kotlinx.serialization with strict config.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["readObject", "XMLDecoder", "SerializationUtils"]))
            context.Report("Deserializing untrusted data can lead to remote code execution.", token.Line);
    }
}

public sealed class KotlinHttpCleartextRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0008";
    public override string Name => "Using http:// URLs is insecure";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use https:// to prevent eavesdropping and man-in-the-middle attacks.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.StringsContaining(context.Tokens, "http://"))
            context.Report("Using http:// URLs is insecure; use https:// instead.", token.Line);
    }
}

public sealed class KotlinInsecureCookieRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0009";
    public override string Name => "Cookies should be created with the Secure and HttpOnly flags";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Set the cookie HttpOnly and Secure properties when it is created.";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinXmlExternalEntityRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0010";
    public override string Name => "XML parsers should not be vulnerable to XXE attacks";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.SecurityHotspot;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Configure the factory to disable external entities (setFeature and setExpandEntityReferences).";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens,
                     ["DocumentBuilderFactory", "SAXParserFactory", "XMLReader", "TransformerFactory"]))
            context.Report("Make sure XML processing is configured securely against XXE attacks.", token.Line);
    }
}

public sealed class KotlinWeakTlsRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0011";
    public override string Name => "Old TLS and SSL protocols are insecure";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Only use TLSv1.2 or TLSv1.3 for the transport layer.";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinSensitiveLoggingRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0012";
    public override string Name => "Sensitive data should not be logged";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Remove sensitive data from log lines; log references that do not expose the value.";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinLocaleIndependentCaseRule : PatternRuleBase
{
    public override string Key => "QG-KT-BUG-0001";
    public override string Name => "String case-shifting methods should be called with an explicit Locale";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Call toLowerCase() or toUpperCase() with a Locale argument.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["toLowerCase", "toUpperCase"]))
            context.Report("Use Locale when calling toLowerCase() or toUpperCase().", token.Line);
    }
}

public sealed class KotlinPrintlnRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0001";
    public override string Name => "print calls should not remain in production code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Replace println/print calls with a proper logger.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["println", "print"]))
            context.Report("Replace this console output with a logger.", token.Line);
    }
}

public sealed class KotlinNotNullAssertionRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0002";
    public override string Name => "The not-null assertion operator (!!) should not be used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Replace !! with safe calls, explicit null checks or the elvis operator.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Text == "!" && tokens[i + 1].Text == "!")
                context.Report("Avoid using the not-null assertion operator (!!).", tokens[i].Line);
        }
    }
}

public sealed class KotlinInfiniteLoopRule : RuleBase
{
    public override string Key => "QG-KT-SML-0003";
    public override string Name => "A loop should be able to end";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Give the loop a way out: a condition that becomes false, or a break on the case that ends it.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var loop in context.Root.OfKind(Syntax.NodeKind.Loop))
        {
            if (loop.Text != "while")
                continue;
            var condition = loop.Children.FirstOrDefault(c => c.Kind != Syntax.NodeKind.Block);
            if (condition is not { Kind: Syntax.NodeKind.BooleanLiteral } || condition.Text != "true")
                continue;
            // 'while (true)' with a way out is the ordinary way to write a loop whose end is decided
            // inside it — a reader, a parser, a queue. Only a body that can never leave is a defect.
            var body = loop.FirstChild(Syntax.NodeKind.Block);
            if (body != null && body.OfKind(Syntax.NodeKind.Jump)
                    .Any(j => j.Text is "break" or "return" or "throw"))
                continue;

            context.Report("This loop has no way out: the condition is always true and nothing in the "
                           + "body leaves it, so whatever runs after it never runs.", loop.Line);
        }
    }
}

public sealed class KotlinEmptyCatchRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0004";
    public override string Name => "Empty catch blocks should not be left";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Log the exception or rethrow it; never swallow it silently.";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinRunBlockingRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0005";
    public override string Name => "runBlocking should not be used in production code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Prefer suspending functions over blocking the current thread with runBlocking.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        foreach (var token in RuleMatchers.Names(context.Tokens, ["runBlocking"]))
        {
            if (token.Line <= lines.Length && RuleMatchers.LineContains(lines[token.Line - 1], "import"))
                continue;
            context.Report("Prefer suspending functions over runBlocking in production code.", token.Line);
        }
    }
}

public sealed class KotlinSystemExitRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0006";
    public override string Name => "System.exit should not be called in application code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Return an error status instead of terminating the whole process.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "System") && tokens[i + 1].Text == "."
                && RuleMatchers.IsName(tokens[i + 2], "exit"))
                context.Report("Avoid calling System.exit(); this halts the whole process.", tokens[i].Line);
        }
    }
}

public sealed class KotlinThreadControlRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0007";
    public override string Name => "Thread.stop/suspend/resume should not be used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use coroutine cancellation or interruption primitives to control threads.";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinTypeNameConventionRule : PatternRuleBase
{
    public override string Key => "QG-KT-CNV-0001";
    public override string Name => "Type names should comply with a naming convention";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename this type using UpperCamelCase.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Keyword)
                continue;
            if (tokens[i].Text is not ("class" or "record" or "enum" or "object" or "interface"))
                continue;
            var name = tokens[i + 1];
            if (RuleMatchers.IsIdentifier(name) && char.IsLower(name.Text[0]))
                context.Report("Rename this type to follow the UpperCamelCase convention.", name.Line);
        }
    }
}

public sealed class KotlinServerSideRequestForgeryRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0013";
    public override string Name => "Server-side requests and file paths should not use user-controlled URLs";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and whitelist URLs and paths before use in network or file operations.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = -1;
            if (RuleMatchers.IsName(tokens[i], "HttpURLConnection")
                || RuleMatchers.IsName(tokens[i], "URL")
                || RuleMatchers.IsName(tokens[i], "File"))
                sink = i;
            else if (RuleMatchers.IsName(tokens[i], "Files") && i + 2 < tokens.Count
                && tokens[i + 1].Text == "." && RuleMatchers.IsName(tokens[i + 2], "readAllBytes"))
                sink = i + 2;
            if (sink < 0)
                continue;
            if (sink + 1 >= tokens.Count || tokens[sink + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, sink) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Make sure this URL or file path is not user-controlled.", tokens[i].Line);
        }
    }
}

public sealed class KotlinQueryInjectionRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0014";
    public override string Name => "Make sure using this query is safe";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use parameterized queries instead of concatenating or templating query strings.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!RuleMatchers.LineContains(line, "createQuery")
                && !RuleMatchers.LineContains(line, "createStatement")
                && !RuleMatchers.LineContains(line, "execute"))
                continue;
            var hasSql = context.Tokens.Any(t => t.Line == i + 1 && RuleMatchers.IsString(t)
                && LanguageRuleSupport.ContainsSqlKeyword(t.Text));
            if (!hasSql)
                continue;
            var stripped = LanguageRuleSupport.StripStrings(line);
            if (!stripped.Contains('+') && !RuleMatchers.LineContains(line, "$")
                && !context.IsTaintedLine(i + 1))
                continue;
            context.Report("Make sure this query is not vulnerable to injection.", i + 1);
        }
    }
}

public sealed class KotlinHeaderInjectionRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0015";
    public override string Name => "Response headers should not be set with user-controlled values";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate header values and never embed user input directly into response headers.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "addHeader")
                && !RuleMatchers.IsName(tokens[i], "setHeader"))
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

public sealed class KotlinCorsWildcardRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0016";
    public override string Name => "Wildcard origins should not be allowed in CORS headers";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Restrict Access-Control-Allow-Origin to a fixed set of trusted origins.";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinSystemGcRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0008";
    public override string Name => "System.gc() calls should not be used";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Let the JVM manage garbage collection; avoid calling System.gc().";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinDirectThreadRunRule : PatternRuleBase
{
    public override string Key => "QG-KT-BUG-0002";
    public override string Name => "Thread.run() should not be called directly";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Call start() instead of run() to execute the thread asynchronously.";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinLdapInjectionRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0017";
    public override string Name => "Make sure using this LDAP filter is safe";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Sanitize and parameterize LDAP filters; never concatenate user input into them.";
    public override string[] Languages => ["kt"];

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

public sealed class KotlinOpenRedirectRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0018";
    public override string Name => "Open redirects should not be triggered by user input";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate the redirect target against a fixed allowlist of URLs.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "sendRedirect"))
            {
                if (i + 1 < tokens.Count && tokens[i + 1].Text == "("
                    && !(RuleMatchers.NextNonParenIsString(tokens, i) && !context.IsTaintedLine(tokens[i].Line)))
                    context.Report("Make sure this redirect target is not user-controlled.", tokens[i].Line);
                continue;
            }
            if (!RuleMatchers.IsName(tokens[i], "setHeader") && !RuleMatchers.IsName(tokens[i], "setIntHeader"))
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 1, "(");
            if (open < 0 || open + 1 >= tokens.Count)
                continue;
            var name = tokens[open + 1];
            while (name.Kind == TokenKind.Comment && open + 1 < tokens.Count)
            {
                open++;
                name = tokens[open + 1];
            }
            if (!RuleMatchers.IsString(name)
                || !name.Text.Contains("location", StringComparison.OrdinalIgnoreCase))
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
            context.Report("Make sure this redirect header value is not user-controlled.", tokens[i].Line);
        }
    }
}

public sealed class KotlinTrustAllCertificatesRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0019";
    public override string Name => "SSL/TLS certificate validation should not be disabled";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Do not trust every certificate; implement proper hostname verification.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "ALLOW_ALL_HOSTNAME_VERIFIER"))
            {
                context.Report("Do not accept all hostnames during TLS verification.", tokens[i].Line);
                continue;
            }
            if (RuleMatchers.IsName(tokens[i], "checkServerTrusted"))
            {
                var open = LanguageRuleSupport.NextIndex(tokens, i + 1, "{");
                if (open < 0)
                    continue;
                var j = open + 1;
                while (j < tokens.Count && tokens[j].Kind == TokenKind.Comment)
                    j++;
                if (j < tokens.Count && tokens[j].Text == "}")
                    context.Report("Do not skip server certificate validation in the trust manager.", tokens[i].Line);
                continue;
            }
            if (!RuleMatchers.IsName(tokens[i], "setHostnameVerifier"))
                continue;
            var limit = Math.Min(i + 12, tokens.Count);
            for (var j = i + 1; j < limit; j++)
            {
                if (tokens[j].Text == "true")
                    context.Report("Do not accept all hostnames during TLS verification.", tokens[i].Line);
            }
        }
    }
}

public sealed class KotlinReflectionInjectionRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0020";
    public override string Name => "Make sure reflection is not used with untrusted input";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Do not use Class.forName or getMethod with user-controlled names.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "forName")
                && !RuleMatchers.IsName(tokens[i], "getMethod"))
                continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Make sure this reflection call does not use user-controlled input.", tokens[i].Line);
        }
    }
}

public sealed class KotlinUnsafeWebViewRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0021";
    public override string Name => "WebView JavaScript should be enabled only for trusted content";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Enable JavaScript only where the loaded content is under your control.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            // the bridge itself is QG-KT-SEC-0052, which reads the call on the tree; reporting it
            // here as well put two identifiers on one line
            if (!RuleMatchers.IsName(tokens[i], "javaScriptEnabled"))
                continue;
            var limit = Math.Min(i + 4, tokens.Count);
            for (var j = i + 1; j < limit; j++)
            {
                if (tokens[j].Text == "true")
                    context.Report("Enable WebView JavaScript only for trusted content.", tokens[i].Line);
            }
        }
    }
}

public sealed class KotlinWebViewFileAccessRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0022";
    public override string Name => "WebView file access should be disabled";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Keep allowFileAccess and related settings disabled unless strictly required.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        string[] settings = ["allowFileAccess", "allowFileAccessFromFileURLs", "allowUniversalAccessFromFileURLs"];
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsIdentifier(tokens[i]) || !RuleMatchers.Contains(tokens[i].Text, settings))
                continue;
            var limit = Math.Min(i + 4, tokens.Count);
            for (var j = i + 1; j < limit; j++)
            {
                if (tokens[j].Text == "true")
                    context.Report("WebView file access should be disabled to prevent local file exposure.", tokens[i].Line);
            }
        }
    }
}

public sealed class KotlinWorldReadableFileRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0023";
    public override string Name => "World-readable or world-writable files should not be created";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use MODE_PRIVATE to restrict file access to the application.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens,
                     ["MODE_WORLD_READABLE", "MODE_WORLD_WRITEABLE", "MODE_WORLD_WRITABLE"]))
            context.Report("Do not create world-readable or world-writable files.", token.Line);
    }
}

public sealed class KotlinZipSlipRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0024";
    public override string Name => "Zip entry names should not escape the extraction directory";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate each Zip entry name and reject names containing '..'.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "ZipEntry"))
                continue;
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;
            var arg = i + 2;
            while (arg < tokens.Count && tokens[arg].Kind == TokenKind.Comment)
                arg++;
            if (arg >= tokens.Count)
                continue;
            if (RuleMatchers.IsString(tokens[arg]))
            {
                if (tokens[arg].Text.Contains(".."))
                    context.Report("This Zip entry name can escape the extraction directory.", tokens[i].Line);
                continue;
            }
            if (!context.IsTaintedLine(tokens[i].Line))
                context.Report("Make sure this Zip entry name is not user-controlled.", tokens[i].Line);
        }
    }
}

public sealed class KotlinReDosRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0025";
    public override string Name => "Regular expressions should not be built from user input";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use fixed regex patterns and avoid nested quantifiers that enable catastrophic backtracking.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var sink = -1;
            if (RuleMatchers.IsName(tokens[i], "Regex"))
                sink = i;
            else if (RuleMatchers.IsName(tokens[i], "Pattern") && i + 2 < tokens.Count
                && tokens[i + 1].Text == "." && RuleMatchers.IsName(tokens[i + 2], "compile"))
                sink = i + 2;
            if (sink < 0 || sink + 1 >= tokens.Count || tokens[sink + 1].Text != "(")
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, sink))
            {
                var str = sink + 2;
                while (str < tokens.Count && tokens[str].Kind == TokenKind.Comment)
                    str++;
                if (str < tokens.Count && IsCatastrophic(tokens[str].Text))
                    context.Report("This regular expression can lead to catastrophic backtracking.", tokens[i].Line);
                continue;
            }
            context.Report("Do not build regular expressions from user input.", tokens[i].Line);
        }
    }

    private static bool IsCatastrophic(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] != '(')
                continue;
            var close = text.IndexOf(')', i);
            if (close < 0)
                continue;
            var inner = text.Substring(i, close - i);
            if ((inner.Contains('+') || inner.Contains('*'))
                && close + 1 < text.Length && (text[close + 1] == '+' || text[close + 1] == '*'))
                return true;
            i = close;
        }
        return false;
    }
}

public sealed class KotlinTimingAttackRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0026";
    public override string Name => "Credentials should not be compared with a regular comparison";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Compare secrets using a constant-time comparison such as MessageDigest.isEqual.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsIdentifier(tokens[i]) || !IsSecretName(tokens[i].Text))
                continue;
            var limit = Math.Min(i + 6, tokens.Count);
            for (var j = i + 1; j < limit; j++)
            {
                if (tokens[j].Text is not ("==" or "!="))
                    continue;
                if (j + 1 < tokens.Count && tokens[j + 1].Text == "null")
                    break;
                context.Report("Use a constant-time comparison when comparing credentials.", tokens[i].Line);
                break;
            }
        }
    }

    /// <summary>
    /// Whether a name really denotes a secret. The bare word "token" is deliberately absent: in a
    /// compiler, a parser or a lexer — which is most of the code that has one — a token is a piece
    /// of syntax, and 'operationToken == PLUS' is not a credential comparison.
    /// </summary>
    private static bool IsSecretName(string name)
    {
        var lower = name.ToLowerInvariant();
        foreach (var word in new[]
                 {
                     "password", "passwd", "secret", "credential", "apikey", "api_key",
                     "privatekey", "accesstoken", "refreshtoken", "authtoken", "sessiontoken"
                 })
        {
            if (lower.Contains(word, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

}

public sealed class KotlinSharedPreferencesSecretRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0027";
    public override string Name => "Secrets should not be stored in plain SharedPreferences";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Store sensitive data with EncryptedSharedPreferences instead of plain SharedPreferences.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!RuleMatchers.LineContains(line, "putString")
                && !RuleMatchers.LineContains(line, "getSharedPreferences"))
                continue;
            if (!LanguageRuleSupport.HasCredentialSubstring(line))
                continue;
            context.Report("Do not store credentials in plain SharedPreferences.", i + 1);
        }
    }
}

public sealed class KotlinLogInjectionRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0028";
    public override string Name => "Log output should not be built from user-controlled data";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Sanitize user input before writing it to log output.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        string[] levels = [".info(", ".debug(", ".warn(", ".error(", ".trace("];
        for (var i = 0; i < lines.Length; i++)
        {
            var isLogCall = levels.Any(level => RuleMatchers.LineContains(lines[i], level));
            if (!isLogCall || !context.IsTaintedLine(i + 1))
                continue;
            context.Report("Sanitize user input before including it in log output.", i + 1);
        }
    }
}

public sealed class KotlinMutablePendingIntentRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0029";
    public override string Name => "PendingIntents should be immutable";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Create PendingIntents with the FLAG_IMMUTABLE flag.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "PendingIntent") || tokens[i + 1].Text != ".")
                continue;
            if (!RuleMatchers.Contains(tokens[i + 2].Text,
                    ["getActivity", "getBroadcast", "getService", "getForegroundService"]))
                continue;
            var line = tokens[i].Line <= lines.Length ? lines[tokens[i].Line - 1] : "";
            if (RuleMatchers.LineContains(line, "FLAG_IMMUTABLE"))
                continue;
            context.Report("Create this PendingIntent with FLAG_IMMUTABLE.", tokens[i].Line);
        }
    }
}

public sealed class KotlinWebViewPasswordSaveRule : PatternRuleBase
{
    public override string Key => "QG-KT-SEC-0030";
    public override string Name => "WebView password saving should be disabled";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Do not enable WebView password saving; use a secure credential store.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "setSavePassword"))
                continue;
            var limit = Math.Min(i + 4, tokens.Count);
            for (var j = i + 1; j < limit; j++)
            {
                if (tokens[j].Text == "true")
                    context.Report("Do not enable WebView password saving.", tokens[i].Line);
            }
        }
    }
}

public sealed class KotlinStringBuilderInLoopRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0009";
    public override string Name => "StringBuilder should not be created inside loops";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Hoist the StringBuilder creation outside the loop.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text is not ("for" or "while" or "do"))
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 1, "{");
            if (open < 0)
                continue;
            var close = KotlinRuleSupport.FindMatchingBrace(tokens, open);
            if (close < 0)
                continue;
            for (var j = open + 1; j < close; j++)
            {
                if (RuleMatchers.IsName(tokens[j], "StringBuilder")
                    || RuleMatchers.IsName(tokens[j], "StringBuffer"))
                {
                    context.Report("Do not create a StringBuilder inside a loop; hoist it outside.", tokens[i].Line);
                    break;
                }
            }
        }
    }
}

public sealed class KotlinExplicitNullCheckRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0010";
    public override string Name => "Prefer safe-call operators over explicit null checks";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use the safe-call operator (?.) or let instead of a manual null check.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "if")
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 1, "(");
            if (open < 0)
                continue;
            var close = LanguageRuleSupport.NextIndex(tokens, open + 1, ")");
            if (close < 0)
                continue;
            string? name = null;
            for (var j = open + 1; j + 2 < close; j++)
            {
                if (RuleMatchers.IsIdentifier(tokens[j]) && tokens[j + 1].Text is "!=" or "=="
                    && tokens[j + 2].Text == "null")
                {
                    name = tokens[j].Text;
                    break;
                }
            }
            if (name == null)
                continue;
            var bodyOpen = LanguageRuleSupport.NextIndex(tokens, close + 1, "{");
            if (bodyOpen < 0)
                continue;
            var bodyClose = KotlinRuleSupport.FindMatchingBrace(tokens, bodyOpen);
            if (bodyClose < 0)
                continue;
            for (var j = bodyOpen + 1; j + 1 < bodyClose; j++)
            {
                if (RuleMatchers.IsName(tokens[j], name) && tokens[j + 1].Text == ".")
                {
                    context.Report("Prefer the safe-call operator (?.) or let over an explicit null check.", tokens[i].Line);
                    break;
                }
            }
        }
    }
}

public sealed class KotlinCompanionMutableStateRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0012";
    public override string Name => "Companion object state should be immutable";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Replace mutable var properties in the companion object with immutable vals.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Text != "companion" || tokens[i + 1].Text != "object")
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 2, "{");
            if (open < 0)
                continue;
            var close = KotlinRuleSupport.FindMatchingBrace(tokens, open);
            if (close < 0)
                continue;
            for (var j = open + 1; j < close; j++)
            {
                if (tokens[j].Text == "var")
                {
                    context.Report("Avoid mutable state in the companion object.", tokens[i].Line);
                    break;
                }
            }
        }
    }
}

public sealed class KotlinDataClassEqualsRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0013";
    public override string Name => "Data classes should not override equals or hashCode";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Let the compiler generate equals/hashCode for the data class.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Text != "data" || tokens[i + 1].Text != "class")
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 2, "{");
            if (open < 0)
                continue;
            var close = KotlinRuleSupport.FindMatchingBrace(tokens, open);
            if (close < 0)
                continue;
            for (var j = open + 1; j < close; j++)
            {
                if (RuleMatchers.IsName(tokens[j], "equals") || RuleMatchers.IsName(tokens[j], "hashCode"))
                {
                    context.Report("Data classes generate equals/hashCode automatically; do not override them.", tokens[i].Line);
                    break;
                }
            }
        }
    }
}

public sealed class KotlinLongFunctionRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0014";
    public override string Name => "Functions should not be too long";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Split this function into smaller, focused functions.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        // a test names its cases in prose, and the underscore is how Kotlin writes that prose
        if (LanguageRuleSupport.IsTestFile(context.File.Path, System.IO.Path.GetFileName(context.File.Path)))
            return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "fun")
                continue;
            var name = i + 1;
            if (name < tokens.Count && tokens[name].Text == "<")
            {
                while (name < tokens.Count && tokens[name].Text != ">")
                    name++;
                name++;
            }
            if (name >= tokens.Count || !RuleMatchers.IsIdentifier(tokens[name]))
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, name + 1, "{");
            if (open < 0)
                continue;
            var close = KotlinRuleSupport.FindMatchingBrace(tokens, open);
            if (close < 0)
                continue;
            var minLine = int.MaxValue;
            var maxLine = 0;
            for (var j = open + 1; j < close; j++)
            {
                if (tokens[j].Line < minLine)
                    minLine = tokens[j].Line;
                if (tokens[j].Line > maxLine)
                    maxLine = tokens[j].Line;
            }
            if (maxLine - minLine + 1 > 80)
                context.Report("This function is too long; extract smaller functions.", tokens[i].Line);
        }
    }
}

public sealed class KotlinNestedStringTemplateRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0015";
    public override string Name => "Nested string templates should be avoided";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Extract the inner expression into a variable before interpolating it.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (!RuleMatchers.IsString(token))
                continue;
            var depth = 0;
            var nested = false;
            for (var i = 0; i + 1 < token.Text.Length; i++)
            {
                if (token.Text[i] == '$' && token.Text[i + 1] == '{')
                {
                    depth++;
                    i++;
                    continue;
                }
                if (token.Text[i] == '}')
                {
                    if (depth > 0)
                        depth--;
                    continue;
                }
                if (depth > 0 && token.Text[i] == '$')
                {
                    nested = true;
                    break;
                }
            }
            if (nested)
                context.Report("Avoid nested string templates; extract the inner expression.", token.Line);
        }
    }
}

public sealed class KotlinSizeEmptyCheckRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0016";
    public override string Name => "isEmpty() and isNotEmpty() should be used instead of size comparisons";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Replace the size comparison with isEmpty() or isNotEmpty().";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var next = i + 1;
            if (RuleMatchers.IsName(tokens[i], "count") && next + 1 < tokens.Count
                && tokens[next].Text == "(" && tokens[next + 1].Text == ")")
                next = next + 2;
            else if (RuleMatchers.IsName(tokens[i], "size") || RuleMatchers.IsName(tokens[i], "length"))
                next = i + 1;
            else
                continue;
            if (i - 1 < 0 || tokens[i - 1].Text != ".")
                continue;
            while (next < tokens.Count && tokens[next].Kind == TokenKind.Comment)
                next++;
            if (next + 1 >= tokens.Count || tokens[next].Text is not ("==" or "!="))
                continue;
            if (tokens[next + 1].Text != "0")
                continue;
            context.Report("Use isEmpty() or isNotEmpty() instead of comparing size with 0.", tokens[i].Line);
        }
    }
}

public sealed class KotlinRangeLoopRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0017";
    public override string Name => "Prefer until over inclusive ranges in for loops";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use the until operator to exclude the upper bound when iterating indices.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "for")
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 1, "(");
            if (open < 0)
                continue;
            var close = LanguageRuleSupport.NextIndex(tokens, open + 1, ")");
            if (close < 0)
                continue;
            for (var j = open + 1; j + 1 < close; j++)
            {
                if (tokens[j].Text == "." && tokens[j + 1].Text == ".")
                {
                    context.Report("Use until to exclude the upper bound in this range loop.", tokens[i].Line);
                    break;
                }
            }
        }
    }
}

public sealed class KotlinBooleanComparisonRule : PatternRuleBase
{
    public override string Key => "QG-KT-SML-0018";
    public override string Name => "Boolean literals should not be compared with operators";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Remove the redundant comparison with a boolean literal.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Text is not ("==" or "!="))
                continue;
            if (tokens[i + 1].Text is not ("true" or "false"))
                continue;
            context.Report("Remove the redundant comparison with a boolean literal.", tokens[i].Line);
        }
    }
}

public sealed class KotlinThreadSleepInCoroutineRule : PatternRuleBase
{
    public override string Key => "QG-KT-BUG-0003";
    public override string Name => "Thread.sleep should not be used inside coroutines";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use the suspending delay() function instead of Thread.sleep.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var coroutine = tokens.Any(t => t.Text == "suspend" || RuleMatchers.Contains(t.Text,
            ["launch", "async", "withContext", "coroutineScope", "supervisorScope", "delay"]));
        if (!coroutine)
            return;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "Thread") && tokens[i + 1].Text == "."
                && RuleMatchers.IsName(tokens[i + 2], "sleep"))
                context.Report("Replace Thread.sleep with the suspending delay() function.", tokens[i].Line);
        }
    }
}

public sealed class KotlinGlobalScopeRule : PatternRuleBase
{
    public override string Key => "QG-KT-BUG-0004";
    public override string Name => "GlobalScope should not be used for long-running work";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use an application-scoped CoroutineScope that can be cancelled.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "GlobalScope") || tokens[i + 1].Text != ".")
                continue;
            if (RuleMatchers.IsName(tokens[i + 2], "launch") || RuleMatchers.IsName(tokens[i + 2], "async"))
                context.Report("GlobalScope coroutines cannot be cancelled; use a scoped CoroutineScope instead.", tokens[i].Line);
        }
    }
}

public sealed class KotlinDoubleComparisonRule : PatternRuleBase
{
    public override string Key => "QG-KT-BUG-0005";
    public override string Name => "Floating-point values should not be compared with ==";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Compare floating-point values with an epsilon tolerance instead of ==";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text is not ("==" or "!="))
                continue;
            if (i > 0 && tokens[i - 1].Kind == TokenKind.Number && tokens[i - 1].Text.Contains('.'))
            {
                context.Report("Do not compare floating-point values with ==", tokens[i].Line);
                continue;
            }
            if (i + 1 < tokens.Count && tokens[i + 1].Kind == TokenKind.Number
                && tokens[i + 1].Text.Contains('.'))
                context.Report("Do not compare floating-point values with ==", tokens[i].Line);
        }
    }
}

public sealed class KotlinCollectionModificationRule : PatternRuleBase
{
    public override string Key => "QG-KT-BUG-0006";
    public override string Name => "Collections should not be modified while being iterated";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Collect the items to change first, or iterate over a snapshot copy.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "for")
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 1, "(");
            if (open < 0)
                continue;
            var close = LanguageRuleSupport.NextIndex(tokens, open + 1, ")");
            if (close < 0)
                continue;
            var inIdx = -1;
            for (var j = open + 1; j < close; j++)
            {
                if (tokens[j].Text == "in")
                {
                    inIdx = j;
                    break;
                }
            }
            if (inIdx < 0)
                continue;
            var nameIdx = inIdx + 1;
            while (nameIdx < tokens.Count && tokens[nameIdx].Kind == TokenKind.Comment)
                nameIdx++;
            if (nameIdx >= tokens.Count || !RuleMatchers.IsIdentifier(tokens[nameIdx]))
                continue;
            var name = tokens[nameIdx].Text;
            var bodyOpen = LanguageRuleSupport.NextIndex(tokens, close + 1, "{");
            if (bodyOpen < 0)
                continue;
            var bodyClose = KotlinRuleSupport.FindMatchingBrace(tokens, bodyOpen);
            if (bodyClose < 0)
                continue;
            for (var j = bodyOpen + 1; j + 2 < bodyClose; j++)
            {
                if (!RuleMatchers.IsName(tokens[j], name) || tokens[j + 1].Text != ".")
                    continue;
                if (RuleMatchers.Contains(tokens[j + 2].Text,
                        ["add", "remove", "removeAt", "removeAll", "addAll", "clear"]))
                {
                    context.Report("This collection is modified while it is being iterated.", tokens[i].Line);
                    break;
                }
            }
        }
    }
}

public sealed class KotlinIgnoredCancellationRule : PatternRuleBase
{
    public override string Key => "QG-KT-BUG-0007";
    public override string Name => "Coroutine cancellation exceptions should be rethrown";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Rethrow CancellationException to preserve coroutine cancellation semantics.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "catch")
                continue;
            var open = LanguageRuleSupport.NextIndex(tokens, i + 1, "(");
            if (open < 0)
                continue;
            var close = LanguageRuleSupport.NextIndex(tokens, open + 1, ")");
            if (close < 0)
                continue;
            var isCancellation = false;
            for (var j = open + 1; j < close; j++)
            {
                if (tokens[j].Text == "CancellationException")
                {
                    isCancellation = true;
                    break;
                }
            }
            if (!isCancellation)
                continue;
            var bodyOpen = LanguageRuleSupport.NextIndex(tokens, close + 1, "{");
            if (bodyOpen < 0)
                continue;
            var bodyClose = KotlinRuleSupport.FindMatchingBrace(tokens, bodyOpen);
            if (bodyClose < 0)
                continue;
            var rethrown = false;
            for (var j = bodyOpen + 1; j < bodyClose; j++)
            {
                if (tokens[j].Text == "throw")
                {
                    rethrown = true;
                    break;
                }
            }
            if (!rethrown)
                context.Report("Rethrow CancellationException to preserve coroutine cancellation.", tokens[i].Line);
        }
    }
}

public sealed class KotlinFunctionNameConventionRule : PatternRuleBase
{
    public override string Key => "QG-KT-CNV-0003";
    public override string Name => "Function names should comply with a naming convention";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename this function using lowerCamelCase.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        // a test names its cases in prose, and the underscore is how Kotlin writes that prose
        if (LanguageRuleSupport.IsTestFile(context.File.Path, System.IO.Path.GetFileName(context.File.Path)))
            return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "fun")
                continue;
            var name = i + 1;
            if (name < tokens.Count && tokens[name].Text == "<")
            {
                while (name < tokens.Count && tokens[name].Text != ">")
                    name++;
                name++;
            }

            // An extension function writes its receiver first: 'fun KotlinFileContext.reportIssue'.
            // The name is what follows the dot, and the receiver is a type, so it is upper case on
            // purpose — reading it as the name reports every extension function in the file. A
            // nullable receiver puts a question mark between the type and the dot.
            while (name < tokens.Count && RuleMatchers.IsIdentifier(tokens[name]))
            {
                var dot = name + 1;
                if (dot < tokens.Count && tokens[dot].Text == "?")
                    dot++;
                if (dot >= tokens.Count || tokens[dot].Text != ".")
                    break;
                name = dot + 1;
            }

            if (name >= tokens.Count || !RuleMatchers.IsIdentifier(tokens[name]))
                continue;
            var value = tokens[name].Text;
            if (value.Length == 0 || (!char.IsUpper(value[0]) && !value.Contains('_')))
                continue;
            // a name in backticks is a sentence, which is how Kotlin tests are named
            if (value.Contains(' ') || IsComposable(tokens, i))
                continue;
            // An external function is the name the other side exports — a C entry point, a WASI
            // import — and renaming it breaks the link. The declaration says so with 'external'.
            if (IsExternal(tokens, i))
                continue;

            context.Report("Rename this function to follow the lowerCamelCase convention.", tokens[name].Line);
        }
    }

    /// <summary>
    /// Whether the function carries the Compose annotation. A composable is named in upper camel
    /// case by the framework's own convention — it is a component, not a procedure — so reporting
    /// one is reporting the Android standard.
    /// </summary>
    /// <summary>Whether the declaration binds to a symbol outside the program, whose name is fixed.</summary>
    private static bool IsExternal(IReadOnlyList<Tokenization.Token> tokens, int keyword)
    {
        for (var back = keyword - 1; back >= 0 && back >= keyword - 6; back--)
        {
            if (tokens[back].Text == "external")
                return true;
            if (tokens[back].Text is "}" or "{" or ";")
                break;
        }
        return false;
    }

    private static bool IsComposable(IReadOnlyList<Token> tokens, int functionKeyword)
    {
        for (var i = functionKeyword - 1; i >= 0 && functionKeyword - i < 24; i--)
        {
            if (tokens[i].Text is "}" or ";")
                return false;
            if (tokens[i].Text is "Composable" or "Preview")
                return true;
        }
        return false;
    }
}

public sealed class KotlinConstantNameConventionRule : PatternRuleBase
{
    public override string Key => "QG-KT-CNV-0004";
    public override string Name => "Constants should comply with a naming convention";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename this constant using UPPER_SNAKE_CASE.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (tokens[i].Text != "const" || tokens[i + 1].Text != "val")
                continue;
            var name = tokens[i + 2];
            if (RuleMatchers.IsIdentifier(name) && name.Text.Any(char.IsLower))
                context.Report("Rename this constant to follow the UPPER_SNAKE_CASE convention.", name.Line);
        }
    }
}

public sealed class KotlinPackageNameConventionRule : PatternRuleBase
{
    public override string Key => "QG-KT-CNV-0005";
    public override string Name => "Package names should comply with a naming convention";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename this package to use only lowercase identifiers.";
    public override string[] Languages => ["kt"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "package")
                continue;
            var j = i + 1;
            while (j < tokens.Count && tokens[j].Text != ";" && tokens[j].Line == tokens[i].Line)
            {
                if (RuleMatchers.IsIdentifier(tokens[j]) && tokens[j].Text.Any(char.IsUpper))
                {
                    context.Report("Package names should be lowercase.", tokens[j].Line);
                    break;
                }
                j++;
            }
        }
    }
}

internal static class KotlinRuleSupport
{
    internal static int FindMatchingBrace(IReadOnlyList<Token> tokens, int open)
    {
        var depth = 0;
        for (var i = open; i < tokens.Count; i++)
        {
            if (tokens[i].Text == "{")
                depth++;
            else if (tokens[i].Text == "}")
            {
                depth--;
                if (depth == 0)
                    return i;
            }
        }
        return -1;
    }
}