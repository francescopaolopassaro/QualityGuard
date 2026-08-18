using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class PythonRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PythonEvalRule(),
        new PythonSubprocessCommandRule(),
        new PythonUnsafeDeserializationRule(),
        new PythonSqlInjectionRule(),
        new PythonWeakCryptoRule(),
        new PythonHardcodedCredentialsRule(),
        new PythonInsecureRandomRule(),
        new PythonCleartextHttpRule(),
        new PythonShellTrueRule(),
        new PythonAssertRule(),
        new PythonEnvSecretsRule(),
        new PythonXxeRule(),
        new PythonMktempRule(),
        new PythonVerifyFalseRule(),
        new PythonMutableDefaultRule(),
        new PythonPrintRule(),
        new PythonBareExceptRule(),
        new PythonEmptyExceptRule(),
        new PythonWhileTrueRule(),
        new PythonWildcardImportRule(),
        new PythonSsrfRule(),
        new PythonTemplateInjectionRule(),
        new PythonShelveOpenRule(),
        new PythonRangeLenRule(),
        new PythonBoolComparisonRule(),
        new PythonLdapInjectionRule(),
        new PythonHeaderInjectionRule(),
        new PythonOpenRedirectRule(),
        new PythonCrlfInjectionRule(),
        new PythonAesEcbRule(),
        new PythonZipSlipRule(),
        new PythonDebugModeRule(),
        new PythonXssRule(),
        new PythonHostKeyVerificationRule(),
        new PythonInsecureFilePermissionsRule(),
        new PythonSmtpWithoutTlsRule(),
        new PythonRegexDosRule(),
        new PythonDillDeserializationRule(),
        new PythonCleartextFtpRule(),
        new PythonUnusedImportRule(),
        new PythonIdentityComparisonRule(),
        new PythonEqWithoutHashRule(),
        new PythonNoneComparisonRule(),
        new PythonMultipleStatementsRule(),
        new PythonDivisionByZeroRule(),
        new PythonBroadExceptRule(),
        new PythonFloatComparisonRule(),
        new PythonNaiveDateTimeRule(),
        new PythonRemoveDuringIterationRule(),
        new PythonFunctionNamingRule(),
        new PythonClassNameConventionRule(),
        new PythonConstantNamingRule(),
        new PythonCookieWithoutSecureRule(),
        new PythonCookieWithoutHttpOnlyRule()
    ];

    internal static readonly string[] CredentialNames =
        ["password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "credential", "credentials"];

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

    /// <summary>
    /// Which lines sit inside a triple-quoted string. Those carry text, not code: a script that
    /// writes another language embeds the whole of it that way, and reading it line by line found
    /// statements, semicolons and braces belonging to the other language.
    /// </summary>
    internal static bool[] InsideTripleQuotes(string[] lines)
    {
    var inside = new bool[lines.Length];
    var delimiter = string.Empty;
    for (var i = 0; i < lines.Length; i++)
    {
    var line = lines[i];
    if (delimiter.Length > 0)
    {
    inside[i] = true;
    if (line.Contains(delimiter, StringComparison.Ordinal))
    delimiter = string.Empty;
    continue;
    }
    foreach (var mark in Marks)
    {
    var open = line.IndexOf(mark, StringComparison.Ordinal);
    if (open < 0)
    continue;
    // a string that opens and closes on the same line carries no following lines
    if (line.IndexOf(mark, open + mark.Length, StringComparison.Ordinal) < 0)
    delimiter = mark;
    break;
    }
    }
    return inside;
    }

    private static readonly string[] Marks = ["\"\"\"", "'''"];
}

public sealed class PythonEvalRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0001";
    public override string Name => "Arbitrary code execution via eval";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Avoid eval/exec/compile of dynamic code; parse input with a safe library (e.g. ast) instead.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "eval") || RuleMatchers.IsName(tokens[i], "exec"))
                context.Report("Do not evaluate arbitrary code.", tokens[i].Line);
            else if (RuleMatchers.IsName(tokens[i], "compile") && (i == 0 || tokens[i - 1].Text != "."))
                context.Report("Do not compile arbitrary code.", tokens[i].Line);
        }
    }
}

public sealed class PythonSubprocessCommandRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0002";
    public override string Name => "Shell command built from dynamic input";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Pass commands as argument lists without a shell and validate input strictly.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        foreach (var i in PythonRuleSet.QualifiedCall(tokens, ["os", "subprocess"],
                     ["system", "popen", "call", "Popen", "run", "check_call", "check_output"]))
        {
            if (!RuleMatchers.NextNonParenIsString(tokens, i))
                context.Report("Do not build shell commands from dynamic input.", tokens[i].Line);
        }
    }
}

public sealed class PythonUnsafeDeserializationRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0003";
    public override string Name => "Unsafe deserialization endpoint";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Deserialize only trusted data; prefer safe formats (JSON) or restrict pickles/yaml loaders.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var lines = PythonRuleSet.Lines(context);
        foreach (var i in PythonRuleSet.QualifiedCall(tokens, ["pickle", "yaml", "cPickle", "_pickle"], ["load", "loads"]))
        {
            if (RuleMatchers.IsName(tokens[i - 2], "yaml")
                && RuleMatchers.LineContains(lines[tokens[i].Line - 1], "Loader"))
                continue;
            context.Report("Unsafe deserialization may allow remote code execution.", tokens[i].Line);
        }
    }
}

public sealed class PythonSqlInjectionRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0004";
    public override string Name => "SQL query built by string concatenation";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use parameterized queries or an ORM and never concatenate values into SQL.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        foreach (var t in RuleMatchers.Names(context.Tokens, ["execute"]))
        {
            var line = lines[t.Line - 1];
            if (!PythonRuleSet.HasSqlKeyword(line))
                continue;
            if (RuleMatchers.LineContains(line, "%")
                || RuleMatchers.LineContains(line, ".format(")
                || RuleMatchers.LineContains(line, "+")
                || line.Contains("f\""))
                context.Report("Use parameterized queries to prevent SQL injection.", t.Line);
        }
    }
}

public sealed class PythonWeakCryptoRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0005";
    public override string Name => "Weak cryptographic hashing is used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Replace MD5/SHA-1 with a strong algorithm such as SHA-256 or higher.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var i in PythonRuleSet.QualifiedCall(context.Tokens, ["hashlib"], ["md5", "sha1"]))
            context.Report("Weak cryptographic hashing function is used.", context.Tokens[i].Line);
    }
}

public sealed class PythonHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0006";
    public override string Name => "Hard-coded credentials";
    public override Severity Severity => Severity.Blocker;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Store secrets in environment variables or a secret manager instead of source code.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsIdentifier(tokens[i])
                || !RuleMatchers.Contains(tokens[i].Text, PythonRuleSet.CredentialNames, true))
                continue;
            if (tokens[i + 1].Text is "=" or "==" && RuleMatchers.IsString(tokens[i + 2]))
                context.Report("Do not hard-code credentials.", tokens[i].Line);
        }
    }
}

public sealed class PythonInsecureRandomRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0007";
    public override string Name => "Pseudo-random number generator used for security";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use secrets.token_bytes or secrets.SystemRandom for security-sensitive randomness.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var i in PythonRuleSet.QualifiedCall(context.Tokens, ["random"], ["random", "choice", "randrange"]))
            context.Report("Do not use pseudo-random functions for security purposes.", context.Tokens[i].Line);
    }
}

public sealed class PythonCleartextHttpRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0008";
    public override string Name => "Cleartext HTTP communication";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use HTTPS to encrypt data in transit.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        if (LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
            return;

        foreach (var token in context.Tokens)
        {
            if (token.Kind != TokenKind.String)
                continue;
            if (!CleartextProtocols.IsExposedAddress(token.Text, out var scheme, out var instead))
                continue;
            context.Report(CleartextProtocols.Advice(scheme, instead), token.Line);
        }
    }
}

public sealed class PythonShellTrueRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0009";
    public override string Name => "Shell execution with shell=True";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Avoid shell=True; pass an argument list to the subprocess module.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "shell=True"))
                context.Report("The command is passed to the shell; avoid shell=True.", i + 1);
        }
    }
}

public sealed class PythonAssertRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0010";
    public override string Name => "Assertions used for input validation";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Replace assert-based checks with explicit validation that runs under python -O.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        // in a test an assert is the assertion, not a validation that disappears in production
        if (IsTestFile(context.File.FileName))
            return;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            if (function.Text.StartsWith("test", StringComparison.Ordinal))
                continue;
            var parameters = SyntaxQuery.Parameters(function).Select(p => p.Text).ToHashSet(StringComparer.Ordinal);
            if (parameters.Count == 0)
                continue;

            foreach (var assertion in function.OfKind(NodeKind.Jump))
            {
                if (assertion.Text != "assert" || SyntaxQuery.EnclosingFunction(assertion) != function)
                    continue;
                // only an assert that checks an argument is standing in for input validation; the
                // others state an internal invariant, which is what assert is for
                if (!SyntaxQuery.Identifiers(assertion).Any(i => parameters.Contains(i.Text)))
                    continue;
                context.Report(assertion, "This check on an argument disappears when Python runs with -O, "
                                          + "so the value reaches the rest of the function unvalidated; "
                                          + "raise an explicit error instead.");
            }
        }
    }

    private static bool IsTestFile(string fileName)
        => fileName.StartsWith("test_", StringComparison.OrdinalIgnoreCase)
           || fileName.EndsWith("_test.py", StringComparison.OrdinalIgnoreCase)
           || fileName.Equals("conftest.py", StringComparison.OrdinalIgnoreCase);
}

public sealed class PythonEnvSecretsRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0011";
    public override string Name => "Secrets read from environment variables";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Avoid logging or echoing secrets; keep them encrypted at rest.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!RuleMatchers.LineContains(lines[i], "os.environ"))
                continue;
            if (new[] { "password", "secret", "token", "key" }.Any(kw => RuleMatchers.LineContains(lines[i], kw)))
                context.Report("Do not place secrets in cleartext; prefer a secrets manager.", i + 1);
        }
    }
}

public sealed class PythonXxeRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0012";
    public override string Name => "XML parsing prone to XXE";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Disable external entities and DTD processing when parsing XML.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var i in PythonRuleSet.QualifiedCall(context.Tokens, ["etree", "ElementTree"], ["fromstring", "parse"]))
            context.Report("XML parsing may be vulnerable to XXE; disable external entities.", context.Tokens[i].Line);
    }
}

public sealed class PythonMktempRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0013";
    public override string Name => "Insecure temporary file creation";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use tempfile.mkstemp or TemporaryFile which create secure files.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var i in PythonRuleSet.QualifiedCall(context.Tokens, ["tempfile"], ["mktemp"]))
            context.Report("Avoid tempfile.mktemp; use a secure temporary file API.", context.Tokens[i].Line);
    }
}

public sealed class PythonVerifyFalseRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0014";
    public override string Name => "TLS certificate verification disabled";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Keep certificate verification enabled; verify=False exposes the connection to MITM attacks.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "verify=False"))
                context.Report("SSL certificate verification is disabled.", i + 1);
        }
    }
}

public sealed class PythonMutableDefaultRule : PatternRuleBase
{
    public override string Key => "QG-PY-BUG-0001";
    public override string Name => "Mutable default arguments";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use None as the default and initialize inside the function body.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!lines[i].TrimStart().StartsWith("def ", StringComparison.Ordinal))
                continue;
            if (lines[i].Contains("=[]") || lines[i].Contains("={}"))
                context.Report("Mutable default argument is shared across calls.", i + 1);
        }
    }
}

public sealed class PythonPrintRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0001";
    public override string Name => "Debug print statements";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use the logging module and remove leftover print statements.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        // a script prints because printing is what it does; the smell is a print left inside library
        // code, where the caller expects a return value and gets output on the console instead
        if (context.File.Content.Contains("__main__", StringComparison.Ordinal))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "print"))
        {
            if (call.Ancestor(NodeKind.ClassDeclaration) == null)
                continue;
            context.Report(call, "This print writes to the console from inside a class; return the value "
                                 + "or log it, so the caller decides where it goes.");
        }
    }
}

public sealed class PythonBareExceptRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0002";
    public override string Name => "Bare except clause";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Catch specific exceptions or at least Exception, never a bare except.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Kind == TokenKind.Keyword && tokens[i].Text == "except" && tokens[i + 1].Text == ":")
                context.Report("Do not catch broad exceptions with a bare except.", tokens[i].Line);
        }
    }
}

public sealed class PythonEmptyExceptRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0003";
    public override string Name => "Empty except block";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Handle the exception or re-raise it instead of silently passing.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "except") && RuleMatchers.LineContains(lines[i], ": pass"))
                context.Report("Empty except block silently swallows errors.", i + 1);
        }
    }
}

public sealed class PythonWhileTrueRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0004";
    public override string Name => "Infinite loop without exit condition";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Ensure the loop has a guaranteed break condition to avoid hanging the process.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "while True:"))
                context.Report("Unconditional loop may never terminate.", i + 1);
        }
    }
}

public sealed class PythonWildcardImportRule : PatternRuleBase
{
    public override string Key => "QG-PY-CNV-0001";
    public override string Name => "Wildcard imports should not be used";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Import explicit names to avoid polluting the namespace.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "import *"))
                context.Report("Avoid wildcard imports.", i + 1);
        }
    }
}

public sealed class PythonSsrfRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0015";
    public override string Name => "Server-side request forgery via dynamic URL";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Fetch only trusted URLs and restrict the set of allowed outbound targets.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        foreach (var i in PythonRuleSet.QualifiedCall(tokens, ["requests"], ["get", "post"]))
            CheckUrl(context, tokens, i);
        foreach (var i in PythonRuleSet.QualifiedCall(tokens, ["urllib", "request"], ["urlopen"]))
            CheckUrl(context, tokens, i);
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "urlopen"))
                continue;
            if (i >= 2 && tokens[i - 1].Text == ".")
                continue;
            CheckUrl(context, tokens, i);
        }
    }

    private static void CheckUrl(IRuleContext context, IReadOnlyList<Token> tokens, int i)
    {
        // Reporting whenever the argument was not a plain literal flagged every request a test
        // suite makes. What makes this a finding is the untrusted input, so that is what is asked.
        if (context.IsTaintedLine(tokens[i].Line))
            context.Report("Do not fetch URLs derived from untrusted input.", tokens[i].Line);
    }
}

public sealed class PythonPathTraversalRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0016";
    public override string Name => "File path built from untrusted input";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and canonicalize file paths and restrict access to a safe base directory.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var call in QualityGuard.Core.Syntax.SyntaxQuery.InvocationsNamed(context.Root,
                     "open", "Path", "remove", "unlink", "rmtree", "copyfile"))
        {
            var argument = QualityGuard.Core.Syntax.SyntaxQuery.ArgumentAt(call, 0);
            if (argument == null || !context.IsTainted(argument))
                continue;
            context.Report(call, "This path comes from outside the program; validate it against the "
                                 + "directory you intend to serve before opening it.", withFlow: true);
        }
    }
}

public sealed class PythonTemplateInjectionRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0017";
    public override string Name => "Server-side template injection";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Never render templates built from user input; use sandboxed engines with static templates.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "from_string") && !RuleMatchers.IsName(tokens[i], "Template"))
                continue;
            if (!RuleMatchers.NextNonParenIsString(tokens, i) || context.IsTaintedLine(tokens[i].Line))
                context.Report("Do not build templates from untrusted input.", tokens[i].Line);
        }
    }
}

public sealed class PythonShelveOpenRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0018";
    public override string Name => "Unsafe shelve deserialization";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "shelve relies on pickle; only open shelves from trusted sources or use a safe format.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var i in PythonRuleSet.QualifiedCall(context.Tokens, ["shelve"], ["open"]))
            context.Report("shelve uses pickle internally; do not open untrusted shelves.", context.Tokens[i].Line);
    }
}

public sealed class PythonRangeLenRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0005";
    public override string Name => "range(len(sequence)) anti-pattern";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Iterate directly over the sequence with enumerate() instead of indexing by range(len()).";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "range(len("))
                context.Report("Iterate over the sequence directly instead of range(len(...)).", i + 1);
        }
    }
}

public sealed class PythonBoolComparisonRule : PatternRuleBase
{
    public override string Key => "QG-PY-BUG-0002";
    public override string Name => "Comparison against True or False";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Compare the value directly instead of comparing against True or False.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "== True") || RuleMatchers.LineContains(lines[i], "== False"))
                context.Report("Compare the value directly instead of against True/False.", i + 1);
        }
    }
}

public sealed class PythonLdapInjectionRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0019";
    public override string Name => "LDAP query built from concatenated input";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Parameterize LDAP search filters; never concatenate user input into them.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        if (!RuleMatchers.HasNameAny(context.Tokens, ["ldap3", "ldap"]))
            return;
        var lines = PythonRuleSet.Lines(context);
        foreach (var t in RuleMatchers.Names(context.Tokens, ["search", "search_s"]))
        {
            var line = lines[t.Line - 1];
            if (!RuleMatchers.LineContains(line, "+")
                && !RuleMatchers.LineContains(line, "%")
                && !RuleMatchers.LineContains(line, ".format(")
                && !line.Contains("f\""))
                continue;
            context.Report("Do not build LDAP search filters from untrusted input.", t.Line);
        }
    }
}

public sealed class PythonHeaderInjectionRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0020";
    public override string Name => "Response headers set with user-controlled values";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate header values and never embed user input directly into response headers.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!RuleMatchers.LineContains(line, "set_header(")
                && !RuleMatchers.LineContains(line, "add_header(")
                && !RuleMatchers.LineContains(line, "headers["))
                continue;
            var hasString = line.Contains('"') || line.Contains('\'');
            if (hasString && !context.IsTaintedLine(i + 1))
                continue;
            context.Report("Make sure this response header value is not user-controlled.", i + 1);
        }
    }
}

public sealed class PythonOpenRedirectRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0021";
    public override string Name => "Open redirect to user-controlled URL";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Only redirect to whitelisted relative targets, never to arbitrary user input.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "redirect"))
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Do not redirect to URLs derived from untrusted input.", tokens[i].Line);
        }
    }
}

public sealed class PythonCrlfInjectionRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0022";
    public override string Name => "CRLF injection into headers or logs";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Sanitize line break characters from user input before it reaches headers or logs.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var crlf = line.Contains("\\r\\n", StringComparison.Ordinal)
                || RuleMatchers.LineContains(line, "%0d")
                || RuleMatchers.LineContains(line, "%0a");
            if (!crlf)
                continue;
            if (!RuleMatchers.LineContains(line, "set_header")
                && !RuleMatchers.LineContains(line, "headers[")
                && !RuleMatchers.LineContains(line, "logger.")
                && !RuleMatchers.LineContains(line, "logging.")
                && !RuleMatchers.LineContains(line, "print("))
                continue;
            context.Report("User input reaching headers or logs may inject CRLF sequences.", i + 1);
        }
    }
}

public sealed class PythonAesEcbRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0023";
    public override string Name => "ECB mode used for encryption";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use an authenticated mode such as GCM or CBC with a random IV instead of ECB.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "MODE_ECB")
                || RuleMatchers.LineContains(lines[i], "modes.ECB"))
                context.Report("ECB mode does not provide semantic security; use CBC or GCM.", i + 1);
        }
    }
}

public sealed class PythonZipSlipRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0024";
    public override string Name => "Archive extraction without path validation";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and sanitize archive member paths before extracting to avoid zip slip.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var t in RuleMatchers.Names(context.Tokens, ["extractall", "unpack_archive"]))
            context.Report("Archive extraction may be vulnerable to path traversal (zip slip); validate member paths.", t.Line);
    }
}

public sealed class PythonDebugModeRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0025";
    public override string Name => "Debug mode enabled in production";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Disable debug mode outside development; it leaks stack traces and enables remote code execution.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "debug=True"))
                context.Report("Do not enable debug mode in production.", i + 1);
        }
    }
}

public sealed class PythonXssRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0026";
    public override string Name => "Unsafe HTML rendering of user input";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Never mark user input as safe HTML or render templates built from untrusted input.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "Markup")
                && !RuleMatchers.IsName(tokens[i], "render_template_string"))
                continue;
            if (RuleMatchers.NextNonParenIsString(tokens, i) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Do not mark user input as safe HTML or render templates from untrusted input.", tokens[i].Line);
        }
    }
}

public sealed class PythonHostKeyVerificationRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0027";
    public override string Name => "SSH host key verification disabled";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Keep host key verification enabled; auto-accepting unknown host keys enables MITM attacks.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "AutoAddPolicy")
                || RuleMatchers.LineContains(lines[i], "WarningPolicy"))
                context.Report("Disabling SSH host key verification enables man-in-the-middle attacks.", i + 1);
        }
    }
}

public sealed class PythonInsecureFilePermissionsRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0028";
    public override string Name => "World-writable file permissions";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use restrictive file permissions and never chmod 0777.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var stripped = LanguageRuleSupport.StripStrings(lines[i]);
            if (!RuleMatchers.LineContains(stripped, "chmod"))
                continue;
            if (stripped.Contains("0777") || stripped.Contains("0o777") || stripped.Contains(" 777"))
                context.Report("World-writable file permissions are insecure; use restrictive modes.", i + 1);
        }
    }
}

public sealed class PythonSmtpWithoutTlsRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0029";
    public override string Name => "SMTP messages sent without TLS";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use SMTP_SSL or call starttls() to protect mail transmission.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        if (!RuleMatchers.HasNameAny(context.Tokens, ["sendmail"]))
            return;
        if (RuleMatchers.HasNameAny(context.Tokens, ["starttls", "SMTP_SSL"]))
            return;
        var reported = false;
        foreach (var t in RuleMatchers.Names(context.Tokens, ["sendmail"]))
        {
            if (reported)
                break;
            reported = true;
            context.Report("SMTP connections should use TLS via SMTP_SSL or starttls().", t.Line);
        }
    }
}

public sealed class PythonRegexDosRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0030";
    public override string Name => "Regular expression built from user input";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Never compile regular expressions from untrusted input; use fixed, validated patterns.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        foreach (var i in PythonRuleSet.QualifiedCall(tokens, ["re"],
                     ["compile", "search", "match", "findall", "finditer", "sub", "fullmatch"]))
        {
            if (RuleMatchers.NextNonParenIsString(tokens, i) && !context.IsTaintedLine(tokens[i].Line))
                continue;
            context.Report("Do not use untrusted input as a regular expression pattern.", tokens[i].Line);
        }
    }
}

public sealed class PythonDillDeserializationRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0031";
    public override string Name => "Unsafe dill deserialization";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Dill can execute arbitrary code; only deserialize data from trusted sources.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var i in PythonRuleSet.QualifiedCall(context.Tokens, ["dill"], ["load", "loads"]))
            context.Report("Dill deserialization can execute arbitrary code; only deserialize trusted data.", context.Tokens[i].Line);
    }
}

public sealed class PythonCleartextFtpRule : PatternRuleBase
{
    public override string Key => "QG-PY-SEC-0032";
    public override string Name => "Cleartext FTP communication";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use FTPS or SFTP to protect credentials and data in transit.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        foreach (var i in PythonRuleSet.QualifiedCall(tokens, ["ftplib"], ["FTP"]))
            context.Report("FTP transmits data and credentials in cleartext; use SFTP or FTPS.", tokens[i].Line);
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!RuleMatchers.IsName(tokens[i], "FTP"))
                continue;
            if (i > 0 && tokens[i - 1].Text == ".")
                continue;
            if (i + 1 < tokens.Count && tokens[i + 1].Text == "(")
                context.Report("FTP transmits data and credentials in cleartext; use SFTP or FTPS.", tokens[i].Line);
        }
    }
}

public sealed class PythonUnusedImportRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0006";
    public override string Name => "Unused imports should be removed";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Remove imports that are never referenced in the module.";
    public override string[] Languages => ["py"];

    /// <summary>
    /// Modules whose import is the point. 'from __future__ import annotations' changes how the file
    /// is compiled and is never named again; the typing modules are imported for annotations that a
    /// checker reads and the interpreter does not.
    /// </summary>
    private static readonly string[] ImportedForEffect =
        ["__future__", "typing", "typing_extensions", "sklearn.experimental"];

    public override void Execute(IRuleContext context)
    {
        // a package initialiser exists to re-export what it imports
        if (context.File.FileName.Equals("__init__.py", StringComparison.OrdinalIgnoreCase))
            return;

        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (ImportedForEffect.Any(m => lines[i].Contains(m, StringComparison.Ordinal)))
                continue;

            // '# noqa' is how Python says the line is deliberate: an import kept to re-export a
            // name, or one a checker was told to leave alone. Reading past it took the marker for
            // part of the imported name and reported the whole comment back at the reader.
            var statement = lines[i];
            var note = statement.IndexOf('#');
            if (note >= 0)
            {
                if (statement[note..].Contains("noqa", StringComparison.OrdinalIgnoreCase))
                    continue;
                statement = statement[..note];
            }

            var names = ImportedNames(statement);
            foreach (var name in names)
            {
                if (name == "*")
                    continue;
                var used = false;
                for (var j = 0; j < lines.Length && !used; j++)
                {
                    if (j == i)
                        continue;
                    // a name that appears in a comment or inside a string is used: annotations are
                    // written as strings when the type would otherwise be a forward reference, and
                    // a docstring example names what it demonstrates
                    if (LanguageRuleSupport.ContainsWord(lines[j], name))
                        used = true;
                }
                if (!used)
                    context.Report($"Remove this unused import: {name}.", i + 1);
            }
        }
    }

    private static string[] ImportedNames(string line)
    {
        var trimmed = line.TrimStart();
        if (trimmed.StartsWith("from ", StringComparison.Ordinal))
        {
            var idx = trimmed.IndexOf(" import ", StringComparison.Ordinal);
            if (idx < 0)
                return [];
            return ParseNames(trimmed[(idx + " import ".Length)..]);
        }
        if (trimmed.StartsWith("import ", StringComparison.Ordinal))
            return ParseNames(trimmed["import ".Length..]);
        return [];
    }

    private static string[] ParseNames(string items)
    {
        var names = new List<string>();
        foreach (var part in items.Split(','))
        {
            var item = part.Trim();
            if (item.Length == 0)
                continue;
            var asIdx = item.IndexOf(" as ", StringComparison.Ordinal);
            names.Add(asIdx >= 0 ? item[(asIdx + 4)..].Trim() : item.Split('.')[0]);
        }
        return names.ToArray();
    }
}

public sealed class PythonIdentityComparisonRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0007";
    public override string Name => "Do not test identity against True or False";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Test the value directly; comparisons to True/False are redundant.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        // 'assert x is True' is how a test states that the value is that exact object, and a suite
        // written that way produced a hundred and seventy findings on one project. In code that
        // runs in production the comparison is still worth straightening out.
        if (LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
            return;

        // Reading raw lines found the words inside docstrings — "If *auto_store* is True" is prose,
        // not a comparison. Tokens carry no comment and no string content, so only code is left.
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Text != "is" || tokens[i + 1].Text is not ("True" or "False"))
                continue;
            context.Report("Compare the value directly instead of testing identity with True/False.",
                tokens[i].Line);
        }
    }
}

public sealed class PythonVagueVariableNameRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0008";
    public override string Name => "Variables should have descriptive names";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename this variable to something that describes its purpose.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var vague = new[] { "foo", "bar", "baz", "tmp", "temp", "var", "value", "val", "data" };
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsIdentifier(tokens[i]) || !RuleMatchers.Contains(tokens[i].Text, vague))
                continue;
            if (tokens[i + 1].Text == "=")
                context.Report($"Rename '{tokens[i].Text}' to a more descriptive name.", tokens[i].Line);
        }
    }
}

public sealed class PythonPassInExceptRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0009";
    public override string Name => "Pass used to ignore an exception";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Handle the exception or re-raise it instead of silently ignoring it.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length - 1; i++)
        {
            if (!lines[i].TrimStart().StartsWith("except", StringComparison.Ordinal))
                continue;
            if (RuleMatchers.LineContains(lines[i], "pass"))
                continue;
            var j = i + 1;
            while (j < lines.Length && string.IsNullOrWhiteSpace(lines[j]))
                j++;
            if (j < lines.Length && lines[j].Trim() == "pass")
                context.Report("This except block silently ignores the exception.", i + 1);
        }
    }
}

public sealed class PythonEqWithoutHashRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0010";
    public override string Name => "Define __hash__ when overriding __eq__";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "When overriding __eq__, also define __hash__ so instances remain hashable.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        if (lines.Any(l => RuleMatchers.LineContains(l, "def __hash__")))
            return;
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "def __eq__"))
                context.Report("This class defines __eq__ without __hash__; instances are unhashable.", i + 1);
        }
    }
}

public sealed class PythonGlobalStatementRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0012";
    public override string Name => "Avoid the global statement";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Pass values explicitly instead of relying on global state.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var t in context.Tokens)
        {
            if (t.Kind == TokenKind.Keyword && t.Text == "global")
                context.Report("Avoid using the global statement.", t.Line);
        }
    }
}

public sealed class PythonMissingDocstringRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0013";
    public override string Name => "Functions should have docstrings";
    public override Severity Severity => Severity.Info;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string FixAdvice => "Document the purpose of the function with a docstring.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in QualityGuard.Core.Syntax.SyntaxQuery.Functions(context.Root))
        {
            if (function.Text.Length == 0 || function.Text[0] == '_')
                continue; // private helpers document themselves through their name
            var body = function.FirstChild(QualityGuard.Core.Syntax.NodeKind.Block);
            if (body == null || body.Range.LineCount < 8)
                continue;
            var first = body.Children.FirstOrDefault();
            var hasDocstring = first != null
                && first.DescendantsAndSelf().Any(n => n.Kind == QualityGuard.Core.Syntax.NodeKind.StringLiteral);
            if (!hasDocstring)
                context.Report(function, $"Document what '{function.Text}' does: it is part of the public surface.");
        }
    }
}

public sealed class PythonNoneComparisonRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0014";
    public override string Name => "Compare to None with 'is' instead of '=='";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use 'is None' or 'is not None' for identity comparison with None.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "== None")
                || RuleMatchers.LineContains(lines[i], "!= None"))
                context.Report("Use 'is None' instead of comparing with '==' or '!='.", i + 1);
        }
    }
}

public sealed class PythonMultipleStatementsRule : PatternRuleBase
{
    public override string Key => "QG-PY-SML-0015";
    public override string Name => "One statement per line";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Split statements onto separate lines for readability.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        var inText = PythonRuleSet.InsideTripleQuotes(lines);
        for (var i = 0; i < lines.Length; i++)
        {
            // a triple-quoted string can hold a whole file of another language, semicolons included
            if (inText[i])
                continue;
            var stripped = LanguageRuleSupport.StripStrings(lines[i]);
            // what follows a '#' is a note about the statement, not another one — and stripping the
            // strings first leaves the marker in place even when the code before it held a quote
            var comment = stripped.IndexOf('#');
            if (comment >= 0)
                stripped = stripped[..comment];
            if (stripped.Trim().Length == 0)
                continue;
            // a trailing semicolon closes one statement; it takes a second one after it to matter
            var separator = stripped.IndexOf(';');
            if (separator >= 0 && stripped[(separator + 1)..].Trim().Length > 0)
                context.Report("Avoid multiple statements on a single line.", i + 1);
        }
    }
}

public sealed class PythonDivisionByZeroRule : PatternRuleBase
{
    public override string Key => "QG-PY-BUG-0003";
    public override string Name => "Division by zero";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Guard the divisor against zero before dividing or computing modulo.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Symbol || tokens[i].Text is not ("/" or "//" or "%" or "/="))
                continue;
            if (i + 1 >= tokens.Count)
                continue;
            if (tokens[i + 1].Kind == TokenKind.Number && IsZero(tokens[i + 1].Text))
                context.Report("This operation divides by zero.", tokens[i].Line);
            else if (i + 3 < tokens.Count && tokens[i + 1].Text == "("
                && tokens[i + 2].Kind == TokenKind.Number && IsZero(tokens[i + 2].Text)
                && tokens[i + 3].Text == ")")
                context.Report("This operation divides by zero.", tokens[i].Line);
        }
    }

    private static bool IsZero(string text)
        => double.TryParse(text, out var v) && v == 0.0;
}

public sealed class PythonBroadExceptRule : PatternRuleBase
{
    public override string Key => "QG-PY-BUG-0004";
    public override string Name => "Broad except clause hides errors";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Catch specific exceptions so KeyboardInterrupt and SystemExit are not swallowed.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Keyword || tokens[i].Text != "except")
                continue;
            var j = i + 1;
            if (j < tokens.Count && tokens[j].Text == "(")
                continue;
            if (RuleMatchers.IsName(tokens[j], "Exception") || RuleMatchers.IsName(tokens[j], "BaseException"))
                context.Report("Catching broad Exception may hide programming errors and interrupt signals.", tokens[i].Line);
        }
    }
}

public sealed class PythonFloatComparisonRule : PatternRuleBase
{
    public override string Key => "QG-PY-BUG-0005";
    public override string Name => "Floating point values compared for equality";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Compare floating point numbers within an epsilon tolerance instead of with '=='.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var stripped = LanguageRuleSupport.StripStrings(lines[i]);
            if (!stripped.Contains("==") && !stripped.Contains("!="))
                continue;
            if (!System.Text.RegularExpressions.Regex.IsMatch(stripped, @"\d\.\d"))
                continue;
            context.Report("Do not compare floating point values for equality.", i + 1);
        }
    }
}

public sealed class PythonNaiveDateTimeRule : PatternRuleBase
{
    public override string Key => "QG-PY-BUG-0006";
    public override string Name => "Time-zone naive datetime";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Pass tzinfo (e.g. datetime.timezone.utc) so datetimes are time-zone aware.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var lines = PythonRuleSet.Lines(context);
        foreach (var i in PythonRuleSet.QualifiedCall(tokens, ["datetime", "date"], ["now", "utcnow", "today"]))
        {
            var line = lines[tokens[i].Line - 1];
            if (RuleMatchers.LineContains(line, "timezone") || RuleMatchers.LineContains(line, "tzinfo"))
                continue;
            context.Report("Naive datetime is time-zone unaware; use an explicit timezone.", tokens[i].Line);
        }
    }
}

public sealed class PythonRemoveDuringIterationRule : PatternRuleBase
{
    public override string Key => "QG-PY-BUG-0007";
    public override string Name => "Collection modified during iteration";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Iterate over a copy of the list or collect items first, then remove them.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        var loops = new List<int>();
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var trimmed = line.TrimStart();
            if (trimmed.Length == 0)
                continue;
            var indent = line.Length - trimmed.Length;
            while (loops.Count > 0 && indent <= loops[^1])
                loops.RemoveAt(loops.Count - 1);
            if (trimmed.StartsWith("for ", StringComparison.Ordinal) && trimmed.EndsWith(":", StringComparison.Ordinal))
                loops.Add(indent);
            if (loops.Count > 0 && RuleMatchers.LineContains(line, ".remove("))
                context.Report("Mutating a collection while iterating over it may skip elements or raise errors.", i + 1);
        }
    }
}

public sealed class PythonFunctionNamingRule : PatternRuleBase
{
    public override string Key => "QG-PY-CNV-0002";
    public override string Name => "Function names should use snake_case";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename the function to snake_case to follow Python conventions.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].TrimStart();
            if (!trimmed.StartsWith("def ", StringComparison.Ordinal))
                continue;
            var name = trimmed["def ".Length..].TrimStart()
                .Split(['(', ' ', '='], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (string.IsNullOrEmpty(name) || !name.Any(char.IsUpper))
                continue;
            context.Report($"Rename function '{name}' to snake_case.", i + 1);
        }
    }
}

public sealed class PythonClassNameConventionRule : PatternRuleBase
{
    public override string Key => "QG-PY-CNV-0003";
    public override string Name => "Class names should use PascalCase";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename the class to PascalCase to follow Python conventions.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].TrimStart();
            if (!trimmed.StartsWith("class ", StringComparison.Ordinal))
                continue;
            var name = trimmed["class ".Length..].TrimStart()
                .Split(['(', ' ', ':'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (string.IsNullOrEmpty(name) || !char.IsLower(name[0]))
                continue;
            context.Report($"Rename class '{name}' to PascalCase.", i + 1);
        }
    }
}

public sealed class PythonConstantNamingRule : PatternRuleBase
{
    public override string Key => "QG-PY-CNV-0004";
    public override string Name => "Constants should use UPPER_SNAKE_CASE";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Name module-level constants in UPPER_SNAKE_CASE.";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        var lines = PythonRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0 || line[0] is ' ' or '\t')
                continue;
            var trimmed = line.Trim();
            if (trimmed.StartsWith("#", StringComparison.Ordinal))
                continue;
            var eq = trimmed.IndexOf('=');
            if (eq <= 0)
                continue;
            var name = trimmed[..eq].Trim();
            if (name.Contains(' ') || name.Contains('(') || name.Length < 2)
                continue;
            if (name.Any(char.IsUpper) || !name.Any(char.IsLower))
                continue;
            // '__title__', '__version__' and their kind are module metadata, and the surrounding
            // underscores are the convention that names them. Asking for upper case there asks a
            // module to break the shape every tool reads it by.
            if (name.StartsWith("__", StringComparison.Ordinal)
                && name.EndsWith("__", StringComparison.Ordinal))
                continue;
            var value = trimmed[(eq + 1)..].TrimStart();
            if (!IsLiteralValue(value))
                continue;
            context.Report($"Name this module-level constant '{name}' in UPPER_SNAKE_CASE.", i + 1);
        }
    }

    private static bool IsLiteralValue(string value)
    {
        if (value.Length == 0)
            return false;
        if (value[0] is '"' or '\'' or '[' or '{' or '(')
            return true;
        if (char.IsDigit(value[0]) || value[0] == '-')
            return true;
        return value.StartsWith("True", StringComparison.Ordinal)
            || value.StartsWith("False", StringComparison.Ordinal)
            || value.StartsWith("None", StringComparison.Ordinal);
    }
}

/// <summary>
/// A cookie set on a response without one of the two flags that keep it out of reach. Unlike the
/// JavaScript middleware, the Python frameworks default both of these to off, so an argument that
/// is simply not there is as much a decision as one written as False.
/// </summary>
public abstract class PythonCookieFlagRule : PatternRuleBase
{
    private static readonly string[] Setters = ["set_cookie", "set_signed_cookie"];

    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["py"];

    /// <summary>The keyword argument this rule insists on.</summary>
    protected abstract string Flag { get; }

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser
            || LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!Setters.Contains(name, StringComparer.Ordinal))
                continue;

            var arguments = SyntaxQuery.Arguments(call);
            // 'set_cookie(cookie)' on a cookie jar takes the whole cookie and has no flags to give;
            // the response API this rule is about is called with a name and a value. Without the
            // type of the receiver the shape is what tells them apart, and reading every call
            // reported a client library's own jar a dozen times.
            if (arguments.Count(a => a.Kind != NodeKind.NamedArgument) < 2)
                continue;
            // arguments forwarded from elsewhere say nothing about what was actually passed
            if (arguments.Any(a => a.Text.StartsWith('*')))
                continue;

            var given = arguments
                .FirstOrDefault(a => a.Kind == NodeKind.NamedArgument && a.Text == Flag);
            // absent means the framework default applies, and that default is off
            if (given is not null && !IsOff(given))
                continue;

            context.Report(call, Advice);
        }
    }

    /// <summary>Whether the value given to the flag leaves the protection off.</summary>
    private static bool IsOff(SyntaxNode argument)
    {
        var value = argument.Children.LastOrDefault();
        return value is not null && value.Text is "False" or "None" or "0" or "\"\"";
    }

    protected abstract string Advice { get; }
}

public sealed class PythonCookieWithoutSecureRule : PythonCookieFlagRule
{
    public override string Key => "QG-PY-SEC-0093";
    public override string Name => "A cookie should not travel in the clear";
    protected override string Flag => "secure";

    protected override string Advice =>
        "This cookie is set without asking for the flag that keeps it off plain connections, and the "
        + "framework leaves that off by default. The browser will then send it over HTTP as readily "
        + "as HTTPS, where anyone on the path can read it.";
}

public sealed class PythonCookieWithoutHttpOnlyRule : PythonCookieFlagRule
{
    public override string Key => "QG-PY-SEC-0094";
    public override string Name => "A cookie should be out of reach of script";
    protected override string Flag => "httponly";

    protected override string Advice =>
        "This cookie is set without asking for the flag that hides it from script, and the framework "
        + "leaves that off by default. Anything running on the page can then read it, so one "
        + "scripting flaw anywhere on the site takes the session with it.";
}
