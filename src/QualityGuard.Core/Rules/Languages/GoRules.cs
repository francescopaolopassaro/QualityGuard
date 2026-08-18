using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class GoRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new GoExecCommandRule(),
        new GoSqlInjectionRule(),
        new GoWeakCryptoRule(),
        new GoHardcodedCredentialsRule(),
        new GoCleartextHttpRule(),
        new GoInsecureRandomRule(),
        new GoInsecureSkipVerifyRule(),
        new GoShCRule(),
        new GoPanicRule(),
        new GoDeferInLoopRule(),
        new GoUnsafePackageRule(),
        new GoDebugPrintRule(),
        new GoGotoRule(),
        new GoInfiniteForRule(),
        new GoSsrfRule(),
        new GoPathTraversalRule(),
        new GoTemplateInjectionRule(),
        new GoNewZeroValueRule(),
        new GoElseAfterReturnRule()
    ];

    internal static readonly string[] CredentialNames =
        ["password", "passwd", "secret", "token", "api_key", "apikey", "credential", "credentials"];

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

public sealed class GoExecCommandRule : PatternRuleBase
{
    public override string Key => "QG-GO-SEC-0001";
    public override string Name => "Shell command built from dynamic input";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Avoid exec.Command with dynamic arguments; always pass a static command name.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        foreach (var i in GoRuleSet.QualifiedCall(tokens, ["exec"], ["Command"]))
        {
            if (!RuleMatchers.NextNonParenIsString(tokens, i))
                context.Report("Do not build shell commands from dynamic input.", tokens[i].Line);
        }
    }
}

public sealed class GoSqlInjectionRule : PatternRuleBase
{
    public override string Key => "QG-GO-SEC-0002";
    public override string Name => "SQL query built by string concatenation";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use prepared statements and bind parameters instead of string concatenation.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var lines = GoRuleSet.Lines(context);
        foreach (var i in GoRuleSet.QualifiedCall(tokens, ["db", "sqlx"], ["Query", "Exec", "QueryRow"]))
        {
            var line = lines[tokens[i].Line - 1];
            if (!GoRuleSet.HasSqlKeyword(line))
                continue;
            if (RuleMatchers.LineContains(line, "fmt.Sprintf(") || RuleMatchers.LineContains(line, "+"))
                context.Report("Use parameterized queries to prevent SQL injection.", tokens[i].Line);
        }
    }
}

public sealed class GoWeakCryptoRule : PatternRuleBase
{
    public override string Key => "QG-GO-SEC-0003";
    public override string Name => "Weak cryptographic hashing is used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Replace MD5/SHA-1 with a strong algorithm such as SHA-256 or higher.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        foreach (var t in RuleMatchers.StringsContaining(context.Tokens, "crypto/md5"))
            context.Report("Weak cryptographic hashing function is used.", t.Line);
        foreach (var t in RuleMatchers.StringsContaining(context.Tokens, "crypto/sha1"))
            context.Report("Weak cryptographic hashing function is used.", t.Line);
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if ((RuleMatchers.IsName(tokens[i], "md5") || RuleMatchers.IsName(tokens[i], "sha1"))
                && tokens[i + 1].Kind == TokenKind.Symbol && tokens[i + 1].Text == ".")
                context.Report("Weak cryptographic hashing function is used.", tokens[i].Line);
        }
    }
}

public sealed class GoHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-GO-SEC-0004";
    public override string Name => "Hard-coded credentials";
    public override Severity Severity => Severity.Blocker;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Read secrets from environment variables or a secret manager instead of source code.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            if (!RuleMatchers.IsIdentifier(tokens[i])
                || !RuleMatchers.Contains(tokens[i].Text, GoRuleSet.CredentialNames, true))
                continue;
            if (tokens[i + 1].Text is "=" or "==" && RuleMatchers.IsString(tokens[i + 2]))
            {
                context.Report("Do not hard-code credentials.", tokens[i].Line);
                continue;
            }
            if (i + 3 < tokens.Count && tokens[i + 1].Text == ":" && tokens[i + 2].Text == "="
                && RuleMatchers.IsString(tokens[i + 3]))
                context.Report("Do not hard-code credentials.", tokens[i].Line);
        }
    }
}

public sealed class GoCleartextHttpRule : PatternRuleBase
{
    public override string Key => "QG-GO-SEC-0005";
    public override string Name => "Cleartext HTTP communication";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use HTTPS to encrypt data in transit.";
    public override string[] Languages => ["go"];

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

public sealed class GoInsecureRandomRule : PatternRuleBase
{
    public override string Key => "QG-GO-SEC-0006";
    public override string Name => "Pseudo-random number generator used for security";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use crypto/rand instead of math/rand for security-sensitive values.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        foreach (var t in RuleMatchers.StringsContaining(context.Tokens, "math/rand"))
            context.Report("math/rand is not cryptographically secure.", t.Line);
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "rand")
                && tokens[i + 1].Kind == TokenKind.Symbol && tokens[i + 1].Text == ".")
                context.Report("math/rand is not cryptographically secure.", tokens[i].Line);
        }
    }
}

public sealed class GoInsecureSkipVerifyRule : PatternRuleBase
{
    public override string Key => "QG-GO-SEC-0007";
    public override string Name => "TLS certificate verification disabled";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Keep InsecureSkipVerify false to protect against MITM attacks.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        var lines = GoRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "InsecureSkipVerify: true"))
                context.Report("SSL certificate verification is disabled.", i + 1);
        }
    }
}

public sealed class GoShCRule : PatternRuleBase
{
    public override string Key => "QG-GO-SEC-0008";
    public override string Name => "Shell invocation through sh -c";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Avoid invoking sh -c; execute the intended program directly.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        var lines = GoRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "sh -c"))
                context.Report("Shell invocation may allow command injection.", i + 1);
        }
    }
}

public sealed class GoPanicRule : PatternRuleBase
{
    public override string Key => "QG-GO-BUG-0001";
    public override string Name => "A function that returns an error should not panic";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        // Panic is not wrong in Go: main, init and a code generator use it for a failure nobody can
        // recover from. It is wrong in a function that already promises to return an error, because
        // there the caller has asked to handle failure and this bypasses the answer it expects.
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!ReturnsError(context, function))
                continue;
            var body = SyntaxQuery.Body(function);
            if (body == null)
                continue;

            foreach (var call in SyntaxQuery.InvocationsNamed(body, "panic"))
            {
                if (SyntaxQuery.EnclosingFunction(call) != function)
                    continue;

                context.Report($"'{function.Text}' returns an error, so its caller is already prepared "
                               + "to handle a failure — and a panic goes past that answer, unwinds the "
                               + "stack and ends the process unless something recovers. Return the "
                               + "error.", call.Range.StartLine);
            }
        }
    }

    /// <summary>Whether the signature promises an error among its results.</summary>
    private static bool ReturnsError(IRuleContext context, SyntaxNode function)
    {
        var lines = LanguageRuleSupport.Lines(context);
        var line = function.Range.StartLine - 1 < lines.Length && function.Range.StartLine > 0
            ? lines[function.Range.StartLine - 1]
            : string.Empty;
        // What follows the parameter list, not what follows the last parenthesis on the line: the
        // results of a Go function are themselves parenthesised — '(path string) ([]byte, error)'.
        var open = line.IndexOf('(');
        if (open < 0)
            return false;
        var depth = 0;
        for (var i = open; i < line.Length; i++)
        {
            if (line[i] == '(')
                depth++;
            else if (line[i] == ')')
            {
                depth--;
                if (depth != 0)
                    continue;
                // a method declares its receiver first, so the results come after the next list
                var rest = line[(i + 1)..];
                var next = rest.IndexOf('(');
                if (next >= 0 && rest[..next].Trim().Length > 0)
                    return ReturnsErrorAfter(rest);
                return LanguageRuleSupport.ContainsWord(rest, "error");
            }
        }
        return false;
    }

    private static bool ReturnsErrorAfter(string rest)
    {
        var open = rest.IndexOf('(');
        var depth = 0;
        for (var i = open; i >= 0 && i < rest.Length; i++)
        {
            if (rest[i] == '(')
                depth++;
            else if (rest[i] == ')')
            {
                depth--;
                if (depth == 0)
                    return LanguageRuleSupport.ContainsWord(rest[(i + 1)..], "error");
            }
        }
        return false;
    }
}

public sealed class GoUnsafePackageRule : PatternRuleBase
{
    public override string Key => "QG-GO-SML-0001";
    public override string Name => "Unsafe package should not be used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Avoid the unsafe package; it defeats Go type safety.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        foreach (var t in context.Tokens)
        {
            if (RuleMatchers.IsString(t) && t.Text == "unsafe")
                context.Report("Avoid using the unsafe package.", t.Line);
        }
    }
}

public sealed class GoDebugPrintRule : PatternRuleBase
{
    public override string Key => "QG-GO-SML-0002";
    public override string Name => "Debug output statements";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use a structured logger and remove leftover fmt print statements.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        foreach (var i in GoRuleSet.QualifiedCall(tokens, ["fmt"], ["Println", "Print", "Printf"]))
            context.Report("Remove this debug output statement.", tokens[i].Line);
    }
}

public sealed class GoGotoRule : PatternRuleBase
{
    public override string Key => "QG-GO-SML-0003";
    public override string Name => "Goto statements should not be used";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Replace goto with structured control flow.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        foreach (var t in context.Tokens)
        {
            if (t.Kind == TokenKind.Keyword && t.Text == "goto")
                context.Report("Avoid using goto statements.", t.Line);
        }
    }
}

public sealed class GoInfiniteForRule : PatternRuleBase
{
    public override string Key => "QG-GO-SML-0004";
    public override string Name => "Infinite loop without exit condition";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Ensure the loop has a guaranteed break/return to avoid hanging the process.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        var lines = GoRuleSet.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "for {"))
                context.Report("Unconditional loop may never terminate.", i + 1);
        }
    }
}

public sealed class GoSsrfRule : PatternRuleBase
{
    public override string Key => "QG-GO-SEC-0009";
    public override string Name => "Server-Side Request Forgery via HTTP client";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and allow list destination URLs and prevent access to internal hosts.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        foreach (var i in GoRuleSet.QualifiedCall(tokens, ["http", "client"], ["Get", "Post", "NewRequest"]))
        {
            if (!RuleMatchers.NextNonParenIsString(tokens, i) || context.IsTaintedLine(tokens[i].Line))
                context.Report("Validate and allow list URLs passed to the HTTP client.", tokens[i].Line);
        }
    }
}

public sealed class GoPathTraversalRule : PatternRuleBase
{
    public override string Key => "QG-GO-SEC-0010";
    public override string Name => "Path traversal via user-controlled file path";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate and sanitize file paths against a base directory allow list.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        foreach (var i in GoRuleSet.QualifiedCall(tokens, ["os", "ioutil"], ["Open", "ReadFile"]))
        {
            if (!RuleMatchers.NextNonParenIsString(tokens, i) || context.IsTaintedLine(tokens[i].Line))
                context.Report("Validate file paths passed to file access calls.", tokens[i].Line);
        }
    }
}

public sealed class GoTemplateInjectionRule : PatternRuleBase
{
    public override string Key => "QG-GO-SEC-0011";
    public override string Name => "HTML template injection via unescaped cast";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Avoid casting raw strings to template.HTML; escape untrusted data.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        foreach (var i in GoRuleSet.QualifiedCall(context.Tokens, ["template"], ["HTML"]))
            context.Report("Casting to template.HTML disables escaping and allows injection.", context.Tokens[i].Line);
    }
}

public sealed class GoNewZeroValueRule : PatternRuleBase
{
    public override string Key => "QG-GO-SML-0005";
    public override string Name => "new(T) used instead of composite literal";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Prefer &T{} over new(T) for clarity and consistency.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (RuleMatchers.IsName(tokens[i], "new") && tokens[i + 1].Text == "(")
                context.Report("Prefer &T{} over new(T).", tokens[i].Line);
        }
    }
}

public sealed class GoElseAfterReturnRule : PatternRuleBase
{
    public override string Key => "QG-GO-CNV-0001";
    public override string Name => "Unnecessary else after return";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Remove the else block and return directly to reduce nesting.";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        foreach (var branch in context.Root.OfKind(QualityGuard.Core.Syntax.NodeKind.If))
        {
            var body = branch.FirstChild(QualityGuard.Core.Syntax.NodeKind.Block);
            var otherwise = branch.FirstChild(QualityGuard.Core.Syntax.NodeKind.Else);
            if (body == null || otherwise == null || body.Children.Count == 0)
                continue;
            var last = body.Children[^1];
            if (last.Kind != QualityGuard.Core.Syntax.NodeKind.Jump || last.Text is not ("return" or "continue" or "break"))
                continue;
            context.Report(otherwise, "The branch above always leaves the function, so this else only adds nesting.");
        }
    }
}

/// <summary>
/// A deferred call inside a loop. This used to be a line pattern that asked only whether the file
/// contained a loop anywhere, so every defer in a file that had one was reported. Containment is a
/// question about the tree, and it is asked here.
/// </summary>
public sealed class GoDeferInLoopRule : RuleBase
{
    public override string Key => "QG-GO-BUG-0004";
    public override string Name => "Deferred calls should not be made inside loops";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";
    public override string[] Languages => ["go"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            foreach (var statement in loop.Descendants())
            {
                // the parser keeps a defer as an expression statement whose text is the keyword
                if (statement.Kind is not (NodeKind.Jump or NodeKind.ExpressionStatement)
                    || statement.Text != "defer")
                    continue;
                // a defer inside a function literal runs when that literal returns, which is the
                // per-iteration behaviour the fix asks for
                var owner = statement.Ancestors().FirstOrDefault(
                    a => a.Kind is NodeKind.Loop or NodeKind.Lambda or NodeKind.FunctionDeclaration);
                if (owner != loop)
                    continue;

                context.Report("Deferred calls run when the function returns, not at the end of the "
                               + "iteration, so every pass adds another one and the files or "
                               + "connections stay open until the whole function finishes.",
                    statement.Range.StartLine);
            }
        }
    }
}
