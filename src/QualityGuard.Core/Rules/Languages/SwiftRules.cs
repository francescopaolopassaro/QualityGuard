using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Swift, the language of native iOS. The defects that matter here are the ones the compiler
/// deliberately lets through: the operators that turn a recoverable situation into a crash (try!,
/// as!, force unwrap), the ones that only crash on some devices (a main-queue deadlock), and the
/// habits that leak data off the phone (a secret in UserDefaults, cleartext transport).
///
/// Swift is read with the structural parser, so these rules stay on what that tree really knows —
/// declarations, blocks, control flow, literals — and use tokens only where the tree has nothing to
/// say.
/// </summary>
public static class SwiftRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new SwiftForceTryRule(),
        new SwiftForceCastRule(),
        new SwiftFloatingPointEqualityRule(),
        new SwiftEmptyCatchRule(),
        new SwiftMainQueueSyncRule(),
        new SwiftBooleanLiteralComparisonRule(),
        new SwiftBooleanReturnedThroughIfRule(),
        new SwiftPrintRule(),
        new SwiftCleartextTransportRule(),
        new SwiftWeakHashRule(),
        new SwiftSecretInUserDefaultsRule(),
        new SwiftSqlInterpolationRule(),
        new SwiftTypeNameConventionRule(),
        new SwiftEmptyBodyRule()
    ];
}

public abstract class SwiftRuleBase : RuleBase
{
    public override string[] Languages => ["swift"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static string[] Lines(IRuleContext context) => LanguageRuleSupport.Lines(context);

    /// <summary>The text of a line with its string literals blanked out and its comment cut off.</summary>
    protected static string Code(string line)
    {
        var span = line.AsSpan();
        var comment = line.IndexOf("//", StringComparison.Ordinal);
        if (comment >= 0)
            span = span[..comment];

        var builder = new System.Text.StringBuilder(span.Length);
        var inString = false;
        foreach (var c in span)
        {
            if (c == '"')
            {
                inString = !inString;
                builder.Append('"');
                continue;
            }
            builder.Append(inString ? ' ' : c);
        }
        return builder.ToString();
    }
}

public sealed class SwiftForceTryRule : SwiftRuleBase
{
    public override string Key => "QG-SW-BUG-0001";
    public override string Name => "A throwing call should not be forced";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        var lines = Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var code = Code(lines[i]);
            var at = code.IndexOf("try!", StringComparison.Ordinal);
            if (at < 0)
                continue;

            context.Report("'try!' turns every error this call can raise into a crash. The compiler "
                           + "asked for a decision and this answers 'it cannot fail' — which holds "
                           + "until the file is missing, the disk is full or the response is not the "
                           + "one the parser expected. Use try with a catch, or try? when nil is a "
                           + "usable answer.", i + 1);
        }
    }
}

public sealed class SwiftForceCastRule : SwiftRuleBase
{
    public override string Key => "QG-SW-BUG-0002";
    public override string Name => "A cast should not be forced";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        var lines = Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var code = Code(lines[i]);
            var at = code.IndexOf("as!", StringComparison.Ordinal);
            if (at < 0)
                continue;
            // the storyboard idiom: the cell type is guaranteed by the identifier registered with it
            if (code.Contains("dequeueReusable", StringComparison.Ordinal))
                continue;

            context.Report("'as!' crashes when the value is not of that type, and the value comes from "
                           + "somewhere this code does not control — a decoded payload, a nib, a "
                           + "collection of Any. Use 'as?' and handle the case where it is not, or "
                           + "change the type so the cast is not needed.", i + 1);
        }
    }
}

public sealed class SwiftFloatingPointEqualityRule : SwiftRuleBase
{
    public override string Key => "QG-SW-BUG-0003";
    public override string Name => "Floating point values should not be compared for equality";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!="))
                continue;
            var literal = comparison.Children.FirstOrDefault(
                c => c.Kind == NodeKind.NumberLiteral && c.Text.Contains('.'));
            if (literal == null)
                continue;

            context.Report($"A decimal such as {literal.Text} has no exact representation, so this "
                           + "comparison is true only when the two values were produced by the very "
                           + "same operations. Compare the distance between them against a tolerance "
                           + "the domain justifies.", comparison.Range.StartLine);
        }
    }
}

public sealed class SwiftEmptyCatchRule : SwiftRuleBase
{
    public override string Key => "QG-SW-BUG-0004";
    public override string Name => "An error should not be caught and dropped";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        foreach (var catchNode in context.Root.OfKind(NodeKind.Catch))
        {
            var body = catchNode.FirstChild(NodeKind.Block);
            if (body == null || body.Children.Count > 0)
                continue;

            context.Report("This catch throws the error away, so the failure leaves no trace: the user "
                           + "sees an empty screen and the logs say the operation succeeded. Handle the "
                           + "error, or log it and say so in the interface.", catchNode.Range.StartLine);
        }
    }
}

public sealed class SwiftMainQueueSyncRule : SwiftRuleBase
{
    public override string Key => "QG-SW-BUG-0005";
    public override string Name => "The main queue should not be waited on synchronously";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        var lines = Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var code = Code(lines[i]).Replace(" ", string.Empty);
            if (!code.Contains("DispatchQueue.main.sync", StringComparison.Ordinal))
                continue;

            context.Report("Waiting on the main queue deadlocks the moment this runs on the main queue "
                           + "itself — the queue cannot start the block because it is blocked waiting "
                           + "for it. The application freezes and the watchdog kills it. Use async, or "
                           + "call the work directly when you are already on the main queue.", i + 1);
        }
    }
}

public sealed class SwiftBooleanLiteralComparisonRule : SwiftRuleBase
{
    public override string Key => "QG-SW-SML-0004";
    public override string Name => "A boolean should not be compared to a boolean literal";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!="))
                continue;
            var literal = comparison.Children.FirstOrDefault(c => c.Kind == NodeKind.BooleanLiteral);
            if (literal == null)
                continue;

            var suggestion = (comparison.Text == "==") == (literal.Text == "true")
                ? "the expression itself"
                : "the negated expression";
            context.Report($"Comparing a boolean against {literal.Text} adds a step that says nothing. "
                           + $"Write {suggestion}.", comparison.Range.StartLine);
        }
    }
}

public sealed class SwiftBooleanReturnedThroughIfRule : SwiftRuleBase
{
    public override string Key => "QG-SW-SML-0001";
    public override string Name => "A condition that is already a boolean should be returned directly";
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var ifNode in context.Root.OfKind(NodeKind.If))
        {
            var elseNode = ifNode.Parent?.Children
                .SkipWhile(c => c != ifNode)
                .Skip(1)
                .FirstOrDefault();
            if (elseNode is not { Kind: NodeKind.Else })
                elseNode = ifNode.FirstChild(NodeKind.Else);
            if (elseNode == null)
                continue;

            var first = ReturnedBoolean(ifNode.FirstChild(NodeKind.Block));
            var second = ReturnedBoolean(elseNode.FirstChild(NodeKind.Block));
            if (first == null || second == null || first == second)
                continue;

            context.Report("One branch returns true and the other returns false, so six lines repeat "
                           + "what the condition already says. Return the condition itself, negated if "
                           + "the branches are the other way round.", ifNode.Range.StartLine);
        }
    }

    private static string? ReturnedBoolean(SyntaxNode? block)
    {
        if (block is not { Children.Count: 1 })
            return null;
        var jump = block.Children[0];
        if (jump.Kind != NodeKind.Jump || jump.Children.Count != 1)
            return null;
        var value = jump.Children[0];
        return value.Kind == NodeKind.BooleanLiteral ? value.Text : null;
    }
}

public sealed class SwiftPrintRule : SwiftRuleBase
{
    public override string Key => "QG-SW-SML-0002";
    public override string Name => "Diagnostics should go through a logger";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
            return;

        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            var name = SyntaxQuery.InvokedName(invocation);
            if (name is not ("print" or "NSLog" or "debugPrint" or "dump"))
                continue;

            context.Report($"'{name}' writes to the device console, where nobody sees it after the app "
                           + "ships, and it cannot be switched off or filtered by level. Its arguments "
                           + "are still evaluated in release builds. Use Logger from OSLog, with the "
                           + "level and the category the message deserves.", invocation.Range.StartLine);
        }
    }
}

public sealed class SwiftCleartextTransportRule : SwiftRuleBase
{
    public override string Key => "QG-SW-SEC-0001";
    public override string Name => "Traffic should not travel in cleartext";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (token.Kind != TokenKind.String)
                continue;
            var text = token.Text;
            if (!text.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                continue;
            // the loopback and the documentation hosts never leave the machine
            if (text.Contains("localhost", StringComparison.OrdinalIgnoreCase)
                || text.Contains("127.0.0.1", StringComparison.Ordinal)
                || text.Contains("example.com", StringComparison.OrdinalIgnoreCase)
                || text.Contains("www.w3.org", StringComparison.OrdinalIgnoreCase)
                || text.Contains("schemas.", StringComparison.OrdinalIgnoreCase))
                continue;

            context.Report("This address is plain HTTP, so everything the app sends and receives over "
                           + "it — tokens included — travels readable across whatever network the "
                           + "phone is on, and anyone on that network can change the answer. Use "
                           + "https.", token.Line);
        }
    }
}

public sealed class SwiftWeakHashRule : SwiftRuleBase
{
    private static readonly string[] Broken = ["Insecure.MD5", "Insecure.SHA1", "CC_MD5", "CC_SHA1"];

    public override string Key => "QG-SW-SEC-0002";
    public override string Name => "A broken hash should not protect anything";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        var lines = Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var code = Code(lines[i]).Replace(" ", string.Empty);
            var found = Broken.FirstOrDefault(b => code.Contains(b, StringComparison.Ordinal));
            if (found == null)
                continue;

            context.Report($"'{found}' is broken: two different inputs with the same digest can be "
                           + "produced on a laptop, so the digest no longer proves anything about what "
                           + "was hashed. Use SHA-256 or better, and a password hash such as PBKDF2 or "
                           + "Argon2 when the input is a password.", i + 1);
        }
    }
}

public sealed class SwiftSecretInUserDefaultsRule : SwiftRuleBase
{
    private static readonly string[] Secrets = ["password", "token", "secret", "apikey", "api_key",
        "credential", "privatekey", "accesstoken", "refreshtoken"];

    public override string Key => "QG-SW-SEC-0003";
    public override string Name => "A secret should be kept in the keychain";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "45min";

    public override void Execute(IRuleContext context)
    {
        var lines = Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var code = Code(lines[i]);
            if (!code.Contains("UserDefaults", StringComparison.Ordinal))
                continue;
            var lowered = lines[i].ToLowerInvariant();
            var secret = Secrets.FirstOrDefault(s => lowered.Contains(s, StringComparison.Ordinal));
            if (secret == null)
                continue;

            context.Report($"UserDefaults is a plist inside the app container: it is not encrypted, it "
                           + $"survives in backups and it is readable on a jailbroken device. A "
                           + $"'{secret}' does not belong there. Store it in the keychain, which the "
                           + "system protects with the device passcode.", i + 1);
        }
    }
}

public sealed class SwiftSqlInterpolationRule : SwiftRuleBase
{
    private static readonly string[] Verbs = ["SELECT ", "INSERT ", "UPDATE ", "DELETE ", "select ",
        "insert ", "update ", "delete "];

    public override string Key => "QG-SW-SEC-0004";
    public override string Name => "A query should not be built by interpolation";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        var lines = Lines(context);
        foreach (var token in context.Tokens)
        {
            if (token.Kind != TokenKind.String)
                continue;
            var text = token.Text;
            if (!Verbs.Any(v => text.Contains(v, StringComparison.Ordinal)))
                continue;
            // the tokenizer resolves escapes, so the interpolation marker is read from the source line
            var source = token.Line - 1 < lines.Length ? lines[token.Line - 1] : string.Empty;
            if (!source.Contains("\\(", StringComparison.Ordinal))
                continue;

            context.Report("This query is assembled with string interpolation, so whatever the "
                           + "interpolated value contains becomes part of the statement — a quote in a "
                           + "user's name is enough to change what it does. Bind the values as "
                           + "parameters instead.", token.Line);
        }
    }
}

public sealed class SwiftTypeNameConventionRule : SwiftRuleBase
{
    public override string Key => "QG-SW-CNV-0001";
    public override string Name => "A type should be named in upper camel case";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var declaration in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var name = declaration.Text;
            if (name.Length == 0 || char.IsUpper(name[0]) || name[0] == '_')
                continue;

            context.Report($"'{name}' starts in lower case, where every type in the standard library "
                           + "and in every framework starts in upper case. The reader has to work out "
                           + "whether the name is a type or a value.", declaration.Range.StartLine);
        }
    }
}

public sealed class SwiftEmptyBodyRule : SwiftRuleBase
{
    public override string Key => "QG-SW-SML-0003";
    public override string Name => "A function should not have an empty body";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var body = function.FirstChild(NodeKind.Block);
            if (body == null || body.Children.Count > 0)
                continue;
            // a required initialiser and a protocol conformance often have nothing to do
            if (function.Text is "init" or "deinit" or "" )
                continue;
            var line = context.File.Content.Split('\n').ElementAtOrDefault(function.Range.StartLine - 1) ?? string.Empty;
            if (line.Contains("override", StringComparison.Ordinal)
                || line.Contains("protocol", StringComparison.Ordinal))
                continue;

            context.Report($"'{function.Text}' does nothing, so every caller believes something happened "
                           + "when nothing did. Give it a body, or say why it is empty in a comment — a "
                           + "deliberately empty hook is a decision, and it should read as one.",
                function.Range.StartLine);
        }
    }
}
