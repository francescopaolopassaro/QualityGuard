using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Python rules chosen by measurement rather than by taste: each one closes a gap that
/// <c>tools/compare_expectations.py</c> found against an annotated reference corpus, picked from the
/// checks whose expected lines we covered least.
/// </summary>
public static class PythonMeasuredRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PythonStatementWithoutEffectRule(),
        new PythonRedundantParenthesesRule(),
        new PythonTypeVarNameRule(),
        new PythonSpecialMethodReturnRule(),
        new PythonUnconditionalAssertionRule(),
        new PythonDedicatedAssertionRule(),
        new PythonWeakSslProtocolRule(),
        new PythonPredictableSaltRule(),
        new PythonJwtVerificationRule(),
        new PythonPermissiveCorsRule(),
        new PythonWeakPasswordHashRule(),
        new PythonConstantOperandRule()
    ];
}

public abstract class PythonMeasuredRuleBase : RuleBase
{
    public override string[] Languages => ["py"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static string SourceLine(IRuleContext context, int line)
    {
        var lines = LanguageRuleSupport.Lines(context);
        return line - 1 >= 0 && line - 1 < lines.Length ? lines[line - 1] : string.Empty;
    }

    /// <summary>The dotted name a call invokes, with the receiver.</summary>
    protected static string CallName(SyntaxNode call) => SyntaxQuery.InvokedDottedName(call);

    /// <summary>The named argument with this name, or null.</summary>
    protected static SyntaxNode? NamedArgument(SyntaxNode call, string name)
    {
        var list = call.FirstChild(NodeKind.ArgumentList);
        if (list == null)
            return null;
        foreach (var argument in list.Children)
        {
            if (argument.Kind == NodeKind.NamedArgument && argument.Text == name)
                return argument.Children.LastOrDefault();
            if (argument.Kind == NodeKind.Assignment && argument.Text == "="
                && SyntaxQuery.SimpleName(argument.ChildAt(0)) == name)
                return argument.ChildAt(1);
        }
        return null;
    }
}

public sealed class PythonStatementWithoutEffectRule : PythonMeasuredRuleBase
{
    public override string Key => "QG-PY-BUG-0149";
    public override string Name => "A statement should do something";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var statement in context.Root.OfKind(NodeKind.ExpressionStatement))
        {
            if (statement.Children.Count != 1)
                continue;
            var expression = statement.Children[0];

            var pointless = expression.Kind switch
            {
                // a bare name or a member access evaluates and discards
                NodeKind.Identifier or NodeKind.MemberSelect => true,
                // a comparison written as a statement is almost always a forgotten assignment
                NodeKind.Binary => expression.Text is "==" or "!=" or "<" or ">" or "<=" or ">="
                    or "+" or "-" or "*" or "/",
                _ => false
            };
            if (!pointless)
                continue;
            // a string on its own is a docstring, and Ellipsis is how a stub body is written
            if (expression.Kind == NodeKind.Identifier && expression.Text is "..." or "Ellipsis")
                continue;
            // a member access can trigger a property, which is why only a plain chain counts
            if (expression.Kind == NodeKind.MemberSelect
                && expression.DescendantsAndSelf().Any(n => n.Kind == NodeKind.Invocation))
                continue;

            context.Report("This statement computes a value and throws it away, so it changes nothing. "
                           + "Either an assignment is missing, or a call lost its parentheses.",
                statement.Range.StartLine);
        }
    }
}

public sealed class PythonRedundantParenthesesRule : PythonMeasuredRuleBase
{
    public override string Key => "QG-PY-CNV-0008";
    public override string Name => "Parentheses should not be doubled";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Symbol || tokens[i].Text != "(")
                continue;
            if (tokens[i + 1].Kind != TokenKind.Symbol || tokens[i + 1].Text != "(")
                continue;
            // a call taking a tuple, a generator or another call opens two parentheses for a reason
            if (i > 0 && (tokens[i - 1].Kind is TokenKind.Identifier or TokenKind.Keyword
                          || tokens[i - 1].Text is ")" or "]"))
                continue;
            var close = Matching(tokens, i);
            var inner = Matching(tokens, i + 1);
            if (close < 0 || inner != close - 1)
                continue;

            context.Report("The inner parentheses group what the outer ones already group, so one pair "
                           + "says everything the two say together.", tokens[i].Line);
        }
    }

    private static int Matching(IReadOnlyList<Token> tokens, int open)
    {
        var depth = 0;
        for (var i = open; i < tokens.Count && i - open < 512; i++)
        {
            if (tokens[i].Kind != TokenKind.Symbol)
                continue;
            if (tokens[i].Text is "(" or "[" or "{")
                depth++;
            else if (tokens[i].Text is ")" or "]" or "}")
            {
                depth--;
                if (depth == 0)
                    return i;
            }
        }
        return -1;
    }
}

public sealed class PythonTypeVarNameRule : PythonMeasuredRuleBase
{
    private static readonly string[] Factories = ["TypeVar", "ParamSpec", "NewType", "TypeVarTuple"];

    public override string Key => "QG-PY-CNV-0009";
    public override string Name => "A type variable should carry its own name";
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            if (assignment.Text != "=")
                continue;
            var target = SyntaxQuery.SimpleName(assignment.ChildAt(0));
            var call = assignment.ChildAt(1);
            if (target.Length == 0 || call is not { Kind: NodeKind.Invocation })
                continue;
            var factory = SyntaxQuery.InvokedName(call);
            if (!Factories.Contains(factory))
                continue;
            var declared = SyntaxQuery.ArgumentAt(call, 0);
            if (declared is not { Kind: NodeKind.StringLiteral } || declared.Text == target)
                continue;

            context.Report($"'{factory}' is told its name is '{declared.Text}' while the variable is "
                           + $"called '{target}'. Every error message and every traceback shows the "
                           + "first, and nothing in the file explains where it came from.",
                assignment.Range.StartLine);
        }
    }
}

public sealed class PythonSpecialMethodReturnRule : PythonMeasuredRuleBase
{
    /// <summary>Special methods whose return type the language fixes, with what they must answer.</summary>
    private static readonly Dictionary<string, (string Type, NodeKind Literal)> Expected =
        new(StringComparer.Ordinal)
        {
            ["__bool__"] = ("bool", NodeKind.BooleanLiteral),
            ["__len__"] = ("int", NodeKind.NumberLiteral),
            ["__index__"] = ("int", NodeKind.NumberLiteral),
            ["__hash__"] = ("int", NodeKind.NumberLiteral),
            ["__str__"] = ("str", NodeKind.StringLiteral),
            ["__repr__"] = ("str", NodeKind.StringLiteral),
            ["__format__"] = ("str", NodeKind.StringLiteral),
        };

    public override string Key => "QG-PY-BUG-0150";
    public override string Name => "A special method should return the type the language expects";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!Expected.TryGetValue(method.Text, out var expected))
                continue;
            var body = SyntaxQuery.Body(method);
            if (body == null)
                continue;

            foreach (var jump in body.OfKind(NodeKind.Jump))
            {
                if (jump.Text != "return" || jump.Children.Count == 0)
                    continue;
                var value = jump.Children[0];
                // only a literal is judged: anything computed needs a type the engine cannot promise
                if (value.Kind is not (NodeKind.BooleanLiteral or NodeKind.NumberLiteral
                    or NodeKind.StringLiteral or NodeKind.NullLiteral))
                    continue;
                if (value.Kind == expected.Literal)
                    continue;
                // a float is not an int, and __len__ refuses one
                if (expected.Literal == NodeKind.NumberLiteral && value.Kind == NodeKind.NumberLiteral)
                    continue;
                if (SyntaxQuery.EnclosingFunction(jump) != method)
                    continue;

                context.Report($"'{method.Text}' has to answer with {expected.Type}: the interpreter "
                               + "calls it and raises TypeError on anything else, at the moment the "
                               + "object is used rather than where it was written.",
                    jump.Range.StartLine);
            }
        }
    }
}

public sealed class PythonUnconditionalAssertionRule : PythonMeasuredRuleBase
{
    public override string Key => "QG-PY-BUG-0151";
    public override string Name => "An assertion should be able to fail";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            var alwaysTrue = name switch
            {
                "assertTrue" => Literal(call, "True"),
                "assertFalse" => Literal(call, "False"),
                "assertIsNone" => Literal(call, "None"),
                "assertIsNotNone" => Literal(call, "True") || Literal(call, "False"),
                _ => false
            };
            if (!alwaysTrue)
                continue;

            context.Report($"'{name}' is given a constant, so the assertion passes whatever the code "
                           + "under test does. The test reports success and checks nothing.",
                call.Range.StartLine);
        }
    }

    private static bool Literal(SyntaxNode call, string text)
    {
        var argument = SyntaxQuery.ArgumentAt(call, 0);
        return argument is { Kind: NodeKind.BooleanLiteral or NodeKind.NullLiteral }
               && argument.Text == text;
    }
}

public sealed class PythonDedicatedAssertionRule : PythonMeasuredRuleBase
{
    public override string Key => "QG-PY-SML-0251";
    public override string Name => "The assertion that names the check should be used";
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "assertTrue", "assertFalse"))
        {
            var argument = SyntaxQuery.ArgumentAt(call, 0);
            if (argument is not { Kind: NodeKind.Binary })
                continue;

            var name = SyntaxQuery.InvokedName(call);
            var dedicated = (name, argument.Text) switch
            {
                ("assertTrue", "==") => "assertEqual",
                ("assertTrue", "!=") => "assertNotEqual",
                ("assertTrue", "is") => "assertIs",
                ("assertTrue", "in") => "assertIn",
                ("assertFalse", "==") => "assertNotEqual",
                ("assertFalse", "!=") => "assertEqual",
                ("assertFalse", "is") => "assertIsNot",
                ("assertFalse", "in") => "assertNotIn",
                _ => null
            };
            if (dedicated == null)
                continue;

            context.Report($"'{name}' with a comparison reports only 'False is not True' when it "
                           + $"fails. '{dedicated}' prints both values, which is the whole difference "
                           + "between a test that tells you what broke and one that does not.",
                call.Range.StartLine);
        }
    }
}

public sealed class PythonWeakSslProtocolRule : PythonMeasuredRuleBase
{
    private static readonly string[] Obsolete =
    [
        "PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1",
        "SSLv2_METHOD", "SSLv3_METHOD", "TLSv1_METHOD", "TLSv1_1_METHOD"
    ];

    public override string Key => "QG-PY-SEC-0085";
    public override string Name => "An obsolete TLS version should not be selected";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (token.Kind is not (TokenKind.Identifier or TokenKind.Keyword))
                continue;
            if (!Obsolete.Contains(token.Text))
                continue;

            context.Report($"'{token.Text}' selects a protocol version with published attacks against "
                           + "it, and a client that offers it can be pushed down onto it. Ask for "
                           + "PROTOCOL_TLS_CLIENT and let the library negotiate.", token.Line);
        }
    }
}

public sealed class PythonPredictableSaltRule : PythonMeasuredRuleBase
{
    private static readonly string[] Hashers =
        ["pbkdf2_hmac", "scrypt", "crypt", "hash", "derive", "kdf"];

    public override string Key => "QG-PY-SEC-0086";
    public override string Name => "A salt should be unpredictable";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!Hashers.Contains(name))
                continue;

            var salt = NamedArgument(call, "salt")
                       ?? (name is "pbkdf2_hmac" ? SyntaxQuery.ArgumentAt(call, 2) : null)
                       ?? (name is "crypt" ? SyntaxQuery.ArgumentAt(call, 1) : null);
            if (salt is not { Kind: NodeKind.StringLiteral })
                continue;

            context.Report("The salt is written into the code, so every password is hashed with the "
                           + "same one — and a table computed once breaks all of them together. "
                           + "Generate a fresh salt per password with os.urandom and store it beside "
                           + "the hash.", call.Range.StartLine);
        }
    }
}

public sealed class PythonJwtVerificationRule : PythonMeasuredRuleBase
{
    public override string Key => "QG-PY-SEC-0087";
    public override string Name => "A token should be verified before it is trusted";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (name is not ("decode" or "process_jwt"))
                continue;
            var receiver = SyntaxQuery.Receiver(call);
            if (name == "decode" && !receiver.Contains("jwt", StringComparison.OrdinalIgnoreCase))
                continue;

            var reason = name == "process_jwt"
                ? "'process_jwt' reads the token without checking its signature at all"
                : Disabled(context, call)
                    ? "verification is switched off on this call"
                    : null;
            if (reason == null)
                continue;

            context.Report($"{reason}, so anything the caller sends is believed — including a token "
                           + "the caller wrote. Verify the signature against the key that issued it.",
                call.Range.StartLine);
        }
    }

    private static bool Disabled(IRuleContext context, SyntaxNode call)
    {
        var verify = NamedArgument(call, "verify");
        if (verify is { Kind: NodeKind.BooleanLiteral, Text: "False" })
            return true;
        var options = NamedArgument(call, "options");
        if (options == null)
            return false;
        var line = SourceLine(context, options.Range.StartLine).Replace(" ", string.Empty);
        return line.Contains("\"verify_signature\":False", StringComparison.Ordinal)
               || line.Contains("'verify_signature':False", StringComparison.Ordinal);
    }
}

public sealed class PythonPermissiveCorsRule : PythonMeasuredRuleBase
{
    public override string Key => "QG-PY-SEC-0088";
    public override string Name => "Cross-origin access should name the origins it allows";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!line.Contains("Access-Control-Allow-Origin", StringComparison.OrdinalIgnoreCase)
                && !line.Contains("CORS_ORIGIN_ALLOW_ALL", StringComparison.Ordinal)
                && !line.Contains("CORS_ALLOW_ALL_ORIGINS", StringComparison.Ordinal))
                continue;
            var permissive = line.Contains("\"*\"", StringComparison.Ordinal)
                             || line.Contains("'*'", StringComparison.Ordinal)
                             || line.Contains("= True", StringComparison.Ordinal)
                             || line.Contains("=True", StringComparison.Ordinal);
            if (!permissive)
                continue;

            context.Report("Any site may read the responses of this service from a visitor's browser, "
                           + "with whatever the visitor is authorised to see. Name the origins that "
                           + "are allowed.", i + 1);
        }
    }
}

public sealed class PythonWeakPasswordHashRule : PythonMeasuredRuleBase
{
    private static readonly string[] Fast =
        ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "new"];

    public override string Key => "QG-PY-SEC-0089";
    public override string Name => "A password needs a slow hash";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "45min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!Fast.Contains(name) || !SyntaxQuery.Receiver(call).Contains("hashlib", StringComparison.Ordinal))
                continue;
            // the argument has to be the password: a digest of a file or a token is a different thing
            var argument = SyntaxQuery.ArgumentAt(call, 0);
            var mentioned = argument == null ? string.Empty : SyntaxQuery.DottedName(argument);
            if (!LanguageRuleSupport.IsCredentialName(mentioned))
                continue;

            context.Report($"'{name}' is built to be fast, which is the opposite of what a password "
                           + "needs: a graphics card tries billions of candidates a second against it. "
                           + "Use a function designed for passwords — argon2, bcrypt or scrypt — with "
                           + "a per-password salt.", call.Range.StartLine);
        }
    }
}

public sealed class PythonConstantOperandRule : PythonMeasuredRuleBase
{
    public override string Key => "QG-PY-BUG-0152";
    public override string Name => "A constant should not decide a condition";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var operation in context.Root.OfKind(NodeKind.Binary))
        {
            if (operation.Text is not ("and" or "or"))
                continue;
            var constant = operation.Children.FirstOrDefault(
                c => c.Kind == NodeKind.BooleanLiteral
                     || (c.Kind == NodeKind.Identifier && c.Text is "True" or "False"));
            if (constant == null)
                continue;

            var fixes = operation.Text == "and"
                ? constant.Text == "False" ? "always false" : "decided by the other operand alone"
                : constant.Text == "True" ? "always true" : "decided by the other operand alone";
            context.Report($"'{constant.Text}' makes this condition {fixes}, so one side of the branch "
                           + "behind it is code that never runs. A constant left in a condition is "
                           + "usually a debugging change that stayed.", operation.Range.StartLine);
        }
    }
}
