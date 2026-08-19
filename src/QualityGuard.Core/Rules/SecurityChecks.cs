using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Cryptography as it is actually misused. None of these is exotic: a salt typed into the source, an
/// initialisation vector of zeros, a cipher left in the mode that leaks the shape of the data, a key
/// short enough to be worth attacking, a signing secret committed with the code. They all compile,
/// they all run, and the failure is silent — the data looks encrypted right up to the moment somebody
/// reads it.
/// </summary>
public static class SecurityCheckSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PredictableSaltRuleCs(), new PredictableSaltRuleKotlin(),
        new PredictableCipherIvRuleCs(), new PredictableCipherIvRuleKotlin(),
        new WeakCipherModeRuleKotlin(),
        new WeakKeySizeRuleKotlin(), new WeakKeySizeRulePhp(),
        new JwtSecretRuleCs(), new JwtSecretRulePython()
    ];
}

public abstract class SecurityCheckBase : RuleBase
{
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    /// <summary>
    /// Whether the argument is a value written in the source rather than produced at run time: a
    /// literal, or a name this file gives a literal to. Anything the file cannot follow is left
    /// alone — a rule about secrets must not guess.
    /// </summary>
    protected static bool WrittenInTheSource(SyntaxNode? argument, IRuleContext context)
    {
        if (argument == null)
            return false;
        if (argument.Kind is NodeKind.StringLiteral or NodeKind.InterpolatedString)
            return true;
        // "literal".getBytes() and its relatives: the bytes are the literal
        if (argument.Kind == NodeKind.Invocation)
        {
            var receiver = argument.ChildAt(0)?.ChildAt(0);
            return receiver is { Kind: NodeKind.StringLiteral };
        }
        // 'new byte[] { 1, 2, 3 }' reaches the tree as a creation with an initialiser, and an array
        // of constants is exactly the value this rule is about
        if (IsConstantArray(argument))
            return true;
        if (argument.Kind != NodeKind.Identifier)
            return false;

        var name = argument.Text;
        // A parameter of the enclosing function carries whatever the caller passed, so the value is
        // not in this file at all. Looking the name up across the whole file found the local of
        // another method and reported the one call that was written correctly.
        var owner = SyntaxQuery.EnclosingFunction(argument);
        if (owner?.FirstChild(NodeKind.ParameterList)?.ChildrenOf(NodeKind.Parameter)
                .Any(pa => pa.Text == name) == true)
            return false;

        var scope = owner ?? context.Root;
        return scope.OfKind(NodeKind.VariableDeclaration, NodeKind.FieldDeclaration)
            .Concat(context.Root.OfKind(NodeKind.FieldDeclaration))
            .Where(d => d.Text == name)
            .Any(d => d.OfKind(NodeKind.StringLiteral).Any()
                      || d.DescendantsAndSelf().Any(IsConstantArray));
    }

    /// <summary>An array whose contents are written out, or one created empty — zeros either way.</summary>
    private static bool IsConstantArray(SyntaxNode node)
    {
        if (node.Kind is not (NodeKind.ArrayCreation or NodeKind.ObjectCreation or NodeKind.ListLiteral))
            return false;
        if (!node.Text.Contains("[]", StringComparison.Ordinal)
            && node.Kind != NodeKind.ArrayCreation && node.Kind != NodeKind.ListLiteral)
            return false;
        var initialiser = node.FirstChild(NodeKind.ObjectInitializer) ?? node;
        return initialiser.OfKind(NodeKind.NumberLiteral).Any()
               || node.OfKind(NodeKind.NumberLiteral).Any()
               || initialiser.Children.Count == 0;
    }

    protected static IReadOnlyList<SyntaxNode> ArgumentsOf(SyntaxNode call) => SyntaxQuery.Arguments(call);
}

public abstract class PredictableSaltRule : SecurityCheckBase
{
    /// <summary>The calls that derive a key from a password, and where the salt sits in each.</summary>
    private static readonly Dictionary<string, int> SaltPosition = new(StringComparer.Ordinal)
    {
        ["Rfc2898DeriveBytes"] = 1,
        ["PasswordDeriveBytes"] = 1,
        ["PBEKeySpec"] = 1,
        ["PBEParameterSpec"] = 0,
        ["pbkdf2_hmac"] = 2,
        ["generateSecret"] = 1,
        ["SecretKeyFactory"] = 1
    };

    public override string Name => "The salt of a password hash has to be unpredictable";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var call in context.Root.OfKind(NodeKind.Invocation, NodeKind.ObjectCreation))
        {
            var name = call.Kind == NodeKind.ObjectCreation
                ? Semantics.TypeResolver.Normalize(call.Text)
                : SyntaxQuery.InvokedName(call);
            if (!SaltPosition.TryGetValue(name, out var position))
                continue;

            var arguments = ArgumentsOf(call);
            if (arguments.Count <= position)
                continue;
            if (!WrittenInTheSource(arguments[position], context))
                continue;

            context.Report("The salt is written in the source, so every password in the system is "
                           + "hashed with the same one. That is what a rainbow table is built against: "
                           + "one precomputation breaks every account at once. Generate a salt per "
                           + "password from a cryptographic random source and store it with the hash.",
                call.Range.StartLine);
        }
    }
}

public sealed class PredictableSaltRuleCs : PredictableSaltRule
{
    public override string Key => "QG-CS-SEC-0067";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class PredictableSaltRuleKotlin : PredictableSaltRule
{
    public override string Key => "QG-KT-SEC-0037";
    public override string[] Languages => ["kt"];
}

public abstract class PredictableCipherIvRule : SecurityCheckBase
{
    /// <summary>Where the initialisation vector is passed, by the call that takes it.</summary>
    private static readonly Dictionary<string, int> VectorPosition = new(StringComparer.Ordinal)
    {
        ["IvParameterSpec"] = 0,
        ["GcmParameterSpec"] = 1,
        ["CreateEncryptor"] = 1,
        ["CreateDecryptor"] = 1
    };

    public override string Name => "An initialisation vector has to be unpredictable";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var call in context.Root.OfKind(NodeKind.Invocation, NodeKind.ObjectCreation))
        {
            var name = call.Kind == NodeKind.ObjectCreation
                ? Semantics.TypeResolver.Normalize(call.Text)
                : SyntaxQuery.InvokedName(call);
            if (!VectorPosition.TryGetValue(name, out var position))
                continue;

            var arguments = ArgumentsOf(call);
            if (arguments.Count <= position || !WrittenInTheSource(arguments[position], context))
                continue;

            context.Report("The initialisation vector is fixed in the source, so the same message "
                           + "always encrypts to the same bytes. An observer who sees two ciphertexts "
                           + "match knows the plaintexts match, and in block chaining a repeated vector "
                           + "leaks the beginning of every message. Draw a fresh vector at random and "
                           + "send it alongside the ciphertext.", call.Range.StartLine);
        }
    }
}

public sealed class PredictableCipherIvRuleCs : PredictableCipherIvRule
{
    public override string Key => "QG-CS-SEC-0071";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class PredictableCipherIvRuleKotlin : PredictableCipherIvRule
{
    public override string Key => "QG-KT-SEC-0038";
    public override string[] Languages => ["kt"];
}

public abstract class WeakCipherModeRule : SecurityCheckBase
{
    public override Severity Severity => Severity.Critical;
    public override string Name => "A cipher should be used with a mode that hides the shape of the data";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (token.Kind != Tokenization.TokenKind.String)
                continue;
            var value = token.Text;
            var slash = value.IndexOf('/');
            if (slash < 0)
                continue;

            var parts = value.Split('/');
            if (parts.Length < 2)
                continue;
            var mode = parts[1].Trim();
            var padding = parts.Length > 2 ? parts[2].Trim() : string.Empty;

            // 'AES/ECB/...' encrypts each block on its own, so identical blocks stay identical and
            // the picture is still visible through the ciphertext
            var electronicCodebook = mode.Equals("ECB", StringComparison.OrdinalIgnoreCase);
            // An authenticated mode carries its own integrity check, and 'NoPadding' is how it is
            // spelled: GCM and its relatives are the recommendation, not the defect.
            var authenticated = mode.StartsWith("GCM", StringComparison.OrdinalIgnoreCase)
                                || mode.StartsWith("CCM", StringComparison.OrdinalIgnoreCase)
                                || mode.StartsWith("Poly1305", StringComparison.OrdinalIgnoreCase);
            // 'RSA/.../NoPadding' and PKCS1 v1.5 are both broken in ways with names and papers
            var weakPadding = !authenticated
                              && (padding.Equals("NoPadding", StringComparison.OrdinalIgnoreCase)
                                  || padding.StartsWith("PKCS1Padding", StringComparison.OrdinalIgnoreCase));
            if (!electronicCodebook && !weakPadding)
                continue;

            context.Report($"'{value}' asks for a transformation that does not hide what it encrypts: "
                           + (electronicCodebook
                               ? "every identical block produces identical output, so the structure of "
                                 + "the data survives encryption."
                               : "the padding chosen here is one attackers have working techniques "
                                 + "against.")
                           + " Use an authenticated mode — GCM, or CBC with a separate MAC.",
                token.Line);
        }
    }
}

public sealed class WeakCipherModeRuleKotlin : WeakCipherModeRule
{
    public override string Key => "QG-KT-SEC-0043";
    public override string[] Languages => ["kt"];
}

public abstract class WeakKeySizeRule : SecurityCheckBase
{
    /// <summary>The smallest key each family is still worth generating.</summary>
    private static readonly Dictionary<string, int> Minimum = new(StringComparer.OrdinalIgnoreCase)
    {
        ["RSA"] = 2048, ["DSA"] = 2048, ["DH"] = 2048, ["AES"] = 128, ["EC"] = 224
    };

    public override string Name => "A generated key should be long enough to be worth generating";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (name is not ("init" or "initialize" or "generate_private_key" or "generateKeyPair"
                or "setKeySize" or "openssl_pkey_new"))
                continue;

            var arguments = ArgumentsOf(call);
            var size = arguments.Select(a => a.Kind == NodeKind.NumberLiteral
                                             && int.TryParse(a.Text, out var n) ? n : 0)
                .FirstOrDefault(n => n > 0);
            if (size == 0)
                continue;

            // the family is named nearby: in the call itself, or in the factory that produced it
            var family = Minimum.Keys.FirstOrDefault(k => context.Tokens.Any(t =>
                t.Line >= call.Range.StartLine - 3 && t.Line <= call.Range.EndLine
                && t.Text.Contains(k, StringComparison.OrdinalIgnoreCase)));
            if (family == null || size >= Minimum[family])
                continue;

            context.Report($"A {size}-bit {family} key is below what is considered out of reach today, "
                           + $"and keys outlive the code that made them: use at least {Minimum[family]} "
                           + "bits so the data stays protected for as long as it matters.",
                call.Range.StartLine);
        }
    }
}

public sealed class WeakKeySizeRuleKotlin : WeakKeySizeRule
{
    public override string Key => "QG-KT-SEC-0039";
    public override string[] Languages => ["kt"];
}

public sealed class WeakKeySizeRulePhp : WeakKeySizeRule
{
    public override string Key => "QG-PP-SEC-0048";
    public override string[] Languages => ["php"];
}

public abstract class JwtSecretRule : SecurityCheckBase
{
    /// <summary>Calls that sign or verify a token, where the key is one of the arguments.</summary>
    private static readonly string[] TokenCalls =
        ["encode", "decode", "Sign", "SignedString", "CreateToken", "WriteToken", "sign", "verify"];

    public override string Name => "The key that signs a token should not be in the source";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;
        // the file has to be about tokens at all: a bare 'encode' is any encoding in the world
        if (!context.Tokens.Any(t => t.Text.Contains("jwt", StringComparison.OrdinalIgnoreCase)
                                     || t.Text.Contains("JsonWebToken", StringComparison.Ordinal)
                                     || t.Text.Contains("SymmetricSecurityKey", StringComparison.Ordinal)))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!TokenCalls.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;

            foreach (var argument in ArgumentsOf(call))
            {
                if (argument.Kind != NodeKind.StringLiteral || argument.Text.Length < 8)
                    continue;
                // an algorithm name or a claim is a short word, not a key
                if (!argument.Text.Any(char.IsDigit) && argument.Text.All(char.IsLetter))
                    continue;

                context.Report("The key that signs tokens is written in the source, so anyone with the "
                               + "repository can mint a token this system will accept — including one "
                               + "that says they are somebody else. Read it from configuration the "
                               + "deployment supplies, and rotate the one that has been committed.",
                    call.Range.StartLine);
                break;
            }
        }
    }
}

public sealed class JwtSecretRuleCs : JwtSecretRule
{
    public override string Key => "QG-CS-SEC-0082";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class JwtSecretRulePython : JwtSecretRule
{
    public override string Key => "QG-PY-SEC-0078";
    public override string[] Languages => ["py"];
}
