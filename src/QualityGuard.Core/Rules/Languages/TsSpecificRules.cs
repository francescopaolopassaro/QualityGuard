using System.Text.RegularExpressions;
using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class TsSpecificRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new TsWeakHashingRule(),
        new TsNonNullableAssertionRule(),
        new TsRedundantTypeCastRule(),
        new TsOptionalChainingAssignmentRule(),
    ];
}

public abstract class TsSpecificRuleBase : RuleBase
{
    public override string[] Languages => ["ts"];
    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;
}

/// <summary>
/// S4790: Hashing data is security-sensitive — MD5 and SHA-1 are broken.
/// Detect usage of createHash('md5'), createHash('sha1'), createHash('MD5'), etc.
/// </summary>
public sealed class TsWeakHashingRule : TsSpecificRuleBase
{
    public override string Key => "QG-TS-SEC-0008";
    public override string Name => "Weak hashing algorithm";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use SHA-256 or stronger hashing algorithms.";

    private static readonly string[] WeakAlgorithms =
        ["md5", "sha1", "MD5", "SHA1", "sha-1", "SHA-1"];

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var invocation in SyntaxQuery.Invocations(context.Root))
        {
            var dotted = SyntaxQuery.InvokedDottedName(invocation);
            // crypto.createHash('md5'), createHash("sha1"), etc.
            if (!dotted.Contains("createHash", StringComparison.Ordinal))
                continue;

            var args = SyntaxQuery.Arguments(invocation);
            if (args.Count < 1)
                continue;
            var argText = args[0].Text.Trim().Trim('"', '\'');
            if (WeakAlgorithms.Contains(argText))
            {
                context.Report(
                    $"'{argText}' is a weak hashing algorithm. Use SHA-256 or stronger.",
                    invocation.Range.StartLine);
            }
        }
    }
}

/// <summary>
/// Non-null assertion (!) after an expression bypasses TypeScript's null checks.
/// Prefer nullish coalescing (??) or optional chaining (?.) for safety.
/// </summary>
public sealed class TsNonNullableAssertionRule : TsSpecificRuleBase
{
    public override string Key => "QG-TS-SML-0009";
    public override string Name => "Non-null assertion bypasses null checks";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";
    public override string FixAdvice => "Use optional chaining (?.) or nullish coalescing (??) instead.";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            // ! is used as non-null assertion when preceded by an identifier and followed by . or [ or (
            if (tokens[i].Kind != TokenKind.Symbol || tokens[i].Text != "!")
                continue;
            if (i == 0)
                continue;
            var prev = tokens[i - 1];
            var next = tokens[i + 1];
            // Non-null assertion: identifier!) or identifier![ or identifier!.
            if (prev.Kind == TokenKind.Identifier
                && next.Kind == TokenKind.Symbol
                && next.Text is "." or "[" or "(")
            {
                context.Report(
                    "Non-null assertion (!) bypasses TypeScript's null-safety. "
                    + "Use optional chaining (?.) or nullish coalescing (??) instead.",
                    tokens[i].Line);
            }
        }
    }
}

/// <summary>
/// Redundant type cast: casting a value to its own type using 'as' is unnecessary.
/// </summary>
public sealed class TsRedundantTypeCastRule : TsSpecificRuleBase
{
    public override string Key => "QG-TS-SML-0010";
    public override string Name => "Redundant type assertion";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "2min";
    public override string FixAdvice => "Remove the unnecessary type assertion.";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        // Look for patterns like: value as Type where value's text is "undefined as X" or "null as X"
        // or literal as Type where the type matches the literal
        foreach (var invocation in SyntaxQuery.Invocations(context.Root))
        {
            // Actually, we need to look at 'as' expressions at the AST level
            // Since the parser doesn't have a dedicated AsExpression node,
            // we use token scanning: look for 'as' keyword between an expression and a type
        }

        // Fallback: token-based scan for `x as typeof x` which is always redundant
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 3; i++)
        {
            if (tokens[i].Text != "as" || tokens[i].Kind != TokenKind.Keyword)
                continue;
            // Check for: identifier as typeof identifier (same name)
            if (i >= 1 && i + 2 < tokens.Count
                && tokens[i - 1].Kind == TokenKind.Identifier
                && tokens[i + 1].Text == "typeof"
                && tokens[i + 2].Kind == TokenKind.Identifier
                && tokens[i - 1].Text == tokens[i + 2].Text)
            {
                context.Report(
                    $"'{tokens[i - 1].Text} as typeof {tokens[i + 2].Text}' is redundant. "
                    + "Remove the assertion.",
                    tokens[i].Line);
            }
        }
    }
}

/// <summary>
/// Assignment inside optional chaining (e.g., obj?.prop = value) is not valid TypeScript
/// and indicates a misunderstanding of the operator.
/// </summary>
public sealed class TsOptionalChainingAssignmentRule : TsSpecificRuleBase
{
    public override string Key => "QG-TS-BUG-0016";
    public override string Name => "Optional chaining on assignment target";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "5min";
    public override string FixAdvice => "Use a regular property access or null check instead.";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            // Pattern: xxx?.yyy = or xxx?.yyy[z] =
            if (Regex.IsMatch(line, @"\w+\?\.\w+\s*(\[.*\])?\s*="))
            {
                context.Report(
                    "Optional chaining (?.) cannot be used on the left side of an assignment. "
                    + "Use a null check or conditional assignment instead.",
                    i + 1);
            }
        }
    }
}
