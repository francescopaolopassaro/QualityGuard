using System.Text.RegularExpressions;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Decides whether something shaped like a credential is worth reporting.
///
/// A pattern that recognises the shape of a key recognises the documentation's key just as well.
/// `AKIAIOSFODNN7EXAMPLE` is the identifier every cloud manual uses in its examples; it appears in
/// tutorials, in fixtures and in the tests that check a redactor removes it. So does a placeholder
/// waiting to be filled in — an environment lookup, a template hole, a row of the same character.
/// Reporting those teaches the reader that the rule cries wolf, and the real key that follows is
/// skipped with the rest.
///
/// Each entry below is one shape that is not a secret, whatever it looks like.
/// </summary>
public static partial class SecretFilters
{
    /// <summary>Too short to be a key at all.</summary>
    [GeneratedRegex(@"^.{1,5}$")]
    private static partial Regex TooShort();

    /// <summary>The words that appear in a credential nobody ever used.</summary>
    [GeneratedRegex(@"sample|example|placeholder|replace|change|foo|bar|test|fake|abcd|dummy"
                    + @"|redacted|cafebabe|deadbeef|whatever|123456|default|qwerty|obfuscated"
                    + @"|p[@a]ssw[o0]rd|hunter2|letmein|abc123|undefined|yourkey|your_",
        RegexOptions.IgnoreCase)]
    private static partial Regex SoundsFake();

    /// <summary>A value read at run time rather than written down: this is the fix, not the defect.</summary>
    [GeneratedRegex(@"\b(get)?env(iron)?\b|process\.env\.|config[\(\[]|Read-Host|System\.getenv"
                    + @"|os\.getenv|ENV\[|getenv\(",
        RegexOptions.IgnoreCase)]
    private static partial Regex ReadAtRunTime();

    /// <summary>A hole in a template, in any of the syntaxes that spell one.</summary>
    [GeneratedRegex(@"\$\{[^}]+\}|\$\$?\w+\${0,2}\b|\{\{|^\s*\{[^}]+\}\s*$|^\s*<[^>]+>\s*$"
                    + @"|^\s*\[[^\]]+\]\s*$|%\([^)]+\)s|%[A-Z_]+%|\$\(|`[^`]+`|\(\(.*\)\)")]
    private static partial Regex Placeholder();

    /// <summary>Already protected, or deliberately shortened for display.</summary>
    [GeneratedRegex(@"^encrypted:|^\{cipher\}|^arn:aws:secretsmanager:|^op:/|\.\.\.|^(?i)enc\[")]
    private static partial Regex NotInTheClear();

    /// <summary>The same character over and over: somebody held down a key.</summary>
    [GeneratedRegex(@"(?<char>[\w\*\.])\k<char>{3}|^(?<repeat>.)\k<repeat>*$")]
    private static partial Regex OneCharacterRepeated();

    /// <summary>Letters only, or digits only — a key is neither.</summary>
    [GeneratedRegex(@"^[a-zA-Z\-_]+$|^\d+$")]
    private static partial Regex NoMixture();

    /// <summary>Whether this text should be left alone even though it has the shape of a credential.</summary>
    public static bool LooksLikeAPlaceholder(string text)
        => string.IsNullOrWhiteSpace(text)
           || TooShort().IsMatch(text)
           || SoundsFake().IsMatch(text)
           || ReadAtRunTime().IsMatch(text)
           || Placeholder().IsMatch(text)
           || NotInTheClear().IsMatch(text)
           || OneCharacterRepeated().IsMatch(text)
           || NoMixture().IsMatch(text);

    /// <summary>
    /// Whether the file is one where a credential-shaped string is expected: a test that checks a
    /// redactor, a fixture, a sample in the documentation.
    /// </summary>
    public static bool IsIllustrative(string path)
    {
        var normalised = path.Replace('\\', '/');
        return normalised.Contains("/test", StringComparison.OrdinalIgnoreCase)
               || normalised.Contains("/fixture", StringComparison.OrdinalIgnoreCase)
               || normalised.Contains("/example", StringComparison.OrdinalIgnoreCase)
               || normalised.Contains("/sample", StringComparison.OrdinalIgnoreCase)
               || normalised.Contains("/docs/", StringComparison.OrdinalIgnoreCase)
               || normalised.EndsWith(".md", StringComparison.OrdinalIgnoreCase);
    }
}
