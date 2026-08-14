using QualityGuard.Core.Models;
using QualityGuard.Core.Rules.Catalog;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Shared metadata plumbing for rules written in code. Documentation comes from the YAML catalog when
/// an entry with the same key exists, so a rule never has to hardcode its own prose.
/// </summary>
public abstract class RuleBase : IRule
{
    public abstract string Key { get; }
    public abstract string Name { get; }
    public abstract Severity Severity { get; }
    public abstract IssueKind Kind { get; }
    public abstract string RemediationEffort { get; }
    public abstract string[] Languages { get; }
    public abstract void Execute(IRuleContext context);

    /// <summary>Category segment of the key: SEC, BUG, SML, PRF or CNV.</summary>
    public string Category
    {
        get
        {
            var parts = Key.Split('-');
            return parts.Length >= 3 ? parts[2] : "SML";
        }
    }

    public virtual RuleDescription Description => RuleDocs.For(Key, Name, Kind, Category);

    public virtual string[] Tags => RuleDocs.TagsFor(Key, []);

    public virtual int[] Cwe => RuleDocs.CweFor(Key, []);

    public virtual string[] Owasp => RuleDocs.OwaspFor(Key, []);
}

public abstract class PatternRuleBase : RuleBase;

public static class RuleMatchers
{
    public static bool IsIdentifier(Token token) => token.Kind == TokenKind.Identifier;

    public static bool IsString(Token token) => token.Kind == TokenKind.String;

    public static bool IsSymbol(Token token, string symbol) => token.Kind == TokenKind.Symbol && token.Text == symbol;

    public static bool IsName(Token token, string name, bool caseInsensitive = false)
        => IsIdentifier(token) && (caseInsensitive
            ? string.Equals(token.Text, name, StringComparison.OrdinalIgnoreCase)
            : token.Text == name);

    public static bool NextNonParenIsString(IReadOnlyList<Token> tokens, int index)
    {
        for (var j = index + 1; j < tokens.Count; j++)
        {
            var t = tokens[j];
            if (t.Text == "(")
                continue;
            if (t.Text is ";" or "," or "=" or "{" or ")" or "]")
                return false;
            return IsString(t);
        }
        return false;
    }

    public static IEnumerable<Token> Names(IReadOnlyList<Token> tokens, string[] names,
        bool caseInsensitive = false)
    {
        foreach (var token in tokens)
        {
            if (IsIdentifier(token) && Contains(token.Text, names, caseInsensitive))
                yield return token;
        }
    }

    public static bool Contains(string text, string[] names, bool caseInsensitive = false)
    {
        for (var i = 0; i < names.Length; i++)
        {
            if (caseInsensitive
                ? string.Equals(text, names[i], StringComparison.OrdinalIgnoreCase)
                : text == names[i])
                return true;
        }
        return false;
    }

    public static bool HasNameAny(IReadOnlyList<Token> tokens, string[] names, bool caseInsensitive = false)
        => Names(tokens, names, caseInsensitive).Any();

    public static bool HasStringContaining(IReadOnlyList<Token> tokens, params string[] fragments)
    {
        foreach (var token in tokens)
        {
            if (!IsString(token))
                continue;
            for (var i = 0; i < fragments.Length; i++)
            {
                if (token.Text.Contains(fragments[i], StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    public static IEnumerable<Token> StringsContaining(IReadOnlyList<Token> tokens, string fragment,
        bool caseInsensitive = true)
    {
        foreach (var token in tokens)
        {
            if (IsString(token) && token.Text.Contains(fragment,
                    caseInsensitive ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                yield return token;
        }
    }

    public static bool LineContains(string line, string fragment, bool caseInsensitive = true)
        => line.Contains(fragment, caseInsensitive ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    public static bool LineEndsWith(string line, string suffix)
        => line.TrimEnd().EndsWith(suffix, StringComparison.Ordinal);

    public static string[] SplitWords(string line)
        => line.Split([' ', '\t', '(', ')', '=', ',', ';'], StringSplitOptions.RemoveEmptyEntries);
}