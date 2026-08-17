using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Regular-expression rules that need the shape of the pattern rather than a list of its parts: a
/// group that can match nothing, an anchor in a place where it can never hold, a lazy quantifier that
/// only slows the engine down. They read the pattern with a small recursive scanner, and every one of
/// them stays silent on a construct it does not recognise.
/// </summary>
public static class RegexStructureRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new EmptyStringRepetitionRule(),
        new ImpossibleBoundaryRule(),
        new ReluctantQuantifierRule()
    ];
}

/// <summary>One element of a pattern: what it matches, and how many times.</summary>
public readonly record struct RegexAtom(string Text, string Body, char Kind, string Quantifier)
{
    /// <summary>'g' group, 'c' character class, 'e' escape, 'a' zero-width assertion, 'l' literal.</summary>
    public bool IsOptional => Quantifier.StartsWith('*') || Quantifier.StartsWith('?')
                              || Quantifier.StartsWith("{0,") || Quantifier == "{0}";

    public bool Repeats => Quantifier.Length > 0 && Quantifier[0] is '*' or '+' or '?' or '{';
}

/// <summary>
/// Splits a pattern into its top-level atoms and alternatives. It is a scanner, not a grammar: what
/// it cannot read it returns as a literal, so a rule built on it can only be wrong by staying quiet.
/// </summary>
public static class RegexShape
{
    private static readonly string[] ZeroWidthEscapes = ["b", "B", "A", "z", "Z", "G"];

    /// <summary>The top-level alternatives of a pattern, split on the bars that are not nested.</summary>
    public static List<string> Alternatives(string pattern)
    {
        var parts = new List<string>();
        var depth = 0;
        var start = 0;
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == (char)92)
            {
                i++;
                continue;
            }
            if (c == '[')
            {
                i = SkipClass(pattern, i);
                continue;
            }
            if (c == '(')
                depth++;
            else if (c == ')')
                depth--;
            else if (c == '|' && depth == 0)
            {
                parts.Add(pattern[start..i]);
                start = i + 1;
            }
        }
        parts.Add(pattern[start..]);
        return parts;
    }

    /// <summary>The atoms of one alternative, in order.</summary>
    public static List<RegexAtom> Atoms(string alternative)
    {
        var atoms = new List<RegexAtom>();
        for (var i = 0; i < alternative.Length;)
        {
            var start = i;
            char kind;
            var body = string.Empty;

            var c = alternative[i];
            if (c == '(')
            {
                var end = MatchingParen(alternative, i);
                if (end < 0)
                    return atoms; // unbalanced: stop rather than guess
                var inside = alternative[(i + 1)..end];
                kind = LooksLikeAssertion(inside) ? 'a' : 'g';
                body = StripGroupPrefix(inside);
                i = end + 1;
            }
            else if (c == '[')
            {
                var end = SkipClass(alternative, i);
                kind = 'c';
                i = end + 1;
            }
            else if (c == (char)92 && i + 1 < alternative.Length)
            {
                var next = alternative[i + 1].ToString();
                kind = ZeroWidthEscapes.Contains(next, StringComparer.Ordinal) ? 'a' : 'e';
                i += 2;
                if (i < alternative.Length && alternative[i] == '{')
                    i = alternative.IndexOf('}', i) is var brace && brace > 0 ? brace + 1 : i;
            }
            else if (c is '^' or '$')
            {
                kind = 'a';
                i++;
            }
            else
            {
                kind = 'l';
                i++;
            }

            var quantifier = ReadQuantifier(alternative, ref i);
            atoms.Add(new RegexAtom(alternative[start..i], body, kind, quantifier));
        }
        return atoms;
    }

    /// <summary>Whether a group, read as a whole, can match without consuming a character.</summary>
    public static bool MatchesEmpty(string body)
    {
        foreach (var alternative in Alternatives(body))
        {
            var atoms = Atoms(alternative);
            if (atoms.All(CanSkip))
                return true;
        }
        return false;
    }

    private static bool CanSkip(RegexAtom atom)
    {
        if (atom.Kind == 'a')
            return true;
        if (atom.IsOptional)
            return true;
        return atom.Kind == 'g' && MatchesEmpty(atom.Body);
    }

    /// <summary>The quantifier that follows an atom, with its lazy or possessive suffix.</summary>
    private static string ReadQuantifier(string text, ref int i)
    {
        if (i >= text.Length)
            return string.Empty;
        var start = i;
        if (text[i] is '*' or '+' or '?')
            i++;
        else if (text[i] == '{')
        {
            var end = text.IndexOf('}', i);
            if (end < 0)
                return string.Empty;
            i = end + 1;
        }
        else
        {
            return string.Empty;
        }
        if (i < text.Length && text[i] is '?' or '+')
            i++;
        return text[start..i];
    }

    /// <summary>Group syntax that asserts instead of matching: look-ahead, look-behind, bare flags.</summary>
    private static bool LooksLikeAssertion(string inside)
        => inside.StartsWith("?=", StringComparison.Ordinal)
           || inside.StartsWith("?!", StringComparison.Ordinal)
           || inside.StartsWith("?<=", StringComparison.Ordinal)
           || inside.StartsWith("?<!", StringComparison.Ordinal)
           || (inside.StartsWith('?') && !inside.Contains(':') && inside.All(
               c => c is '?' or '-' or 'i' or 'm' or 's' or 'x' or 'u' or 'U' or 'a' or 'l'));

    /// <summary>Removes '?:', '?i:' and the naming of a capture, leaving what the group matches.</summary>
    private static string StripGroupPrefix(string inside)
    {
        if (!inside.StartsWith('?'))
            return inside;
        var colon = inside.IndexOf(':');
        if (colon > 0)
            return inside[(colon + 1)..];
        if (inside.StartsWith("?<", StringComparison.Ordinal) || inside.StartsWith("?P<", StringComparison.Ordinal))
        {
            var close = inside.IndexOf('>');
            return close > 0 ? inside[(close + 1)..] : inside;
        }
        return string.Empty; // '(?i)' and friends match nothing at all
    }

    private static int MatchingParen(string text, int open)
    {
        var depth = 0;
        for (var i = open; i < text.Length; i++)
        {
            var c = text[i];
            if (c == (char)92)
            {
                i++;
                continue;
            }
            if (c == '[')
            {
                i = SkipClass(text, i);
                continue;
            }
            if (c == '(')
                depth++;
            else if (c == ')' && --depth == 0)
                return i;
        }
        return -1;
    }

    private static int SkipClass(string text, int open)
    {
        for (var i = open + 1; i < text.Length; i++)
        {
            if (text[i] == (char)92)
            {
                i++;
                continue;
            }
            if (text[i] == ']' && i > open + 1)
                return i;
        }
        return text.Length - 1;
    }
}

public abstract class RegexStructureRuleBase : RuleBase
{
    public override string[] Languages => [];
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "15min";

    /// <summary>
    /// Patterns whose meaning depends on a flag the scanner does not track are left alone: under
    /// multiline an anchor holds in places it otherwise could not, and under ungreedy the quantifiers
    /// mean the opposite of what they say.
    /// </summary>
    protected static bool DependsOnFlags(string pattern)
        => pattern.Contains("(?m", StringComparison.Ordinal)
           || pattern.Contains("(?U", StringComparison.Ordinal);
}

public sealed class EmptyStringRepetitionRule : RegexStructureRuleBase
{
    public override string Key => "QG-ALL-BUG-0039";
    public override string Name => "A repeated group should not match the empty string";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, pattern) in RegexLiterals.In(context))
        {
            foreach (var alternative in RegexShape.Alternatives(pattern))
            {
                var reported = false;
                foreach (var atom in RegexShape.Atoms(alternative))
                {
                    if (atom.Kind != 'g' || !atom.Repeats || !RegexShape.MatchesEmpty(atom.Body))
                        continue;

                    context.Report(node, $"'{atom.Text}' repeats a group that matches the empty string, "
                                         + "so the repetition can succeed without reading anything. The "
                                         + "quantifier adds nothing, and on some engines the match "
                                         + "loops instead of finishing.");
                    reported = true;
                    break;
                }
                if (reported)
                    break;
            }
        }
    }
}

public sealed class ImpossibleBoundaryRule : RegexStructureRuleBase
{
    public override string Key => "QG-ALL-BUG-0040";
    public override string Name => "An anchor should be in a position where it can hold";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, pattern) in RegexLiterals.In(context))
        {
            if (DependsOnFlags(pattern))
                continue;
            var offender = Impossible(pattern);
            if (offender == null)
                continue;

            context.Report(node, $"'{offender}' is placed where it can never hold: the pattern asks for "
                                 + "text on the far side of the start or the end of the input, so this "
                                 + "branch never matches anything at all.");
        }
    }

    /// <summary>The first anchor that has text on the side where the input has already ended.</summary>
    private static string? Impossible(string pattern)
    {
        foreach (var alternative in RegexShape.Alternatives(pattern))
        {
            var atoms = RegexShape.Atoms(alternative);
            for (var i = 0; i < atoms.Count; i++)
            {
                var text = atoms[i].Text;
                var consumesBefore = atoms.Take(i).Any(Consumes);
                var consumesAfter = atoms.Skip(i + 1).Any(Consumes);

                if (text is "^" or @"\A" && consumesBefore)
                    return text;
                // '$' also holds just before a trailing newline, so text that can be one is fine
                if (text is "$" or @"\z" or @"\Z" && consumesAfter
                    && !atoms.Skip(i + 1).Any(MayBeNewline))
                    return text;
                if (atoms[i].Kind == 'g' && Impossible(atoms[i].Body) is { } nested)
                    return nested;
            }
        }
        return null;
    }

    /// <summary>
    /// Whether an atom can stand for a newline, which is what makes text after a '$' possible.
    /// </summary>
    private static bool MayBeNewline(RegexAtom atom)
        => atom.Text.Contains('.') || atom.Text.Contains('n') || atom.Text.Contains('R')
           || atom.Text.Contains('s');

    /// <summary>Whether an atom has to read at least one character.</summary>
    private static bool Consumes(RegexAtom atom)
        => atom.Kind != 'a' && !atom.IsOptional
           && (atom.Kind != 'g' || !RegexShape.MatchesEmpty(atom.Body));
}

public sealed class ReluctantQuantifierRule : RegexStructureRuleBase
{
    /// <summary>Atoms that match nearly anything, so a lazy repetition of them scans one step at a time.</summary>
    private static readonly string[] Wide = [".", @"\S", @"\D", @"\W", @"\w", @"\d", @"\s"];

    public override string Key => "QG-ALL-SML-0052";
    public override string Name => "A lazy quantifier before a fixed terminator should be a negated class";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, pattern) in RegexLiterals.In(context))
        {
            if (DependsOnFlags(pattern))
                continue;

            foreach (var alternative in RegexShape.Alternatives(pattern))
            {
                var atoms = RegexShape.Atoms(alternative);
                for (var i = 0; i < atoms.Count - 1; i++)
                {
                    var atom = atoms[i];
                    if (!atom.Quantifier.EndsWith('?') || atom.Quantifier == "?")
                        continue;
                    // '{42}?' is a lazy suffix on a fixed count: it changes nothing and costs nothing
                    if (atom.Quantifier.StartsWith('{') && !atom.Quantifier.Contains(','))
                        continue;
                    // the terminator has to end the alternative, or a negated class would swallow
                    // the characters that come after it
                    if (i + 1 != atoms.Count - 1)
                        continue;
                    var head = atom.Text[..^atom.Quantifier.Length];
                    if (!Wide.Contains(head, StringComparer.Ordinal))
                        continue;
                    // the terminator has to be one fixed thing, or the negated class would be wrong
                    var next = atoms[i + 1];
                    if (next.Repeats || next.Kind is 'g' or 'a')
                        continue;

                    context.Report(node, $"'{atom.Text}' gives up a character at a time until "
                                         + $"'{next.Text}' turns up, which is the slowest way to reach "
                                         + "it and reads past it on backtracking. A class that excludes "
                                         + "the terminator says the same thing and matches in one pass.");
                    break;
                }
            }
        }
    }
}
