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
        new EmptyStringRepetitionRuleCs(),
        new EmptyStringRepetitionRuleJava(),
        new EmptyStringRepetitionRuleKotlin(),
        new EmptyStringRepetitionRuleJs(),
        new EmptyStringRepetitionRulePython(),
        new EmptyStringRepetitionRulePhp(),
        new EmptyStringRepetitionRuleGo(),
        new EmptyStringRepetitionRuleDart(),
        new EmptyStringRepetitionRuleRuby(),
        new EmptyStringRepetitionRuleSwift(),
        new EmptyStringRepetitionRuleCss(),
        new EmptyStringRepetitionRuleHtml(),
        new EmptyStringRepetitionRuleXml(),
        new EmptyStringRepetitionRuleTerraform(),
        new EmptyStringRepetitionRuleDockerfile(),
        new EmptyStringRepetitionRuleKubernetes(),
        new EmptyStringRepetitionRuleCloudFormation(),
        new EmptyStringRepetitionRuleJson(),
        new ImpossibleBoundaryRuleCs(),
        new ImpossibleBoundaryRuleJava(),
        new ImpossibleBoundaryRuleKotlin(),
        new ImpossibleBoundaryRuleJs(),
        new ImpossibleBoundaryRulePython(),
        new ImpossibleBoundaryRulePhp(),
        new ImpossibleBoundaryRuleGo(),
        new ImpossibleBoundaryRuleDart(),
        new ImpossibleBoundaryRuleRuby(),
        new ImpossibleBoundaryRuleSwift(),
        new ImpossibleBoundaryRuleCss(),
        new ImpossibleBoundaryRuleHtml(),
        new ImpossibleBoundaryRuleXml(),
        new ImpossibleBoundaryRuleTerraform(),
        new ImpossibleBoundaryRuleDockerfile(),
        new ImpossibleBoundaryRuleKubernetes(),
        new ImpossibleBoundaryRuleCloudFormation(),
        new ImpossibleBoundaryRuleJson(),
        new ReluctantQuantifierRuleCs(),
        new ReluctantQuantifierRuleRuby(),
        new ReluctantQuantifierRuleSwift(),
        new ReluctantQuantifierRuleCss(),
        new ReluctantQuantifierRuleHtml(),
        new ReluctantQuantifierRuleXml(),
        new ReluctantQuantifierRuleTerraform(),
        new ReluctantQuantifierRuleDockerfile(),
        new ReluctantQuantifierRuleKubernetes(),
        new ReluctantQuantifierRuleCloudFormation(),
        new ReluctantQuantifierRuleJson(),
        new ReluctantQuantifierRuleJava(),
        new ReluctantQuantifierRuleKotlin(),
        new ReluctantQuantifierRuleJs(),
        new ReluctantQuantifierRulePython(),
        new ReluctantQuantifierRulePhp(),
        new ReluctantQuantifierRuleGo(),
        new ReluctantQuantifierRuleDart()
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

public abstract class EmptyStringRepetitionRule : RegexStructureRuleBase
{
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

public sealed class EmptyStringRepetitionRuleCs : EmptyStringRepetitionRule
{
    public override string Key => "QG-CS-BUG-0188";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class EmptyStringRepetitionRuleJava : EmptyStringRepetitionRule
{
    public override string Key => "QG-JV-BUG-0242";
    public override string[] Languages => ["java"];
}

public sealed class EmptyStringRepetitionRuleKotlin : EmptyStringRepetitionRule
{
    public override string Key => "QG-KT-BUG-0069";
    public override string[] Languages => ["kt"];
}

public sealed class EmptyStringRepetitionRuleJs : EmptyStringRepetitionRule
{
    public override string Key => "QG-JS-BUG-0186";
    public override string[] Languages => ["js", "ts"];
}

public sealed class EmptyStringRepetitionRulePython : EmptyStringRepetitionRule
{
    public override string Key => "QG-PY-BUG-0192";
    public override string[] Languages => ["py"];
}

public sealed class EmptyStringRepetitionRulePhp : EmptyStringRepetitionRule
{
    public override string Key => "QG-PP-BUG-0089";
    public override string[] Languages => ["php"];
}

public sealed class EmptyStringRepetitionRuleGo : EmptyStringRepetitionRule
{
    public override string Key => "QG-GO-BUG-0045";
    public override string[] Languages => ["go"];
}

public sealed class EmptyStringRepetitionRuleDart : EmptyStringRepetitionRule
{
    public override string Key => "QG-DART-BUG-0043";
    public override string[] Languages => ["dart"];
}

public sealed class EmptyStringRepetitionRuleRuby : EmptyStringRepetitionRule
{
    public override string Key => "QG-RB-BUG-0023";
    public override string[] Languages => ["rb"];
}

public sealed class EmptyStringRepetitionRuleSwift : EmptyStringRepetitionRule
{
    public override string Key => "QG-SW-BUG-0027";
    public override string[] Languages => ["swift"];
}

public sealed class EmptyStringRepetitionRuleCss : EmptyStringRepetitionRule
{
    public override string Key => "QG-CSS-BUG-0052";
    public override string[] Languages => ["css"];
}

public sealed class EmptyStringRepetitionRuleHtml : EmptyStringRepetitionRule
{
    public override string Key => "QG-HTML-BUG-0052";
    public override string[] Languages => ["html"];
}

public sealed class EmptyStringRepetitionRuleXml : EmptyStringRepetitionRule
{
    public override string Key => "QG-XML-BUG-0027";
    public override string[] Languages => ["xml"];
}

public sealed class EmptyStringRepetitionRuleTerraform : EmptyStringRepetitionRule
{
    public override string Key => "QG-TF-BUG-0022";
    public override string[] Languages => ["tf"];
}

public sealed class EmptyStringRepetitionRuleDockerfile : EmptyStringRepetitionRule
{
    public override string Key => "QG-DK-BUG-0029";
    public override string[] Languages => ["dk"];
}

public sealed class EmptyStringRepetitionRuleKubernetes : EmptyStringRepetitionRule
{
    public override string Key => "QG-K8-BUG-0022";
    public override string[] Languages => ["k8"];
}

public sealed class EmptyStringRepetitionRuleCloudFormation : EmptyStringRepetitionRule
{
    public override string Key => "QG-CF-BUG-0022";
    public override string[] Languages => ["cf"];
}

public sealed class EmptyStringRepetitionRuleJson : EmptyStringRepetitionRule
{
    public override string Key => "QG-JSON-BUG-0023";
    public override string[] Languages => ["json"];
}

public abstract class ImpossibleBoundaryRule : RegexStructureRuleBase
{
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

public sealed class ImpossibleBoundaryRuleCs : ImpossibleBoundaryRule
{
    public override string Key => "QG-CS-BUG-0189";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class ImpossibleBoundaryRuleJava : ImpossibleBoundaryRule
{
    public override string Key => "QG-JV-BUG-0243";
    public override string[] Languages => ["java"];
}

public sealed class ImpossibleBoundaryRuleKotlin : ImpossibleBoundaryRule
{
    public override string Key => "QG-KT-BUG-0070";
    public override string[] Languages => ["kt"];
}

public sealed class ImpossibleBoundaryRuleJs : ImpossibleBoundaryRule
{
    public override string Key => "QG-JS-BUG-0187";
    public override string[] Languages => ["js", "ts"];
}

public sealed class ImpossibleBoundaryRulePython : ImpossibleBoundaryRule
{
    public override string Key => "QG-PY-BUG-0193";
    public override string[] Languages => ["py"];
}

public sealed class ImpossibleBoundaryRulePhp : ImpossibleBoundaryRule
{
    public override string Key => "QG-PP-BUG-0090";
    public override string[] Languages => ["php"];
}

public sealed class ImpossibleBoundaryRuleGo : ImpossibleBoundaryRule
{
    public override string Key => "QG-GO-BUG-0046";
    public override string[] Languages => ["go"];
}

public sealed class ImpossibleBoundaryRuleDart : ImpossibleBoundaryRule
{
    public override string Key => "QG-DART-BUG-0044";
    public override string[] Languages => ["dart"];
}

public sealed class ImpossibleBoundaryRuleRuby : ImpossibleBoundaryRule
{
    public override string Key => "QG-RB-BUG-0024";
    public override string[] Languages => ["rb"];
}

public sealed class ImpossibleBoundaryRuleSwift : ImpossibleBoundaryRule
{
    public override string Key => "QG-SW-BUG-0028";
    public override string[] Languages => ["swift"];
}

public sealed class ImpossibleBoundaryRuleCss : ImpossibleBoundaryRule
{
    public override string Key => "QG-CSS-BUG-0053";
    public override string[] Languages => ["css"];
}

public sealed class ImpossibleBoundaryRuleHtml : ImpossibleBoundaryRule
{
    public override string Key => "QG-HTML-BUG-0053";
    public override string[] Languages => ["html"];
}

public sealed class ImpossibleBoundaryRuleXml : ImpossibleBoundaryRule
{
    public override string Key => "QG-XML-BUG-0028";
    public override string[] Languages => ["xml"];
}

public sealed class ImpossibleBoundaryRuleTerraform : ImpossibleBoundaryRule
{
    public override string Key => "QG-TF-BUG-0023";
    public override string[] Languages => ["tf"];
}

public sealed class ImpossibleBoundaryRuleDockerfile : ImpossibleBoundaryRule
{
    public override string Key => "QG-DK-BUG-0030";
    public override string[] Languages => ["dk"];
}

public sealed class ImpossibleBoundaryRuleKubernetes : ImpossibleBoundaryRule
{
    public override string Key => "QG-K8-BUG-0023";
    public override string[] Languages => ["k8"];
}

public sealed class ImpossibleBoundaryRuleCloudFormation : ImpossibleBoundaryRule
{
    public override string Key => "QG-CF-BUG-0023";
    public override string[] Languages => ["cf"];
}

public sealed class ImpossibleBoundaryRuleJson : ImpossibleBoundaryRule
{
    public override string Key => "QG-JSON-BUG-0024";
    public override string[] Languages => ["json"];
}

public abstract class ReluctantQuantifierRule : RegexStructureRuleBase
{
    /// <summary>Atoms that match nearly anything, so a lazy repetition of them scans one step at a time.</summary>
    private static readonly string[] Wide = [".", @"\S", @"\D", @"\W", @"\w", @"\d", @"\s"];
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

public sealed class ReluctantQuantifierRuleCs : ReluctantQuantifierRule
{
    public override string Key => "QG-CS-SML-0545";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class ReluctantQuantifierRuleJava : ReluctantQuantifierRule
{
    public override string Key => "QG-JV-SML-0506";
    public override string[] Languages => ["java"];
}

public sealed class ReluctantQuantifierRuleKotlin : ReluctantQuantifierRule
{
    public override string Key => "QG-KT-SML-0128";
    public override string[] Languages => ["kt"];
}

public sealed class ReluctantQuantifierRuleJs : ReluctantQuantifierRule
{
    public override string Key => "QG-JS-SML-0422";
    public override string[] Languages => ["js", "ts"];
}

public sealed class ReluctantQuantifierRulePython : ReluctantQuantifierRule
{
    public override string Key => "QG-PY-SML-0301";
    public override string[] Languages => ["py"];
}

public sealed class ReluctantQuantifierRulePhp : ReluctantQuantifierRule
{
    public override string Key => "QG-PP-SML-0166";
    public override string[] Languages => ["php"];
}

public sealed class ReluctantQuantifierRuleGo : ReluctantQuantifierRule
{
    public override string Key => "QG-GO-SML-0080";
    public override string[] Languages => ["go"];
}

public sealed class ReluctantQuantifierRuleDart : ReluctantQuantifierRule
{
    public override string Key => "QG-DART-SML-0045";
    public override string[] Languages => ["dart"];
}

public sealed class ReluctantQuantifierRuleRuby : ReluctantQuantifierRule
{
    public override string Key => "QG-RB-SML-0031";
    public override string[] Languages => ["rb"];
}

public sealed class ReluctantQuantifierRuleSwift : ReluctantQuantifierRule
{
    public override string Key => "QG-SW-SML-0015";
    public override string[] Languages => ["swift"];
}

public sealed class ReluctantQuantifierRuleCss : ReluctantQuantifierRule
{
    public override string Key => "QG-CSS-SML-0036";
    public override string[] Languages => ["css"];
}

public sealed class ReluctantQuantifierRuleHtml : ReluctantQuantifierRule
{
    public override string Key => "QG-HTML-SML-0108";
    public override string[] Languages => ["html"];
}

public sealed class ReluctantQuantifierRuleXml : ReluctantQuantifierRule
{
    public override string Key => "QG-XML-SML-0023";
    public override string[] Languages => ["xml"];
}

public sealed class ReluctantQuantifierRuleTerraform : ReluctantQuantifierRule
{
    public override string Key => "QG-TF-SML-0015";
    public override string[] Languages => ["tf"];
}

public sealed class ReluctantQuantifierRuleDockerfile : ReluctantQuantifierRule
{
    public override string Key => "QG-DK-SML-0029";
    public override string[] Languages => ["dk"];
}

public sealed class ReluctantQuantifierRuleKubernetes : ReluctantQuantifierRule
{
    public override string Key => "QG-K8-SML-0023";
    public override string[] Languages => ["k8"];
}

public sealed class ReluctantQuantifierRuleCloudFormation : ReluctantQuantifierRule
{
    public override string Key => "QG-CF-SML-0016";
    public override string[] Languages => ["cf"];
}

public sealed class ReluctantQuantifierRuleJson : ReluctantQuantifierRule
{
    public override string Key => "QG-JSON-SML-0011";
    public override string[] Languages => ["json"];
}
