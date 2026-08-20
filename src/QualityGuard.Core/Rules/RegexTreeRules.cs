using System.Globalization;
using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Rules that need the pattern read as a tree: what an element can match, what follows it, how deeply
/// the pattern nests. They all go through <see cref="RegexSyntax"/>, which returns nothing for a
/// pattern it cannot read with certainty, so an unreadable pattern is never reported on.
/// </summary>
public static class RegexTreeRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new AnchoredAlternationRuleJava(),
        new AnchoredAlternationRuleKotlin(),
        new AnchoredAlternationRulePython(),
        new AnchoredAlternationRulePhp(),
        new GraphemeClusterInClassRuleJava(),
        new GraphemeClusterInClassRuleKotlin(),
        new GraphemeClusterInClassRuleJs(),
        new GraphemeClusterInClassRulePython(),
        new GraphemeClusterInClassRulePhp(),
        new PossessiveQuantifierStarvesRuleJava(),
        new PossessiveQuantifierStarvesRulePython(),
        new PossessiveQuantifierStarvesRulePhp(),
        new ContradictoryLookAheadRuleJava(),
        new ContradictoryLookAheadRulePython(),
        new ContradictoryLookAheadRulePhp(),
        new EmptyRegexGroupRuleJava(),
        new EmptyRegexGroupRuleJs(),
        new EmptyRegexGroupRulePython(),
        new EmptyRegexGroupRulePhp(),
        new VerboseRegexShorthandRuleJava(),
        new VerboseRegexShorthandRuleJs(),
        new VerboseRegexShorthandRulePython(),
        new VerboseRegexShorthandRulePhp(),
        new PointlessNonCapturingGroupRuleJava(),
        new PointlessNonCapturingGroupRulePython(),
        new PointlessNonCapturingGroupRulePhp(),
        new ControlEscapeOutOfRangeRuleJava(),
        new OctalEscapeInPatternRulePython(),
        new UnicodeCaseFoldingRuleJava(),
        new OverbuiltRegexRuleJava(),
        new OverbuiltRegexRuleKotlin(),
        new OverbuiltRegexRuleJs(),
        new OverbuiltRegexRulePython(),
        new OverbuiltRegexRulePhp(),
        new UndefinedGroupNameRuleJava(),
        new UndefinedGroupNameRuleJs(),
        new UndefinedGroupNameRulePython(),
        new LiteralPatternReplaceRuleJava(),
        new LiteralPatternReplaceRulePython(),
        new LiteralPatternReplaceRulePhp()
    ];
}

public abstract class RegexTreeRuleBase : RuleBase
{
    public override string[] Languages => [];
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    /// <summary>Every pattern literal in the file that could be read into a tree.</summary>
    protected static IEnumerable<(SyntaxNode Node, string Pattern, RegexNode Tree)> Patterns(IRuleContext context)
    {
        foreach (var literal in RegexLiterals.In(context))
        {
            var tree = RegexSyntax.Parse(literal.Pattern);
            if (tree != null)
                yield return (literal.Node, literal.Pattern, tree);
        }
    }

    /// <summary>
    /// The first element the node is bound to read. Unlike a plain walk to the leftmost leaf this
    /// gives up as soon as the path crosses something that may be skipped, because then the element
    /// found is not the one the next character has to satisfy.
    /// </summary>
    protected static RegexNode? MandatoryFirst(RegexNode node)
    {
        switch (node.Kind)
        {
            case RegexKind.Sequence:
                foreach (var child in node.Children)
                {
                    if (child.Kind == RegexKind.Anchor || RegexSyntax.MatchesEmpty(child))
                        continue; // a zero-width element does not decide the next character
                    return MandatoryFirst(child);
                }
                return null;
            case RegexKind.Group:
                return node.GroupKind is RegexGroupKind.Capturing or RegexGroupKind.NonCapturing
                           or RegexGroupKind.Named or RegexGroupKind.Atomic && node.Children.Count == 1
                    ? MandatoryFirst(node.Children[0])
                    : null;
            case RegexKind.Repetition:
                return node.Min == 0 ? null : MandatoryFirst(node.Children[0]);
            case RegexKind.Literal:
            case RegexKind.Escape:
            case RegexKind.CharacterClass:
                return node;
            default:
                return null;
        }
    }

    /// <summary>Every sequence in the pattern, the pattern itself included when it is one.</summary>
    protected static IEnumerable<IReadOnlyList<RegexNode>> Sequences(RegexNode tree)
    {
        foreach (var node in tree.SelfAndDescendants())
        {
            if (node.Kind == RegexKind.Sequence)
                yield return node.Children;
        }
    }
}

/// <summary>
/// An anchor binds tighter than a bar, so '^a|b|c$' anchors the first branch at the start, the last at
/// the end and leaves the middle one floating. Almost always the author meant all of them.
/// </summary>
public abstract class AnchoredAlternationRule : RegexTreeRuleBase
{
    public override string Name => "Alternatives should be grouped when the pattern is anchored";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, _, tree) in Patterns(context))
        {
            if (tree.Kind != RegexKind.Alternation || tree.Children.Count < 2)
                continue;

            var atStart = tree.Children.Count(StartsAnchored);
            var atEnd = tree.Children.Count(EndsAnchored);
            if ((atStart == 0 || atStart == tree.Children.Count)
                && (atEnd == 0 || atEnd == tree.Children.Count))
                continue;

            context.Report(node, "The anchor in this pattern binds to one alternative only, because an "
                                 + "anchor takes precedence over the bar. Wrap the alternatives in a "
                                 + "non-capturing group so the anchor applies to all of them.");
        }
    }

    private static bool StartsAnchored(RegexNode branch)
        => RegexSyntax.Elements(branch).FirstOrDefault() is { Kind: RegexKind.Anchor } anchor
           && anchor.Text is "^" or "\\A";

    private static bool EndsAnchored(RegexNode branch)
        => RegexSyntax.Elements(branch).LastOrDefault() is { Kind: RegexKind.Anchor } anchor
           && anchor.Text is "$" or "\\z" or "\\Z";
}

public sealed class AnchoredAlternationRuleJava : AnchoredAlternationRule
{
    public override string Key => "QG-JV-BUG-0123";
    public override string[] Languages => ["java"];
}

public sealed class AnchoredAlternationRuleKotlin : AnchoredAlternationRule
{
    public override string Key => "QG-KT-BUG-0025";
    public override string[] Languages => ["kt"];
}

public sealed class AnchoredAlternationRulePython : AnchoredAlternationRule
{
    public override string Key => "QG-PY-BUG-0059";
    public override string[] Languages => ["py"];
}

public sealed class AnchoredAlternationRulePhp : AnchoredAlternationRule
{
    public override string Key => "QG-PP-BUG-0026";
    public override string[] Languages => ["php"];
}

/// <summary>
/// A character class lists code points, not characters as a reader sees them. A letter written with a
/// separate combining mark therefore enters the class as two independent members, and the class starts
/// matching the bare letter and the bare accent instead of the accented letter.
/// </summary>
public abstract class GraphemeClusterInClassRule : RegexTreeRuleBase
{
    public override string Name => "A character class should not list a combined character";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, _, tree) in Patterns(context))
        {
            foreach (var characterClass in tree.SelfAndDescendants()
                         .Where(n => n.Kind == RegexKind.CharacterClass))
            {
                if (!characterClass.ClassItems.Any(HasCombiningMark))
                    continue;

                context.Report(node, $"'{characterClass.Text}' lists a character that is written with a "
                                     + "separate combining mark, so the class holds the base character "
                                     + "and the mark as two independent members. Write the combined "
                                     + "characters as alternatives instead.");
                break;
            }
        }
    }

    private static bool HasCombiningMark(string item)
        => item.Any(c => CharUnicodeInfo.GetUnicodeCategory(c)
            is UnicodeCategory.NonSpacingMark or UnicodeCategory.SpacingCombiningMark
            or UnicodeCategory.EnclosingMark);
}

public sealed class GraphemeClusterInClassRuleJava : GraphemeClusterInClassRule
{
    public override string Key => "QG-JV-BUG-0127";
    public override string[] Languages => ["java"];
}

public sealed class GraphemeClusterInClassRuleKotlin : GraphemeClusterInClassRule
{
    public override string Key => "QG-KT-BUG-0026";
    public override string[] Languages => ["kt"];
}

public sealed class GraphemeClusterInClassRuleJs : GraphemeClusterInClassRule
{
    public override string Key => "QG-JS-BUG-0064";
    public override string[] Languages => ["js", "ts"];
}

public sealed class GraphemeClusterInClassRulePython : GraphemeClusterInClassRule
{
    public override string Key => "QG-PY-BUG-0062";
    public override string[] Languages => ["py"];
}

public sealed class GraphemeClusterInClassRulePhp : GraphemeClusterInClassRule
{
    public override string Key => "QG-PP-BUG-0029";
    public override string[] Languages => ["php"];
}

/// <summary>
/// A possessive quantifier never gives back what it took. When the element after it can only match
/// characters the quantifier already accepts, there is nothing left for it and the match always fails.
/// </summary>
public abstract class PossessiveQuantifierStarvesRule : RegexTreeRuleBase
{
    public override Severity Severity => Severity.Critical;

    public override string Name => "A possessive quantifier should leave something for what follows";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, _, tree) in Patterns(context))
        {
            foreach (var sequence in Sequences(tree))
            {
                for (var i = 0; i + 1 < sequence.Count; i++)
                {
                    var repetition = sequence[i];
                    if (repetition is not { Kind: RegexKind.Repetition, RepeatMode: RegexRepeat.Possessive }
                        || !repetition.IsUnbounded)
                        continue;

                    var next = MandatoryFirst(sequence[i + 1]);
                    if (next == null)
                        continue;

                    var consumed = RegexCharSet.Of(repetition.Children[0]);
                    if (!RegexCharSet.Of(next).IsSubsetOf(consumed))
                        continue;

                    context.Report(node, $"'{repetition.Text}' never gives back what it matched, and "
                                         + $"'{next.Text}' can only match characters it already took, so "
                                         + "this pattern can never match. Move the element in front of "
                                         + "the possessive quantifier, or make the quantifier greedy.");
                    break;
                }
            }
        }
    }
}

public sealed class PossessiveQuantifierStarvesRuleJava : PossessiveQuantifierStarvesRule
{
    public override string Key => "QG-JV-BUG-0132";
    public override string[] Languages => ["java"];
}

public sealed class PossessiveQuantifierStarvesRulePython : PossessiveQuantifierStarvesRule
{
    public override string Key => "QG-PY-BUG-0066";
    public override string[] Languages => ["py"];
}

public sealed class PossessiveQuantifierStarvesRulePhp : PossessiveQuantifierStarvesRule
{
    public override string Key => "QG-PP-BUG-0032";
    public override string[] Languages => ["php"];
}

/// <summary>
/// A look-ahead reads without consuming, so what follows it has to satisfy both the assertion and
/// itself at the same position. When the two cannot hold together the pattern never matches.
/// </summary>
public abstract class ContradictoryLookAheadRule : RegexTreeRuleBase
{
    public override Severity Severity => Severity.Critical;

    public override string Name => "A look-ahead should not contradict what follows it";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, _, tree) in Patterns(context))
        {
            foreach (var sequence in Sequences(tree))
            {
                for (var i = 0; i + 1 < sequence.Count; i++)
                {
                    var look = sequence[i];
                    if (look.Kind != RegexKind.Group || look.Children.Count != 1)
                        continue;
                    if (look.GroupKind is not (RegexGroupKind.LookAhead or RegexGroupKind.NegativeLookAhead))
                        continue;

                    var asserted = MandatoryFirst(look.Children[0]);
                    var next = MandatoryFirst(sequence[i + 1]);
                    if (asserted == null || next == null)
                        continue;

                    var assertedSet = RegexCharSet.Of(asserted);
                    var nextSet = RegexCharSet.Of(next);

                    if (look.GroupKind == RegexGroupKind.LookAhead)
                    {
                        if (assertedSet.Intersects(nextSet))
                            continue;
                    }
                    else
                    {
                        // a negative look-ahead only settles the question when it rejects exactly one
                        // element: '(?!ab)a' is fine, because 'a' still matches when 'b' does not follow
                        if (RegexSyntax.Elements(look.Children[0]).Count != 1 || !nextSet.IsSubsetOf(assertedSet))
                            continue;
                    }

                    context.Report(node, $"'{look.Text}' asserts what the next position holds without "
                                         + $"consuming it, and '{next.Text}' has to match that same "
                                         + "position, which it never can. Move the assertion behind the "
                                         + "element it describes, or turn it into a look-behind.");
                    break;
                }
            }
        }
    }
}

public sealed class ContradictoryLookAheadRuleJava : ContradictoryLookAheadRule
{
    public override string Key => "QG-JV-BUG-0136";
    public override string[] Languages => ["java"];
}

public sealed class ContradictoryLookAheadRulePython : ContradictoryLookAheadRule
{
    public override string Key => "QG-PY-BUG-0069";
    public override string[] Languages => ["py"];
}

public sealed class ContradictoryLookAheadRulePhp : ContradictoryLookAheadRule
{
    public override string Key => "QG-PP-BUG-0035";
    public override string[] Languages => ["php"];
}

/// <summary>
/// A pair of parentheses with nothing between them either survived a refactoring or was meant to match
/// literal parentheses that were never escaped. Both readings are a defect.
/// </summary>
public abstract class EmptyRegexGroupRule : RegexTreeRuleBase
{
    public override IssueKind Kind => IssueKind.CodeSmell;

    public override Severity Severity => Severity.Major;

    public override string Name => "A pattern should not contain an empty group";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, _, tree) in Patterns(context))
        {
            foreach (var group in tree.SelfAndDescendants().Where(n => n.Kind == RegexKind.Group))
            {
                if (group.GroupKind is not (RegexGroupKind.Capturing or RegexGroupKind.NonCapturing
                    or RegexGroupKind.Named))
                    continue;
                if (group.Children.Count != 1 || group.Children[0].Children.Count != 0
                    || group.Children[0].Kind != RegexKind.Sequence)
                    continue;

                context.Report(node, $"'{group.Text}' groups nothing, so it matches the empty string and "
                                     + "changes nothing about the pattern. Remove it, or escape the "
                                     + "parentheses if the text to match really contains them.");
                break;
            }
        }
    }
}

public sealed class EmptyRegexGroupRuleJava : EmptyRegexGroupRule
{
    public override string Key => "QG-JV-SML-0350";
    public override string[] Languages => ["java"];
}

public sealed class EmptyRegexGroupRuleJs : EmptyRegexGroupRule
{
    public override string Key => "QG-JS-SML-0162";
    public override string[] Languages => ["js", "ts"];
}

public sealed class EmptyRegexGroupRulePython : EmptyRegexGroupRule
{
    public override string Key => "QG-PY-SML-0108";
    public override string[] Languages => ["py"];
}

public sealed class EmptyRegexGroupRulePhp : EmptyRegexGroupRule
{
    public override string Key => "QG-PP-SML-0101";
    public override string[] Languages => ["php"];
}

/// <summary>
/// Several constructs have a shorter spelling that every regex flavour understands, and the long form
/// gives the reader more to check for the same behaviour.
/// </summary>
public abstract class VerboseRegexShorthandRule : RegexTreeRuleBase
{
    public override IssueKind Kind => IssueKind.CodeSmell;

    public override Severity Severity => Severity.Minor;

    public override string RemediationEffort => "5min";

    public override string Name => "A pattern should use the shorthand for what it spells out";

    /// <summary>
    /// Whether the shorthands match ASCII only. Where they fold in Unicode instead — Python does, on
    /// text — '[A-Za-z0-9_]' and '\w' are different sets, and swapping one for the other changes
    /// what the pattern accepts.
    /// </summary>
    protected virtual bool ShorthandsAreAscii => true;

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, pattern, tree) in Patterns(context))
        {
            var dotAll = RegexSyntax.InlineFlags(pattern).Contains('s', StringComparison.Ordinal);
            foreach (var element in tree.SelfAndDescendants())
            {
                var shorter = element.Kind switch
                {
                    RegexKind.CharacterClass when ShorthandsAreAscii => ClassShorthand(element, dotAll),
                    RegexKind.Repetition => QuantifierShorthand(element),
                    _ => null
                };
                if (shorter == null)
                    continue;

                var written = element.Kind == RegexKind.Repetition ? element.QuantifierText : element.Text;
                context.Report(node, $"'{written}' is the long way of writing '{shorter}'. Use the "
                                     + "shorthand so the pattern says the same thing with less to read.");
                break;
            }
        }
    }

    private static string? ClassShorthand(RegexNode characterClass, bool dotAll)
    {
        var items = characterClass.ClassItems;
        if (items.Count == 1 && items[0] == "0-9")
            return characterClass.Negated ? "\\D" : "\\d";
        if (items.Count == 4 && items.Contains("A-Z") && items.Contains("a-z")
            && items.Contains("0-9") && items.Contains("_"))
            return characterClass.Negated ? "\\W" : "\\w";
        if (characterClass.Negated || items.Count != 2)
            return null;

        // a class holding a shorthand and its opposite matches every character there is
        var pairs = new[] { ("\\w", "\\W"), ("\\d", "\\D"), ("\\s", "\\S") };
        foreach (var (one, other) in pairs)
        {
            if (!items.Contains(one) || !items.Contains(other))
                continue;
            // '[\s\S]' is the usual way of saying "any character, newline included"; only with the
            // dot-all flag on does the dot mean the same thing
            if (one == "\\s" && !dotAll)
                return null;
            return ".";
        }
        return null;
    }

    private static string? QuantifierShorthand(RegexNode repetition)
    {
        if (!repetition.QuantifierText.StartsWith('{'))
            return null;
        var suffix = repetition.QuantifierText.EndsWith('?') || repetition.QuantifierText.EndsWith('+')
            ? repetition.QuantifierText[^1].ToString()
            : string.Empty;
        return (repetition.Min, repetition.Max) switch
        {
            (0, 1) => "?" + suffix,
            (0, -1) => "*" + suffix,
            (1, -1) => "+" + suffix,
            var (min, max) when min == max && repetition.QuantifierText.Contains(',')
                => "{" + min.ToString(CultureInfo.InvariantCulture) + "}" + suffix,
            _ => null
        };
    }
}

public sealed class VerboseRegexShorthandRuleJava : VerboseRegexShorthandRule
{
    public override string Key => "QG-JV-SML-0351";
    public override string[] Languages => ["java"];
}

public sealed class VerboseRegexShorthandRuleJs : VerboseRegexShorthandRule
{
    public override string Key => "QG-JS-SML-0163";
    public override string[] Languages => ["js", "ts"];
}

public sealed class VerboseRegexShorthandRulePython : VerboseRegexShorthandRule
{
    public override string Key => "QG-PY-SML-0109";
    public override string[] Languages => ["py"];
    protected override bool ShorthandsAreAscii => false;
}

public sealed class VerboseRegexShorthandRulePhp : VerboseRegexShorthandRule
{
    public override string Key => "QG-PP-SML-0105";
    public override string[] Languages => ["php"];
}

/// <summary>
/// A non-capturing group earns its parentheses when it holds alternatives together or gives a
/// quantifier something to repeat. With neither, it only adds noise.
/// </summary>
public abstract class PointlessNonCapturingGroupRule : RegexTreeRuleBase
{
    public override IssueKind Kind => IssueKind.CodeSmell;

    public override Severity Severity => Severity.Minor;

    public override string RemediationEffort => "5min";

    public override string Name => "A non-capturing group should group something";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, _, tree) in Patterns(context))
        {
            var quantified = tree.SelfAndDescendants()
                .Where(n => n.Kind == RegexKind.Repetition)
                .Select(n => n.Children[0])
                .ToHashSet();

            foreach (var group in tree.SelfAndDescendants().Where(n => n.Kind == RegexKind.Group))
            {
                if (group.GroupKind != RegexGroupKind.NonCapturing || group.GroupFlags.Length > 0)
                    continue;
                if (quantified.Contains(group) || group.Children.Count != 1)
                    continue;
                var body = group.Children[0];
                if (body.Kind == RegexKind.Alternation || body.Children.Count == 0
                                                       && body.Kind == RegexKind.Sequence)
                    continue;

                context.Report(node, $"'{group.Text}' holds neither alternatives nor anything a "
                                     + "quantifier repeats, so the group changes nothing. Drop the "
                                     + "parentheses and leave what they contain.");
                break;
            }
        }
    }
}

public sealed class PointlessNonCapturingGroupRuleJava : PointlessNonCapturingGroupRule
{
    public override string Key => "QG-JV-SML-0353";
    public override string[] Languages => ["java"];
}

public sealed class PointlessNonCapturingGroupRulePython : PointlessNonCapturingGroupRule
{
    public override string Key => "QG-PY-SML-0110";
    public override string[] Languages => ["py"];
}

public sealed class PointlessNonCapturingGroupRulePhp : PointlessNonCapturingGroupRule
{
    public override string Key => "QG-PP-SML-0106";
    public override string[] Languages => ["php"];
}

/// <summary>
/// The '\cX' escape takes the character 64 positions below X in ASCII. Outside the '@' to '_' range
/// that subtraction lands nowhere sensible, and the engine still performs it without a word.
/// </summary>
public sealed class ControlEscapeOutOfRangeRuleJava : RegexTreeRuleBase
{
    public override string Key => "QG-JV-BUG-0137";
    public override string[] Languages => ["java"];

    public override string Name => "A control-character escape should name a character in range";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, _, tree) in Patterns(context))
        {
            foreach (var escape in tree.SelfAndDescendants().Where(n => n.Kind == RegexKind.Escape))
            {
                if (escape.Text.Length != 3 || escape.Text[1] != 'c')
                    continue;
                var named = escape.Text[2];
                if (named is >= '@' and <= '_')
                    continue;

                context.Report(node, $"'{escape.Text}' asks for the control character 64 positions below "
                                     + $"'{named}', which is outside the '@' to '_' range this escape is "
                                     + "defined for. Name the upper-case letter of the control character "
                                     + "you meant, or write the character itself.");
                break;
            }
        }
    }
}

/// <summary>
/// A backslash followed by digits reads as a reference to a group. When no such group exists the engine
/// silently treats the digits as an octal code point instead, which is almost never what was written.
/// </summary>
public sealed class OctalEscapeInPatternRulePython : RegexTreeRuleBase
{
    public override string Key => "QG-PY-SML-0112";
    public override string[] Languages => ["py"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override string Name => "A pattern should not use an octal escape";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, _, tree) in Patterns(context))
        {
            var groups = tree.SelfAndDescendants().Count(n => n is { Kind: RegexKind.Group, CaptureNumber: > 0 });
            foreach (var escape in tree.SelfAndDescendants())
            {
                var octal = OctalText(escape, groups);
                if (octal == null)
                    continue;

                context.Report(node, $"'{octal}' reads as a reference to a group, and being none it "
                                     + "becomes an octal character code instead. Write the character as "
                                     + "a hexadecimal escape so it cannot be read two ways.");
                break;
            }
        }
    }

    private static string? OctalText(RegexNode node, int groups)
    {
        if (node.Kind == RegexKind.Escape && node.Text.Length > 2 && node.Text[1] == '0')
            return node.Text;
        if (node.Kind != RegexKind.BackReference || node.Reference.Length < 2)
            return null;
        if (!node.Reference.All(c => c is >= '0' and <= '7'))
            return null;
        return int.TryParse(node.Reference, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
               && number > groups
            ? node.Text
            : null;
    }
}

/// <summary>
/// Case-insensitive matching only folds ASCII letters unless the pattern says otherwise. A pattern that
/// contains accented letters and asks for case insensitivity therefore stays case sensitive exactly
/// where it was meant not to be.
/// </summary>
public sealed class UnicodeCaseFoldingRuleJava : RegexTreeRuleBase
{
    public override string Key => "QG-JV-BUG-0126";
    public override string[] Languages => ["java"];

    public override string Name => "Case-insensitive matching of non-ASCII letters should say so";

    public override void Execute(IRuleContext context)
    {
        foreach (var literal in RegexLiterals.In(context))
        {
            if (!HasNonAsciiLetter(literal.Pattern))
                continue;
            var flags = RegexSyntax.InlineFlags(literal.Pattern) + InlineGroupFlags(literal.Pattern);
            if (!flags.Contains('i', StringComparison.Ordinal)
                || flags.Contains('u', StringComparison.Ordinal) || flags.Contains('U', StringComparison.Ordinal))
                continue;

            context.Report(literal.Node, "This pattern matches without regard to case and contains letters "
                                         + "outside ASCII, whose case is still compared exactly. Add the "
                                         + "'u' flag, or the Unicode case option at the call site, so "
                                         + "every letter folds the same way.");
        }

        foreach (var call in SyntaxQuery.InvocationsOf(context.Root, "Pattern.compile"))
        {
            var pattern = SyntaxQuery.ArgumentAt(call, 0);
            var options = SyntaxQuery.ArgumentAt(call, 1);
            if (pattern == null || options == null || !SyntaxQuery.IsStringLiteral(pattern)
                || !HasNonAsciiLetter(pattern.Text))
                continue;
            var written = options.Text;
            if (!written.Contains("CASE_INSENSITIVE", StringComparison.Ordinal)
                || written.Contains("UNICODE_CASE", StringComparison.Ordinal)
                || written.Contains("UNICODE_CHARACTER_CLASS", StringComparison.Ordinal))
                continue;

            context.Report(pattern, "This pattern is compiled without regard to case and contains letters "
                                    + "outside ASCII, whose case is still compared exactly. Add the "
                                    + "Unicode case option next to the case-insensitive one.");
        }
    }

    private static bool HasNonAsciiLetter(string pattern) => pattern.Any(c => c > 127 && char.IsLetter(c));

    /// <summary>Flags set by a group that scopes them, as in '(?i:...)'.</summary>
    private static string InlineGroupFlags(string pattern)
    {
        var flags = string.Empty;
        for (var i = 0; i + 2 < pattern.Length; i++)
        {
            if (pattern[i] != '(' || pattern[i + 1] != '?')
                continue;
            var scan = i + 2;
            while (scan < pattern.Length && char.IsAsciiLetter(pattern[scan]))
                scan++;
            if (scan < pattern.Length && pattern[scan] == ':')
                flags += pattern[(i + 2)..scan];
        }
        return flags;
    }
}

/// <summary>
/// Complexity here is nesting: every alternation, quantifier, assertion and flag group costs as much as
/// the depth it sits at. Past a point the pattern stops being readable and starts hiding its own bugs,
/// and the fix is to split it or to write the logic as code.
/// </summary>
public abstract class OverbuiltRegexRule : RegexTreeRuleBase
{
    private const int Limit = 20;

    public override IssueKind Kind => IssueKind.CodeSmell;

    public override Severity Severity => Severity.Major;

    public override string RemediationEffort => "30min";

    public override string Name => "A regular expression should not be too complicated";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, _, tree) in Patterns(context))
        {
            var score = Complexity(tree, 0);
            if (score <= Limit)
                continue;

            context.ReportCosting($"This pattern scores {score} for nesting against a limit of "
                                  + $"{Limit}: every alternative, quantifier and assertion costs as much "
                                  + "as the depth it sits at. Split it into named parts, or match the "
                                  + "pieces in code.", (score - Limit) * 2, node.Range.StartLine);
        }
    }

    private static int Complexity(RegexNode node, int level) => node.Kind switch
    {
        RegexKind.Alternation => level + Math.Max(0, node.Children.Count - 2)
                                       + node.Children.Sum(c => Complexity(c, level + 1)),
        RegexKind.Repetition => level + Complexity(node.Children[0], level + 1),
        RegexKind.CharacterClass => 1,
        RegexKind.BackReference => 1,
        RegexKind.Group => GroupCost(node, level),
        _ => node.Children.Sum(c => Complexity(c, level))
    };

    private static int GroupCost(RegexNode group, int level)
    {
        var nests = group.GroupKind is RegexGroupKind.LookAhead or RegexGroupKind.NegativeLookAhead
                        or RegexGroupKind.LookBehind or RegexGroupKind.NegativeLookBehind
                    || group.GroupFlags.Length > 0;
        var inner = group.Children.Sum(c => Complexity(c, nests ? level + 1 : level));
        return nests ? level + inner : inner;
    }
}

public sealed class OverbuiltRegexRuleJava : OverbuiltRegexRule
{
    public override string Key => "QG-JV-SML-0310";
    public override string[] Languages => ["java"];
}

public sealed class OverbuiltRegexRuleKotlin : OverbuiltRegexRule
{
    public override string Key => "QG-KT-SML-0039";
    public override string[] Languages => ["kt"];
}

public sealed class OverbuiltRegexRuleJs : OverbuiltRegexRule
{
    public override string Key => "QG-JS-SML-0148";
    public override string[] Languages => ["js", "ts"];
}

public sealed class OverbuiltRegexRulePython : OverbuiltRegexRule
{
    public override string Key => "QG-PY-SML-0089";
    public override string[] Languages => ["py"];
}

public sealed class OverbuiltRegexRulePhp : OverbuiltRegexRule
{
    public override string Key => "QG-PP-SML-0092";
    public override string[] Languages => ["php"];
}

/// <summary>
/// A reference to a group by name only works when a group of that name exists in the same pattern.
/// When it does not, the engine either fails to compile the pattern or reads the reference as text.
/// </summary>
public abstract class UndefinedGroupNameRule : RegexTreeRuleBase
{
    public override IssueKind Kind => IssueKind.CodeSmell;

    public override Severity Severity => Severity.Major;

    public override string Name => "A named group reference should point at a group that exists";

    public override void Execute(IRuleContext context)
    {
        foreach (var (node, _, tree) in Patterns(context))
        {
            var declared = tree.SelfAndDescendants()
                .Where(n => n.GroupName is { Length: > 0 })
                .Select(n => n.GroupName!)
                .ToHashSet(StringComparer.Ordinal);

            foreach (var reference in tree.SelfAndDescendants().Where(n => n.Kind == RegexKind.BackReference))
            {
                if (reference.Reference.Length == 0 || char.IsAsciiDigit(reference.Reference[0])
                    || declared.Contains(reference.Reference))
                    continue;

                context.Report(node, $"'{reference.Text}' refers to a group named "
                                     + $"'{reference.Reference}', and this pattern declares no such "
                                     + "group. Name the group it should point at, or fix the spelling.");
                break;
            }
        }
    }
}

public sealed class UndefinedGroupNameRuleJava : UndefinedGroupNameRule
{
    public override string Key => "QG-JV-SML-0315";
    public override string[] Languages => ["java"];
}

public sealed class UndefinedGroupNameRuleJs : UndefinedGroupNameRule
{
    public override string Key => "QG-JS-SML-0149";
    public override string[] Languages => ["js", "ts"];
}

public sealed class UndefinedGroupNameRulePython : UndefinedGroupNameRule
{
    public override string Key => "QG-PY-SML-0091";
    public override string[] Languages => ["py"];
}

/// <summary>
/// Replacing text through the regex engine compiles a pattern on every call. When the pattern holds no
/// regex feature at all, the plain text replacement does the same work without the engine.
/// </summary>
public abstract class LiteralPatternReplaceRule : RegexTreeRuleBase
{
    public override IssueKind Kind => IssueKind.CodeSmell;

    public override Severity Severity => Severity.Major;

    public override string RemediationEffort => "5min";

    /// <summary>The call that goes through the engine, and the one to use instead.</summary>
    protected abstract (string Called, string Instead) Replacement { get; }

    /// <summary>The receiver the call must sit on, when the name alone does not identify it.</summary>
    protected virtual string? Receiver => null;

    public override string Name => "Plain text should be replaced without the regex engine";

    public override void Execute(IRuleContext context)
    {
        var (called, instead) = Replacement;
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (SyntaxQuery.InvokedName(call) != called)
                continue;
            if (Receiver != null && SyntaxQuery.Receiver(call) != Receiver)
                continue;
            var argument = SyntaxQuery.ArgumentAt(call, 0);
            if (argument == null || !SyntaxQuery.IsStringLiteral(argument))
                continue;

            var pattern = Undelimited(argument.Text);
            if (pattern.Length == 0)
                continue;
            var tree = RegexSyntax.Parse(pattern);
            if (tree == null || !IsPlainText(tree))
                continue;

            context.Report(argument, $"'{called}' compiles this argument as a pattern, and the pattern "
                                     + $"matches plain text. Call '{instead}' instead: same result, "
                                     + "without building a regular expression on every call.");
        }
    }

    /// <summary>PHP wraps its patterns in a delimiter; the other languages pass the pattern as it is.</summary>
    protected virtual string Undelimited(string written) => written;

    private static bool IsPlainText(RegexNode tree)
    {
        var elements = RegexSyntax.Elements(tree);
        if (tree.Kind != RegexKind.Sequence && tree.Kind != RegexKind.Literal && tree.Kind != RegexKind.Escape)
            return false;
        foreach (var element in elements)
        {
            if (element.Kind == RegexKind.Literal)
                continue;
            // an escaped metacharacter stands for itself, which is exactly what plain text means
            if (element.Kind == RegexKind.Escape && element.Text.Length == 2
                                                 && !char.IsAsciiLetterOrDigit(element.Text[1]))
                continue;
            return false;
        }
        return true;
    }
}

public sealed class LiteralPatternReplaceRuleJava : LiteralPatternReplaceRule
{
    public override string Key => "QG-JV-SML-0291";
    public override string[] Languages => ["java"];
    protected override (string Called, string Instead) Replacement => ("replaceAll", "replace");
}

public sealed class LiteralPatternReplaceRulePython : LiteralPatternReplaceRule
{
    public override string Key => "QG-PY-SML-0069";
    public override string[] Languages => ["py"];
    protected override (string Called, string Instead) Replacement => ("sub", "str.replace");
    protected override string? Receiver => "re";
}

public sealed class LiteralPatternReplaceRulePhp : LiteralPatternReplaceRule
{
    public override string Key => "QG-PP-SML-0088";
    public override string[] Languages => ["php"];
    protected override (string Called, string Instead) Replacement => ("preg_replace", "str_replace");

    protected override string Undelimited(string written)
    {
        if (written.Length < 2 || char.IsLetterOrDigit(written[0]) || written[0] == '\\')
            return string.Empty;
        var close = written[0] switch
        {
            '(' => ')', '[' => ']', '{' => '}', '<' => '>',
            _ => written[0]
        };
        var end = written.LastIndexOf(close);
        return end <= 0 ? string.Empty : written[1..end];
    }
}
