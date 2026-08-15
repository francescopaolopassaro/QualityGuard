using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Rules that read the regular expression itself, not the code around it.
///
/// A pattern is a small program written inside a string literal, and the compiler checks none of it.
/// The analyzer below walks the pattern once and hands every rule the pieces it needs — character
/// classes, alternations, quantifiers, group references — so a defect is reported with the position
/// and the reason, instead of the whole literal being flagged as "suspicious".
/// </summary>
public static class RegexRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new DuplicateCharacterInClassRule(),
        new SingleCharacterClassRule(),
        new SingleCharacterAlternationRule(),
        new RepeatedSpaceInPatternRule(),
        new EmptyAlternativeRule(),
        new RedundantAlternativeRule(),
        new CatastrophicBacktrackingRule(),
        new UnresolvedBackReferenceRule(),
        new ControlCharacterInPatternRule()
    ];
}

/// <summary>Where a pattern literal was found, and the pattern itself.</summary>
public readonly record struct RegexLiteral(SyntaxNode Node, string Pattern);

/// <summary>
/// Finds the string literals that are really regular expressions. The receiver matters: Replace,
/// Split and Match exist on strings and collections too, where the argument is plain text.
/// </summary>
public static class RegexLiterals
{
    private static readonly string[] AlwaysPatterns =
    [
        "MustCompile", "MustCompilePOSIX", "new_regex", "RegExp", "Regex", "compile", "findall",
        "fullmatch", "IsMatch", "Matches"
    ];

    private static readonly string[] OnlyWithRegexReceiver =
        ["Match", "Replace", "Split", "match", "search", "test", "exec", "matches", "sub", "subn"];

    private static readonly string[] RegexReceivers =
        ["Regex", "RegExp", "re", "Pattern", "regexp"];

    public static IEnumerable<RegexLiteral> In(IRuleContext context)
    {
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            var certain = AlwaysPatterns.Contains(name, StringComparer.Ordinal);
            if (!certain && !(OnlyWithRegexReceiver.Contains(name, StringComparer.Ordinal)
                              && RegexReceivers.Contains(SyntaxQuery.Receiver(call), StringComparer.Ordinal)))
                continue;

            foreach (var argument in SyntaxQuery.Arguments(call).Where(SyntaxQuery.IsStringLiteral))
            {
                if (argument.Text.Length > 1)
                    yield return new RegexLiteral(argument, argument.Text);
                break; // the pattern is the first string argument; the rest are input or replacements
            }
        }

        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            if (creation.Text is not ("Regex" or "RegExp"))
                continue;
            var argument = SyntaxQuery.Arguments(creation).FirstOrDefault(SyntaxQuery.IsStringLiteral);
            if (argument is { Text.Length: > 1 })
                yield return new RegexLiteral(argument, argument.Text);
        }
    }
}

/// <summary>
/// A single pass over a pattern, recording the parts the rules ask about. It is deliberately a
/// scanner and not a full grammar: everything it reports must be true of the pattern whatever the
/// flavour, so constructs it does not recognise are skipped rather than guessed at.
/// </summary>
public sealed class RegexPattern
{
    public sealed record CharacterClass(int Start, IReadOnlyList<string> Items, bool Negated);

    /// <summary>Alternatives of one group, or of the pattern itself when <c>Start</c> is zero.</summary>
    public sealed record Alternation(int Start, IReadOnlyList<string> Alternatives);

    public List<CharacterClass> Classes { get; } = [];
    public List<Alternation> Alternations { get; } = [];

    /// <summary>Quantified groups whose body is itself quantified: the shape that backtracks forever.</summary>
    public List<string> NestedQuantifiers { get; } = [];

    public List<int> BackReferences { get; } = [];
    public int CapturingGroups { get; private set; }
    public bool HasRepeatedSpace { get; private set; }
    public bool HasControlCharacter { get; private set; }

    public static RegexPattern Parse(string pattern)
    {
        var result = new RegexPattern();
        var alternatives = new List<string>();
        var current = new System.Text.StringBuilder();
        var groupStack = new Stack<(int Start, List<string> Alternatives, System.Text.StringBuilder Text)>();
        var spaces = 0;

        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];

            if (c == ' ')
            {
                spaces++;
                if (spaces >= 2)
                    result.HasRepeatedSpace = true;
            }
            else
            {
                spaces = 0;
            }

            if (char.IsControl(c))
                result.HasControlCharacter = true;

            switch (c)
            {
                case '\\' when i + 1 < pattern.Length:
                    var escaped = pattern[i + 1];
                    if (char.IsDigit(escaped) && escaped != '0')
                        result.BackReferences.Add(escaped - '0');
                    current.Append(c).Append(escaped);
                    i++;
                    continue;

                case '[':
                    i = result.ReadClass(pattern, i);
                    current.Append('.');
                    continue;

                case '(':
                    groupStack.Push((i, alternatives, current));
                    alternatives = [];
                    current = new System.Text.StringBuilder();
                    if (!IsNonCapturing(pattern, i))
                        result.CapturingGroups++;
                    continue;

                case ')':
                {
                    alternatives.Add(current.ToString());
                    var body = string.Join('|', alternatives);
                    if (groupStack.Count > 0)
                    {
                        var (start, outerAlternatives, outerText) = groupStack.Pop();
                        if (alternatives.Count > 1)
                            result.Alternations.Add(new Alternation(start, alternatives));
                        if (IsQuantified(pattern, i) && EndsWithQuantifier(body))
                            result.NestedQuantifiers.Add(body);
                        alternatives = outerAlternatives;
                        current = outerText;
                        current.Append('(').Append(body).Append(')');
                    }
                    else
                    {
                        alternatives = [];
                        current = new System.Text.StringBuilder();
                    }
                    continue;
                }

                case '|':
                    alternatives.Add(current.ToString());
                    current = new System.Text.StringBuilder();
                    continue;

                default:
                    current.Append(c);
                    continue;
            }
        }

        alternatives.Add(current.ToString());
        if (alternatives.Count > 1)
            result.Alternations.Add(new Alternation(0, alternatives));
        return result;
    }

    /// <summary>Reads a character class and returns the index of its closing bracket.</summary>
    private int ReadClass(string pattern, int start)
    {
        var items = new List<string>();
        var i = start + 1;
        var negated = i < pattern.Length && pattern[i] == '^';
        if (negated)
            i++;
        // a bracket in first position is a literal, not the end of the class
        if (i < pattern.Length && pattern[i] == ']')
        {
            items.Add("]");
            i++;
        }

        while (i < pattern.Length && pattern[i] != ']')
        {
            if (pattern[i] == '\\' && i + 1 < pattern.Length)
            {
                items.Add(pattern.Substring(i, 2));
                i += 2;
                continue;
            }
            if (i + 2 < pattern.Length && pattern[i + 1] == '-' && pattern[i + 2] != ']')
            {
                items.Add(pattern.Substring(i, 3));
                i += 3;
                continue;
            }
            items.Add(pattern[i].ToString());
            i++;
        }

        Classes.Add(new CharacterClass(start, items, negated));
        return i;
    }

    /// <summary>`(?:`, lookarounds and flags do not capture; `(?&lt;name&gt;` and `(?'name'` do.</summary>
    private static bool IsNonCapturing(string pattern, int open)
    {
        if (open + 1 >= pattern.Length || pattern[open + 1] != '?')
            return false;
        if (open + 2 >= pattern.Length)
            return true;
        var marker = pattern[open + 2];
        if (marker == '\'')
            return false;
        // (?<name> captures, while (?<= and (?<! are lookbehind
        return marker != '<' || (open + 3 < pattern.Length && pattern[open + 3] is '=' or '!');
    }

    private static bool IsQuantified(string pattern, int close)
        => close + 1 < pattern.Length && pattern[close + 1] is '*' or '+' or '{';

    private static bool EndsWithQuantifier(string body)
        => body.Length > 1 && body[^1] is '*' or '+' && body[^2] != '\\';
}

public abstract class RegexRuleBase : RuleBase
{
    public override string[] Languages => [];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    protected static IEnumerable<(RegexLiteral Literal, RegexPattern Parsed)> Patterns(IRuleContext context)
    {
        foreach (var literal in RegexLiterals.In(context))
        {
            RegexPattern parsed;
            try
            {
                parsed = RegexPattern.Parse(literal.Pattern);
            }
            catch (Exception)
            {
                continue; // a pattern the scanner cannot follow is left to the validity rule
            }
            yield return (literal, parsed);
        }
    }
}

public sealed class DuplicateCharacterInClassRule : RegexRuleBase
{
    public override string Key => "QG-ALL-BUG-0025";
    public override string Name => "A character class should not list the same character twice";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var (literal, parsed) in Patterns(context))
        {
            foreach (var characterClass in parsed.Classes)
            {
                var duplicate = characterClass.Items
                    .GroupBy(item => item, StringComparer.Ordinal)
                    .FirstOrDefault(group => group.Count() > 1);
                if (duplicate == null)
                    continue;
                context.Report(literal.Node, $"'{duplicate.Key}' appears twice in the same character "
                                             + "class. One of the two was meant to be a different "
                                             + "character, or the class can be shortened.");
                break;
            }
        }
    }
}

public sealed class SingleCharacterClassRule : RegexRuleBase
{
    public override string Key => "QG-ALL-SML-0039";
    public override string Name => "A character class holding one character should be that character";

    public override void Execute(IRuleContext context)
    {
        foreach (var (literal, parsed) in Patterns(context))
        {
            var single = parsed.Classes.FirstOrDefault(c => !c.Negated && c.Items.Count == 1
                                                            && c.Items[0].Length == 1
                                                            && c.Items[0] is not ("^" or "]"));
            if (single == null)
                continue;
            context.Report(literal.Node, $"The class [{single.Items[0]}] matches exactly one character; "
                                         + $"write '{single.Items[0]}' and let the reader see it at a glance.");
        }
    }
}

public sealed class SingleCharacterAlternationRule : RegexRuleBase
{
    public override string Key => "QG-ALL-SML-0040";
    public override string Name => "Alternations of single characters should be a character class";

    public override void Execute(IRuleContext context)
    {
        foreach (var (literal, parsed) in Patterns(context))
        {
            var alternation = parsed.Alternations.FirstOrDefault(
                a => a.Alternatives.Count >= 2 && a.Alternatives.All(alt => alt.Length == 1 && alt[0] != '\\'));
            if (alternation == null)
                continue;
            var asClass = string.Concat(alternation.Alternatives);
            context.Report(literal.Node, $"'{string.Join('|', alternation.Alternatives)}' is a choice between "
                                         + $"single characters; write [{asClass}], which the engine matches "
                                         + "without backtracking.");
        }
    }
}

public sealed class RepeatedSpaceInPatternRule : RegexRuleBase
{
    public override string Key => "QG-ALL-SML-0041";
    public override string Name => "Repeated spaces in a pattern should be written as a count";

    public override void Execute(IRuleContext context)
    {
        foreach (var (literal, parsed) in Patterns(context))
        {
            if (!parsed.HasRepeatedSpace)
                continue;
            context.Report(literal.Node, "This pattern contains several spaces in a row, which nobody can "
                                         + "count while reading. Write the number explicitly, as in ' {3}'.");
        }
    }
}

public sealed class EmptyAlternativeRule : RegexRuleBase
{
    public override string Key => "QG-ALL-BUG-0026";
    public override string Name => "An alternation should not contain an empty branch";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var (literal, parsed) in Patterns(context))
        {
            if (!parsed.Alternations.Any(a => a.Alternatives.Any(alt => alt.Length == 0)))
                continue;
            context.Report(literal.Node, "One branch of this alternation is empty, so the whole group "
                                         + "matches the empty string and the other branches never decide "
                                         + "anything. Remove the stray '|' or write what it should match.");
        }
    }
}

public sealed class RedundantAlternativeRule : RegexRuleBase
{
    public override string Key => "QG-ALL-BUG-0027";
    public override string Name => "An alternation should not repeat the same branch";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var (literal, parsed) in Patterns(context))
        {
            var repeated = parsed.Alternations
                .SelectMany(a => a.Alternatives)
                .Where(alt => alt.Length > 0)
                .GroupBy(alt => alt, StringComparer.Ordinal)
                .FirstOrDefault(group => group.Count() > 1);
            if (repeated == null)
                continue;
            context.Report(literal.Node, $"The branch '{repeated.Key}' appears more than once in the same "
                                         + "alternation; the second one can never match, so one of them is "
                                         + "not the branch that was meant.");
        }
    }
}

public sealed class CatastrophicBacktrackingRule : RegexRuleBase
{
    public override string Key => "QG-ALL-BUG-0028";
    public override string Name => "A quantifier should not be applied to an already repeating group";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        foreach (var (literal, parsed) in Patterns(context))
        {
            if (parsed.NestedQuantifiers.Count == 0)
                continue;
            var body = parsed.NestedQuantifiers[0];
            context.Report(literal.Node, $"'({body})' repeats a group that already repeats. On an input "
                                         + "that almost matches, the engine tries every way of splitting "
                                         + "the text and the match takes exponential time. Rewrite the "
                                         + "group so only one level repeats.");
        }
    }
}

public sealed class UnresolvedBackReferenceRule : RegexRuleBase
{
    public override string Key => "QG-ALL-BUG-0029";
    public override string Name => "A back reference should point at a group that exists";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var (literal, parsed) in Patterns(context))
        {
            var dangling = parsed.BackReferences.FirstOrDefault(r => r > parsed.CapturingGroups);
            if (dangling == 0)
                continue;
            context.Report(literal.Node, $"\\{dangling} refers to capturing group {dangling}, but the "
                                         + $"pattern declares {parsed.CapturingGroups}. The reference either "
                                         + "never matches or is read as an escape, depending on the engine.");
        }
    }
}

public sealed class ControlCharacterInPatternRule : RegexRuleBase
{
    public override string Key => "QG-ALL-BUG-0030";
    public override string Name => "A pattern should not contain a raw control character";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var (literal, parsed) in Patterns(context))
        {
            if (!parsed.HasControlCharacter)
                continue;
            context.Report(literal.Node, "This pattern contains a control character written literally. It "
                                         + "is invisible in review and disappears through copy and paste; "
                                         + "write the escape (\\t, \\n, \\x1b) instead.");
        }
    }
}
