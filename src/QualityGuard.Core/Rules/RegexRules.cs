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
        new DuplicateCharacterInClassRuleCs(),
        new DuplicateCharacterInClassRuleJava(),
        new DuplicateCharacterInClassRuleKotlin(),
        new DuplicateCharacterInClassRuleJs(),
        new DuplicateCharacterInClassRulePython(),
        new DuplicateCharacterInClassRulePhp(),
        new DuplicateCharacterInClassRuleGo(),
        new DuplicateCharacterInClassRuleDart(),
        new DuplicateCharacterInClassRuleRuby(),
        new DuplicateCharacterInClassRuleSwift(),
        new DuplicateCharacterInClassRuleCss(),
        new DuplicateCharacterInClassRuleHtml(),
        new DuplicateCharacterInClassRuleXml(),
        new DuplicateCharacterInClassRuleTerraform(),
        new DuplicateCharacterInClassRuleDockerfile(),
        new DuplicateCharacterInClassRuleKubernetes(),
        new DuplicateCharacterInClassRuleCloudFormation(),
        new DuplicateCharacterInClassRuleJson(),
        new SingleCharacterClassRuleCs(),
        new SingleCharacterClassRuleJava(),
        new SingleCharacterClassRuleKotlin(),
        new SingleCharacterClassRuleJs(),
        new SingleCharacterClassRulePython(),
        new SingleCharacterClassRulePhp(),
        new SingleCharacterClassRuleGo(),
        new SingleCharacterClassRuleDart(),
        new SingleCharacterClassRuleRuby(),
        new SingleCharacterClassRuleSwift(),
        new SingleCharacterClassRuleCss(),
        new SingleCharacterClassRuleHtml(),
        new SingleCharacterClassRuleXml(),
        new SingleCharacterClassRuleTerraform(),
        new SingleCharacterClassRuleDockerfile(),
        new SingleCharacterClassRuleKubernetes(),
        new SingleCharacterClassRuleCloudFormation(),
        new SingleCharacterClassRuleJson(),
        new SingleCharacterAlternationRuleCs(),
        new SingleCharacterAlternationRuleJava(),
        new SingleCharacterAlternationRuleKotlin(),
        new SingleCharacterAlternationRuleJs(),
        new SingleCharacterAlternationRulePython(),
        new SingleCharacterAlternationRulePhp(),
        new SingleCharacterAlternationRuleGo(),
        new SingleCharacterAlternationRuleDart(),
        new SingleCharacterAlternationRuleRuby(),
        new SingleCharacterAlternationRuleSwift(),
        new SingleCharacterAlternationRuleCss(),
        new SingleCharacterAlternationRuleHtml(),
        new SingleCharacterAlternationRuleXml(),
        new SingleCharacterAlternationRuleTerraform(),
        new SingleCharacterAlternationRuleDockerfile(),
        new SingleCharacterAlternationRuleKubernetes(),
        new SingleCharacterAlternationRuleCloudFormation(),
        new SingleCharacterAlternationRuleJson(),
        new RepeatedSpaceInPatternRuleCs(),
        new RepeatedSpaceInPatternRuleJava(),
        new RepeatedSpaceInPatternRuleKotlin(),
        new RepeatedSpaceInPatternRuleJs(),
        new RepeatedSpaceInPatternRulePython(),
        new RepeatedSpaceInPatternRulePhp(),
        new RepeatedSpaceInPatternRuleGo(),
        new RepeatedSpaceInPatternRuleDart(),
        new RepeatedSpaceInPatternRuleRuby(),
        new RepeatedSpaceInPatternRuleSwift(),
        new RepeatedSpaceInPatternRuleCss(),
        new RepeatedSpaceInPatternRuleHtml(),
        new RepeatedSpaceInPatternRuleXml(),
        new RepeatedSpaceInPatternRuleTerraform(),
        new RepeatedSpaceInPatternRuleDockerfile(),
        new RepeatedSpaceInPatternRuleKubernetes(),
        new RepeatedSpaceInPatternRuleCloudFormation(),
        new RepeatedSpaceInPatternRuleJson(),
        new EmptyAlternativeRuleCs(),
        new EmptyAlternativeRuleJava(),
        new EmptyAlternativeRuleKotlin(),
        new EmptyAlternativeRuleJs(),
        new EmptyAlternativeRulePython(),
        new EmptyAlternativeRulePhp(),
        new EmptyAlternativeRuleGo(),
        new EmptyAlternativeRuleDart(),
        new EmptyAlternativeRuleRuby(),
        new EmptyAlternativeRuleSwift(),
        new EmptyAlternativeRuleCss(),
        new EmptyAlternativeRuleHtml(),
        new EmptyAlternativeRuleXml(),
        new EmptyAlternativeRuleTerraform(),
        new EmptyAlternativeRuleDockerfile(),
        new EmptyAlternativeRuleKubernetes(),
        new EmptyAlternativeRuleCloudFormation(),
        new EmptyAlternativeRuleJson(),
        new RedundantAlternativeRuleCs(),
        new RedundantAlternativeRuleJava(),
        new RedundantAlternativeRuleKotlin(),
        new RedundantAlternativeRuleJs(),
        new RedundantAlternativeRulePython(),
        new RedundantAlternativeRulePhp(),
        new RedundantAlternativeRuleGo(),
        new RedundantAlternativeRuleDart(),
        new RedundantAlternativeRuleRuby(),
        new RedundantAlternativeRuleSwift(),
        new RedundantAlternativeRuleCss(),
        new RedundantAlternativeRuleHtml(),
        new RedundantAlternativeRuleXml(),
        new RedundantAlternativeRuleTerraform(),
        new RedundantAlternativeRuleDockerfile(),
        new RedundantAlternativeRuleKubernetes(),
        new RedundantAlternativeRuleCloudFormation(),
        new RedundantAlternativeRuleJson(),
        new CatastrophicBacktrackingRuleCs(),
        new CatastrophicBacktrackingRuleJava(),
        new CatastrophicBacktrackingRuleKotlin(),
        new CatastrophicBacktrackingRuleJs(),
        new CatastrophicBacktrackingRulePython(),
        new CatastrophicBacktrackingRulePhp(),
        new CatastrophicBacktrackingRuleGo(),
        new CatastrophicBacktrackingRuleDart(),
        new CatastrophicBacktrackingRuleRuby(),
        new CatastrophicBacktrackingRuleSwift(),
        new CatastrophicBacktrackingRuleCss(),
        new CatastrophicBacktrackingRuleHtml(),
        new CatastrophicBacktrackingRuleXml(),
        new CatastrophicBacktrackingRuleTerraform(),
        new CatastrophicBacktrackingRuleDockerfile(),
        new CatastrophicBacktrackingRuleKubernetes(),
        new CatastrophicBacktrackingRuleCloudFormation(),
        new CatastrophicBacktrackingRuleJson(),
        new UnresolvedBackReferenceRuleCs(),
        new UnresolvedBackReferenceRuleJava(),
        new UnresolvedBackReferenceRuleKotlin(),
        new UnresolvedBackReferenceRuleJs(),
        new UnresolvedBackReferenceRulePython(),
        new UnresolvedBackReferenceRulePhp(),
        new UnresolvedBackReferenceRuleGo(),
        new UnresolvedBackReferenceRuleDart(),
        new UnresolvedBackReferenceRuleRuby(),
        new UnresolvedBackReferenceRuleSwift(),
        new UnresolvedBackReferenceRuleCss(),
        new UnresolvedBackReferenceRuleHtml(),
        new UnresolvedBackReferenceRuleXml(),
        new UnresolvedBackReferenceRuleTerraform(),
        new UnresolvedBackReferenceRuleDockerfile(),
        new UnresolvedBackReferenceRuleKubernetes(),
        new UnresolvedBackReferenceRuleCloudFormation(),
        new UnresolvedBackReferenceRuleJson(),
        new ControlCharacterInPatternRuleCs(),
        new ControlCharacterInPatternRuleRuby(),
        new ControlCharacterInPatternRuleSwift(),
        new ControlCharacterInPatternRuleCss(),
        new ControlCharacterInPatternRuleHtml(),
        new ControlCharacterInPatternRuleXml(),
        new ControlCharacterInPatternRuleTerraform(),
        new ControlCharacterInPatternRuleDockerfile(),
        new ControlCharacterInPatternRuleKubernetes(),
        new ControlCharacterInPatternRuleCloudFormation(),
        new ControlCharacterInPatternRuleJson(),
        new ControlCharacterInPatternRuleJava(),
        new ControlCharacterInPatternRuleKotlin(),
        new ControlCharacterInPatternRuleJs(),
        new ControlCharacterInPatternRulePython(),
        new ControlCharacterInPatternRulePhp(),
        new ControlCharacterInPatternRuleGo(),
        new ControlCharacterInPatternRuleDart()
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

    /// <summary>
    /// Methods that take a regular expression on an ordinary string receiver. In Java this is how
    /// most patterns in a codebase are written — 'text.matches(...)', 'text.replaceAll(...)' — and
    /// requiring a Pattern receiver skipped every one of them.
    /// </summary>
    private static readonly string[] StringRegexMethods =
        ["matches", "replaceAll", "replaceFirst", "split"];

    /// <summary>
    /// PHP writes every pattern as a plain function call, and wraps it in a delimiter of its own
    /// choosing with the flags after the closing one.
    /// </summary>
    private static readonly string[] PhpPatternFunctions =
    [
        "preg_match", "preg_match_all", "preg_replace", "preg_replace_callback",
        "preg_replace_callback_array", "preg_split", "preg_grep"
    ];

    public static IEnumerable<RegexLiteral> In(IRuleContext context)
    {
        var stringMethodsCarryRegex = context.Language.LanguageKey is "java" or "kt";
        var php = context.Language.LanguageKey == "php";

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (php && PhpPatternFunctions.Contains(name, StringComparer.Ordinal))
            {
                // argument zero is the pattern; argument one is the replacement, and reading that
                // one as a regex reported on the text a match is turned into
                var written = SyntaxQuery.ArgumentAt(call, 0);
                if (written != null && SyntaxQuery.IsStringLiteral(written)
                    && Undelimit(written.Text) is { Length: > 1 } pattern)
                    yield return new RegexLiteral(written, pattern);
                continue;
            }

            var certain = AlwaysPatterns.Contains(name, StringComparer.Ordinal)
                          || (stringMethodsCarryRegex
                              && StringRegexMethods.Contains(name, StringComparer.Ordinal));
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

    /// <summary>
    /// Strips the delimiters PHP wraps a pattern in, and the flags that follow the closing one.
    /// Returns an empty string when the text is not delimited, because then it is not a pattern.
    /// </summary>
    private static string Undelimit(string written)
    {
        if (written.Length < 2)
            return string.Empty;
        var open = written[0];
        if (char.IsLetterOrDigit(open) || open == (char)92 || open == ' ')
            return string.Empty;
        var close = open switch
        {
            '(' => ')', '[' => ']', '{' => '}', '<' => '>',
            _ => open
        };
        var end = written.LastIndexOf(close);
        if (end <= 0)
            return string.Empty;
        // the flags sit after the closing delimiter and change what the pattern means; carrying them
        // back as an inline group keeps every rule reading one thing
        var flags = written[(end + 1)..].Trim();
        var inline = flags.Length > 0 ? "(?" + flags + ")" : string.Empty;
        return inline + written[1..end];
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

public abstract class DuplicateCharacterInClassRule : RegexRuleBase
{
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
                if (duplicate != null)
                {
                    context.Report(literal.Node, $"'{duplicate.Key}' appears twice in the same "
                                                 + "character class. One of the two was meant to be a "
                                                 + "different character, or the class can be "
                                                 + "shortened.");
                    break;
                }

                // A range covers the characters between its ends, so '[0-99]' and '[0-73-9]' repeat
                // themselves without repeating a symbol. Matching only identical items missed every
                // overlap, which is the form this mistake usually takes.
                var overlap = Overlapping(characterClass.Items);
                if (overlap == null)
                    continue;
                context.Report(literal.Node, $"'{overlap.Value.Second}' is already covered by "
                                             + $"'{overlap.Value.First}' in this character class, so "
                                             + "one of the two does nothing. Widen the range, or "
                                             + "correct the character that was meant.");
                break;
            }
        }
    }

    /// <summary>
    /// The first pair of items in a class where one already matches everything the other does. A
    /// range is expanded to the set it stands for; anything the parser could not read is skipped
    /// rather than guessed at.
    /// </summary>
    private static (string First, string Second)? Overlapping(IReadOnlyList<string> items)
    {
        var sets = new List<(string Text, HashSet<char> Chars)>();
        foreach (var item in items)
        {
            var chars = Expand(item);
            if (chars == null)
                continue;
            foreach (var (text, previous) in sets)
            {
                if (previous.Overlaps(chars))
                    return (text, item);
            }
            sets.Add((item, chars));
        }
        return null;
    }

    /// <summary>The characters an item stands for, or null when it is not a plain literal or range.</summary>
    private static HashSet<char>? Expand(string item)
    {
        if (item.Length == 1 && !char.IsControl(item[0]))
            return [item[0]];
        if (item.Length == 3 && item[1] == '-' && item[0] <= item[2]
            && char.IsLetterOrDigit(item[0]) && char.IsLetterOrDigit(item[2]))
        {
            var set = new HashSet<char>();
            for (var c = item[0]; c <= item[2]; c++)
                set.Add(c);
            return set;
        }
        return null;
    }

}

public sealed class DuplicateCharacterInClassRuleCs : DuplicateCharacterInClassRule
{
    public override string Key => "QG-CS-BUG-0174";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class DuplicateCharacterInClassRuleJava : DuplicateCharacterInClassRule
{
    public override string Key => "QG-JV-BUG-0228";
    public override string[] Languages => ["java"];
}

public sealed class DuplicateCharacterInClassRuleKotlin : DuplicateCharacterInClassRule
{
    public override string Key => "QG-KT-BUG-0055";
    public override string[] Languages => ["kt"];
}

public sealed class DuplicateCharacterInClassRuleJs : DuplicateCharacterInClassRule
{
    public override string Key => "QG-JS-BUG-0172";
    public override string[] Languages => ["js", "ts"];
}

public sealed class DuplicateCharacterInClassRulePython : DuplicateCharacterInClassRule
{
    public override string Key => "QG-PY-BUG-0178";
    public override string[] Languages => ["py"];
}

public sealed class DuplicateCharacterInClassRulePhp : DuplicateCharacterInClassRule
{
    public override string Key => "QG-PP-BUG-0075";
    public override string[] Languages => ["php"];
}

public sealed class DuplicateCharacterInClassRuleGo : DuplicateCharacterInClassRule
{
    public override string Key => "QG-GO-BUG-0031";
    public override string[] Languages => ["go"];
}

public sealed class DuplicateCharacterInClassRuleDart : DuplicateCharacterInClassRule
{
    public override string Key => "QG-DART-BUG-0029";
    public override string[] Languages => ["dart"];
}

public sealed class DuplicateCharacterInClassRuleRuby : DuplicateCharacterInClassRule
{
    public override string Key => "QG-RB-BUG-0017";
    public override string[] Languages => ["rb"];
}

public sealed class DuplicateCharacterInClassRuleSwift : DuplicateCharacterInClassRule
{
    public override string Key => "QG-SW-BUG-0021";
    public override string[] Languages => ["swift"];
}

public sealed class DuplicateCharacterInClassRuleCss : DuplicateCharacterInClassRule
{
    public override string Key => "QG-CSS-BUG-0046";
    public override string[] Languages => ["css"];
}

public sealed class DuplicateCharacterInClassRuleHtml : DuplicateCharacterInClassRule
{
    public override string Key => "QG-HTML-BUG-0046";
    public override string[] Languages => ["html"];
}

public sealed class DuplicateCharacterInClassRuleXml : DuplicateCharacterInClassRule
{
    public override string Key => "QG-XML-BUG-0021";
    public override string[] Languages => ["xml"];
}

public sealed class DuplicateCharacterInClassRuleTerraform : DuplicateCharacterInClassRule
{
    public override string Key => "QG-TF-BUG-0016";
    public override string[] Languages => ["tf"];
}

public sealed class DuplicateCharacterInClassRuleDockerfile : DuplicateCharacterInClassRule
{
    public override string Key => "QG-DK-BUG-0023";
    public override string[] Languages => ["dk"];
}

public sealed class DuplicateCharacterInClassRuleKubernetes : DuplicateCharacterInClassRule
{
    public override string Key => "QG-K8-BUG-0016";
    public override string[] Languages => ["k8"];
}

public sealed class DuplicateCharacterInClassRuleCloudFormation : DuplicateCharacterInClassRule
{
    public override string Key => "QG-CF-BUG-0016";
    public override string[] Languages => ["cf"];
}

public sealed class DuplicateCharacterInClassRuleJson : DuplicateCharacterInClassRule
{
    public override string Key => "QG-JSON-BUG-0017";
    public override string[] Languages => ["json"];
}

public abstract class SingleCharacterClassRule : RegexRuleBase
{
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

public sealed class SingleCharacterClassRuleCs : SingleCharacterClassRule
{
    public override string Key => "QG-CS-SML-0533";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class SingleCharacterClassRuleJava : SingleCharacterClassRule
{
    public override string Key => "QG-JV-SML-0494";
    public override string[] Languages => ["java"];
}

public sealed class SingleCharacterClassRuleKotlin : SingleCharacterClassRule
{
    public override string Key => "QG-KT-SML-0116";
    public override string[] Languages => ["kt"];
}

public sealed class SingleCharacterClassRuleJs : SingleCharacterClassRule
{
    public override string Key => "QG-JS-SML-0410";
    public override string[] Languages => ["js", "ts"];
}

public sealed class SingleCharacterClassRulePython : SingleCharacterClassRule
{
    public override string Key => "QG-PY-SML-0289";
    public override string[] Languages => ["py"];
}

public sealed class SingleCharacterClassRulePhp : SingleCharacterClassRule
{
    public override string Key => "QG-PP-SML-0154";
    public override string[] Languages => ["php"];
}

public sealed class SingleCharacterClassRuleGo : SingleCharacterClassRule
{
    public override string Key => "QG-GO-SML-0068";
    public override string[] Languages => ["go"];
}

public sealed class SingleCharacterClassRuleDart : SingleCharacterClassRule
{
    public override string Key => "QG-DART-SML-0033";
    public override string[] Languages => ["dart"];
}

public sealed class SingleCharacterClassRuleRuby : SingleCharacterClassRule
{
    public override string Key => "QG-RB-SML-0028";
    public override string[] Languages => ["rb"];
}

public sealed class SingleCharacterClassRuleSwift : SingleCharacterClassRule
{
    public override string Key => "QG-SW-SML-0012";
    public override string[] Languages => ["swift"];
}

public sealed class SingleCharacterClassRuleCss : SingleCharacterClassRule
{
    public override string Key => "QG-CSS-SML-0033";
    public override string[] Languages => ["css"];
}

public sealed class SingleCharacterClassRuleHtml : SingleCharacterClassRule
{
    public override string Key => "QG-HTML-SML-0105";
    public override string[] Languages => ["html"];
}

public sealed class SingleCharacterClassRuleXml : SingleCharacterClassRule
{
    public override string Key => "QG-XML-SML-0020";
    public override string[] Languages => ["xml"];
}

public sealed class SingleCharacterClassRuleTerraform : SingleCharacterClassRule
{
    public override string Key => "QG-TF-SML-0012";
    public override string[] Languages => ["tf"];
}

public sealed class SingleCharacterClassRuleDockerfile : SingleCharacterClassRule
{
    public override string Key => "QG-DK-SML-0026";
    public override string[] Languages => ["dk"];
}

public sealed class SingleCharacterClassRuleKubernetes : SingleCharacterClassRule
{
    public override string Key => "QG-K8-SML-0020";
    public override string[] Languages => ["k8"];
}

public sealed class SingleCharacterClassRuleCloudFormation : SingleCharacterClassRule
{
    public override string Key => "QG-CF-SML-0013";
    public override string[] Languages => ["cf"];
}

public sealed class SingleCharacterClassRuleJson : SingleCharacterClassRule
{
    public override string Key => "QG-JSON-SML-0008";
    public override string[] Languages => ["json"];
}

public abstract class SingleCharacterAlternationRule : RegexRuleBase
{
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

public sealed class SingleCharacterAlternationRuleCs : SingleCharacterAlternationRule
{
    public override string Key => "QG-CS-SML-0534";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class SingleCharacterAlternationRuleJava : SingleCharacterAlternationRule
{
    public override string Key => "QG-JV-SML-0495";
    public override string[] Languages => ["java"];
}

public sealed class SingleCharacterAlternationRuleKotlin : SingleCharacterAlternationRule
{
    public override string Key => "QG-KT-SML-0117";
    public override string[] Languages => ["kt"];
}

public sealed class SingleCharacterAlternationRuleJs : SingleCharacterAlternationRule
{
    public override string Key => "QG-JS-SML-0411";
    public override string[] Languages => ["js", "ts"];
}

public sealed class SingleCharacterAlternationRulePython : SingleCharacterAlternationRule
{
    public override string Key => "QG-PY-SML-0290";
    public override string[] Languages => ["py"];
}

public sealed class SingleCharacterAlternationRulePhp : SingleCharacterAlternationRule
{
    public override string Key => "QG-PP-SML-0155";
    public override string[] Languages => ["php"];
}

public sealed class SingleCharacterAlternationRuleGo : SingleCharacterAlternationRule
{
    public override string Key => "QG-GO-SML-0069";
    public override string[] Languages => ["go"];
}

public sealed class SingleCharacterAlternationRuleDart : SingleCharacterAlternationRule
{
    public override string Key => "QG-DART-SML-0034";
    public override string[] Languages => ["dart"];
}

public sealed class SingleCharacterAlternationRuleRuby : SingleCharacterAlternationRule
{
    public override string Key => "QG-RB-SML-0029";
    public override string[] Languages => ["rb"];
}

public sealed class SingleCharacterAlternationRuleSwift : SingleCharacterAlternationRule
{
    public override string Key => "QG-SW-SML-0013";
    public override string[] Languages => ["swift"];
}

public sealed class SingleCharacterAlternationRuleCss : SingleCharacterAlternationRule
{
    public override string Key => "QG-CSS-SML-0034";
    public override string[] Languages => ["css"];
}

public sealed class SingleCharacterAlternationRuleHtml : SingleCharacterAlternationRule
{
    public override string Key => "QG-HTML-SML-0106";
    public override string[] Languages => ["html"];
}

public sealed class SingleCharacterAlternationRuleXml : SingleCharacterAlternationRule
{
    public override string Key => "QG-XML-SML-0021";
    public override string[] Languages => ["xml"];
}

public sealed class SingleCharacterAlternationRuleTerraform : SingleCharacterAlternationRule
{
    public override string Key => "QG-TF-SML-0013";
    public override string[] Languages => ["tf"];
}

public sealed class SingleCharacterAlternationRuleDockerfile : SingleCharacterAlternationRule
{
    public override string Key => "QG-DK-SML-0027";
    public override string[] Languages => ["dk"];
}

public sealed class SingleCharacterAlternationRuleKubernetes : SingleCharacterAlternationRule
{
    public override string Key => "QG-K8-SML-0021";
    public override string[] Languages => ["k8"];
}

public sealed class SingleCharacterAlternationRuleCloudFormation : SingleCharacterAlternationRule
{
    public override string Key => "QG-CF-SML-0014";
    public override string[] Languages => ["cf"];
}

public sealed class SingleCharacterAlternationRuleJson : SingleCharacterAlternationRule
{
    public override string Key => "QG-JSON-SML-0009";
    public override string[] Languages => ["json"];
}

public abstract class RepeatedSpaceInPatternRule : RegexRuleBase
{
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

public sealed class RepeatedSpaceInPatternRuleCs : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-CS-SML-0535";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class RepeatedSpaceInPatternRuleJava : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-JV-SML-0496";
    public override string[] Languages => ["java"];
}

public sealed class RepeatedSpaceInPatternRuleKotlin : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-KT-SML-0118";
    public override string[] Languages => ["kt"];
}

public sealed class RepeatedSpaceInPatternRuleJs : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-JS-SML-0412";
    public override string[] Languages => ["js", "ts"];
}

public sealed class RepeatedSpaceInPatternRulePython : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-PY-SML-0291";
    public override string[] Languages => ["py"];
}

public sealed class RepeatedSpaceInPatternRulePhp : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-PP-SML-0156";
    public override string[] Languages => ["php"];
}

public sealed class RepeatedSpaceInPatternRuleGo : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-GO-SML-0070";
    public override string[] Languages => ["go"];
}

public sealed class RepeatedSpaceInPatternRuleDart : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-DART-SML-0035";
    public override string[] Languages => ["dart"];
}

public sealed class RepeatedSpaceInPatternRuleRuby : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-RB-SML-0030";
    public override string[] Languages => ["rb"];
}

public sealed class RepeatedSpaceInPatternRuleSwift : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-SW-SML-0014";
    public override string[] Languages => ["swift"];
}

public sealed class RepeatedSpaceInPatternRuleCss : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-CSS-SML-0035";
    public override string[] Languages => ["css"];
}

public sealed class RepeatedSpaceInPatternRuleHtml : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-HTML-SML-0107";
    public override string[] Languages => ["html"];
}

public sealed class RepeatedSpaceInPatternRuleXml : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-XML-SML-0022";
    public override string[] Languages => ["xml"];
}

public sealed class RepeatedSpaceInPatternRuleTerraform : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-TF-SML-0014";
    public override string[] Languages => ["tf"];
}

public sealed class RepeatedSpaceInPatternRuleDockerfile : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-DK-SML-0028";
    public override string[] Languages => ["dk"];
}

public sealed class RepeatedSpaceInPatternRuleKubernetes : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-K8-SML-0022";
    public override string[] Languages => ["k8"];
}

public sealed class RepeatedSpaceInPatternRuleCloudFormation : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-CF-SML-0015";
    public override string[] Languages => ["cf"];
}

public sealed class RepeatedSpaceInPatternRuleJson : RepeatedSpaceInPatternRule
{
    public override string Key => "QG-JSON-SML-0010";
    public override string[] Languages => ["json"];
}

public abstract class EmptyAlternativeRule : RegexRuleBase
{
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

public sealed class EmptyAlternativeRuleCs : EmptyAlternativeRule
{
    public override string Key => "QG-CS-BUG-0175";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class EmptyAlternativeRuleJava : EmptyAlternativeRule
{
    public override string Key => "QG-JV-BUG-0229";
    public override string[] Languages => ["java"];
}

public sealed class EmptyAlternativeRuleKotlin : EmptyAlternativeRule
{
    public override string Key => "QG-KT-BUG-0056";
    public override string[] Languages => ["kt"];
}

public sealed class EmptyAlternativeRuleJs : EmptyAlternativeRule
{
    public override string Key => "QG-JS-BUG-0173";
    public override string[] Languages => ["js", "ts"];
}

public sealed class EmptyAlternativeRulePython : EmptyAlternativeRule
{
    public override string Key => "QG-PY-BUG-0179";
    public override string[] Languages => ["py"];
}

public sealed class EmptyAlternativeRulePhp : EmptyAlternativeRule
{
    public override string Key => "QG-PP-BUG-0076";
    public override string[] Languages => ["php"];
}

public sealed class EmptyAlternativeRuleGo : EmptyAlternativeRule
{
    public override string Key => "QG-GO-BUG-0032";
    public override string[] Languages => ["go"];
}

public sealed class EmptyAlternativeRuleDart : EmptyAlternativeRule
{
    public override string Key => "QG-DART-BUG-0030";
    public override string[] Languages => ["dart"];
}

public sealed class EmptyAlternativeRuleRuby : EmptyAlternativeRule
{
    public override string Key => "QG-RB-BUG-0018";
    public override string[] Languages => ["rb"];
}

public sealed class EmptyAlternativeRuleSwift : EmptyAlternativeRule
{
    public override string Key => "QG-SW-BUG-0022";
    public override string[] Languages => ["swift"];
}

public sealed class EmptyAlternativeRuleCss : EmptyAlternativeRule
{
    public override string Key => "QG-CSS-BUG-0047";
    public override string[] Languages => ["css"];
}

public sealed class EmptyAlternativeRuleHtml : EmptyAlternativeRule
{
    public override string Key => "QG-HTML-BUG-0047";
    public override string[] Languages => ["html"];
}

public sealed class EmptyAlternativeRuleXml : EmptyAlternativeRule
{
    public override string Key => "QG-XML-BUG-0022";
    public override string[] Languages => ["xml"];
}

public sealed class EmptyAlternativeRuleTerraform : EmptyAlternativeRule
{
    public override string Key => "QG-TF-BUG-0017";
    public override string[] Languages => ["tf"];
}

public sealed class EmptyAlternativeRuleDockerfile : EmptyAlternativeRule
{
    public override string Key => "QG-DK-BUG-0024";
    public override string[] Languages => ["dk"];
}

public sealed class EmptyAlternativeRuleKubernetes : EmptyAlternativeRule
{
    public override string Key => "QG-K8-BUG-0017";
    public override string[] Languages => ["k8"];
}

public sealed class EmptyAlternativeRuleCloudFormation : EmptyAlternativeRule
{
    public override string Key => "QG-CF-BUG-0017";
    public override string[] Languages => ["cf"];
}

public sealed class EmptyAlternativeRuleJson : EmptyAlternativeRule
{
    public override string Key => "QG-JSON-BUG-0018";
    public override string[] Languages => ["json"];
}

public abstract class RedundantAlternativeRule : RegexRuleBase
{
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

public sealed class RedundantAlternativeRuleCs : RedundantAlternativeRule
{
    public override string Key => "QG-CS-BUG-0176";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class RedundantAlternativeRuleJava : RedundantAlternativeRule
{
    public override string Key => "QG-JV-BUG-0230";
    public override string[] Languages => ["java"];
}

public sealed class RedundantAlternativeRuleKotlin : RedundantAlternativeRule
{
    public override string Key => "QG-KT-BUG-0057";
    public override string[] Languages => ["kt"];
}

public sealed class RedundantAlternativeRuleJs : RedundantAlternativeRule
{
    public override string Key => "QG-JS-BUG-0174";
    public override string[] Languages => ["js", "ts"];
}

public sealed class RedundantAlternativeRulePython : RedundantAlternativeRule
{
    public override string Key => "QG-PY-BUG-0180";
    public override string[] Languages => ["py"];
}

public sealed class RedundantAlternativeRulePhp : RedundantAlternativeRule
{
    public override string Key => "QG-PP-BUG-0077";
    public override string[] Languages => ["php"];
}

public sealed class RedundantAlternativeRuleGo : RedundantAlternativeRule
{
    public override string Key => "QG-GO-BUG-0033";
    public override string[] Languages => ["go"];
}

public sealed class RedundantAlternativeRuleDart : RedundantAlternativeRule
{
    public override string Key => "QG-DART-BUG-0031";
    public override string[] Languages => ["dart"];
}

public sealed class RedundantAlternativeRuleRuby : RedundantAlternativeRule
{
    public override string Key => "QG-RB-BUG-0019";
    public override string[] Languages => ["rb"];
}

public sealed class RedundantAlternativeRuleSwift : RedundantAlternativeRule
{
    public override string Key => "QG-SW-BUG-0023";
    public override string[] Languages => ["swift"];
}

public sealed class RedundantAlternativeRuleCss : RedundantAlternativeRule
{
    public override string Key => "QG-CSS-BUG-0048";
    public override string[] Languages => ["css"];
}

public sealed class RedundantAlternativeRuleHtml : RedundantAlternativeRule
{
    public override string Key => "QG-HTML-BUG-0048";
    public override string[] Languages => ["html"];
}

public sealed class RedundantAlternativeRuleXml : RedundantAlternativeRule
{
    public override string Key => "QG-XML-BUG-0023";
    public override string[] Languages => ["xml"];
}

public sealed class RedundantAlternativeRuleTerraform : RedundantAlternativeRule
{
    public override string Key => "QG-TF-BUG-0018";
    public override string[] Languages => ["tf"];
}

public sealed class RedundantAlternativeRuleDockerfile : RedundantAlternativeRule
{
    public override string Key => "QG-DK-BUG-0025";
    public override string[] Languages => ["dk"];
}

public sealed class RedundantAlternativeRuleKubernetes : RedundantAlternativeRule
{
    public override string Key => "QG-K8-BUG-0018";
    public override string[] Languages => ["k8"];
}

public sealed class RedundantAlternativeRuleCloudFormation : RedundantAlternativeRule
{
    public override string Key => "QG-CF-BUG-0018";
    public override string[] Languages => ["cf"];
}

public sealed class RedundantAlternativeRuleJson : RedundantAlternativeRule
{
    public override string Key => "QG-JSON-BUG-0019";
    public override string[] Languages => ["json"];
}

public abstract class CatastrophicBacktrackingRule : RegexRuleBase
{
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

public sealed class CatastrophicBacktrackingRuleCs : CatastrophicBacktrackingRule
{
    public override string Key => "QG-CS-BUG-0177";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class CatastrophicBacktrackingRuleJava : CatastrophicBacktrackingRule
{
    public override string Key => "QG-JV-BUG-0231";
    public override string[] Languages => ["java"];
}

public sealed class CatastrophicBacktrackingRuleKotlin : CatastrophicBacktrackingRule
{
    public override string Key => "QG-KT-BUG-0058";
    public override string[] Languages => ["kt"];
}

public sealed class CatastrophicBacktrackingRuleJs : CatastrophicBacktrackingRule
{
    public override string Key => "QG-JS-BUG-0175";
    public override string[] Languages => ["js", "ts"];
}

public sealed class CatastrophicBacktrackingRulePython : CatastrophicBacktrackingRule
{
    public override string Key => "QG-PY-BUG-0181";
    public override string[] Languages => ["py"];
}

public sealed class CatastrophicBacktrackingRulePhp : CatastrophicBacktrackingRule
{
    public override string Key => "QG-PP-BUG-0078";
    public override string[] Languages => ["php"];
}

public sealed class CatastrophicBacktrackingRuleGo : CatastrophicBacktrackingRule
{
    public override string Key => "QG-GO-BUG-0034";
    public override string[] Languages => ["go"];
}

public sealed class CatastrophicBacktrackingRuleDart : CatastrophicBacktrackingRule
{
    public override string Key => "QG-DART-BUG-0032";
    public override string[] Languages => ["dart"];
}

public sealed class CatastrophicBacktrackingRuleRuby : CatastrophicBacktrackingRule
{
    public override string Key => "QG-RB-BUG-0020";
    public override string[] Languages => ["rb"];
}

public sealed class CatastrophicBacktrackingRuleSwift : CatastrophicBacktrackingRule
{
    public override string Key => "QG-SW-BUG-0024";
    public override string[] Languages => ["swift"];
}

public sealed class CatastrophicBacktrackingRuleCss : CatastrophicBacktrackingRule
{
    public override string Key => "QG-CSS-BUG-0049";
    public override string[] Languages => ["css"];
}

public sealed class CatastrophicBacktrackingRuleHtml : CatastrophicBacktrackingRule
{
    public override string Key => "QG-HTML-BUG-0049";
    public override string[] Languages => ["html"];
}

public sealed class CatastrophicBacktrackingRuleXml : CatastrophicBacktrackingRule
{
    public override string Key => "QG-XML-BUG-0024";
    public override string[] Languages => ["xml"];
}

public sealed class CatastrophicBacktrackingRuleTerraform : CatastrophicBacktrackingRule
{
    public override string Key => "QG-TF-BUG-0019";
    public override string[] Languages => ["tf"];
}

public sealed class CatastrophicBacktrackingRuleDockerfile : CatastrophicBacktrackingRule
{
    public override string Key => "QG-DK-BUG-0026";
    public override string[] Languages => ["dk"];
}

public sealed class CatastrophicBacktrackingRuleKubernetes : CatastrophicBacktrackingRule
{
    public override string Key => "QG-K8-BUG-0019";
    public override string[] Languages => ["k8"];
}

public sealed class CatastrophicBacktrackingRuleCloudFormation : CatastrophicBacktrackingRule
{
    public override string Key => "QG-CF-BUG-0019";
    public override string[] Languages => ["cf"];
}

public sealed class CatastrophicBacktrackingRuleJson : CatastrophicBacktrackingRule
{
    public override string Key => "QG-JSON-BUG-0020";
    public override string[] Languages => ["json"];
}

public abstract class UnresolvedBackReferenceRule : RegexRuleBase
{
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

public sealed class UnresolvedBackReferenceRuleCs : UnresolvedBackReferenceRule
{
    public override string Key => "QG-CS-BUG-0178";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class UnresolvedBackReferenceRuleJava : UnresolvedBackReferenceRule
{
    public override string Key => "QG-JV-BUG-0232";
    public override string[] Languages => ["java"];
}

public sealed class UnresolvedBackReferenceRuleKotlin : UnresolvedBackReferenceRule
{
    public override string Key => "QG-KT-BUG-0059";
    public override string[] Languages => ["kt"];
}

public sealed class UnresolvedBackReferenceRuleJs : UnresolvedBackReferenceRule
{
    public override string Key => "QG-JS-BUG-0176";
    public override string[] Languages => ["js", "ts"];
}

public sealed class UnresolvedBackReferenceRulePython : UnresolvedBackReferenceRule
{
    public override string Key => "QG-PY-BUG-0182";
    public override string[] Languages => ["py"];
}

public sealed class UnresolvedBackReferenceRulePhp : UnresolvedBackReferenceRule
{
    public override string Key => "QG-PP-BUG-0079";
    public override string[] Languages => ["php"];
}

public sealed class UnresolvedBackReferenceRuleGo : UnresolvedBackReferenceRule
{
    public override string Key => "QG-GO-BUG-0035";
    public override string[] Languages => ["go"];
}

public sealed class UnresolvedBackReferenceRuleDart : UnresolvedBackReferenceRule
{
    public override string Key => "QG-DART-BUG-0033";
    public override string[] Languages => ["dart"];
}

public sealed class UnresolvedBackReferenceRuleRuby : UnresolvedBackReferenceRule
{
    public override string Key => "QG-RB-BUG-0021";
    public override string[] Languages => ["rb"];
}

public sealed class UnresolvedBackReferenceRuleSwift : UnresolvedBackReferenceRule
{
    public override string Key => "QG-SW-BUG-0025";
    public override string[] Languages => ["swift"];
}

public sealed class UnresolvedBackReferenceRuleCss : UnresolvedBackReferenceRule
{
    public override string Key => "QG-CSS-BUG-0050";
    public override string[] Languages => ["css"];
}

public sealed class UnresolvedBackReferenceRuleHtml : UnresolvedBackReferenceRule
{
    public override string Key => "QG-HTML-BUG-0050";
    public override string[] Languages => ["html"];
}

public sealed class UnresolvedBackReferenceRuleXml : UnresolvedBackReferenceRule
{
    public override string Key => "QG-XML-BUG-0025";
    public override string[] Languages => ["xml"];
}

public sealed class UnresolvedBackReferenceRuleTerraform : UnresolvedBackReferenceRule
{
    public override string Key => "QG-TF-BUG-0020";
    public override string[] Languages => ["tf"];
}

public sealed class UnresolvedBackReferenceRuleDockerfile : UnresolvedBackReferenceRule
{
    public override string Key => "QG-DK-BUG-0027";
    public override string[] Languages => ["dk"];
}

public sealed class UnresolvedBackReferenceRuleKubernetes : UnresolvedBackReferenceRule
{
    public override string Key => "QG-K8-BUG-0020";
    public override string[] Languages => ["k8"];
}

public sealed class UnresolvedBackReferenceRuleCloudFormation : UnresolvedBackReferenceRule
{
    public override string Key => "QG-CF-BUG-0020";
    public override string[] Languages => ["cf"];
}

public sealed class UnresolvedBackReferenceRuleJson : UnresolvedBackReferenceRule
{
    public override string Key => "QG-JSON-BUG-0021";
    public override string[] Languages => ["json"];
}

public abstract class ControlCharacterInPatternRule : RegexRuleBase
{
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

public sealed class ControlCharacterInPatternRuleCs : ControlCharacterInPatternRule
{
    public override string Key => "QG-CS-BUG-0179";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class ControlCharacterInPatternRuleJava : ControlCharacterInPatternRule
{
    public override string Key => "QG-JV-BUG-0233";
    public override string[] Languages => ["java"];
}

public sealed class ControlCharacterInPatternRuleKotlin : ControlCharacterInPatternRule
{
    public override string Key => "QG-KT-BUG-0060";
    public override string[] Languages => ["kt"];
}

public sealed class ControlCharacterInPatternRuleJs : ControlCharacterInPatternRule
{
    public override string Key => "QG-JS-BUG-0177";
    public override string[] Languages => ["js", "ts"];
}

public sealed class ControlCharacterInPatternRulePython : ControlCharacterInPatternRule
{
    public override string Key => "QG-PY-BUG-0183";
    public override string[] Languages => ["py"];
}

public sealed class ControlCharacterInPatternRulePhp : ControlCharacterInPatternRule
{
    public override string Key => "QG-PP-BUG-0080";
    public override string[] Languages => ["php"];
}

public sealed class ControlCharacterInPatternRuleGo : ControlCharacterInPatternRule
{
    public override string Key => "QG-GO-BUG-0036";
    public override string[] Languages => ["go"];
}

public sealed class ControlCharacterInPatternRuleDart : ControlCharacterInPatternRule
{
    public override string Key => "QG-DART-BUG-0034";
    public override string[] Languages => ["dart"];
}

public sealed class ControlCharacterInPatternRuleRuby : ControlCharacterInPatternRule
{
    public override string Key => "QG-RB-BUG-0022";
    public override string[] Languages => ["rb"];
}

public sealed class ControlCharacterInPatternRuleSwift : ControlCharacterInPatternRule
{
    public override string Key => "QG-SW-BUG-0026";
    public override string[] Languages => ["swift"];
}

public sealed class ControlCharacterInPatternRuleCss : ControlCharacterInPatternRule
{
    public override string Key => "QG-CSS-BUG-0051";
    public override string[] Languages => ["css"];
}

public sealed class ControlCharacterInPatternRuleHtml : ControlCharacterInPatternRule
{
    public override string Key => "QG-HTML-BUG-0051";
    public override string[] Languages => ["html"];
}

public sealed class ControlCharacterInPatternRuleXml : ControlCharacterInPatternRule
{
    public override string Key => "QG-XML-BUG-0026";
    public override string[] Languages => ["xml"];
}

public sealed class ControlCharacterInPatternRuleTerraform : ControlCharacterInPatternRule
{
    public override string Key => "QG-TF-BUG-0021";
    public override string[] Languages => ["tf"];
}

public sealed class ControlCharacterInPatternRuleDockerfile : ControlCharacterInPatternRule
{
    public override string Key => "QG-DK-BUG-0028";
    public override string[] Languages => ["dk"];
}

public sealed class ControlCharacterInPatternRuleKubernetes : ControlCharacterInPatternRule
{
    public override string Key => "QG-K8-BUG-0021";
    public override string[] Languages => ["k8"];
}

public sealed class ControlCharacterInPatternRuleCloudFormation : ControlCharacterInPatternRule
{
    public override string Key => "QG-CF-BUG-0021";
    public override string[] Languages => ["cf"];
}

public sealed class ControlCharacterInPatternRuleJson : ControlCharacterInPatternRule
{
    public override string Key => "QG-JSON-BUG-0022";
    public override string[] Languages => ["json"];
}
