using System.Globalization;

namespace QualityGuard.Core.Analysis;

public enum RegexKind
{
    /// <summary>A run of elements matched one after the other.</summary>
    Sequence,

    /// <summary>Branches separated by a bar.</summary>
    Alternation,

    /// <summary>Anything written between parentheses, whatever it does.</summary>
    Group,

    /// <summary>A bracket expression, with the members it lists.</summary>
    CharacterClass,

    /// <summary>An element with the quantifier that follows it.</summary>
    Repetition,

    /// <summary>A single ordinary character.</summary>
    Literal,

    /// <summary>A backslash escape that stands for a character or a family of them.</summary>
    Escape,

    /// <summary>Something that holds at a position without reading a character.</summary>
    Anchor,

    /// <summary>A reference back to what a group captured.</summary>
    BackReference,

    /// <summary>The dot.</summary>
    Dot
}

public enum RegexGroupKind
{
    Capturing,
    NonCapturing,
    Named,
    LookAhead,
    NegativeLookAhead,
    LookBehind,
    NegativeLookBehind,

    /// <summary>An atomic group: what it matched is never given back.</summary>
    Atomic,

    /// <summary>A group that only turns flags on or off for what follows.</summary>
    FlagsOnly
}

public enum RegexRepeat
{
    Greedy,
    Lazy,

    /// <summary>Never backtracks: what it consumed stays consumed.</summary>
    Possessive
}

/// <summary>
/// One node of a parsed pattern. A single class rather than a hierarchy because rules read patterns
/// by walking and asking questions, and the fields that do not apply to a node stay at their default.
/// </summary>
public sealed class RegexNode
{
    public RegexKind Kind { get; init; }

    /// <summary>The pattern text this node was read from, unchanged.</summary>
    public string Text { get; init; } = string.Empty;

    /// <summary>Offset of <see cref="Text"/> inside the whole pattern.</summary>
    public int Start { get; init; }

    public List<RegexNode> Children { get; } = [];

    public RegexGroupKind GroupKind { get; init; }

    public string? GroupName { get; init; }

    /// <summary>Flag letters carried by a group prefix, with a minus in front of the ones turned off.</summary>
    public string GroupFlags { get; init; } = string.Empty;

    /// <summary>Ordinal number of a capturing group, counted from one; zero when the group captures nothing.</summary>
    public int CaptureNumber { get; init; }

    public bool Negated { get; init; }

    /// <summary>Members of a bracket expression, each kept as written.</summary>
    public IReadOnlyList<string> ClassItems { get; init; } = [];

    public int Min { get; init; }

    /// <summary>Upper bound of a repetition; -1 when there is none.</summary>
    public int Max { get; init; }

    public RegexRepeat RepeatMode { get; init; }

    /// <summary>Quantifier as written, suffix included.</summary>
    public string QuantifierText { get; init; } = string.Empty;

    /// <summary>Group number or name a back reference points at.</summary>
    public string Reference { get; init; } = string.Empty;

    /// <summary>The single child of a repetition or a group, or null when there is none.</summary>
    public RegexNode? Body => Children.Count == 1 ? Children[0] : null;

    public bool IsOptional => Kind == RegexKind.Repetition && Min == 0;

    public bool IsUnbounded => Kind == RegexKind.Repetition && Max < 0;

    public IEnumerable<RegexNode> Descendants()
    {
        foreach (var child in Children)
        {
            yield return child;
            foreach (var inner in child.Descendants())
                yield return inner;
        }
    }

    public IEnumerable<RegexNode> SelfAndDescendants()
    {
        yield return this;
        foreach (var node in Descendants())
            yield return node;
    }
}

/// <summary>
/// Reads a regular expression into a tree. It parses the constructs the flavours share and gives up —
/// returning null — on anything it cannot read with certainty, so a rule built on it can only fail by
/// staying quiet. Nothing here is flavour specific: what a pattern means under a given engine is the
/// rule's business, not the parser's.
/// </summary>
public static class RegexSyntax
{
    private static readonly char[] ZeroWidthEscapes = ['b', 'B', 'A', 'z', 'Z', 'G'];

    /// <summary>Parses a pattern; null when the text is not a regular expression this parser can read.</summary>
    public static RegexNode? Parse(string pattern)
    {
        if (string.IsNullOrEmpty(pattern))
            return null;
        var reader = new Reader(pattern);
        var root = reader.ReadAlternation();
        return root != null && reader.AtEnd ? root : null;
    }

    /// <summary>The flags a pattern turns on through a leading inline group, as written.</summary>
    public static string InlineFlags(string pattern)
    {
        var flags = string.Empty;
        var i = 0;
        while (i + 2 < pattern.Length && pattern[i] == '(' && pattern[i + 1] == '?')
        {
            var close = pattern.IndexOf(')', i);
            if (close < 0)
                break;
            var body = pattern[(i + 2)..close];
            if (body.Length == 0 || !body.All(IsFlagLetter))
                break;
            flags += body;
            i = close + 1;
        }
        return flags;
    }

    private static bool IsFlagLetter(char c) => c is 'i' or 'm' or 's' or 'x' or 'u' or 'U' or 'a' or 'l' or '-';

    /// <summary>The branches of an alternation, or the node itself when it is not one.</summary>
    public static IReadOnlyList<RegexNode> Branches(RegexNode node)
        => node.Kind == RegexKind.Alternation ? node.Children : [node];

    /// <summary>The elements of a sequence, or the node itself when it is not one.</summary>
    public static IReadOnlyList<RegexNode> Elements(RegexNode node)
        => node.Kind == RegexKind.Sequence ? node.Children : [node];

    /// <summary>Whether the node can match having read nothing at all.</summary>
    public static bool MatchesEmpty(RegexNode node) => node.Kind switch
    {
        RegexKind.Sequence => node.Children.All(MatchesEmpty),
        RegexKind.Alternation => node.Children.Any(MatchesEmpty),
        RegexKind.Repetition => node.Min == 0 || MatchesEmpty(node.Children[0]),
        RegexKind.Group => node.GroupKind is RegexGroupKind.FlagsOnly or RegexGroupKind.LookAhead
                               or RegexGroupKind.NegativeLookAhead or RegexGroupKind.LookBehind
                               or RegexGroupKind.NegativeLookBehind
                           || node.Children.Count == 0
                           || MatchesEmpty(node.Children[0]),
        RegexKind.Anchor => true,
        RegexKind.BackReference => true,
        _ => false
    };

    /// <summary>Whether the node must read at least one character for the match to go on.</summary>
    public static bool IsMandatory(RegexNode node) => !MatchesEmpty(node);

    /// <summary>
    /// The first element a node reads, looking through sequences, groups and repetitions. Null when the
    /// node reads nothing, or when the first element depends on a branch.
    /// </summary>
    public static RegexNode? FirstConsuming(RegexNode node)
    {
        switch (node.Kind)
        {
            case RegexKind.Sequence:
                foreach (var child in node.Children)
                {
                    var first = FirstConsuming(child);
                    if (first != null)
                        return first;
                    if (!MatchesEmpty(child))
                        return null;
                }
                return null;
            case RegexKind.Group:
                return node.Children.Count == 1 && node.GroupKind
                           is RegexGroupKind.Capturing or RegexGroupKind.NonCapturing
                           or RegexGroupKind.Named or RegexGroupKind.Atomic
                    ? FirstConsuming(node.Children[0])
                    : null;
            case RegexKind.Repetition:
                return FirstConsuming(node.Children[0]);
            case RegexKind.Literal:
            case RegexKind.Escape:
            case RegexKind.CharacterClass:
            case RegexKind.Dot:
                return node;
            default:
                return null;
        }
    }

    private sealed class Reader(string pattern)
    {
        private int _index;
        private int _captures;

        public bool AtEnd => _index >= pattern.Length;

        public RegexNode? ReadAlternation()
        {
            var start = _index;
            var branches = new List<RegexNode>();
            while (true)
            {
                var branch = ReadSequence();
                if (branch == null)
                    return null;
                branches.Add(branch);
                if (_index < pattern.Length && pattern[_index] == '|')
                {
                    _index++;
                    continue;
                }
                break;
            }
            if (branches.Count == 1)
                return branches[0];
            var node = new RegexNode
            {
                Kind = RegexKind.Alternation, Start = start, Text = pattern[start.._index]
            };
            node.Children.AddRange(branches);
            return node;
        }

        private RegexNode? ReadSequence()
        {
            var start = _index;
            var items = new List<RegexNode>();
            while (_index < pattern.Length && pattern[_index] != '|' && pattern[_index] != ')')
            {
                var atom = ReadAtom();
                if (atom == null)
                    return null;
                items.Add(ReadQuantifier(atom));
            }
            if (items.Count == 1)
                return items[0];
            var node = new RegexNode
            {
                Kind = RegexKind.Sequence, Start = start, Text = pattern[start.._index]
            };
            node.Children.AddRange(items);
            return node;
        }

        private RegexNode ReadQuantifier(RegexNode atom)
        {
            if (_index >= pattern.Length)
                return atom;
            var start = _index;
            int min;
            int max;
            switch (pattern[_index])
            {
                case '*':
                    min = 0;
                    max = -1;
                    _index++;
                    break;
                case '+':
                    min = 1;
                    max = -1;
                    _index++;
                    break;
                case '?':
                    min = 0;
                    max = 1;
                    _index++;
                    break;
                case '{':
                    var close = pattern.IndexOf('}', _index);
                    if (close < 0)
                        return atom;
                    var bounds = pattern[(_index + 1)..close];
                    if (!ReadBounds(bounds, out min, out max))
                        return atom; // '{a}' is a literal brace, not a count
                    _index = close + 1;
                    break;
                default:
                    return atom;
            }

            var mode = RegexRepeat.Greedy;
            if (_index < pattern.Length && pattern[_index] == '?')
            {
                mode = RegexRepeat.Lazy;
                _index++;
            }
            else if (_index < pattern.Length && pattern[_index] == '+')
            {
                mode = RegexRepeat.Possessive;
                _index++;
            }

            var node = new RegexNode
            {
                Kind = RegexKind.Repetition,
                Start = atom.Start,
                Text = pattern[atom.Start.._index],
                Min = min,
                Max = max,
                RepeatMode = mode,
                QuantifierText = pattern[start.._index]
            };
            node.Children.Add(atom);
            return node;
        }

        private static bool ReadBounds(string bounds, out int min, out int max)
        {
            min = 0;
            max = -1;
            if (bounds.Length == 0)
                return false;
            var comma = bounds.IndexOf(',');
            if (comma < 0)
            {
                if (!int.TryParse(bounds, NumberStyles.None, CultureInfo.InvariantCulture, out min))
                    return false;
                max = min;
                return true;
            }
            var low = bounds[..comma];
            var high = bounds[(comma + 1)..];
            if (!int.TryParse(low, NumberStyles.None, CultureInfo.InvariantCulture, out min))
                return false;
            if (high.Length == 0)
                return true;
            return int.TryParse(high, NumberStyles.None, CultureInfo.InvariantCulture, out max);
        }

        private RegexNode? ReadAtom()
        {
            var c = pattern[_index];
            return c switch
            {
                '(' => ReadGroup(),
                '[' => ReadCharacterClass(),
                '\\' => ReadEscape(),
                '^' or '$' => Single(RegexKind.Anchor),
                '.' => Single(RegexKind.Dot),
                '*' or '+' or '?' => null, // a quantifier with nothing to repeat: not a pattern we read
                _ => Single(RegexKind.Literal)
            };
        }

        private RegexNode Single(RegexKind kind)
        {
            var start = _index;
            var length = char.IsHighSurrogate(pattern[_index]) && _index + 1 < pattern.Length ? 2 : 1;
            _index += length;
            return new RegexNode { Kind = kind, Start = start, Text = pattern[start.._index] };
        }

        private RegexNode? ReadGroup()
        {
            var start = _index;
            _index++; // '('
            var kind = RegexGroupKind.Capturing;
            string? name = null;
            var flags = string.Empty;
            var capture = 0;

            if (_index < pattern.Length && pattern[_index] == '?')
            {
                var rest = pattern[_index..];
                if (rest.StartsWith("?:", StringComparison.Ordinal))
                {
                    kind = RegexGroupKind.NonCapturing;
                    _index += 2;
                }
                else if (rest.StartsWith("?=", StringComparison.Ordinal))
                {
                    kind = RegexGroupKind.LookAhead;
                    _index += 2;
                }
                else if (rest.StartsWith("?!", StringComparison.Ordinal))
                {
                    kind = RegexGroupKind.NegativeLookAhead;
                    _index += 2;
                }
                else if (rest.StartsWith("?<=", StringComparison.Ordinal))
                {
                    kind = RegexGroupKind.LookBehind;
                    _index += 3;
                }
                else if (rest.StartsWith("?<!", StringComparison.Ordinal))
                {
                    kind = RegexGroupKind.NegativeLookBehind;
                    _index += 3;
                }
                else if (rest.StartsWith("?>", StringComparison.Ordinal))
                {
                    kind = RegexGroupKind.Atomic;
                    _index += 2;
                }
                else if (rest.StartsWith("?P=", StringComparison.Ordinal))
                {
                    // '(?P=name)' is a back reference written as a group, the way Python spells it
                    var close = pattern.IndexOf(')', _index);
                    if (close < 0)
                        return null;
                    var reference = pattern[(_index + 3)..close];
                    _index = close + 1;
                    return new RegexNode
                    {
                        Kind = RegexKind.BackReference, Reference = reference,
                        Start = start, Text = pattern[start.._index]
                    };
                }
                else if (rest.StartsWith("?P<", StringComparison.Ordinal) || rest.StartsWith("?<", StringComparison.Ordinal)
                                                                          || rest.StartsWith("?'", StringComparison.Ordinal))
                {
                    var open = rest.StartsWith("?P<", StringComparison.Ordinal) ? _index + 3 : _index + 2;
                    var terminator = pattern[open - 1] == '\'' ? '\'' : '>';
                    var close = pattern.IndexOf(terminator, open);
                    if (close < 0)
                        return null;
                    kind = RegexGroupKind.Named;
                    name = pattern[open..close];
                    capture = ++_captures;
                    _index = close + 1;
                }
                else
                {
                    // '(?i)' and '(?i:...)': flags, either for what follows or for the group only
                    var scan = _index + 1;
                    while (scan < pattern.Length && IsFlagLetter(pattern[scan]))
                        scan++;
                    if (scan >= pattern.Length || (pattern[scan] != ')' && pattern[scan] != ':'))
                        return null;
                    flags = pattern[(_index + 1)..scan];
                    kind = pattern[scan] == ')' ? RegexGroupKind.FlagsOnly : RegexGroupKind.NonCapturing;
                    _index = pattern[scan] == ')' ? scan : scan + 1;
                }
            }
            else
            {
                capture = ++_captures;
            }

            RegexNode? body = null;
            if (kind != RegexGroupKind.FlagsOnly)
            {
                body = ReadAlternation();
                if (body == null)
                    return null;
            }
            if (_index >= pattern.Length || pattern[_index] != ')')
                return null;
            _index++;

            var node = new RegexNode
            {
                Kind = RegexKind.Group,
                GroupKind = kind,
                GroupName = name,
                GroupFlags = flags,
                CaptureNumber = capture,
                Start = start,
                Text = pattern[start.._index]
            };
            if (body != null)
                node.Children.Add(body);
            return node;
        }

        private RegexNode ReadCharacterClass()
        {
            var start = _index;
            _index++; // '['
            var negated = _index < pattern.Length && pattern[_index] == '^';
            if (negated)
                _index++;
            var items = new List<string>();
            var first = true;
            while (_index < pattern.Length)
            {
                var c = pattern[_index];
                if (c == ']' && !first)
                    break;
                first = false;
                var itemStart = _index;
                if (c == '\\' && _index + 1 < pattern.Length)
                    _index += 2;
                else if (char.IsHighSurrogate(c) && _index + 1 < pattern.Length)
                    _index += 2;
                else
                    _index++;
                // a range keeps its two ends and the dash as one member
                if (_index < pattern.Length && pattern[_index] == '-' && _index + 1 < pattern.Length
                    && pattern[_index + 1] != ']')
                {
                    _index++;
                    if (pattern[_index] == '\\' && _index + 1 < pattern.Length)
                        _index += 2;
                    else
                        _index++;
                }
                items.Add(pattern[itemStart.._index]);
            }
            if (_index < pattern.Length)
                _index++; // ']'

            return new RegexNode
            {
                Kind = RegexKind.CharacterClass,
                Negated = negated,
                ClassItems = items,
                Start = start,
                Text = pattern[start.._index]
            };
        }

        private RegexNode ReadEscape()
        {
            var start = _index;
            _index++; // backslash
            if (_index >= pattern.Length)
                return new RegexNode { Kind = RegexKind.Literal, Start = start, Text = pattern[start..] };

            var c = pattern[_index];
            _index++;

            if (c == 'k' && _index < pattern.Length && (pattern[_index] == '<' || pattern[_index] == '{'))
            {
                var close = pattern.IndexOf(pattern[_index] == '<' ? '>' : '}', _index);
                if (close > 0)
                {
                    var name = pattern[(_index + 1)..close];
                    _index = close + 1;
                    return new RegexNode
                    {
                        Kind = RegexKind.BackReference, Reference = name,
                        Start = start, Text = pattern[start.._index]
                    };
                }
            }

            if (char.IsAsciiDigit(c) && c != '0')
            {
                while (_index < pattern.Length && char.IsAsciiDigit(pattern[_index]))
                    _index++;
                return new RegexNode
                {
                    Kind = RegexKind.BackReference, Reference = pattern[(start + 1).._index],
                    Start = start, Text = pattern[start.._index]
                };
            }

            // '\p{L}', '\x{1F600}' and friends carry a braced argument that belongs to the escape
            if (_index < pattern.Length && pattern[_index] == '{' && c is 'p' or 'P' or 'x' or 'u' or 'N')
            {
                var close = pattern.IndexOf('}', _index);
                if (close > 0)
                    _index = close + 1;
            }
            else if (c is 'x' && _index + 1 < pattern.Length && char.IsAsciiHexDigit(pattern[_index])
                     && char.IsAsciiHexDigit(pattern[_index + 1]))
            {
                _index += 2;
            }
            else if (c == 'u' && _index + 3 < pattern.Length && pattern[_index..(_index + 4)].All(char.IsAsciiHexDigit))
            {
                _index += 4;
            }
            else if (c == 'c' && _index < pattern.Length)
            {
                _index++;
            }
            else if (c == '0')
            {
                while (_index < pattern.Length && pattern[_index] is >= '0' and <= '7')
                    _index++;
            }

            var kind = ZeroWidthEscapes.Contains(c) ? RegexKind.Anchor : RegexKind.Escape;
            return new RegexNode { Kind = kind, Start = start, Text = pattern[start.._index] };
        }
    }
}

/// <summary>
/// The characters an element can match, as far as it can be told. Rules use it to answer one question
/// only — can these two elements ever match the same character — and every operation keeps
/// <see cref="Known"/> false when the answer would be a guess.
/// </summary>
public sealed class RegexCharSet
{
    private readonly bool[] _ascii = new bool[128];

    private RegexCharSet(bool known) => Known = known;

    /// <summary>False when the element was not understood; nothing may be concluded from the set then.</summary>
    public bool Known { get; private set; }

    /// <summary>Whether characters outside the ASCII range are matched too.</summary>
    public bool IncludesNonAscii { get; private set; }

    public static RegexCharSet Unknown { get; } = new(false);

    public bool Intersects(RegexCharSet other)
    {
        if (!Known || !other.Known)
            return true; // unknown means "maybe", and a rule must stay quiet on maybe
        if (IncludesNonAscii && other.IncludesNonAscii)
            return true;
        for (var i = 0; i < _ascii.Length; i++)
        {
            if (_ascii[i] && other._ascii[i])
                return true;
        }
        return false;
    }

    /// <summary>Whether every character this set matches is matched by the other one too.</summary>
    public bool IsSubsetOf(RegexCharSet other)
    {
        if (!Known || !other.Known)
            return false;
        if (IncludesNonAscii && !other.IncludesNonAscii)
            return false;
        for (var i = 0; i < _ascii.Length; i++)
        {
            if (_ascii[i] && !other._ascii[i])
                return false;
        }
        return true;
    }

    /// <summary>The characters one element of a pattern can match; unknown for anything else.</summary>
    public static RegexCharSet Of(RegexNode node)
    {
        switch (node.Kind)
        {
            case RegexKind.Literal:
                return node.Text.Length == 1 ? Single(node.Text[0]) : NonAsciiOnly();
            case RegexKind.Escape:
                return OfEscape(node.Text);
            case RegexKind.CharacterClass:
                return OfClass(node);
            case RegexKind.Repetition:
            case RegexKind.Group:
                return node.Children.Count == 1 ? Of(node.Children[0]) : Unknown;
            default:
                return Unknown;
        }
    }

    private static RegexCharSet Single(char c)
    {
        var set = new RegexCharSet(true);
        set.Add(c);
        return set;
    }

    private static RegexCharSet NonAsciiOnly()
    {
        var set = new RegexCharSet(true) { IncludesNonAscii = true };
        return set;
    }

    private static RegexCharSet OfEscape(string text)
    {
        if (text.Length < 2 || text[0] != '\\')
            return Unknown;
        var set = new RegexCharSet(true);
        switch (text[1])
        {
            case 'd':
                set.AddRange('0', '9');
                return set;
            case 'D':
                set.AddAllAscii();
                set.RemoveRange('0', '9');
                set.IncludesNonAscii = true;
                return set;
            case 'w':
                set.AddWord();
                return set;
            case 'W':
                set.AddAllAscii();
                set.RemoveRange('a', 'z');
                set.RemoveRange('A', 'Z');
                set.RemoveRange('0', '9');
                set.Remove('_');
                set.IncludesNonAscii = true;
                return set;
            case 's':
                foreach (var c in " \t\n\r\f\v")
                    set.Add(c);
                return set;
            case 'S':
                set.AddAllAscii();
                foreach (var c in " \t\n\r\f\v")
                    set.Remove(c);
                set.IncludesNonAscii = true;
                return set;
            case 'n':
                return Single('\n');
            case 'r':
                return Single('\r');
            case 't':
                return Single('\t');
            case 'f':
                return Single('\f');
            case 'e':
                return Single((char)27);
            case 'a':
                return Single((char)7);
        }
        if (text.Length == 2 && !char.IsAsciiLetterOrDigit(text[1]))
            return Single(text[1]); // an escaped punctuation character stands for itself
        return Unknown;
    }

    private static RegexCharSet OfClass(RegexNode node)
    {
        var inner = new RegexCharSet(true);
        foreach (var item in node.ClassItems)
        {
            if (item.Length == 3 && item[1] == '-')
            {
                if (item[0] > item[2])
                    return Unknown;
                inner.AddRange(item[0], item[2]);
            }
            else if (item.Length == 1)
            {
                inner.Add(item[0]);
            }
            else if (item.Length == 2 && item[0] == '\\')
            {
                var escape = OfEscape(item);
                if (!escape.Known)
                    return Unknown;
                inner.Union(escape);
            }
            else
            {
                return Unknown;
            }
        }
        if (!node.Negated)
            return inner;

        var negated = new RegexCharSet(true) { IncludesNonAscii = !inner.IncludesNonAscii };
        negated.AddAllAscii();
        for (var i = 0; i < inner._ascii.Length; i++)
        {
            if (inner._ascii[i])
                negated._ascii[i] = false;
        }
        return negated;
    }

    private void Add(char c)
    {
        if (c < 128)
            _ascii[c] = true;
        else
            IncludesNonAscii = true;
        Known = true;
    }

    private void Remove(char c)
    {
        if (c < 128)
            _ascii[c] = false;
    }

    private void AddRange(char from, char to)
    {
        for (var c = from; c <= to; c++)
        {
            Add(c);
            if (c == char.MaxValue)
                break;
        }
    }

    private void RemoveRange(char from, char to)
    {
        for (var c = from; c <= to; c++)
            Remove(c);
    }

    private void AddAllAscii()
    {
        for (var c = 0; c < 128; c++)
            _ascii[c] = true;
        Known = true;
    }

    private void AddWord()
    {
        AddRange('a', 'z');
        AddRange('A', 'Z');
        AddRange('0', '9');
        Add('_');
    }

    private void Union(RegexCharSet other)
    {
        for (var i = 0; i < _ascii.Length; i++)
        {
            if (other._ascii[i])
                _ascii[i] = true;
        }
        IncludesNonAscii |= other.IncludesNonAscii;
        Known = true;
    }
}
