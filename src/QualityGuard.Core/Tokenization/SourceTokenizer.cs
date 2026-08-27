namespace QualityGuard.Core.Tokenization;

public sealed class SourceTokenizer
{
    private readonly LanguageInfo _language;
    private readonly string _source;
    private readonly List<Token> _tokens = new();

    private const int MaxRegexLen = 8;

    public SourceTokenizer(string source, LanguageInfo language)
    {
        _source = source;
        _language = language;
    }

    public IReadOnlyList<Token> Tokenize()
    {
        var i = 0;
        var line = 1;
        var column = 1;

        while (i < _source.Length)
        {
            var c = _source[i];

            if (IsLineCommentStart(_source, i) || IsDirective(i))
            {
                i = ReadUntilLineEnd(i, ref line, ref column);
                continue;
            }

            if (IsBlockCommentStart(_source, i, out var startLen))
            {
                var startLine = line;
                var startColumn = column;
                i = ReadBlockComment(i + startLen, startLen, ref line, ref column, out var body);
                _tokens.Add(DirectToken(TokenKind.Comment, body, startLine, startColumn));
                continue;
            }

            if (c == '/' && StartsRegexLiteral(i))
            {
                var startLine = line;
                var startColumn = column;
                i = ReadRegexLiteral(i, ref line, ref column, out var pattern);
                _tokens.Add(DirectToken(TokenKind.String, pattern, startLine, startColumn));
                continue;
            }

            if (TryMatchString(_source, i, out var delim))
            {
                var startLine = line;
                var startColumn = column;
                // '$"a {(b ? $"\"{c}\"" : "d")} e"' holds a whole expression between the braces,
                // quotes included. Reading the first inner quote as the end of the literal left the
                // rest of the file as code, which cost every rule below that line.
                i = ReadString(i + delim.Start.Length, delim, ref line, ref column, out var value,
                    delim.IsInterpolated);
                // the parser knows an interpolated literal by the '$' in front of it, so the prefix
                // stays a token of its own even though the delimiter now carries it. A Python 'f'
                // prefix is not that marker: emitting one moved the string one token further away
                // and every token-based rule stopped finding it.
                if (delim.Start.Contains('$'))
                    _tokens.Add(DirectToken(TokenKind.Symbol, "$", startLine, startColumn));
                _tokens.Add(DirectToken(TokenKind.String, value, startLine, startColumn, delim.Prefix));
                continue;
            }

            if (ReadsLifetime(_source, i))
            {
                var j = i + 1;
                while (j < _source.Length && (char.IsLetterOrDigit(_source[j]) || _source[j] == '_'))
                    j++;
                var text = _source[i..j];
                _tokens.Add(DirectToken(TokenKind.Identifier, text, line, column));
                column += text.Length;
                i = j;
                continue;
            }

            if (char.IsWhiteSpace(c))
            {
                if (c == '\n')
                {
                    line++;
                    column = 1;
                }
                else
                {
                    column++;
                }
                i++;
                continue;
            }

            if (IsNumberStart(_source, i, out var numLen))
            {
                var startLine = line;
                var startColumn = column;
                _tokens.Add(DirectToken(TokenKind.Number, _source.Substring(i, numLen), startLine, startColumn));
                i += numLen;
                column += numLen;
                continue;
            }

            if (IsIdentifierStart(c))
            {
                var startLine = line;
                var startColumn = column;
                var len = 1;
                while (i + len < _source.Length && IsIdentifierPart(_source[i + len]))
                    len++;
                var word = _source.Substring(i, len);
                var kind = _language.Keywords.Contains(word, _language.CaseInsensitiveKeywords ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal)
                    ? TokenKind.Keyword
                    : TokenKind.Identifier;
                _tokens.Add(DirectToken(kind, word, startLine, startColumn));
                i += len;
                column += len;
                continue;
            }

            // multi-char operators / punctuation
            var symLen = FindSymbolLength(_source, i);
            var symStartLine = line;
            var symStartColumn = column;
            _tokens.Add(DirectToken(TokenKind.Symbol, _source.Substring(i, symLen), symStartLine, symStartColumn));
            i += symLen;
            column += symLen;
        }
        return _tokens;
    }

    /// <summary>
    /// A preprocessor directive: '#' as the first thing on the line. Left as code it reads as an
    /// operator followed by a keyword, so '#if false' opened a branch that swallowed the declarations
    /// under it and '#endif' turned the next line into a field named 'public'. Every rule downstream
    /// then reported on something nobody wrote.
    /// </summary>
    private bool IsDirective(int i)
    {
        if (!_language.LineDirectives || _source[i] != '#')
            return false;
        for (var back = i - 1; back >= 0; back--)
        {
            if (_source[back] == '\n')
                break;
            if (!char.IsWhiteSpace(_source[back]))
                return false;
        }
        return true;
    }

    private int ReadUntilLineEnd(int i, ref int line, ref int column)
    {
        var start = i;
        while (i < _source.Length && _source[i] != '\n')
        {
            i++;
            column++;
        }
        _tokens.Add(DirectToken(TokenKind.Comment, _source.Substring(start, i - start), line, column - (i - start)));
        return i;
    }

    private static Token DirectToken(TokenKind kind, string text, int line, int column, string prefix = "")
        => new(kind, text, line, column, prefix);

    private bool IsLineCommentStart(string src, int i)
    {
        if (_language.LineComment != null && i + _language.LineComment.Length <= src.Length
            && src.Substring(i, _language.LineComment.Length) == _language.LineComment)
            return true;
        if (_language.HashComments && src[i] == '#')
            return true;
        return false;
    }

    private bool IsBlockCommentStart(string src, int i, out int startLen)
    {
        startLen = 0;
        if (_language.BlockCommentStart == null)
            return false;
        if (i + _language.BlockCommentStart.Length <= src.Length
            && src.Substring(i, _language.BlockCommentStart.Length) == _language.BlockCommentStart)
        {
            startLen = _language.BlockCommentStart.Length;
            return true;
        }
        return false;
    }

    private int ReadBlockComment(int i, int startLen, ref int line, ref int column, out string body)
    {
        var end = _language.BlockCommentEnd ?? _language.BlockCommentStart!;
        var startPos = i;
        var depth = 1;
        while (i < _source.Length)
        {
            if (_language.NestingBlockComments && _language.BlockCommentStart != null
                && i + _language.BlockCommentStart.Length <= _source.Length
                && _source.Substring(i, _language.BlockCommentStart.Length) == _language.BlockCommentStart)
            {
                depth++;
                i += _language.BlockCommentStart.Length;
                column += _language.BlockCommentStart.Length;
                continue;
            }
            if (i + end.Length <= _source.Length && _source.Substring(i, end.Length) == end)
            {
                depth--;
                i += end.Length;
                column += end.Length;
                if (depth == 0)
                    break;
                continue;
            }
            if (_source[i] == '\n')
            {
                line++;
                column = 1;
            }
            else
            {
                column++;
            }
            i++;
        }
        body = _source.Substring(startPos, i - startPos - (depth == 0 ? end.Length : 0));
        return i;
    }

    /// <summary>
    /// Letters that may stand in front of a quote and still leave a string: r for raw, f for a
    /// formatted one, b for bytes, u for unicode, and the pairs of those. Reading the letter as an
    /// identifier and the quote as a separate string made every r"..." pattern look like an
    /// expression, so a rule asking "is this argument a literal?" answered no.
    /// </summary>
    private static readonly string[] StringPrefixes =
        ["rb", "br", "rf", "fr", "r", "f", "b", "u", "R", "F", "B", "U", "Rb", "bR"];

    private bool TryMatchString(string src, int i, out StringDelimiter delim)
    {
        // strings are tried with the longest start first
        foreach (var d in _language.StringDelimiters.OrderByDescending(d => d.Start.Length))
        {
            if (i + d.Start.Length <= src.Length && src.Substring(i, d.Start.Length) == d.Start)
            {
                delim = d;
                return true;
            }
        }

        if (AllowsStringPrefix)
        {
            foreach (var prefix in StringPrefixes)
            {
                if (i + prefix.Length >= src.Length
                    || !src.AsSpan(i).StartsWith(prefix, StringComparison.Ordinal))
                    continue;
                // the letters must open the literal, not end an identifier
                if (i > 0 && (char.IsLetterOrDigit(src[i - 1]) || src[i - 1] == '_'))
                    break;
                foreach (var d in _language.StringDelimiters.OrderByDescending(d => d.Start.Length))
                {
                    if (i + prefix.Length + d.Start.Length > src.Length
                        || src.Substring(i + prefix.Length, d.Start.Length) != d.Start)
                        continue;
                    delim = d with { Start = prefix + d.Start };
                    return true;
                }
            }
        }

        delim = null!;
        return false;
    }

    /// <summary>Languages that write a prefix in front of a string literal.</summary>
    private bool AllowsStringPrefix
        => _language.LanguageKey is LanguageKeys.Python or LanguageKeys.Rust;

    /// <summary>
    /// Whether the apostrophe at this position opens a Rust lifetime rather than a character
    /// literal. A lifetime is a quote, an identifier run, and then anything but another quote —
    /// 'a, 'static, '_. The same shape closed by a quote ('x') is a character literal and goes to
    /// the normal reader. Deciding from the quote alone swallowed everything up to the next
    /// apostrophe in the file into one literal.
    /// </summary>
    private bool ReadsLifetime(string src, int i)
    {
        if (!_language.HasLifetimes || i + 1 >= src.Length || src[i] != '\'')
            return false;
        var c = src[i + 1];
        if (!char.IsLetter(c) && c != '_')
            return false;
        var j = i + 2;
        while (j < src.Length && (char.IsLetterOrDigit(src[j]) || src[j] == '_'))
            j++;
        return j >= src.Length || src[j] != '\'';
    }

    /// <summary>
    /// Whether the slash at this position opens a regular expression rather than a division. Only
    /// JavaScript and its relatives have the literal, and only the previous token can tell the two
    /// apart: a value can be divided, an operator or a keyword cannot. Getting this wrong is not a
    /// detail — a pattern such as /"([^"]+)"/ contains quotes, and reading it as division leaves the
    /// tokenizer inside a string for the rest of the file.
    /// </summary>
    private bool StartsRegexLiteral(int i)
    {
        if (_language.LanguageKey is not (LanguageKeys.JavaScript or LanguageKeys.TypeScript))
            return false;
        if (i + 1 >= _source.Length || _source[i + 1] is '/' or '*' or '=')
            return false;

        for (var back = _tokens.Count - 1; back >= 0; back--)
        {
            var previous = _tokens[back];
            if (previous.Kind == TokenKind.Comment)
                continue;
            if (previous.Kind is TokenKind.Identifier or TokenKind.Number or TokenKind.String)
                return false;
            if (previous.Kind == TokenKind.Keyword)
                return previous.Text is not ("this" or "super" or "true" or "false" or "null");
            return previous.Text is not (")" or "]" or "++" or "--");
        }
        return true;
    }

    /// <summary>Reads a regular expression literal and returns its pattern, without the delimiters.</summary>
    private int ReadRegexLiteral(int i, ref int line, ref int column, out string pattern)
    {
        var sb = new System.Text.StringBuilder();
        i++;
        column++;
        var inClass = false;

        while (i < _source.Length)
        {
            var c = _source[i];
            if (c == '\n')
                break; // a literal never spans lines: whatever this is, it is not one

            if (c == '\\' && i + 1 < _source.Length)
            {
                sb.Append(c).Append(_source[i + 1]);
                i += 2;
                column += 2;
                continue;
            }
            if (c == '[')
                inClass = true;
            else if (c == ']')
                inClass = false;
            else if (c == '/' && !inClass)
            {
                i++;
                column++;
                break;
            }

            sb.Append(c);
            i++;
            column++;
        }

        // The flags belong to the literal, not to the code that follows it — and they change what
        // the pattern means, so they are carried back as an inline group. Without them a rule cannot
        // tell '/x/g' from '/x/', and every rule about a flag was blind.
        var flagStart = i;
        while (i < _source.Length && char.IsAsciiLetter(_source[i]))
        {
            i++;
            column++;
        }

        var flags = _source[flagStart..i];
        pattern = flags.Length > 0 ? "(?" + flags + ")" + sb : sb.ToString();
        return i;
    }

    private int ReadString(int i, StringDelimiter delim, ref int line, ref int column, out string value,
        bool interpolated = false)
    {
        var sb = new System.Text.StringBuilder();
        var hole = 0;
        while (i < _source.Length)
        {
            if (interpolated && _source[i] == '{')
            {
                // '{{' is a brace the string prints, not a hole it opens
                if (i + 1 < _source.Length && _source[i + 1] == '{')
                {
                    sb.Append("{{");
                    i += 2;
                    column += 2;
                    continue;
                }
                hole++;
            }
            else if (interpolated && _source[i] == '}' && hole > 0)
            {
                hole--;
            }

            if (hole == 0
                && i + delim.End.Length <= _source.Length && _source.Substring(i, delim.End.Length) == delim.End)
            {
                // VB, SQL and Pascal escape the delimiter by doubling it: "URL=([^""]+)" holds one
                // quote, not the end of the string. Reading it as the end cut the literal in half and
                // left the rest of the line as code, so a regular expression came out unbalanced and
                // was reported as a pattern that cannot compile. An empty literal is written the same
                // way, so the escape only applies once the string has content.
                var doubled = i + delim.End.Length * 2 <= _source.Length
                              && _source.Substring(i + delim.End.Length, delim.End.Length) == delim.End;
                if (doubled && sb.Length > 0 && !delim.IsVerbatim && delim.Start == delim.End)
                {
                    sb.Append(delim.End);
                    i += delim.End.Length * 2;
                    column += delim.End.Length * 2;
                    continue;
                }

                i += delim.End.Length;
                column += delim.End.Length;
                value = sb.ToString();
                return i;
            }
            if ((delim.IsRaw || delim.PreserveBackslashes) && _source[i] == '\\' && i + 1 < _source.Length)
            {
                sb.Append(_source[i]).Append(_source[i + 1]);
                i += 2;
                column += 2;
                continue;
            }
            if (!delim.IsVerbatim && _source[i] == '\\' && i + 1 < _source.Length)
            {
                sb.Append(_source[i + 1]);
                i += 2;
                column += 2;
                continue;
            }
            if (_source[i] == '\n')
            {
                line++;
                column = 1;
                sb.Append('\n');
            }
            else
            {
                column++;
                sb.Append(_source[i]);
            }
            i++;
        }
        value = sb.ToString();
        return i;
    }

    private static bool IsNumberStart(string src, int i, out int len)
    {
        var c = src[i];
        if (!char.IsDigit(c) && !(c == '.' && i + 1 < src.Length && char.IsDigit(src[i + 1])))
        {
            len = 0;
            return false;
        }
        len = 1;
        while (i + len < src.Length)
        {
            var ch = src[i + len];
            if (char.IsLetterOrDigit(ch) || ch == '.' || ch == '_')
                len++;
            else
                break;
        }
        return true;
    }

    private static bool IsIdentifierStart(char c) => char.IsLetter(c) || c == '_' || c == '$';

    private static bool IsIdentifierPart(char c) => char.IsLetterOrDigit(c) || c == '_' || c == '$';

    private int FindSymbolLength(string src, int i)
    {
        var three = i + 3 <= src.Length ? src.Substring(i, 3) : null;
        if (three is "===" or "!==" or "??=" or "<<=" or ">>=" or "..." or "?->" or "<=>" or ">>>")
            return 3;

        var two = i + 2 <= src.Length ? src.Substring(i, 2) : null;
        return two is "&&" or "||" or "==" or "!=" or "<=" or ">=" or "++" or "--" or "->" or "=>" or "??"
            or "**" or "::" or "//" or "/*" or "*/" or "+=" or "-=" or "*=" or "/=" or "%=" or "&=" or "|="
            or "^=" or "?." or "?[" or "<<" or ">>" or "|>" or ":="
            ? 2
            : 1;
    }
}