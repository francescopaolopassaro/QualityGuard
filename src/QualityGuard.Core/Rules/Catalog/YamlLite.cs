using System.Globalization;

namespace QualityGuard.Core.Rules.Catalog;

/// <summary>Mapping node with typed accessors.</summary>
public sealed class YamlMap : Dictionary<string, object?>
{
    public YamlMap() : base(StringComparer.OrdinalIgnoreCase) { }

    public string? Str(string key) => TryGetValue(key, out var value) ? value as string : null;

    public string Text(string key) => Str(key) ?? string.Empty;

    public string[] Strings(string key)
    {
        if (!TryGetValue(key, out var value) || value == null)
            return [];
        return value switch
        {
            List<object?> list => list.Select(v => v?.ToString() ?? string.Empty)
                .Where(v => v.Length > 0).ToArray(),
            string single => [single],
            _ => []
        };
    }

    public int[] Integers(string key)
        => Strings(key)
            .Select(v => int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : -1)
            .Where(n => n >= 0)
            .ToArray();

    public YamlMap? Map(string key) => TryGetValue(key, out var value) ? value as YamlMap : null;

    public List<YamlMap> Maps(string key)
    {
        if (!TryGetValue(key, out var value) || value is not List<object?> list)
            return [];
        return list.OfType<YamlMap>().ToList();
    }

    public bool Flag(string key)
    {
        var text = Str(key);
        return text is not null && (text.Equals("true", StringComparison.OrdinalIgnoreCase) || text == "1"
                                    || text.Equals("yes", StringComparison.OrdinalIgnoreCase));
    }

    public int? Number(string key)
        => int.TryParse(Str(key), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : null;
}

/// <summary>
/// Minimal YAML reader covering exactly what the rule catalog uses: sequences of mappings, nested
/// mappings, inline and block sequences, quoted scalars and <c>|</c> block text. Keeping it in-house
/// avoids adding a dependency just to read a data file.
/// </summary>
public static class YamlLite
{
    public static List<YamlMap> ParseSequence(string text)
    {
        var lines = Normalize(text);
        var index = 0;
        var value = ParseNode(lines, ref index, 0);
        return value switch
        {
            List<object?> list => list.OfType<YamlMap>().ToList(),
            YamlMap map => [map],
            _ => []
        };
    }

    private static List<string> Normalize(string text)
        => text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n').ToList();

    private static bool IsSkippable(string line)
    {
        var trimmed = line.TrimStart();
        return trimmed.Length == 0 || trimmed.StartsWith('#') || trimmed == "---";
    }

    private static int IndentOf(string line) => line.Length - line.TrimStart().Length;

    private static object? ParseNode(List<string> lines, ref int index, int indent)
    {
        SkipBlanks(lines, ref index);
        if (index >= lines.Count)
            return null;

        return lines[index].TrimStart().StartsWith("- ") || lines[index].TrimStart() == "-"
            ? ParseSequenceNode(lines, ref index, indent)
            : ParseMapNode(lines, ref index, indent);
    }

    private static List<object?> ParseSequenceNode(List<string> lines, ref int index, int indent)
    {
        var items = new List<object?>();
        while (true)
        {
            SkipBlanks(lines, ref index);
            if (index >= lines.Count)
                break;
            var line = lines[index];
            var currentIndent = IndentOf(line);
            var trimmed = line.TrimStart();
            if (currentIndent < indent || !trimmed.StartsWith('-'))
                break;

            var content = trimmed.Length > 1 ? trimmed[1..].TrimStart() : string.Empty;
            var contentIndent = currentIndent + (trimmed.Length - content.Length);
            if (content.Length == 0)
            {
                index++;
                items.Add(ParseNode(lines, ref index, currentIndent + 1));
                continue;
            }

            if (content.Contains(':') && !content.StartsWith('"') && !content.StartsWith('\''))
            {
                lines[index] = new string(' ', contentIndent) + content;
                items.Add(ParseMapNode(lines, ref index, contentIndent));
                continue;
            }

            index++;
            items.Add(Scalar(content));
        }
        return items;
    }

    private static YamlMap ParseMapNode(List<string> lines, ref int index, int indent)
    {
        var map = new YamlMap();
        while (true)
        {
            SkipBlanks(lines, ref index);
            if (index >= lines.Count)
                break;
            var line = lines[index];
            var currentIndent = IndentOf(line);
            var trimmed = line.TrimStart();
            if (currentIndent < indent || trimmed.StartsWith('-'))
                break;

            var colon = FindColon(trimmed);
            if (colon < 0)
            {
                index++;
                continue;
            }

            var key = trimmed[..colon].Trim().Trim('"', '\'');
            var rest = trimmed[(colon + 1)..].Trim();
            index++;

            if (rest is "|" or "|-" or "|+" or ">" or ">-")
            {
                map[key] = ReadBlockScalar(lines, ref index, currentIndent, rest.StartsWith('>'));
                continue;
            }
            if (rest.Length == 0)
            {
                var nested = ParseNode(lines, ref index, currentIndent + 1);
                map[key] = nested;
                continue;
            }
            if (rest.StartsWith('['))
            {
                map[key] = ParseInlineList(rest);
                continue;
            }
            map[key] = Scalar(rest);
        }
        return map;
    }

    private static int FindColon(string text)
    {
        var quote = '\0';
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (quote != '\0')
            {
                if (c == quote)
                    quote = '\0';
                continue;
            }
            if (c is '"' or '\'')
                quote = c;
            else if (c == ':' && (i + 1 == text.Length || text[i + 1] == ' '))
                return i;
        }
        return -1;
    }

    private static string ReadBlockScalar(List<string> lines, ref int index, int parentIndent, bool folded)
    {
        var content = new List<string>();
        var blockIndent = -1;
        while (index < lines.Count)
        {
            var line = lines[index];
            if (line.Trim().Length == 0)
            {
                content.Add(string.Empty);
                index++;
                continue;
            }
            var currentIndent = IndentOf(line);
            if (currentIndent <= parentIndent)
                break;
            blockIndent = blockIndent < 0 ? currentIndent : Math.Min(blockIndent, currentIndent);
            content.Add(line);
            index++;
        }
        while (content.Count > 0 && content[^1].Length == 0)
            content.RemoveAt(content.Count - 1);

        var dedented = content.Select(l => l.Length >= blockIndent && blockIndent > 0 ? l[blockIndent..] : l.TrimStart());
        return folded ? string.Join(' ', dedented).Trim() : string.Join('\n', dedented);
    }

    private static List<object?> ParseInlineList(string text)
    {
        var inner = text.Trim();
        if (inner.StartsWith('['))
            inner = inner[1..];
        if (inner.EndsWith(']'))
            inner = inner[..^1];

        var items = new List<object?>();
        var current = new System.Text.StringBuilder();
        var quote = '\0';
        foreach (var c in inner)
        {
            if (quote != '\0')
            {
                if (c == quote)
                    quote = '\0';
                else
                    current.Append(c);
                continue;
            }
            switch (c)
            {
                case '"' or '\'':
                    quote = c;
                    break;
                case ',':
                    AddItem(items, current);
                    break;
                default:
                    current.Append(c);
                    break;
            }
        }
        AddItem(items, current);
        return items;
    }

    private static void AddItem(List<object?> items, System.Text.StringBuilder buffer)
    {
        var value = buffer.ToString().Trim();
        if (value.Length > 0)
            items.Add(value);
        buffer.Clear();
    }

    private static void SkipBlanks(List<string> lines, ref int index)
    {
        while (index < lines.Count && IsSkippable(lines[index]))
            index++;
    }

    private static string Scalar(string text)
    {
        var value = text.Trim();
        var comment = FindComment(value);
        if (comment >= 0)
            value = value[..comment].TrimEnd();
        if (value.Length >= 2 && value[0] == '\'' && value[^1] == '\'')
            return value[1..^1];
        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
            return Unescape(value[1..^1]);
        return value;
    }

    /// <summary>Escape sequences of a double-quoted scalar; regex patterns depend on <c>\\</c>.</summary>
    private static string Unescape(string text)
    {
        var builder = new System.Text.StringBuilder(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] != '\\' || i + 1 >= text.Length)
            {
                builder.Append(text[i]);
                continue;
            }
            i++;
            builder.Append(text[i] switch
            {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '0' => '\0',
                _ => text[i]
            });
        }
        return builder.ToString();
    }

    private static int FindComment(string text)
    {
        var quote = '\0';
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (quote != '\0')
            {
                if (c == quote)
                    quote = '\0';
                continue;
            }
            if (c is '"' or '\'')
                quote = c;
            else if (c == '#' && i > 0 && text[i - 1] == ' ')
                return i;
        }
        return -1;
    }
}
