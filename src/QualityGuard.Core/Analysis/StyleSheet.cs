namespace QualityGuard.Core.Analysis;

/// <summary>One declaration: <c>color: red !important;</c>.</summary>
public sealed record StyleDeclaration(string Property, string Value, bool Important, int Line);

/// <summary>A rule set, an at-rule, or a nested block of a preprocessor sheet.</summary>
public sealed class StyleRule
{
    /// <summary>Selector text, or the at-rule header including its prelude.</summary>
    public required string Selector { get; init; }

    public required int Line { get; init; }

    public bool IsAtRule => Selector.StartsWith('@');

    public StyleRule? Parent { get; set; }

    public List<StyleDeclaration> Declarations { get; } = [];

    public List<StyleRule> Children { get; } = [];

    /// <summary>
    /// Levels of nesting above this block, counted from the top level of the sheet: a rule written at
    /// the top has depth 0, and only a preprocessor sheet goes deep.
    /// </summary>
    public int Depth
    {
        get
        {
            var depth = -1;
            for (var node = Parent; node != null; node = node.Parent)
                depth++;
            return Math.Max(0, depth);
        }
    }

    /// <summary>
    /// The selector together with the blocks it is written inside. Two '&amp;.hidden' under different
    /// parents are two different selectors, and comparing only their own text made every nested
    /// override in a stylesheet look like a duplicate of the others.
    /// </summary>
    public string Path
    {
        get
        {
            var parts = new List<string>();
            for (var node = this; node != null; node = node.Parent)
            {
                if (node.Selector.Length > 0)
                    parts.Add(node.Selector);
            }
            parts.Reverse();
            return string.Join(" ", parts);
        }
    }

    public IEnumerable<StyleRule> Descendants()
    {
        foreach (var child in Children)
        {
            yield return child;
            foreach (var nested in child.Descendants())
                yield return nested;
        }
    }
}

/// <summary>
/// A stylesheet read as blocks and declarations rather than as text.
///
/// Style defects are almost all about a relationship: the same property set twice in one block, a
/// shorthand followed by the longhand it just overrode, a selector repeated three screens apart. None
/// of that is visible to a line pattern, and a stylesheet is small enough to parse properly — so the
/// reader below handles plain CSS and the preprocessor dialects (SCSS, Sass, Less) in one pass, which
/// is what lets one rule serve all four.
/// </summary>
public static class StyleSheet
{
    public static StyleRule Parse(string content)
    {
        var root = new StyleRule { Selector = string.Empty, Line = 0 };
        var current = root;
        var buffer = new System.Text.StringBuilder();
        var line = 1;
        var bufferLine = 1;

        for (var i = 0; i < content.Length; i++)
        {
            var c = content[i];

            if (c == '\n')
            {
                line++;
                if (buffer.Length == 0)
                    bufferLine = line;
                buffer.Append(' ');
                continue;
            }

            // comments never carry structure, and a brace inside one would close a block
            if (c == '/' && i + 1 < content.Length && content[i + 1] == '*')
            {
                var end = content.IndexOf("*/", i + 2, StringComparison.Ordinal);
                var stop = end < 0 ? content.Length : end + 2;
                line += content[i..stop].Count(ch => ch == '\n');
                i = stop - 1;
                continue;
            }
            if (c == '/' && i + 1 < content.Length && content[i + 1] == '/')
            {
                var end = content.IndexOf('\n', i);
                if (end < 0)
                    break;
                i = end - 1;
                continue;
            }
            if (c is '"' or '\'')
            {
                var quote = c;
                var end = i + 1;
                while (end < content.Length && content[end] != quote)
                {
                    if (content[end] == '\\')
                        end++;
                    end++;
                }
                buffer.Append(content[i..Math.Min(end + 1, content.Length)]);
                i = Math.Min(end, content.Length - 1);
                continue;
            }

            switch (c)
            {
                case '{':
                {
                    var selector = buffer.ToString().Trim();
                    buffer.Clear();
                    var rule = new StyleRule { Selector = selector, Line = bufferLine, Parent = current };
                    current.Children.Add(rule);
                    current = rule;
                    bufferLine = line;
                    continue;
                }
                case '}':
                {
                    AddDeclaration(current, buffer.ToString(), bufferLine);
                    buffer.Clear();
                    current = current.Parent ?? root;
                    bufferLine = line;
                    continue;
                }
                case ';':
                {
                    AddDeclaration(current, buffer.ToString(), bufferLine);
                    buffer.Clear();
                    bufferLine = line;
                    continue;
                }
                default:
                    if (buffer.Length == 0 && !char.IsWhiteSpace(c))
                        bufferLine = line;
                    buffer.Append(c);
                    continue;
            }
        }

        return root;
    }

    private static void AddDeclaration(StyleRule rule, string text, int line)
    {
        text = text.Trim();
        if (text.Length == 0)
            return;
        // an at-rule without a block (@import, @charset) is a statement, not a declaration
        if (text.StartsWith('@'))
        {
            rule.Children.Add(new StyleRule { Selector = text, Line = line, Parent = rule });
            return;
        }

        var colon = text.IndexOf(':');
        if (colon <= 0)
            return;
        var property = text[..colon].Trim();
        var value = text[(colon + 1)..].Trim();
        var important = value.Contains("!important", StringComparison.OrdinalIgnoreCase);
        if (important)
            value = value.Replace("!important", string.Empty, StringComparison.OrdinalIgnoreCase).Trim();

        rule.Declarations.Add(new StyleDeclaration(property, value, important, line));
    }
}
