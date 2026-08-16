namespace QualityGuard.Core.Analysis;

/// <summary>One element of a document, with the attributes written on it and the elements inside it.</summary>
public sealed class HtmlElement
{
    public required string Name { get; init; }

    public required int Line { get; init; }

    public Dictionary<string, string> Attributes { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HtmlElement? Parent { get; set; }

    public List<HtmlElement> Children { get; } = [];

    /// <summary>Text written directly inside the element, without the text of its children.</summary>
    public string Text { get; set; } = string.Empty;

    public string? Attribute(string name) => Attributes.GetValueOrDefault(name);

    public bool Has(string name) => Attributes.ContainsKey(name);

    public IEnumerable<HtmlElement> Descendants()
    {
        foreach (var child in Children)
        {
            yield return child;
            foreach (var nested in child.Descendants())
                yield return nested;
        }
    }

    public IEnumerable<HtmlElement> Named(string name)
        => Descendants().Where(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));

    public override string ToString() => $"<{Name}> ({Children.Count} children)";
}

/// <summary>
/// A markup document read as a tree of elements.
///
/// Almost every markup defect is a missing relationship: an image without its alternative text, a
/// control without the label that names it, a link that opens a new window without cutting the
/// reference back to this one. Those are facts about an element and its attributes, so the reader
/// below keeps both, and stays deliberately forgiving — unclosed tags, custom elements and template
/// syntax are common in real pages and must not derail the parse.
/// </summary>
public static class HtmlDocument
{
    /// <summary>Elements that never have a closing tag.</summary>
    private static readonly string[] VoidElements =
    [
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
        "source", "track", "wbr", "!doctype"
    ];

    public static HtmlElement Parse(string content)
    {
        var root = new HtmlElement { Name = "#document", Line = 0 };
        var current = root;
        var line = 1;

        for (var i = 0; i < content.Length; i++)
        {
            var c = content[i];
            if (c == '\n')
            {
                line++;
                continue;
            }
            if (c != '<')
            {
                if (!char.IsWhiteSpace(c))
                    current.Text += c;
                continue;
            }

            // comments, CDATA and processing instructions carry no structure
            if (content.AsSpan(i).StartsWith("<!--"))
            {
                var end = content.IndexOf("-->", i, StringComparison.Ordinal);
                var stop = end < 0 ? content.Length : end + 3;
                line += content[i..stop].Count(ch => ch == '\n');
                i = stop - 1;
                continue;
            }

            var close = content.IndexOf('>', i);
            if (close < 0)
                break;
            var tag = content[(i + 1)..close].Trim();
            var tagLine = line;
            line += content[i..close].Count(ch => ch == '\n');
            i = close;

            if (tag.Length == 0)
                continue;

            if (tag[0] == '/')
            {
                var name = tag[1..].Trim();
                // close the nearest matching ancestor, tolerating tags that were never closed
                for (var node = current; node != null && node != root; node = node.Parent)
                {
                    if (!string.Equals(node.Name, name, StringComparison.OrdinalIgnoreCase))
                        continue;
                    current = node.Parent ?? root;
                    break;
                }
                continue;
            }

            var selfClosing = tag.EndsWith('/');
            if (selfClosing)
                tag = tag[..^1].TrimEnd();

            var element = ReadElement(tag, tagLine);
            element.Parent = current;
            current.Children.Add(element);

            // a script or a style holds text, not markup: skip to its closing tag
            if (element.Name is "script" or "style")
            {
                var endTag = content.IndexOf($"</{element.Name}", i, StringComparison.OrdinalIgnoreCase);
                if (endTag > 0)
                {
                    line += content[i..endTag].Count(ch => ch == '\n');
                    i = endTag - 1;
                }
                continue;
            }

            if (!selfClosing && !VoidElements.Contains(element.Name, StringComparer.OrdinalIgnoreCase))
                current = element;
        }

        return root;
    }

    private static HtmlElement ReadElement(string tag, int line)
    {
        var space = tag.IndexOfAny([' ', '\t', '\n', '\r']);
        var name = (space < 0 ? tag : tag[..space]).ToLowerInvariant();
        var element = new HtmlElement { Name = name, Line = line };
        if (space < 0)
            return element;

        var rest = tag[space..];
        for (var i = 0; i < rest.Length; i++)
        {
            while (i < rest.Length && char.IsWhiteSpace(rest[i]))
                i++;
            if (i >= rest.Length)
                break;

            var nameStart = i;
            while (i < rest.Length && !char.IsWhiteSpace(rest[i]) && rest[i] != '=')
                i++;
            var attribute = rest[nameStart..i].Trim();
            if (attribute.Length == 0)
                continue;

            var value = string.Empty;
            while (i < rest.Length && char.IsWhiteSpace(rest[i]))
                i++;
            if (i < rest.Length && rest[i] == '=')
            {
                i++;
                while (i < rest.Length && char.IsWhiteSpace(rest[i]))
                    i++;
                if (i < rest.Length && (rest[i] == '"' || rest[i] == '\''))
                {
                    var quote = rest[i];
                    var end = rest.IndexOf(quote, i + 1);
                    if (end < 0)
                        end = rest.Length - 1;
                    value = rest[(i + 1)..end];
                    i = end;
                }
                else
                {
                    var valueStart = i;
                    while (i < rest.Length && !char.IsWhiteSpace(rest[i]))
                        i++;
                    value = rest[valueStart..i];
                    i--;
                }
            }
            else
            {
                i--;
            }

            element.Attributes[attribute] = value;
        }

        return element;
    }
}
