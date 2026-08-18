namespace QualityGuard.Core.Analysis;

/// <summary>
/// One node of a configuration file: a key, the value written next to it, and the block it opens.
/// </summary>
public sealed class ConfigNode
{
    public required string Key { get; init; }

    /// <summary>The scalar written after the key, without quotes. Empty when the key opens a block.</summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>Labels of a block header, as in <c>resource "aws_s3_bucket" "logs" { }</c>.</summary>
    public List<string> Labels { get; } = [];

    public int Line { get; init; }

    public ConfigNode? Parent { get; set; }

    public List<ConfigNode> Children { get; } = [];

    public bool IsListItem { get; init; }

    public IEnumerable<ConfigNode> Descendants()
    {
        foreach (var child in Children)
        {
            yield return child;
            foreach (var nested in child.Descendants())
                yield return nested;
        }
    }

    /// <summary>Direct children with this key, compared without case.</summary>
    public IEnumerable<ConfigNode> ChildrenNamed(string key)
        => Children.Where(c => string.Equals(c.Key, key, StringComparison.OrdinalIgnoreCase));

    public ConfigNode? Child(string key) => ChildrenNamed(key).FirstOrDefault();

    /// <summary>Follows a path of keys, as in <c>Value("spec", "securityContext", "runAsUser")</c>.</summary>
    public ConfigNode? At(params string[] path)
    {
        var node = this;
        foreach (var key in path)
        {
            node = node?.Child(key);
            if (node == null)
                return null;
        }
        return node;
    }

    public string? ValueAt(params string[] path) => At(path)?.Value;

    public bool IsTrue => Value.Equals("true", StringComparison.OrdinalIgnoreCase)
                          || Value.Equals("yes", StringComparison.OrdinalIgnoreCase);

    public bool IsFalse => Value.Equals("false", StringComparison.OrdinalIgnoreCase)
                           || Value.Equals("no", StringComparison.OrdinalIgnoreCase);

    public override string ToString() => Labels.Count > 0
        ? $"{Key} {string.Join(' ', Labels)} ({Children.Count} children)"
        : Value.Length > 0 ? $"{Key} = {Value}" : $"{Key} ({Children.Count} children)";
}

/// <summary>
/// A configuration file read as a tree of keys and blocks.
///
/// Infrastructure rules fail on line matching for the same reason code rules do: the interesting
/// facts are relationships — a value inside a specific block, a setting missing from a container, a
/// port opened next to a source range. Two shapes cover the whole family: braces with optional block
/// labels (HCL, and JSON closely enough) and indentation with list items (YAML). Both produce the
/// same tree, so one rule can serve a manifest and a template.
///
/// It is a reader, not a validator: anything it cannot recognise is skipped, and a rule that finds no
/// node stays silent instead of guessing.
/// </summary>
public static class ConfigTree
{
    public static ConfigNode Parse(string content, string languageKey)
        => languageKey is "tf" or "ar" or "json" ? ParseBraces(content) : ParseIndented(content);

    // ------------------------------------------------------------------ brace syntax (HCL, JSON)

    private static ConfigNode ParseBraces(string content)
    {
        var root = new ConfigNode { Key = string.Empty, Line = 0 };
        var current = root;
        var lines = content.Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            var line = StripComment(lines[i]).Trim();
            if (line.Length == 0)
                continue;

            while (line.StartsWith('}') || line.StartsWith(']'))
            {
                current = current.Parent ?? root;
                line = line[1..].TrimStart().TrimStart(',').TrimStart();
                if (line.Length == 0)
                    break;
            }
            if (line.Length == 0)
                continue;

            var opensBlock = line.EndsWith('{') || line.EndsWith('[');
            var header = opensBlock ? line[..^1].TrimEnd() : line;

            var (key, value, labels) = SplitBraceHeader(header);
            if (key.Length == 0 && !opensBlock)
                continue;

            var node = new ConfigNode { Key = key, Value = value, Line = i + 1, Parent = current };
            node.Labels.AddRange(labels);
            current.Children.Add(node);
            if (opensBlock)
                current = node;
        }
        return root;
    }

    private static (string Key, string Value, List<string> Labels) SplitBraceHeader(string header)
    {
        var labels = new List<string>();
        var equals = IndexOfTopLevel(header, '=');
        if (equals > 0)
        {
            var key = Unquote(header[..equals].Trim());
            var value = Unquote(header[(equals + 1)..].Trim().TrimEnd(','));
            return (key, value, labels);
        }

        var colon = IndexOfTopLevel(header, ':');
        if (colon > 0)
        {
            var key = Unquote(header[..colon].Trim());
            var value = Unquote(header[(colon + 1)..].Trim().TrimEnd(','));
            return (key, value, labels);
        }

        var parts = SplitQuoted(header);
        if (parts.Count == 0)
            return (string.Empty, string.Empty, labels);
        labels.AddRange(parts.Skip(1).Select(Unquote));
        return (Unquote(parts[0]), string.Empty, labels);
    }

    // ------------------------------------------------------------------ indented syntax (YAML)

    private static ConfigNode ParseIndented(string content)
    {
        var root = new ConfigNode { Key = string.Empty, Line = 0 };
        var stack = new List<(int Indent, ConfigNode Node)> { (-1, root) };
        var lines = content.Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            var raw = lines[i].TrimEnd('\r');
            var line = StripComment(raw);
            if (line.Trim().Length == 0)
                continue;
            // a document separator restarts the tree at the top, keeping every object in one file
            if (line.TrimStart().StartsWith("---", StringComparison.Ordinal))
            {
                stack.RemoveRange(1, stack.Count - 1);
                continue;
            }

            var indent = line.Length - line.TrimStart().Length;
            var text = line.Trim();
            var isItem = text.StartsWith("- ", StringComparison.Ordinal) || text == "-";

            if (isItem)
            {
                // an item of a list is a node of its own, so that the keys written on the same line
                // and the keys written under it end up in the same object. Attaching them to the
                // list instead used to scatter one container's settings across its siblings.
                while (stack.Count > 1 && stack[^1].Indent >= indent)
                    stack.RemoveAt(stack.Count - 1);
                var list = stack[^1].Node;
                var item = new ConfigNode
                {
                    Key = string.Empty, Line = i + 1, Parent = list, IsListItem = true
                };
                list.Children.Add(item);
                stack.Add((indent, item));

                text = text.Length > 1 ? text[1..].Trim() : string.Empty;
                indent += 2;
                if (text.Length == 0)
                    continue;
            }

            while (stack.Count > 1 && stack[^1].Indent >= indent)
                stack.RemoveAt(stack.Count - 1);
            var parent = stack[^1].Node;

            var colon = IndexOfTopLevel(text, ':');
            ConfigNode node;
            if (colon > 0)
            {
                node = new ConfigNode
                {
                    Key = Unquote(text[..colon].Trim()),
                    Value = Unquote(text[(colon + 1)..].Trim()),
                    Line = i + 1,
                    Parent = parent
                };
            }
            else
            {
                node = new ConfigNode
                {
                    Key = Unquote(text.TrimEnd(':')),
                    Line = i + 1,
                    Parent = parent
                };
            }

            parent.Children.Add(node);
            stack.Add((indent, node));
        }
        return root;
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>Whether the quote at this position closes a string or was written inside one.</summary>
    private static bool IsEscaped(string text, int index)
    {
        var slashes = 0;
        for (var i = index - 1; i >= 0 && text[i] == '\\'; i--)
            slashes++;
        return slashes % 2 == 1;
    }

    private static string StripComment(string line)
    {
        var inString = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '"' && !IsEscaped(line, i))
                inString = !inString;
            else if (!inString && (c == '#' || (c == '/' && i + 1 < line.Length && line[i + 1] == '/')))
                return line[..i];
        }
        return line;
    }

    private static int IndexOfTopLevel(string text, char target)
    {
        var inString = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '"' && !IsEscaped(text, i))
                inString = !inString;
            else if (!inString && c == target)
                return i;
        }
        return -1;
    }

    private static List<string> SplitQuoted(string text)
    {
        var parts = new List<string>();
        var current = new System.Text.StringBuilder();
        var inString = false;
        var escaped = false;
        foreach (var c in text)
        {
            if (inString && !escaped && c == '\\')
            {
                escaped = true;
                current.Append(c);
                continue;
            }
            if (c == '"' && !escaped)
            {
                inString = !inString;
                current.Append(c);
                continue;
            }
            escaped = false;
            if (!inString && char.IsWhiteSpace(c))
            {
                if (current.Length > 0)
                {
                    parts.Add(current.ToString());
                    current.Clear();
                }
                continue;
            }
            current.Append(c);
        }
        if (current.Length > 0)
            parts.Add(current.ToString());
        return parts;
    }

    private static string Unquote(string text)
    {
        text = text.Trim();
        if (text.Length >= 2 && text[0] == '"' && text[^1] == '"')
            return text[1..^1];
        if (text.Length >= 2 && text[0] == '\'' && text[^1] == '\'')
            return text[1..^1];
        return text;
    }
}
