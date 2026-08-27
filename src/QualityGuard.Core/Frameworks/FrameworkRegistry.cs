using System.Reflection;
using System.Text.RegularExpressions;

namespace QualityGuard.Core.Frameworks;

/// <summary>
/// Loads framework definitions from YAML and provides type/method resolution for rules.
/// </summary>
public sealed class FrameworkRegistry
{
    private readonly List<FrameworkDefinition> _frameworks = [];
    private readonly Dictionary<string, FrameworkDefinition> _byName = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Dictionary<string, string>> _returnTypes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _chainMethods = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<FrameworkDefinition> All => _frameworks;

    public static readonly FrameworkRegistry Empty = new();

    public static FrameworkRegistry Load(string catalogDir)
    {
        var registry = new FrameworkRegistry();

        // Load from embedded resources first
        var assembly = Assembly.GetExecutingAssembly();
        foreach (var name in assembly.GetManifestResourceNames()
                     .Where(n => n.Contains("frameworks", StringComparison.OrdinalIgnoreCase)
                                 && n.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
                     .OrderBy(n => n))
        {
            using var stream = assembly.GetManifestResourceStream(name);
            if (stream == null) continue;
            using var reader = new StreamReader(stream);
            var def = ParseFramework(reader.ReadToEnd());
            if (def != null) registry.Add(def);
        }

        // Also load from filesystem (for testing/development)
        var frameworksDir = Path.Combine(catalogDir, "frameworks");
        if (Directory.Exists(frameworksDir))
        {
            foreach (var file in Directory.GetFiles(frameworksDir, "*.yaml"))
            {
                var content = File.ReadAllText(file);
                var def = ParseFramework(content);
                if (def != null && !_registryContains(registry, def))
                    registry.Add(def);
            }
        }
        return registry;
    }

    private static bool _registryContains(FrameworkRegistry registry, FrameworkDefinition def)
        => registry._frameworks.Any(f =>
            string.Equals(f.Name, def.Name, StringComparison.OrdinalIgnoreCase)
            && string.Equals(f.Language, def.Language, StringComparison.OrdinalIgnoreCase));

    public void Add(FrameworkDefinition framework)
    {
        _frameworks.Add(framework);
        _byName[framework.Name] = framework;

        var key = framework.Language + ":" + framework.Name;
        _returnTypes[key] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in framework.MethodReturns)
        {
            var methodKey = m.Receiver + "." + m.Method;
            _returnTypes[key][methodKey] = m.ReturnsSelf ? m.Receiver : m.Returns;
        }

        _chainMethods[key] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in framework.Chains)
            foreach (var m in c.ChainMethods)
                _chainMethods[key].Add(m);
    }

    /// <summary>
    /// Given a receiver type and method name, returns the framework-known return type.
    /// The "*" receiver matches any type.
    /// </summary>
    public string? ReturnType(string language, string receiverType, string methodName)
    {
        foreach (var fw in _frameworks)
        {
            if (!string.Equals(fw.Language, language, StringComparison.OrdinalIgnoreCase))
                continue;
            var key = fw.Language + ":" + fw.Name;
            if (_returnTypes.TryGetValue(key, out var methods))
            {
                // Try exact match first
                if (methods.TryGetValue(receiverType + "." + methodName, out var exactReturn))
                    return exactReturn;
                // Try wildcard receiver
                if (methods.TryGetValue("*." + methodName, out var wildcardReturn))
                    return wildcardReturn;
            }
        }
        return null;
    }

    /// <summary>
    /// True if the method is a known chain continuation in any framework.
    /// </summary>
    public bool IsChainMethod(string language, string methodName)
    {
        foreach (var fw in _frameworks)
        {
            if (!string.Equals(fw.Language, language, StringComparison.OrdinalIgnoreCase))
                continue;
            var key = fw.Language + ":" + fw.Name;
            if (_chainMethods.TryGetValue(key, out var methods) && methods.Contains(methodName))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Finds the entry point type for a method name (e.g. "assertThat" → "Assertions").
    /// </summary>
    public ChainPattern? FindChain(string language, string entryMethod)
    {
        foreach (var fw in _frameworks)
        {
            if (!string.Equals(fw.Language, language, StringComparison.OrdinalIgnoreCase))
                continue;
            foreach (var c in fw.Chains)
            {
                if (string.Equals(c.Entry, entryMethod, StringComparison.OrdinalIgnoreCase))
                    return c;
            }
        }
        return null;
    }

    /// <summary>
    /// Gets all sinks for a language.
    /// </summary>
    public IEnumerable<SinkSourceMapping> GetSinks(string language)
        => _frameworks.Where(f => string.Equals(f.Language, language, StringComparison.OrdinalIgnoreCase))
                       .SelectMany(f => f.Sinks);

    /// <summary>
    /// Gets all sources for a language.
    /// </summary>
    public IEnumerable<SinkSourceMapping> GetSources(string language)
        => _frameworks.Where(f => string.Equals(f.Language, language, StringComparison.OrdinalIgnoreCase))
                       .SelectMany(f => f.Sources);

    private static FrameworkDefinition? ParseFramework(string yaml)
    {
        var name = ExtractScalar(yaml, "name");
        var lang = ExtractScalar(yaml, "language");
        if (name == null || lang == null) return null;

        return new FrameworkDefinition
        {
            Name = name,
            Language = lang,
            Aliases = ExtractList(yaml, "aliases"),
            Types = ParseTypes(yaml),
            MethodReturns = ParseMethodReturns(yaml),
            Chains = ParseChains(yaml),
            Sinks = ParseMappings(yaml, "sinks"),
            Sources = ParseMappings(yaml, "sources"),
            Sanitizers = ParseSanitizers(yaml),
        };
    }

    private static TypeMapping[] ParseTypes(string yaml)
    {
        var section = ExtractSection(yaml, "types");
        if (section == null) return [];
        var result = new List<TypeMapping>();
        foreach (var block in SplitBlocks(section))
        {
            var n = ExtractScalar(block, "name");
            if (n == null) continue;
            result.Add(new TypeMapping
            {
                Name = n,
                Extends = ExtractList(block, "extends"),
                Implements = ExtractList(block, "implements"),
                IsAbstract = ExtractBool(block, "abstract"),
            });
        }
        return result.ToArray();
    }

    private static MethodReturnMapping[] ParseMethodReturns(string yaml)
    {
        var section = ExtractSection(yaml, "method_returns");
        if (section == null) return [];
        var result = new List<MethodReturnMapping>();
        foreach (var block in SplitBlocks(section))
        {
            var r = ExtractScalar(block, "receiver");
            var m = ExtractScalar(block, "method");
            if (m == null) continue;
            result.Add(new MethodReturnMapping
            {
                Receiver = r ?? "*",
                Method = m,
                Returns = ExtractScalar(block, "returns") ?? "void",
                ReturnsSelf = ExtractBool(block, "returns_self"),
            });
        }
        return result.ToArray();
    }

    private static ChainPattern[] ParseChains(string yaml)
    {
        var section = ExtractSection(yaml, "chains");
        if (section == null) return [];
        var result = new List<ChainPattern>();
        foreach (var block in SplitBlocks(section))
        {
            var e = ExtractScalar(block, "entry");
            if (e == null) continue;
            result.Add(new ChainPattern
            {
                Entry = e,
                Receiver = ExtractScalar(block, "receiver"),
                Returns = ExtractScalar(block, "returns") ?? "void",
                ChainMethods = ExtractList(block, "chain_methods"),
            });
        }
        return result.ToArray();
    }

    private static SinkSourceMapping[] ParseMappings(string yaml, string sectionName)
    {
        var section = ExtractSection(yaml, sectionName);
        if (section == null) return [];
        var result = new List<SinkSourceMapping>();
        foreach (var block in SplitBlocks(section))
        {
            var m = ExtractScalar(block, "method");
            if (m == null) continue;
            result.Add(new SinkSourceMapping
            {
                Method = m,
                Receiver = ExtractScalar(block, "receiver"),
                Args = ExtractIntList(block, "args"),
                Kind = ExtractScalar(block, "kind") ?? "",
            });
        }
        return result.ToArray();
    }

    private static SanitizerMapping[] ParseSanitizers(string yaml)
    {
        var section = ExtractSection(yaml, "sanitizers");
        if (section == null) return [];
        var result = new List<SanitizerMapping>();
        foreach (var block in SplitBlocks(section))
        {
            var m = ExtractScalar(block, "method");
            if (m == null) continue;
            result.Add(new SanitizerMapping
            {
                Method = m,
                Receiver = ExtractScalar(block, "receiver"),
                Kind = ExtractScalar(block, "kind") ?? "",
            });
        }
        return result.ToArray();
    }

    // Simple YAML parsing helpers (no external dependency)
    private static string? ExtractScalar(string yaml, string key)
    {
        var match = Regex.Match(yaml, $@"(?:^|\n)\s*(?:-\s+)?{key}:\s*""?([^""\n]+)""?\s*(?:\n|$)", RegexOptions.None);
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }

    private static bool ExtractBool(string yaml, string key)
    {
        var val = ExtractScalar(yaml, key);
        return val is "true" or "yes" or "1";
    }

    private static string[] ExtractList(string yaml, string key)
    {
        // Try inline list first: key: [a, b, c]
        var match = Regex.Match(yaml, $@"(?:^|\n)\s*(?:-\s+)?{key}:\s*\[([^\]]*)\]", RegexOptions.None);
        if (match.Success)
            return match.Groups[1].Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        // Try multi-line list: key:\n  - item1\n  - item2
        var mlMatch = Regex.Match(yaml, $@"(?:^|\n)\s*(?:-\s+)?{key}:\s*\n((?:\s+-\s+[^\n]+\n?)+)", RegexOptions.None);
        if (mlMatch.Success)
        {
            var items = Regex.Matches(mlMatch.Groups[1].Value, @"-\s+([^\n]+)");
            return items.Select(m => m.Groups[1].Value.Trim()).ToArray();
        }

        return [];
    }

    private static int[] ExtractIntList(string yaml, string key)
    {
        return ExtractList(yaml, key).Where(s => int.TryParse(s, out _)).Select(int.Parse).ToArray();
    }

    private static string? ExtractSection(string yaml, string sectionName)
    {
        // Match top-level section (no indentation before the key)
        var pattern = $@"(?:^|\n){sectionName}:\s*\n(.+?)(?=\n\w|\z)";
        var match = Regex.Match(yaml, pattern, RegexOptions.Singleline);
        if (!match.Success) return null;
        return match.Groups[1].Value;
    }

    private static IEnumerable<string> SplitBlocks(string section)
    {
        // Split YAML list into blocks by top-level "- " at the list indentation level
        var lines = section.Split('\n');
        var current = new System.Text.StringBuilder();
        var listIndent = -1;

        foreach (var line in lines)
        {
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("- "))
            {
                var indent = line.Length - trimmed.Length;
                if (listIndent < 0) listIndent = indent;

                if (indent == listIndent && current.Length > 0)
                {
                    yield return current.ToString();
                    current.Clear();
                }
            }
            current.AppendLine(line);
        }
        if (current.Length > 0)
            yield return current.ToString();
    }
}
