using System.Reflection;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Catalog;

/// <summary>
/// Loads the YAML rule catalog embedded in the assembly. Entries carrying detection clauses become
/// executable rules; entries without them document a hand-written rule with the same key.
/// </summary>
public static class RuleCatalog
{
    private static readonly Lazy<List<CatalogEntry>> Loaded = new(LoadEmbedded);
    private static readonly List<CatalogEntry> External = [];

    public static IReadOnlyList<CatalogEntry> Entries => Loaded.Value.Concat(External).ToList();

    public static IReadOnlyList<IRule> Rules
        => Entries.Where(e => !e.IsDocumentationOnly).Select(e => (IRule)new SpecRule(e)).ToList();

    public static CatalogEntry? Find(string key)
        => Entries.FirstOrDefault(e => string.Equals(e.Key, key, StringComparison.OrdinalIgnoreCase));

    /// <summary>Adds catalog files from disk, used by authoring tools and tests.</summary>
    public static int LoadDirectory(string directory)
    {
        var added = 0;
        foreach (var path in Directory.EnumerateFiles(directory, "*.yaml", SearchOption.AllDirectories))
        {
            foreach (var entry in Parse(File.ReadAllText(path)))
            {
                External.Add(entry);
                added++;
            }
        }
        return added;
    }

    public static IEnumerable<CatalogEntry> Parse(string yaml)
        => YamlLite.ParseSequence(yaml)
            .Where(map => map.Str("key") is { Length: > 0 })
            .Select(CatalogEntry.From);

    private static List<CatalogEntry> LoadEmbedded()
    {
        var entries = new List<CatalogEntry>();
        var assembly = Assembly.GetExecutingAssembly();
        foreach (var name in assembly.GetManifestResourceNames().Where(n => n.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)).OrderBy(n => n))
        {
            using var stream = assembly.GetManifestResourceStream(name);
            if (stream == null)
                continue;
            using var reader = new StreamReader(stream);
            entries.AddRange(Parse(reader.ReadToEnd()));
        }
        return entries;
    }
}

/// <summary>
/// Description provider for rules implemented in code: the catalog is the source of truth, and a
/// category-based English fallback guarantees no finding is ever reported without guidance.
/// </summary>
public static class RuleDocs
{
    public static bool IsCurated(string key) => RuleCatalog.Find(key) != null;

    public static RuleDescription For(string key, string name, IssueKind kind, string category)
        => RuleCatalog.Find(key)?.Description ?? Fallback(name, kind, category);

    public static string[] TagsFor(string key, string[] fallback)
        => RuleCatalog.Find(key)?.Tags is { Length: > 0 } tags ? tags : fallback;

    public static int[] CweFor(string key, int[] fallback)
        => RuleCatalog.Find(key)?.Cwe is { Length: > 0 } cwe ? cwe : fallback;

    public static string[] OwaspFor(string key, string[] fallback)
        => RuleCatalog.Find(key)?.Owasp is { Length: > 0 } owasp ? owasp : fallback;

    private static RuleDescription Fallback(string name, IssueKind kind, string category) => category switch
    {
        "SEC" => new RuleDescription(
            Summary: $"{name}.",
            WhyIsThisAnIssue: "This construct is a known weak spot: it either trusts data the program "
                              + "does not control, or relies on a mechanism that no longer offers the protection "
                              + "it appears to offer. Attackers look for exactly these patterns because they turn "
                              + "ordinary input into a way of changing what the program does.",
            HowToFix: "Stop trusting the incoming value: validate it against an allowed set, or pass it as data "
                      + "(parameter, argument array, encoded output) so it can never be read as code or as a "
                      + "command. Where a weak mechanism is involved, replace it with the current recommended one "
                      + "and keep secrets outside the source.",
            Impact: "An attacker who controls the input can read or change data they should not reach, or run "
                    + "code with the privileges of this process."),
        "BUG" => new RuleDescription(
            Summary: $"{name}.",
            WhyIsThisAnIssue: "The code does not do what it looks like it does. Written this way it works by "
                              + "accident, or fails on inputs that are perfectly ordinary, and the mistake is easy "
                              + "to miss during review because the intent reads correctly.",
            HowToFix: "Make the intended behaviour explicit: fix the condition, the operator or the order of "
                      + "operations so that the code and the intent match, then cover the case that used to fail "
                      + "with a test.",
            Impact: "Wrong results or a crash at run time, on inputs the code is expected to handle."),
        "PRF" => new RuleDescription(
            Summary: $"{name}.",
            WhyIsThisAnIssue: "The operation costs far more than it needs to — usually repeated work inside a "
                              + "loop, or an allocation that could be avoided entirely. It is invisible on small "
                              + "inputs and becomes the bottleneck on real ones.",
            HowToFix: "Move the invariant work out of the loop, reuse the object or buffer instead of recreating "
                      + "it, and pick the data structure whose cost matches how the data is actually accessed.",
            Impact: "Latency and resource use grow with input size, and can degrade the whole process."),
        "CNV" => new RuleDescription(
            Summary: $"{name}.",
            WhyIsThisAnIssue: "The code deviates from the convention the rest of the codebase follows. Nothing "
                              + "breaks today, but every deviation costs a reader a moment of doubt and makes "
                              + "automated formatting and reviews noisier.",
            HowToFix: "Bring the code in line with the surrounding style — naming, layout and structure — so a "
                      + "reader can move through the file without stopping to reinterpret it.",
            Impact: "Slower reviews and diffs polluted by incidental changes."),
        _ => new RuleDescription(
            Summary: $"{name}.",
            WhyIsThisAnIssue: "This is code that works but is harder to change than it should be: the intent is "
                              + "buried, duplicated, or spread across places that must stay in sync. That cost is "
                              + "paid on every future modification.",
            HowToFix: "Simplify: remove what is not used, name what is unclear, and keep one piece of behaviour "
                      + "in one place so the next change touches a single spot.",
            Impact: "Higher chance of introducing a defect the next time this code is edited.")
    };
}
