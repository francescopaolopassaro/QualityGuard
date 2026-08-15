using System.Text.RegularExpressions;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Analysis;

/// <summary>What to scan and what to leave out.</summary>
public sealed class ScanOptions
{
    /// <summary>Files or directories to scan. A directory is always walked to the bottom.</summary>
    public IReadOnlyList<string> Paths { get; init; } = [];

    /// <summary>Glob patterns a file must match to be scanned. Empty means "every known language".</summary>
    public IReadOnlyList<string> Include { get; init; } = [];

    /// <summary>Glob patterns that keep a file out, applied after <see cref="Include"/>.</summary>
    public IReadOnlyList<string> Exclude { get; init; } = [];

    /// <summary>Skip the directories and files that are built, vendored or generated.</summary>
    public bool UseDefaultExcludes { get; init; } = true;

    /// <summary>Files above this size are skipped: they are generated or data, never reviewed code.</summary>
    public int MaxFileKilobytes { get; init; } = 2048;
}

/// <summary>What a scan found, and what it deliberately left behind.</summary>
public sealed record ScanResult(
    IReadOnlyList<string> Files,
    int SkippedUnknownLanguage,
    int SkippedExcluded,
    int SkippedTooLarge,
    int SkippedBinary,
    IReadOnlyList<string> MissingPaths);

/// <summary>
/// Turns the paths given on the command line into the list of files worth analysing.
///
/// The interesting part is what it refuses. A repository is mostly not source written by the team:
/// dependencies, build output, minified bundles and generated code make up the bulk of the bytes,
/// and analysing them produces findings nobody can act on while hiding the ones they can. The
/// default exclusions below encode that, and every one of them can be turned off.
/// </summary>
public static class SourceScanner
{
    /// <summary>Directories that hold dependencies, build output or tool state.</summary>
    public static readonly string[] DefaultExcludedDirectories =
    [
        ".git", ".svn", ".hg", ".idea", ".vs", ".vscode", ".gradle", ".terraform", ".mypy_cache",
        ".pytest_cache", ".ruff_cache", ".tox", ".next", ".nuxt", ".angular", ".cache",
        "bin", "obj", "build", "dist", "out", "target", "node_modules", "bower_components",
        "packages", "vendor", "venv", ".venv", "env", "__pycache__", "coverage", "htmlcov",
        "site-packages", "third_party", "Pods", "DerivedData"
    ];

    /// <summary>Files that are produced by a tool: reviewing them is reviewing the generator.</summary>
    public static readonly string[] DefaultExcludedFiles =
    [
        "*.min.js", "*.min.css", "*.bundle.js", "*.map", "*-lock.json", "*.lock",
        "*.g.cs", "*.g.i.cs", "*.designer.cs", "*.Designer.cs", "*.generated.cs", "*.generated.ts",
        "*_pb2.py", "*_pb.go", "*.pb.go", "*.d.ts", "*.snap"
    ];

    public static ScanResult Scan(ScanOptions options)
    {
        var files = new List<string>();
        var missing = new List<string>();
        int unknown = 0, excluded = 0, tooLarge = 0, binary = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var include = Compile(options.Include);
        var exclude = Compile(options.Exclude);
        var defaultFiles = options.UseDefaultExcludes ? Compile(DefaultExcludedFiles) : [];
        var maxBytes = (long)Math.Max(1, options.MaxFileKilobytes) * 1024;

        foreach (var path in options.Paths)
        {
            var candidates = Candidates(path, options, exclude, missing);
            foreach (var file in candidates)
            {
                if (!seen.Add(Path.GetFullPath(file)))
                    continue;

                var relative = Normalize(file);
                var name = Path.GetFileName(file);

                if (include.Count > 0 && !include.Any(p => p.IsMatch(relative) || p.IsMatch(name)))
                {
                    excluded++;
                    continue;
                }
                if (exclude.Any(p => p.IsMatch(relative) || p.IsMatch(name))
                    || defaultFiles.Any(p => p.IsMatch(name)))
                {
                    excluded++;
                    continue;
                }
                if (BuiltInLanguages.Recognizer.Recognize(file) == null)
                {
                    unknown++;
                    continue;
                }

                var info = new FileInfo(file);
                if (info.Length > maxBytes)
                {
                    tooLarge++;
                    continue;
                }
                if (LooksBinary(file))
                {
                    binary++;
                    continue;
                }

                files.Add(file);
            }
        }

        files.Sort(StringComparer.OrdinalIgnoreCase);
        return new ScanResult(files, unknown, excluded, tooLarge, binary, missing);
    }

    private static IEnumerable<string> Candidates(string path, ScanOptions options,
        List<Regex> exclude, List<string> missing)
    {
        if (File.Exists(path))
            return [path];
        if (!Directory.Exists(path))
        {
            missing.Add(path);
            return [];
        }
        return Walk(path, options, exclude);
    }

    /// <summary>
    /// Walks the tree one directory at a time instead of asking for every file at once, so an
    /// excluded directory costs nothing: node_modules is never opened rather than enumerated and
    /// thrown away.
    /// </summary>
    private static IEnumerable<string> Walk(string root, ScanOptions options, List<Regex> exclude)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            string[] entries;
            try
            {
                entries = Directory.GetFiles(directory);
            }
            catch (Exception)
            {
                // an unreadable directory is reported by its absence, not by stopping the scan
                continue;
            }

            foreach (var file in entries)
                yield return file;

            string[] children;
            try
            {
                children = Directory.GetDirectories(directory);
            }
            catch (Exception)
            {
                continue;
            }

            foreach (var child in children)
            {
                var name = Path.GetFileName(child);
                if (options.UseDefaultExcludes
                    && DefaultExcludedDirectories.Contains(name, StringComparer.OrdinalIgnoreCase))
                    continue;
                if (exclude.Any(p => p.IsMatch(Normalize(child)) || p.IsMatch(name)))
                    continue;
                pending.Push(child);
            }
        }
    }

    /// <summary>A file with a NUL byte in its head is data, whatever its extension says.</summary>
    private static bool LooksBinary(string file)
    {
        try
        {
            using var stream = File.OpenRead(file);
            Span<byte> head = stackalloc byte[512];
            var read = stream.Read(head);
            return head[..read].IndexOf((byte)0) >= 0;
        }
        catch (Exception)
        {
            return true;
        }
    }

    private static string Normalize(string path) => path.Replace('\\', '/');

    private static List<Regex> Compile(IReadOnlyList<string> globs)
    {
        var patterns = new List<Regex>(globs.Count);
        foreach (var glob in globs)
        {
            if (string.IsNullOrWhiteSpace(glob))
                continue;
            // a glob is written against the project ("src/**/*.cs"), while the scanner works with the
            // path the user typed, so the pattern is allowed to start at any directory boundary
            var pattern = GlobToRegex(glob.Trim()).Replace("^", "^(?:.*/)?", StringComparison.Ordinal);
            patterns.Add(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
        }
        return patterns;
    }

    /// <summary>`**` crosses directories, `*` stays inside one, `?` is a single character.</summary>
    public static string GlobToRegex(string glob)
    {
        var pattern = new System.Text.StringBuilder("^");
        for (var i = 0; i < glob.Length; i++)
        {
            var c = glob[i];
            switch (c)
            {
                case '*' when i + 1 < glob.Length && glob[i + 1] == '*':
                    pattern.Append(".*");
                    i++;
                    if (i + 1 < glob.Length && glob[i + 1] == '/')
                        i++;
                    break;
                case '*':
                    pattern.Append("[^/]*");
                    break;
                case '?':
                    pattern.Append("[^/]");
                    break;
                case '\\':
                    pattern.Append('/');
                    break;
                default:
                    pattern.Append(Regex.Escape(c.ToString()));
                    break;
            }
        }
        return pattern.Append('$').ToString();
    }
}
