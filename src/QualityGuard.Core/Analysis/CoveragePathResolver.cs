namespace QualityGuard.Core.Analysis;

/// <summary>
/// Maps the paths inside a coverage report or a git diff to the files the engine actually scanned.
/// A report is written by the runner with paths that follow its own convention — absolute, relative
/// to the project root, or a bare file name — none of which necessarily equals what the scan read.
/// This resolves by exact path first, then by file name when it is unambiguous, then by path suffix,
/// so a file in a nested folder is still found even when the two sources disagree on the leading
/// directories.
/// </summary>
public sealed class CoveragePathResolver
{
    private readonly Dictionary<string, string> _byFull;
    private readonly Dictionary<string, List<string>> _byName;
    private readonly List<string> _known;

    public CoveragePathResolver(IEnumerable<string> scannedPaths)
    {
        _known = scannedPaths
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(Normalize)
            .ToList();
        _byFull = _known.GroupBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        _byName = _known
            .GroupBy(p => System.IO.Path.GetFileName(p), StringComparer.OrdinalIgnoreCase)
            .Where(g => !string.IsNullOrEmpty(g.Key))
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
    }

    public string? Resolve(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;
        var normalized = Normalize(path);

        if (System.IO.Path.IsPathRooted(normalized) && _byFull.TryGetValue(normalized, out var exact)) 
        {
            return exact;
        }

        var fileName = System.IO.Path.GetFileName(normalized);
        if (_byName.TryGetValue(fileName, out var candidates) && candidates.Count == 1)
            return candidates[0];

        // the report lists a relative path ("src/Foo.cs" or "Foo.cs"): find the scanned files whose
        // path ends with exactly that, preferring the longest match for nested trees
        string? best = null;
        foreach (var known in _known)
        {
            if (known.EndsWith("/" + normalized, StringComparison.OrdinalIgnoreCase)
                && (best is null || known.Length > best.Length))
            {
                best = known;
            }
        }
        return best;
    }

    /// <summary>
    /// One spelling for every path comparison: forward slashes, dots and double slashes resolved,
    /// and the machine's case rule applied by the callers through the case-insensitive dictionaries.
    /// </summary>
    public static string Normalize(string path)
    {
        var trimmed = path.Trim().Replace("\\", "/");
        if (trimmed.StartsWith("./", StringComparison.Ordinal))
            trimmed = trimmed[2..];
        if (!System.IO.Path.IsPathRooted(trimmed))
            return trimmed;
        return System.IO.Path.GetFullPath(trimmed).Replace("\\", "/");
    }
}