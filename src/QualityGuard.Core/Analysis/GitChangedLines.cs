using System.Diagnostics;

namespace QualityGuard.Core.Analysis;

/// <summary>
/// Reads the lines a branch actually adds or rewrites against a base, so that "new code" coverage
/// means coverage of the current diff and nothing else.
///
/// The engine stays stateless: git is spawned per run to answer one question — which lines are new —
/// and nothing is written to the working tree. When the caller is not inside a git repository, or
/// git is not on the path, the answer is an empty set and the new-code metrics stay unmeasured
/// rather than being guessed.
/// </summary>
public static class GitChangedLines
{
    /// <summary>
    /// Computes the added lines in the working tree against <paramref name="baseRef"/> (a branch,
    /// tag or commit), for every file in the repository. Keys are absolute paths with forward
    /// slashes, values are the line numbers that count as new.
    /// </summary>
    public static IReadOnlyDictionary<string, IReadOnlySet<int>> Read(string baseRef, string? workingDirectory = null)
        => Read(baseRef, null, workingDirectory);

    /// <summary>
    /// Same as <see cref="Read(string, string?)"/>, but the diff is restricted to the given paths
    /// (relative to the repository root), so a large monorepo does not diff everything.
    /// </summary>
    public static IReadOnlyDictionary<string, IReadOnlySet<int>> Read(
        string baseRef, IReadOnlyList<string>? relativePaths, string? workingDirectory = null)
    {
        var cwd = workingDirectory ?? Environment.CurrentDirectory;
        if (!Run("rev-parse --show-toplevel", cwd, out var rootOut))
            return Empty;
        var root = rootOut.Trim().Length == 0 ? cwd : CoveragePathResolver.Normalize(rootOut.Trim());

        var paths = relativePaths is { Count: > 0 }
            ? " -- " + string.Join(' ', relativePaths.Select(p => Quote(p)))
            : string.Empty;
        var diff = $"diff --no-color --unified=0 \"{baseRef}\"{paths}";
        if (!Run(diff, root, out var diffOut))
            return Empty;

        return Parse(diffOut, root);
    }

    /// <summary>
    /// Turns the base the user named into something git diff accepts. A date (yyyy-MM-dd) is not a
    /// revision git can diff directly, so it becomes the last commit on the first-parent history
    /// strictly before that date — which is what "compare against the code as it was on &lt;date&gt;"
    /// means for a diff. Anything that already names a branch, tag or commit passes through
    /// unchanged, and when git cannot answer (no such date, no repository) the date falls back to
    /// HEAD, which makes the diff itself fail cleanly rather than silently diffing nothing.
    /// </summary>
    public static string Resolve(string baseRef, string? workingDirectory = null)
    {
        if (!IsDate(baseRef))
            return baseRef;
        var cwd = workingDirectory ?? Environment.CurrentDirectory;
        var resolved = Run($"rev-list -n1 --first-parent --before=\"{baseRef}\" HEAD", cwd, out var output)
            ? output.Trim()
            : string.Empty;
        return resolved.Length == 0 ? "HEAD" : resolved;
    }

    /// <summary>Whether the value is a calendar date git can interpret with --before.</summary>
    public static bool IsDate(string value)
        => System.Text.RegularExpressions.Regex.IsMatch(value, @"^\d{4}-\d{2}-\d{2}");

    /// <summary>
    /// Turns the output of <c>git diff --no-color --unified=0</c> into a map of file to added line
    /// numbers. A modified line is an added line: git writes it as one removed and one added line,
    /// and the added one is what the new code is made of.
    /// </summary>
    public static IReadOnlyDictionary<string, IReadOnlySet<int>> Parse(string diffText, string repositoryRoot)
    {
        var result = new Dictionary<string, HashSet<int>>(StringComparer.OrdinalIgnoreCase);
        var currentPath = (string?)null;
        var newLine = 0;
        foreach (var raw in diffText.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith("+++ ", StringComparison.Ordinal))
            {
                currentPath = TargetPath(line[4..]);
                newLine = 0;
                continue;
            }

            if (currentPath is null)
                continue;

            if (line.StartsWith("@@ ", StringComparison.Ordinal))
            {
                newLine = NewSideStart(line);
                continue;
            }

            if (newLine == 0)
                continue;

            if (line.StartsWith('+'))
            {
                SetLines(result, currentPath, repositoryRoot).Add(newLine);
                newLine++;
            }
            else if (line.StartsWith('-'))
            {
                // a removed line has no counterpart on the new side
            }
            else if (line.StartsWith('\\'))
            {
                // "no newline at end of file" marker: no line to count
            }
            else
            {
                newLine++; // context line, present when the hunk was requested with more than zero lines
            }
        }
        return result.ToDictionary(e => e.Key, e => (IReadOnlySet<int>)e.Value,
            StringComparer.OrdinalIgnoreCase);
    }

    private static string Key(string relativePath, string repositoryRoot)
    {
        var normalized = relativePath.Replace('/', Path.DirectorySeparatorChar);
        var full = Path.GetFullPath(Path.Combine(repositoryRoot, normalized));
        return CoveragePathResolver.Normalize(full);
    }

    private static string TargetPath(string header)
    {
        // the header is the new-side file: "/dev/null" for a deletion, otherwise prefixed with b/
        if (string.Equals("/dev/null", header, StringComparison.Ordinal))
            return string.Empty;
        return header.StartsWith("b/", StringComparison.Ordinal) ? header[2..] : header;
    }

    private static HashSet<int> SetLines(Dictionary<string, HashSet<int>> map, string key, string root)
    {
        var actual = Key(key, root);
        if (!map.TryGetValue(actual, out var set))
            map[actual] = set = new HashSet<int>();
        return set;
    }

    private static int NewSideStart(string hunk)
    {
        // @@ -a,b +c,d @@
        var after = hunk.IndexOf(" +", StringComparison.Ordinal);
        if (after < 0)
            return 0;
        var start = after + 2;
        var end = start;
        while (end < hunk.Length && char.IsAsciiDigit(hunk[end]))
            end++;
        return end == start ? 0 : int.Parse(hunk[start..end], System.Globalization.CultureInfo.InvariantCulture);
    }

    private static bool Run(string arguments, string cwd, out string output)
    {
        try
        {
            var start = new ProcessStartInfo
            {
                FileName = "git",
                Arguments = arguments,
                WorkingDirectory = cwd,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8
            };
            using var process = Process.Start(start);
            if (process is null)
            {
                output = string.Empty;
                return false;
            }
            output = process.StandardOutput.ReadToEnd();
            _ = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return process.ExitCode == 0;
        }
        catch (Exception)
        {
            output = string.Empty;
            return false;
        }
    }

    private static string Quote(string path) => "\"" + path.Replace("\"", "\\\"") + "\"";

    private static readonly IReadOnlyDictionary<string, IReadOnlySet<int>> Empty =
        new Dictionary<string, IReadOnlySet<int>>();
}