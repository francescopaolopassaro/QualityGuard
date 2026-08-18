using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace QualityGuard.Core.Analysis;

/// <summary>
/// How much of the code a test suite actually runs, read from the report the language's own tool
/// produced.
///
/// Coverage is not something a static analyser can work out: knowing which lines a test reaches
/// means running the tests. So this reads the file the runner already writes — lcov, Cobertura,
/// JaCoCo or OpenCover — and turns it into a number the quality gate can hold a build to. Without
/// it, a project with no tests at all and a project with a thorough suite look identical from here,
/// and the second one is far cheaper to change safely.
/// </summary>
public sealed partial class CoverageReport
{
    private CoverageReport(int covered, int total, IReadOnlyDictionary<string, double> perFile)
    {
        CoveredLines = covered;
        CoverableLines = total;
        ByFile = perFile;
    }

    /// <summary>Lines the tests reached at least once.</summary>
    public int CoveredLines { get; }

    /// <summary>Lines the tool considered reachable at all.</summary>
    public int CoverableLines { get; }

    /// <summary>Percentage per file, so a gate can ask about what changed.</summary>
    public IReadOnlyDictionary<string, double> ByFile { get; }

    /// <summary>The overall percentage, or zero when the report described nothing.</summary>
    public double Percentage => CoverableLines == 0 ? 0 : CoveredLines * 100.0 / CoverableLines;

    [GeneratedRegex(@"^SF:(.+)$", RegexOptions.Multiline)]
    private static partial Regex LcovFile();

    [GeneratedRegex(@"^DA:(\d+),(\d+)", RegexOptions.Multiline)]
    private static partial Regex LcovLine();

    /// <summary>
    /// Reads whichever of the common formats the file turns out to be. The format is decided by
    /// what is inside rather than by the extension, because every one of these is routinely written
    /// to a name the tool chose.
    /// </summary>
    public static CoverageReport? Read(string path)
    {
        if (!File.Exists(path))
            return null;
        var text = File.ReadAllText(path);
        if (text.Contains("SF:", StringComparison.Ordinal))
            return FromLcov(text);
        if (text.Contains("<coverage", StringComparison.Ordinal))
            return FromCobertura(text);
        if (text.Contains("<report", StringComparison.Ordinal))
            return FromJaCoCo(text);
        if (text.Contains("<CoverageSession", StringComparison.Ordinal))
            return FromOpenCover(text);
        return null;
    }

    private static CoverageReport FromLcov(string text)
    {
        var perFile = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        var covered = 0;
        var total = 0;
        foreach (var section in text.Split("end_of_record", StringSplitOptions.RemoveEmptyEntries))
        {
            var name = LcovFile().Match(section);
            if (!name.Success)
                continue;
            var hit = 0;
            var seen = 0;
            foreach (Match line in LcovLine().Matches(section))
            {
                seen++;
                if (line.Groups[2].Value != "0")
                    hit++;
            }
            if (seen == 0)
                continue;
            covered += hit;
            total += seen;
            perFile[name.Groups[1].Value.Trim()] = hit * 100.0 / seen;
        }
        return new CoverageReport(covered, total, perFile);
    }

    private static CoverageReport? FromCobertura(string text)
    {
        var document = Parse(text);
        if (document?.Root is null)
            return null;
        var perFile = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        var covered = 0;
        var total = 0;
        foreach (var file in document.Descendants("class"))
        {
            var name = file.Attribute("filename")?.Value;
            var lines = file.Descendants("line").ToList();
            if (name is null || lines.Count == 0)
                continue;
            var hit = lines.Count(l => l.Attribute("hits")?.Value is { } h && h != "0");
            covered += hit;
            total += lines.Count;
            perFile[name] = hit * 100.0 / lines.Count;
        }
        return new CoverageReport(covered, total, perFile);
    }

    private static CoverageReport? FromJaCoCo(string text)
    {
        var document = Parse(text);
        if (document?.Root is null)
            return null;
        var perFile = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        var covered = 0;
        var total = 0;
        foreach (var file in document.Descendants("sourcefile"))
        {
            var name = file.Attribute("name")?.Value;
            var counter = file.Elements("counter").FirstOrDefault(c => c.Attribute("type")?.Value == "LINE");
            if (name is null || counter is null)
                continue;
            var missed = Number(counter.Attribute("missed")?.Value);
            var hit = Number(counter.Attribute("covered")?.Value);
            if (missed + hit == 0)
                continue;
            covered += hit;
            total += missed + hit;
            perFile[name] = hit * 100.0 / (missed + hit);
        }
        return new CoverageReport(covered, total, perFile);
    }

    private static CoverageReport? FromOpenCover(string text)
    {
        var document = Parse(text);
        if (document?.Root is null)
            return null;
        var perFile = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        var covered = 0;
        var total = 0;
        foreach (var module in document.Descendants("Module"))
        {
            var files = module.Descendants("File")
                .ToDictionary(f => f.Attribute("uid")?.Value ?? string.Empty,
                    f => f.Attribute("fullPath")?.Value ?? string.Empty);
            foreach (var point in module.Descendants("SequencePoint"))
            {
                var uid = point.Attribute("fileid")?.Value ?? string.Empty;
                if (!files.TryGetValue(uid, out var name) || name.Length == 0)
                    continue;
                total++;
                var hit = point.Attribute("vc")?.Value is { } vc && vc != "0";
                if (hit)
                    covered++;
                perFile.TryGetValue(name, out _);
            }
        }
        // OpenCover counts points rather than lines, so the per-file share is derived from the whole
        return new CoverageReport(covered, total, perFile);
    }

    private static XDocument? Parse(string text)
    {
        try
        {
            return XDocument.Parse(text);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static int Number(string? value)
        => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : 0;
}
