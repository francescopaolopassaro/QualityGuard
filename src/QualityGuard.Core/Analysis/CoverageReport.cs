using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace QualityGuard.Core.Analysis;

/// <summary>
/// A single executable line: how often the tests ran it and, for a line that can take more than one
/// path, how many of those paths they actually tried.
/// </summary>
public sealed class CoverageLine
{
    internal CoverageLine(int number) => Number = number;

    /// <summary>Line number in the file, starting at one.</summary>
    public int Number { get; }

    /// <summary>How many times the tests executed the line. Zero means the line was never reached.</summary>
    public int Hits { get; internal set; }

    /// <summary>Branches the line can take; an ordinary condition has two.</summary>
    public int Conditions { get; internal set; }

    /// <summary>Branches the tests actually took. Never larger than <see cref="Conditions"/>.</summary>
    public int CoveredConditions { get; internal set; }

    /// <summary>Whether the tests reached the line at least once.</summary>
    public bool IsCovered => Hits > 0;
}

/// <summary>
/// Everything known about one file: which lines the test suite can reach, how often it reached each,
/// and how many of its branches both sides explored. A file never appears in the report at all unless
/// the runner listed at least one line for it.
/// </summary>
public sealed class FileCoverage
{
    private readonly Dictionary<int, CoverageLine> _lines = new();

    internal FileCoverage(string path) => Path = path;

    /// <summary>Path as written in the report. Matched against the scanned files by the resolver.</summary>
    public string Path { get; }

    public IReadOnlyDictionary<int, CoverageLine> Lines => _lines;

    public int LinesToCover => _lines.Count;

    public int CoveredLines => _lines.Count(l => l.Value.IsCovered);

    public int ConditionsToCover => _lines.Values.Sum(l => l.Conditions);

    public int CoveredConditions => _lines.Values.Sum(l => Math.Min(l.CoveredConditions, l.Conditions));

    /// <summary>Returns the line at <paramref name="number"/>, creating an unrecorded stub on demand.</summary>
    internal CoverageLine Line(int number)
    {
        if (!_lines.TryGetValue(number, out var line))
            _lines[number] = line = new CoverageLine(number);
        return line;
    }
}

/// <summary>
/// How much of the code a test suite actually runs, read from the report the language's own tool
/// produced.
///
/// Coverage is not something a static analyser can work out: knowing which lines a test reaches
/// means running the tests. So this reads the file the runner already writes — lcov, Cobertura or
/// JaCoCo — and turns it into the numbers a quality gate can hold a build to: how many lines and
/// conditions exist, how many are covered, and the coverage percentages derived from them.
///
/// The percentages follow the same definitions as the reference engine:
/// line coverage counts lines, branch coverage counts conditions, and overall coverage combines
/// both. A file that a test suite reaches only half renders as half covered whatever the absolute
/// numbers, and merging several reports for the same suite keeps the two shares additive.
/// </summary>
public sealed partial class CoverageReport
{
    private CoverageReport(IReadOnlyList<FileCoverage> files)
    {
        Files = files;
        LinesToCover = files.Sum(f => f.LinesToCover);
        CoveredLines = files.Sum(f => f.CoveredLines);
        ConditionsToCover = files.Sum(f => f.ConditionsToCover);
        CoveredConditions = files.Sum(f => f.CoveredConditions);
        Coverage = Percent(CoveredLines + CoveredConditions, LinesToCover + ConditionsToCover);
        LineCoverage = Percent(CoveredLines, LinesToCover);
        BranchCoverage = Percent(CoveredConditions, ConditionsToCover);
    }

    public IReadOnlyList<FileCoverage> Files { get; }

    /// <summary>Executable lines the tests should have reached.</summary>
    public int LinesToCover { get; }

    /// <summary>Lines the tests reached at least once.</summary>
    public int CoveredLines { get; }

    /// <summary>Branches the tests should have explored.</summary>
    public int ConditionsToCover { get; }

    /// <summary>Branches the tests did explore.</summary>
    public int CoveredConditions { get; }

    public int UncoveredLines => LinesToCover - CoveredLines;

    public int UncoveredConditions => ConditionsToCover - CoveredConditions;

    /// <summary>Lines plus conditions: the whole share the tests must cover.</summary>
    public int TotalElements => LinesToCover + ConditionsToCover;

    /// <summary>Whether the report described anything at all.</summary>
    public bool HasData => TotalElements > 0;

    /// <summary>Lines and conditions combined, the single number most teams track.</summary>
    public double Coverage { get; }

    /// <summary>Lines only, so a pure line runner and a branch-aware one stay comparable.</summary>
    public double LineCoverage { get; }

    /// <summary>Conditions only.</summary>
    public double BranchCoverage { get; }

    /// <summary>
    /// Reads whichever of the common formats the file turns out to be. The format is decided by what
    /// is inside rather than by the extension, because every one of these is routinely written to a
    /// name the tool chose.
    /// </summary>
    public static CoverageReport? Read(string path)
    {
        if (!File.Exists(path))
            return null;
        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception)
        {
            return null;
        }
        return Parse(text);
    }

    /// <summary>Detects and parses a coverage report from its text, with no filesystem involved.</summary>
    public static CoverageReport? Parse(string text)
    {
        if (text.Contains("SF:", StringComparison.Ordinal))
            return FromLcov(text);
        if (text.Contains("<coverage", StringComparison.Ordinal))
            return FromCobertura(text);
        if (text.Contains("<report", StringComparison.Ordinal))
            return FromJaCoCo(text);
        return null;
    }

    /// <summary>
    /// Combines several reports into one, the way running the whole suite under a runner that writes
    /// one report per shard works: line hits add up, and a condition is covered if any report covered
    /// it.
    /// </summary>
    public static CoverageReport Merge(IEnumerable<CoverageReport> reports)
    {
        var merged = new Dictionary<string, FileCoverage>(StringComparer.OrdinalIgnoreCase);
        foreach (var report in reports)
        {
            foreach (var file in report.Files)
            {
                if (!merged.TryGetValue(file.Path, out var target))
                    merged[file.Path] = target = new FileCoverage(file.Path);
                foreach (var line in file.Lines.Values)
                {
                    var combined = target.Line(line.Number);
                    combined.Hits += line.Hits;
                    combined.Conditions = Math.Max(combined.Conditions, line.Conditions);
                    combined.CoveredConditions =
                        Math.Min(combined.Conditions, Math.Max(combined.CoveredConditions, line.CoveredConditions));
                }
            }
        }
        return new CoverageReport([.. merged.Values]);
    }

    /// <summary>
    /// The tests themselves are not code the team ships, and letting them drag the percentage up or
    /// down hides what production code looks like. This drops the files that belong to a test suite.
    /// </summary>
    public CoverageReport ExcludingTests()
        => new([.. Files.Where(f => !TestFileDetector.IsTestFile(f.Path))]);

    /// <summary>
    /// Measures only the new code — the lines the current branch added or rewrote — so a small change
    /// is judged on the lines it actually touches instead of on the whole file. A line counts only if
    /// its number is in the new-line set of its file, and a file with no entry contributes nothing.
    /// </summary>
    public NewCodeCoverage NewCode(IReadOnlyDictionary<string, IReadOnlySet<int>> newLinesByFile)
    {
        var linesToCover = 0;
        var coveredLines = 0;
        var conditionsToCover = 0;
        var coveredConditions = 0;
        foreach (var file in Files)
        {
            if (!newLinesByFile.TryGetValue(file.Path, out var newLines))
                continue;
            foreach (var (number, data) in file.Lines)
            {
                if (!newLines.Contains(number))
                    continue;
                linesToCover++;
                if (data.IsCovered)
                    coveredLines++;
                conditionsToCover += data.Conditions;
                coveredConditions += Math.Min(data.CoveredConditions, data.Conditions);
            }
        }
        return new NewCodeCoverage(linesToCover, coveredLines, conditionsToCover, coveredConditions);
    }

    private static double Percent(int covered, int total) => total == 0 ? 0 : covered * 100.0 / total;

    private static CoverageReport FromLcov(string text)
    {
        var files = new List<FileCoverage>();
        foreach (var section in text.Split("end_of_record", StringSplitOptions.RemoveEmptyEntries))
        {
            var name = LcovFile().Match(section);
            if (!name.Success)
                continue;
            var file = new FileCoverage(name.Groups[1].Value.Trim());
            foreach (Match line in LcovLine().Matches(section))
            {
                var hits = int.TryParse(line.Groups[2].Value, NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out var h) ? h : 0;
                file.Line(int.Parse(line.Groups[1].Value, CultureInfo.InvariantCulture)).Hits += hits;
            }
            foreach (Match branch in LcovBranch().Matches(section))
            {
                var lineNumber = int.Parse(branch.Groups[1].Value, CultureInfo.InvariantCulture);
                var taken = branch.Groups[4].Value == "-"
                    ? 0
                    : int.TryParse(branch.Groups[4].Value, NumberStyles.Integer,
                        CultureInfo.InvariantCulture, out var t) ? Math.Max(0, t) : 0;
                var target = file.Line(lineNumber);
                target.Conditions++;
                if (taken > 0)
                    target.CoveredConditions++;
            }
            if (file.Lines.Count > 0)
                files.Add(file);
        }
        return new CoverageReport(files);
    }

    private static CoverageReport? FromCobertura(string text)
    {
        var document = ParseXml(text);
        if (document?.Root is null)
            return null;
        var files = new List<FileCoverage>();
        foreach (var entry in document.Descendants("class"))
        {
            var name = entry.Attribute("filename")?.Value;
            if (string.IsNullOrWhiteSpace(name))
                continue;
            var file = new FileCoverage(name);
            foreach (var line in entry.Descendants("line"))
            {
                var number = ParseInt(line.Attribute("number")?.Value);
                if (number <= 0)
                    continue;
                file.Line(number).Hits += ParseInt(line.Attribute("hits")?.Value);
                var branch = line.Attribute("branch")?.Value;
                if (!string.Equals(branch, "true", StringComparison.OrdinalIgnoreCase))
                    continue;
                var condition = line.Attribute("condition-coverage")?.Value;
                if (condition == null)
                    continue;
                var match = ConditionCoverage().Match(condition);
                if (!match.Success)
                    continue;
                var total = int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture);
                var covered = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
                if (total <= 0)
                    continue;
                var target = file.Line(number);
                target.Conditions = total;
                target.CoveredConditions = Math.Min(covered, total);
            }
            if (file.Lines.Count > 0)
                files.Add(file);
        }
        return files.Count == 0 ? null : new CoverageReport(files);
    }

    private static CoverageReport? FromJaCoCo(string text)
    {
        var document = ParseXml(text);
        if (document?.Root is null)
            return null;
        var files = new List<FileCoverage>();
        foreach (var sourceFile in document.Descendants("sourcefile"))
        {
            var name = sourceFile.Attribute("name")?.Value;
            if (string.IsNullOrWhiteSpace(name))
                continue;
            var package = PackagePath(sourceFile.Ancestors("package").FirstOrDefault()?.Attribute("name")?.Value);
            var file = new FileCoverage(package.Length == 0 ? name : package + "/" + name);
            foreach (var line in sourceFile.Elements("line"))
            {
                var number = ParseInt(line.Attribute("nr")?.Value);
                if (number <= 0)
                    continue;
                var instructionsMissed = ParseInt(line.Attribute("mi")?.Value);
                var instructionsCovered = ParseInt(line.Attribute("ci")?.Value);
                var branchesMissed = ParseInt(line.Attribute("mb")?.Value);
                var branchesCovered = ParseInt(line.Attribute("cb")?.Value);
                if (instructionsMissed + instructionsCovered + branchesMissed + branchesCovered == 0)
                    continue;
                var target = file.Line(number);
                target.Hits = instructionsCovered > 0 ? 1 : 0;
                if (branchesMissed + branchesCovered > 0)
                {
                    target.Conditions = branchesMissed + branchesCovered;
                    target.CoveredConditions = branchesCovered;
                }
            }
            if (file.Lines.Count > 0)
                files.Add(file);
        }
        return files.Count == 0 ? null : new CoverageReport(files);
    }

    private static string PackagePath(string? package)
    {
        if (string.IsNullOrEmpty(package))
            return string.Empty;
        return package.Replace('.', '/');
    }

    private static XDocument? ParseXml(string text)
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

    private static int ParseInt(string? value)
        => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : 0;

    [GeneratedRegex(@"^SF:(.+)$", RegexOptions.Multiline)]
    private static partial Regex LcovFile();

    [GeneratedRegex(@"^DA:(\d+),(\d+)", RegexOptions.Multiline)]
    private static partial Regex LcovLine();

    [GeneratedRegex(@"^BRDA:(\d+),([^,]*),([^,]*),(.+)$", RegexOptions.Multiline)]
    private static partial Regex LcovBranch();

    [GeneratedRegex(@"\((\d+)/(\d+)\)")]
    private static partial Regex ConditionCoverage();
}

/// <summary>
/// The coverage of just the new code: the lines the current diff added or rewrote, judged in
/// isolation so a PR that only touches a small corner is not graded on the whole file. Mirrors the
/// totals and percentages of the full report, but only over the lines that count as new.
/// </summary>
public sealed class NewCodeCoverage
{
    internal NewCodeCoverage(int linesToCover, int coveredLines, int conditionsToCover, int coveredConditions)
    {
        LinesToCover = linesToCover;
        CoveredLines = coveredLines;
        ConditionsToCover = conditionsToCover;
        CoveredConditions = coveredConditions;
        Coverage = Percent(CoveredLines + CoveredConditions, LinesToCover + ConditionsToCover);
        LineCoverage = Percent(CoveredLines, LinesToCover);
        BranchCoverage = Percent(CoveredConditions, ConditionsToCover);
    }

    public int LinesToCover { get; }

    public int CoveredLines { get; }

    public int ConditionsToCover { get; }

    public int CoveredConditions { get; }

    public int UncoveredLines => LinesToCover - CoveredLines;

    public int UncoveredConditions => ConditionsToCover - CoveredConditions;

    /// <summary>Whether any new line was recorded, so the gate can skip the metrics on an empty diff.</summary>
    public bool HasData => LinesToCover + ConditionsToCover > 0;

    public double Coverage { get; }

    public double LineCoverage { get; }

    public double BranchCoverage { get; }

    private static double Percent(int covered, int total) => total == 0 ? 0 : covered * 100.0 / total;
}