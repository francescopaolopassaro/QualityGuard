using System.Globalization;
using QualityGuard.Cli;
using QualityGuard.Core.Analysis;
using QualityGuard.Core.Evaluation;
using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Mcp;

/// <summary>Everything a caller wants a scan to do, mirroring the CLI options.</summary>
public sealed class ScanRequest
{
    public IReadOnlyList<string> Paths { get; init; } = [];
    public IReadOnlyList<string> Include { get; init; } = [];
    public IReadOnlyList<string> Exclude { get; init; } = [];
    public bool UseDefaultExcludes { get; init; } = true;
    public int MaxFileKilobytes { get; init; } = 2048;

    /// <summary>Ask for the whole catalogue instead of the default profile.</summary>
    public bool EveryRule { get; init; }

    /// <summary>Path to a JSON gate config; the built-in gate is used when omitted.</summary>
    public string? GatePath { get; init; }

    /// <summary>Coverage reports from the test runner (LCOV, Cobertura or JaCoCo), merged in order.</summary>
    public IReadOnlyList<string> CoverageFiles { get; init; } = [];

    /// <summary>Base branch/commit/tag that new code is measured against.</summary>
    public string? Base { get; init; }

    /// <summary>Derive the new_* rating metrics from the issues and evaluate them in the gate.</summary>
    public bool NewCodeMode { get; init; }
}

/// <summary>The result of running a scan: the analyses, the aggregated metrics, the gate and the
/// coverage/new-code data that fed them. Everything a report or an AI needs is reachable from here.</summary>
public sealed class ScanOutcome
{
    public required IReadOnlyList<FileAnalysis> Analyses { get; init; }
    public required IReadOnlyDictionary<string, double> Metrics { get; init; }
    public required QualityGateResult Gate { get; init; }
    public QualityGuard.Core.Analysis.CoverageReport? Coverage { get; init; }
    public string? NewCodeBase { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }

    public IReadOnlyList<Issue> AllIssues => Analyses.SelectMany(a => a.Issues).ToList();
}

/// <summary>
/// The in-process pipeline the CLI runs from the command line, exposed here so an MCP tool can drive
/// it without spawning a subprocess: scan, tokenize, parse, run the rules, aggregate the metrics,
/// read the coverage, ask git for the new code and evaluate the gate.
/// </summary>
public static class QualityScanService
{
    public static ScanOutcome Run(ScanRequest request)
    {
        var warnings = new List<string>();

        var conditions = request.GatePath is null
            ? GateConfig.LoadDefault()
            : GateConfig.Load(request.GatePath);

        var analyses = AnalyzeAndScan(request, warnings);
        var metrics = AggregateMetrics(analyses);

        var workingDirectory = request.Paths.Count > 0 ? ScanWorkingDirectory(request.Paths[0]) : null;
        IReadOnlyDictionary<string, IReadOnlySet<int>>? changedLines = null;
        if (request.Base is not null && workingDirectory is not null)
        {
            var gitBase = GitChangedLines.Resolve(request.Base, workingDirectory);
            changedLines = ReadNewCodeBase(metrics, gitBase, workingDirectory, request.Base, warnings);
        }

        if (request.NewCodeMode)
            ApplyNewCodeMetrics(metrics, analyses);

        var coverage = ReadCoverage(request.CoverageFiles, warnings);
        if (coverage is not null)
        {
            coverage = coverage.ExcludingFromSource(analyses);
            ApplyCoverageMetrics(metrics, coverage);
            if (changedLines is not null && request.Base is not null)
                ApplyNewCodeCoverage(metrics, coverage, request.Base, analyses, changedLines, warnings);
        }

        var gate = new QualityGateEvaluator().Evaluate(metrics, conditions);

        return new ScanOutcome
        {
            Analyses = analyses,
            Metrics = metrics,
            Gate = gate,
            Coverage = coverage,
            NewCodeBase = request.Base,
            Warnings = warnings
        };
    }

    private static List<FileAnalysis> AnalyzeAndScan(ScanRequest request, List<string> warnings)
    {
        var options = new ScanOptions
        {
            Paths = request.Paths,
            Include = request.Include,
            Exclude = request.Exclude,
            UseDefaultExcludes = request.UseDefaultExcludes,
            MaxFileKilobytes = request.MaxFileKilobytes
        };

        var scan = SourceScanner.Scan(options);
        foreach (var missing in scan.MissingPaths)
            warnings.Add($"WARNING: {missing} does not exist");

        var files = new List<SourceFile>();
        foreach (var filePath in scan.Files)
        {
            try
            {
                var content = File.ReadAllText(filePath);
                if (BuiltInLanguages.Recognizer.Recognize(filePath, content) is { } lang)
                    files.Add(new SourceFile(filePath, content, lang));
            }
            catch (Exception ex)
            {
                warnings.Add($"WARNING: cannot read {filePath}: {ex.Message}");
            }
        }

        var context = new AnalysisContext(files, new AnalysisOptions());
        var engine = new AnalysisEngine();
        var analyses = engine.Run(context).ToList();

        foreach (var (path, reason) in engine.Unreadable)
            warnings.Add($"SKIPPED {path}: {reason}");

        var rules = RuleRepository.GetBuiltInRules(request.EveryRule);
        foreach (var analysis in analyses)
            RuleEngine.Run(analysis, rules);

        return analyses;
    }

    private static Dictionary<string, double> AggregateMetrics(IReadOnlyList<FileAnalysis> all)
    {
        var metrics = new Dictionary<string, double>();
        var duplicatedLines = 0.0;
        foreach (var a in all)
        {
            var dupLines = a.Duplicates.Sum(d => d.Lines);
            duplicatedLines += dupLines;
            a.Metrics[CoreMetrics.DuplicatedLinesDensity] =
                a.Metrics.GetValueOrDefault(CoreMetrics.Ncloc) > 0
                    ? dupLines / Math.Max(1, a.Metrics[CoreMetrics.Ncloc]) * 100.0
                    : 0;
            foreach (var (k, v) in a.Metrics)
            {
                if (k == CoreMetrics.DuplicatedLinesDensity)
                    continue;
                metrics[k] = metrics.GetValueOrDefault(k) + v;
            }
        }

        var totalNcloc = metrics.GetValueOrDefault(CoreMetrics.Ncloc);
        metrics[CoreMetrics.DuplicatedLinesDensity] = totalNcloc > 0 ? duplicatedLines / totalNcloc * 100.0 : 0;
        metrics[CoreMetrics.Files] = all.Count;

        var issues = all.SelectMany(a => a.Issues).ToList();
        foreach (var (key, value) in QualityRatings.ComputeMetrics(issues, metrics.GetValueOrDefault(CoreMetrics.Ncloc)))
            metrics[key] = value;
        metrics[CoreMetrics.NewSecurityHotspotsReviewed] =
            issues.Any(i => i.Kind == IssueKind.SecurityHotspot) ? 0.0 : 100.0;
        return metrics;
    }

    private static void ApplyNewCodeMetrics(Dictionary<string, double> metrics, IReadOnlyList<FileAnalysis> all)
    {
        var issues = all.SelectMany(a => a.Issues).ToList();
        foreach (var (k, v) in QualityRatings.ComputeNewCodeMetrics(issues,
                     metrics.GetValueOrDefault(CoreMetrics.NewLines)))
        {
            metrics[k] = v;
        }
        metrics[CoreMetrics.NewDuplicatedLinesDensity] = metrics.GetValueOrDefault(CoreMetrics.DuplicatedLinesDensity);
    }

    private static CoverageReport? ReadCoverage(IReadOnlyList<string> files, List<string> warnings)
    {
        var reports = new List<CoverageReport>();
        foreach (var file in files)
        {
            var report = CoverageReport.Read(file);
            if (report is null)
            {
                warnings.Add($"WARNING: {file} is not a recognized coverage report (LCOV, Cobertura or JaCoCo).");
                continue;
            }
            reports.Add(report);
        }
        if (reports.Count == 0)
            return null;
        var merged = reports.Count == 1 ? reports[0] : CoverageReport.Merge(reports);
        return merged.ExcludingTests();
    }

    private static void ApplyCoverageMetrics(Dictionary<string, double> metrics, CoverageReport coverage)
    {
        metrics[CoreMetrics.LinesToCover] = coverage.LinesToCover;
        metrics[CoreMetrics.UncoveredLines] = coverage.UncoveredLines;
        metrics[CoreMetrics.ConditionsToCover] = coverage.ConditionsToCover;
        metrics[CoreMetrics.UncoveredConditions] = coverage.UncoveredConditions;
        metrics[CoreMetrics.Coverage] = coverage.Coverage;
        metrics[CoreMetrics.LineCoverage] = coverage.LineCoverage;
        metrics[CoreMetrics.BranchCoverage] = coverage.BranchCoverage;
    }

    private static string? ScanWorkingDirectory(string scanPath)
    {
        var full = Path.GetFullPath(scanPath);
        if (Directory.Exists(full))
            return full;
        return Path.GetDirectoryName(full);
    }

    private static IReadOnlyDictionary<string, IReadOnlySet<int>>? ReadNewCodeBase(
        Dictionary<string, double> metrics, string gitBase, string? workingDirectory,
        string displayBase, List<string> warnings)
    {
        var git = GitChangedLines.Read(gitBase, workingDirectory);
        if (git.Count == 0)
        {
            warnings.Add($"WARNING: could not read the lines changed since {displayBase} from git; new code is not measured.");
            return null;
        }
        metrics[CoreMetrics.NewLines] = git.Values.Sum(l => l.Count);
        return git;
    }

    private static bool ApplyNewCodeCoverage(Dictionary<string, double> metrics,
        CoverageReport coverage, string baseRef, IReadOnlyList<FileAnalysis> analyses,
        IReadOnlyDictionary<string, IReadOnlySet<int>> git, List<string> warnings)
    {
        var resolver = new CoveragePathResolver(analyses.Select(a => Path.GetFullPath(a.File.Path)));
        var newLinesByFile = new Dictionary<string, IReadOnlySet<int>>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in coverage.Files)
        {
            if (resolver.Resolve(file.Path) is not { } scanned)
                continue;
            if (git.TryGetValue(scanned, out var lines))
                newLinesByFile[file.Path] = lines;
        }
        if (newLinesByFile.Count == 0)
        {
            warnings.Add($"WARNING: no covered file matched the lines changed since {baseRef}; new code coverage is not measured.");
            return false;
        }

        var newCode = coverage.NewCode(newLinesByFile);
        if (!newCode.HasData)
        {
            warnings.Add($"WARNING: no new code with coverage data since {baseRef}; new code coverage is not measured.");
            return false;
        }
        metrics[CoreMetrics.NewLinesToCover] = newCode.LinesToCover;
        metrics[CoreMetrics.NewUncoveredLines] = newCode.UncoveredLines;
        metrics[CoreMetrics.NewConditionsToCover] = newCode.ConditionsToCover;
        metrics[CoreMetrics.NewUncoveredConditions] = newCode.UncoveredConditions;
        metrics[CoreMetrics.NewCoverage] = newCode.Coverage;
        metrics[CoreMetrics.NewLineCoverage] = newCode.LineCoverage;
        metrics[CoreMetrics.NewBranchCoverage] = newCode.BranchCoverage;
        return true;
    }
}