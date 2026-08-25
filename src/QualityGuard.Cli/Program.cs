using QualityGuard.Cli;
using QualityGuard.Core.Analysis;
using QualityGuard.Core.Evaluation;
using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Tokenization;
using QualityGuard.Sources.Sarif;

// the report is English everywhere, so numbers must not pick up the machine's locale
System.Globalization.CultureInfo.DefaultThreadCurrentCulture = System.Globalization.CultureInfo.InvariantCulture;

if (args.Length == 0)
{
    PrintUsage();
    return 2;
}

var paths = ExtractAll(args, "--path", "--dir", "--input", "--file");
var path = paths.FirstOrDefault();
var gateFile = ExtractArg(args, "--gate", "--config");
var sarifOut = ExtractArg(args, "--sarif", "--sarif-out");
// Reports somebody keeps rather than reads once: one page to open in a browser, one Markdown file
// to paste into a review or hand to an assistant. Both carry the same data as the console summary.
var htmlOut = ExtractArg(args, "--html", "--html-out");
var markdownOut = ExtractArg(args, "--markdown", "--md");
var sarifIn = ExtractArg(args, "--sarif-in", "--report");
var coverageFiles = ExtractAll(args, "--coverage", "--coverage-report");
var newCodeBase = ExtractArg(args, "--base", "--diff-base", "--new-code-base");
var verbose = args.Any(a => a is "--verbose" or "-v");
var newCodeMode = args.Any(a => a is "--new-code");
var showFixes = args.Any(a => a is "--fix-hints" or "--how-to-fix") || verbose;
var byFolder = args.Any(a => a is "--by-folder" or "--folders");
var scanOptions = new ScanOptions
{
    Paths = paths,
    Include = ExtractAll(args, "--include", "--only"),
    Exclude = ExtractAll(args, "--exclude", "--ignore"),
    UseDefaultExcludes = !args.Any(a => a is "--no-default-excludes" or "--all-files"),
    MaxFileKilobytes = int.TryParse(ExtractArg(args, "--max-file-kb"), out var kb) ? kb : 2048
};

// The default profile mirrors what the reference engines enable out of the box; '--all-rules' turns
// the conventions and the stylistic checks back on for a full sweep.
var everyRule = args.Any(a => a is "--all-rules" or "--every-rule");

if (args.Any(a => a is "--rules"))
{
    PrintRuleCatalog();
    return 0;
}

if (args.Any(a => a is "--rule-list"))
{
    foreach (var rule in RuleRepository.GetBuiltInRules().OrderBy(r => r.Key, StringComparer.Ordinal))
        Console.WriteLine($"{rule.Key}	{rule.Name}");
    return 0;
}

if (args.Any(a => a is "--dump-ast") && path != null)
{
    DumpTree(path);
    return 0;
}

try
{
    var conditions = gateFile != null ? GateConfig.Load(gateFile) : GateConfig.LoadDefault();

    if (sarifIn != null)
    {
        var report = new SarifReader().Read(sarifIn);
        var result = new QualityGateEvaluator().Evaluate(report.Metrics, conditions);
        PrintResult(result, verbose);
        foreach (var issue in report.Issues)
            PrintIssue(issue, showFixes);
        return result.Status == QualityGateStatus.Failed ? 1 : 0;
    }

    if (path == null)
    {
        Console.Error.WriteLine("ERROR: no input given (use --path or --sarif-in).");
        return 2;
    }

    var vendorPaths = ExtractAll(args, "--vendor", "--third-party");
    var analyses = AnalyzeAndScan(scanOptions, verbose, everyRule, vendorPaths);
    var metrics = AggregateMetrics(analyses);

    // new_lines is a real count whenever a base is given: git is asked which lines the branch added
    // or rewrote, and that total feeds the gate's fudge factor and the new-code ratings alike.
    // Without a base the metric stays unset and the gate treats it as not applicable.
    // git must resolve the repository the scan points at, not whichever directory the CLI was
    // launched from: the scan root is the working directory for the rev-list and the diff
    var workingDirectory = path is null ? null : ScanWorkingDirectory(path);
    var changedLines = newCodeBase is null
        ? null
        : ReadNewCodeBase(metrics, GitChangedLines.Resolve(newCodeBase, workingDirectory), workingDirectory, newCodeBase);

    if (newCodeMode)
        ApplyNewCodeMetrics(metrics, analyses);

    // the gate has to see the coverage, so it is read before the verdict rather than with the summary
    var coverage = ReadCoverage(coverageFiles);
    if (coverage is not null)
    {
        coverage = coverage.ExcludingFromSource(analyses);
        ApplyCoverageMetrics(metrics, coverage);
        if (changedLines is not null)
            ApplyNewCodeCoverage(metrics, coverage, newCodeBase!, analyses, changedLines);
    }

    var gateResult = new QualityGateEvaluator().Evaluate(metrics, conditions);
    PrintResult(gateResult, verbose);

    foreach (var analysis in analyses)
    {
        foreach (var issue in analysis.Issues)
            PrintIssue(issue, showFixes);
        if (verbose)
        {
            Console.WriteLine($"  FILE {analysis.File.FileName}: lines={analysis.Metrics["lines"]} ncloc={analysis.Metrics["ncloc"]} complexity={analysis.Metrics["complexity"]} dups={analysis.Duplicates.Count}");
        }
    }

    PrintQualitySummary(analyses, metrics, coverage, newCodeBase);

    if (byFolder)
        PrintFolderSummary(analyses);

    if (sarifOut != null)
        SarifWriter.Write(sarifOut, analyses, gateResult);

    if (htmlOut != null || markdownOut != null)
    {
        var report = QualityGuard.Cli.Reporting.HtmlReportData.From(analyses, metrics, gateResult);
        if (htmlOut != null)
            QualityGuard.Cli.ReportHTML.ReportGenerator.Generate(htmlOut, report);
        if (markdownOut != null)
            QualityGuard.Cli.Reporting.MarkdownReport.Write(markdownOut, report);
    }

    return gateResult.Status == QualityGateStatus.Failed ? 1 : 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"ERROR: {ex.Message}");
    if (verbose)
        Console.Error.WriteLine(ex);
    return 2;
}

    static List<FileAnalysis> AnalyzeAndScan(ScanOptions options, bool verbose, bool everyRule,
        IReadOnlyList<string> vendorPaths)
    {
    var scan = SourceScanner.Scan(options);
    foreach (var missing in scan.MissingPaths)
        Console.Error.WriteLine($"WARNING: {missing} does not exist");
    if (verbose)
    {
        Console.WriteLine($"SCAN {scan.Files.Count} files to analyse "
                          + $"(skipped: {scan.SkippedUnknownLanguage} unknown language, "
                          + $"{scan.SkippedExcluded} excluded, {scan.SkippedTooLarge} too large, "
                          + $"{scan.SkippedBinary} binary)");
    }

    var files = new List<SourceFile>();
    foreach (var filePath in scan.Files)
    {
        try
        {
            // the content decides for the formats that share an extension, so it is read before the
            // language is settled rather than after
            var content = File.ReadAllText(filePath);
            if (BuiltInLanguages.Recognizer.Recognize(filePath, content) is { } lang)
                files.Add(new SourceFile(filePath, content, lang));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"WARNING: cannot read {filePath}: {ex.Message}");
        }
    }

    var analysisOptions = new AnalysisOptions { VendorPaths = vendorPaths };
    var context = new AnalysisContext(files, analysisOptions);
    var engine = new AnalysisEngine();
    var all = engine.Run(context).ToList();

    // a file the engine could not read is said out loud: a gate that skipped one silently would be
    // worse than one that admits it
    foreach (var (path, reason) in engine.Unreadable)
        Console.WriteLine($"  SKIPPED {path}: {reason}");

    var vendorFiles = all.Where(a => a.File.IsVendor).ToList();
    if (vendorFiles.Count > 0)
        Console.WriteLine(
            $"  VENDOR {vendorFiles.Count} files marked as third-party; rules stay silent on them");

    var rules = RuleRepository.GetBuiltInRules(everyRule);
    foreach (var analysis in all.Where(a => !a.File.IsVendor))
        RuleEngine.Run(analysis, rules);

    return all;
}

static Dictionary<string, double> AggregateMetrics(List<FileAnalysis> all)
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
            // a density is a ratio: summing one per file would report hundreds of per cent
            if (k == CoreMetrics.DuplicatedLinesDensity)
                continue;
            metrics[k] = metrics.GetValueOrDefault(k) + v;
        }
    }

    var totalNcloc = metrics.GetValueOrDefault(CoreMetrics.Ncloc);
    metrics[CoreMetrics.DuplicatedLinesDensity] = totalNcloc > 0 ? duplicatedLines / totalNcloc * 100.0 : 0;
    metrics[CoreMetrics.Files] = all.Count;

    // counts, debt and ratings come from the findings themselves, so every number in the report can
    // be traced back to the lines that produced it
    var issues = all.SelectMany(a => a.Issues).ToList();
    foreach (var (key, value) in QualityRatings.ComputeMetrics(issues, metrics.GetValueOrDefault(CoreMetrics.Ncloc)))
        metrics[key] = value;
    metrics[CoreMetrics.NewSecurityHotspotsReviewed] =
        issues.Any(i => i.Kind == IssueKind.SecurityHotspot) ? 0.0 : 100.0;
    return metrics;
}

static void ApplyNewCodeMetrics(Dictionary<string, double> metrics, List<FileAnalysis> all)
{
    var issues = all.SelectMany(a => a.Issues).ToList();
    foreach (var (k, v) in QualityRatings.ComputeNewCodeMetrics(issues,
                 metrics.GetValueOrDefault(CoreMetrics.NewLines)))
    {
        metrics[k] = v;
    }
    metrics[CoreMetrics.NewDuplicatedLinesDensity] = metrics.GetValueOrDefault(CoreMetrics.DuplicatedLinesDensity);
}

/// <summary>
/// Coverage cannot be worked out by reading code — it takes running the tests — so the number comes
/// from the report the test runner already writes. Several reports for the same suite (one per shard
/// or per test project) are merged into one, and the tests' own files are left out so that the
/// percentage describes production code. Without it the gate has no way of telling a project with a
/// thorough suite from one with none.
/// </summary>
static QualityGuard.Core.Analysis.CoverageReport? ReadCoverage(List<string> files)
{
    var reports = new List<QualityGuard.Core.Analysis.CoverageReport>();
    foreach (var file in files)
    {
        var report = QualityGuard.Core.Analysis.CoverageReport.Read(file);
        if (report is null)
        {
            Console.Error.WriteLine($"WARNING: {file} is not a recognized coverage report "
                                    + "(LCOV, Cobertura or JaCoCo).");
            continue;
        }
        reports.Add(report);
    }
    if (reports.Count == 0)
        return null;
    var merged = reports.Count == 1 ? reports[0] : QualityGuard.Core.Analysis.CoverageReport.Merge(reports);
    return merged.ExcludingTests();
}

/// <summary>
/// The overall coverage numbers into the metric map, computed the way the reference engine defines
/// them: line coverage over lines, branch coverage over conditions, overall coverage over both.
/// </summary>
static void ApplyCoverageMetrics(Dictionary<string, double> metrics,
                                 QualityGuard.Core.Analysis.CoverageReport coverage)
{
    metrics[CoreMetrics.LinesToCover] = coverage.LinesToCover;
    metrics[CoreMetrics.UncoveredLines] = coverage.UncoveredLines;
    metrics[CoreMetrics.ConditionsToCover] = coverage.ConditionsToCover;
    metrics[CoreMetrics.UncoveredConditions] = coverage.UncoveredConditions;
    metrics[CoreMetrics.Coverage] = coverage.Coverage;
    metrics[CoreMetrics.LineCoverage] = coverage.LineCoverage;
    metrics[CoreMetrics.BranchCoverage] = coverage.BranchCoverage;
}

/// <summary>
/// Where git should look for the repository: the scan root itself when it is a directory, its
/// parent when <c>--path</c> names a single file.
/// </summary>
static string? ScanWorkingDirectory(string scanPath)
{
    var full = System.IO.Path.GetFullPath(scanPath);
    if (Directory.Exists(full))
        return full;
    return System.IO.Path.GetDirectoryName(full);
}

/// <summary>
/// Asks git how many lines the current branch added or rewrote against the base, and records that
/// total as <c>new_lines</c> — the real size of the new code, not a stand-in for the whole file. The
/// same map is then given back to the coverage step, so the new-code coverage is computed on exactly
/// the lines this branch touched and the git process runs once per scan. When git cannot answer the
/// metric is left unset, which is how the gate treats a metric it was not given.
/// </summary>
static IReadOnlyDictionary<string, IReadOnlySet<int>>? ReadNewCodeBase(
    Dictionary<string, double> metrics, string gitBase, string? workingDirectory, string displayBase)
{
    var git = GitChangedLines.Read(gitBase, workingDirectory);
    if (git.Count == 0)
    {
        Console.Error.WriteLine($"WARNING: could not read the lines changed since {displayBase} from git; "
                                + "new code is not measured.");
        return null;
    }
    metrics[CoreMetrics.NewLines] = git.Values.Sum(l => l.Count);
    return git;
}

/// <summary>
/// New code means the lines the current branch added or rewrote against the base: the coverage
/// report is restricted to them, and the same percentages are then computed over that smaller set. A
/// gate that asks about <c>new_coverage</c> is then judging the change itself rather than the whole
/// file. Without a base there is no new code to measure, so the <c>new_*</c> metrics are left unset —
/// which is how a gate treats a metric it was not given.
/// </summary>
static bool ApplyNewCodeCoverage(Dictionary<string, double> metrics,
                                 QualityGuard.Core.Analysis.CoverageReport coverage,
                                 string baseRef, List<FileAnalysis> analyses,
                                 IReadOnlyDictionary<string, IReadOnlySet<int>> git)
{
    // git reports absolute paths and the scan may have recorded relative ones, so every scanned file
    // is made absolute (against the working directory) before the two sides are compared
    var resolver = new CoveragePathResolver(analyses.Select(a => System.IO.Path.GetFullPath(a.File.Path)));
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
        Console.Error.WriteLine($"WARNING: no covered file matched the lines changed since {baseRef}; "
                                + "new code coverage is not measured.");
        return false;
    }

    var newCode = coverage.NewCode(newLinesByFile);
    if (!newCode.HasData)
    {
        Console.Error.WriteLine($"WARNING: no new code with coverage data since {baseRef}; "
                                + "new code coverage is not measured.");
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

/// <summary>
/// The numbers of the scan: how much code was read, what was found, how it breaks down by severity,
/// what it costs to fix and which letter each rating lands on. Printed for every run, because a
/// verdict without the figures behind it is impossible to argue with.
/// </summary>
static void PrintQualitySummary(List<FileAnalysis> analyses, Dictionary<string, double> metrics,
                                QualityGuard.Core.Analysis.CoverageReport? coverage = null,
                                string? newCodeBase = null)
{
    if (coverage != null)
    {
        Console.WriteLine($"  Coverage         {coverage.Coverage,5:0.0}%   {coverage.CoveredLines} of "
                          + $"{coverage.LinesToCover} lines and {coverage.CoveredConditions} of "
                          + $"{coverage.ConditionsToCover} conditions "
                          + $"(line {coverage.LineCoverage:0.0}%, branch {coverage.BranchCoverage:0.0}%) "
                          + $"over {coverage.Files.Count} files");
    }
    if (metrics.ContainsKey(CoreMetrics.NewCoverage) && newCodeBase is not null)
    {
        var newLines = metrics.GetValueOrDefault(CoreMetrics.NewLinesToCover);
        var newCovered = newLines - metrics.GetValueOrDefault(CoreMetrics.NewUncoveredLines);
        var newConditions = metrics.GetValueOrDefault(CoreMetrics.NewConditionsToCover);
        var newCoveredConditions = newConditions - metrics.GetValueOrDefault(CoreMetrics.NewUncoveredConditions);
        Console.WriteLine($"  New code         {metrics[CoreMetrics.NewCoverage],5:0.0}%   {newCovered:0} of {newLines:0}"
                          + $" new lines and {newCoveredConditions:0} of {newConditions:0} new conditions "
                          + $"since {newCodeBase}");
    }
    var issues = analyses.SelectMany(a => a.Issues).ToList();
    var debt = (int)metrics.GetValueOrDefault(CoreMetrics.TechnicalDebt);

    Console.WriteLine();
    Console.WriteLine($"SUMMARY  {analyses.Count} files, {metrics.GetValueOrDefault(CoreMetrics.Ncloc):0} ncloc, "
                      + $"{metrics.GetValueOrDefault(CoreMetrics.Complexity):0} complexity, "
                      + $"{metrics.GetValueOrDefault(CoreMetrics.DuplicatedLinesDensity):0.0}% duplicated");

    Console.WriteLine($"  Bugs             {Count(IssueKind.Bug),5}   reliability {Letter(CoreMetrics.ReliabilityRating)}"
                      + $"   {Breakdown(IssueKind.Bug)}");
    Console.WriteLine($"  Vulnerabilities  {Count(IssueKind.Vulnerability),5}   security    {Letter(CoreMetrics.SecurityRating)}"
                      + $"   {Breakdown(IssueKind.Vulnerability)}");
    Console.WriteLine($"  Security hotspots{Count(IssueKind.SecurityHotspot),5}   reviewed    "
                      + $"{metrics.GetValueOrDefault(CoreMetrics.NewSecurityHotspotsReviewed):0}%");
    Console.WriteLine($"  Code smells      {Count(IssueKind.CodeSmell),5}   maintainability {Letter(CoreMetrics.MaintainabilityRating)}"
                      + $"   {Breakdown(IssueKind.CodeSmell)}");
    var ratio = metrics.GetValueOrDefault(CoreMetrics.DebtRatio);
    Console.WriteLine($"  Technical debt   {FormatDebt(debt),5}   ratio {ratio:0.00}% {NextRating(ratio)}");

    // A rating saturates: nearly every codebase lands on A for maintainability, and a letter that
    // never changes tells the reader nothing. The density does change, and it is comparable between
    // one project and the next whatever their size.
    var ncloc = metrics.GetValueOrDefault(CoreMetrics.Ncloc);
    if (ncloc > 0)
    {
        Console.WriteLine($"  Per 1k lines     {issues.Count / ncloc * 1000,5:0.0}   issues"
                          + $"   ({Count(IssueKind.Bug) / ncloc * 1000:0.0} bugs,"
                          + $" {Count(IssueKind.Vulnerability) / ncloc * 1000:0.0} vulnerabilities,"
                          + $" {Count(IssueKind.CodeSmell) / ncloc * 1000:0.0} smells)");
    }

    var worst = issues.GroupBy(i => i.RuleKey)
        .OrderByDescending(g => g.Count())
        .Take(5)
        .ToList();
    if (worst.Count > 0)
    {
        Console.WriteLine("  Most frequent rules:");
        foreach (var group in worst)
            Console.WriteLine($"    {group.Key} {group.Count(),5}  {group.First().Message[..Math.Min(70, group.First().Message.Length)]}");
    }

    // where the work is, which is the question a reader actually has after reading the totals
    var heaviest = analyses
        .Select(a => (Path: a.File.Path, Debt: a.Issues.Sum(i => QualityRatings.EffortMinutes(i.RemediationEffort)),
            Count: a.Issues.Count))
        .Where(f => f.Debt > 0)
        .OrderByDescending(f => f.Debt)
        .Take(5)
        .ToList();
    if (heaviest.Count > 0)
    {
        Console.WriteLine("  Files holding the most debt:");
        foreach (var file in heaviest)
        {
            var name = System.IO.Path.GetFileName(file.Path);
            Console.WriteLine($"    {FormatDebt(file.Debt),6}  {file.Count,4} issues  {name}");
        }
    }

    static string NextRating(double ratio) => ratio switch
    {
        <= 5 => $"(A up to 5%)",
        <= 10 => $"(B up to 10%)",
        <= 20 => $"(C up to 20%)",
        <= 50 => $"(D up to 50%)",
        _ => "(E above 50%)"
    };

    int Count(IssueKind kind) => issues.Count(i => i.Kind == kind);

    string Letter(string metric) => QualityRatings.Letter(metrics.GetValueOrDefault(metric, 1));

    string Breakdown(IssueKind kind)
    {
        var parts = new List<string>();
        foreach (var severity in new[] { Severity.Blocker, Severity.Critical, Severity.Major, Severity.Minor, Severity.Info })
        {
            var count = issues.Count(i => i.Kind == kind && i.Severity == severity);
            if (count > 0)
                parts.Add($"{severity.ToString().ToLowerInvariant()} {count}");
        }
        return parts.Count == 0 ? "-" : string.Join(", ", parts);
    }

    static string FormatDebt(int minutes)
        => minutes >= 480 ? $"{minutes / 480.0:0.0}d" : minutes >= 60 ? $"{minutes / 60.0:0.0}h" : $"{minutes}m";
}

/// <summary>
/// One line per directory, deepest counts rolled up into their parents. On a tree of any size this is
/// what tells you where the debt actually sits: a flat list of issues cannot.
/// </summary>
static void PrintFolderSummary(List<FileAnalysis> analyses)
{
    var folders = new SortedDictionary<string, (int Files, int Bugs, int Vulns, int Smells, double Ncloc)>(
        StringComparer.OrdinalIgnoreCase);

    foreach (var analysis in analyses)
    {
        var folder = Path.GetDirectoryName(analysis.File.Path)?.Replace('\\', '/') ?? ".";
        if (folder.Length == 0)
            folder = ".";
        var current = folders.GetValueOrDefault(folder);
        folders[folder] = (
            current.Files + 1,
            current.Bugs + analysis.IssuesOf(IssueKind.Bug).Count(),
            current.Vulns + analysis.IssuesOf(IssueKind.Vulnerability).Count(),
            current.Smells + analysis.IssuesOf(IssueKind.CodeSmell).Count(),
            current.Ncloc + analysis.Metrics.GetValueOrDefault(CoreMetrics.Ncloc));
    }

    Console.WriteLine();
    Console.WriteLine($"{"FOLDER",-58} {"FILES",5} {"NCLOC",7} {"BUGS",5} {"VULN",5} {"SMELLS",6}");
    foreach (var (folder, totals) in folders)
    {
        var name = folder.Length > 58 ? "…" + folder[^57..] : folder;
        Console.WriteLine($"{name,-58} {totals.Files,5} {totals.Ncloc,7:0} {totals.Bugs,5} "
                          + $"{totals.Vulns,5} {totals.Smells,6}");
    }
}

static void PrintResult(QualityGateResult result, bool verbose)
{
    Console.WriteLine($"QUALITY GATE: {result.Status}");
    foreach (var c in result.Conditions)
    {
        var icon = c.Status == ConditionStatus.Error ? "FAIL" : "OK  ";
        Console.WriteLine($"  [{icon}] {c.Condition.MetricKey}: {FormatNoUnits(c.Measured)} vs {FormatNoUnits(c.Condition.Threshold)} ({c.Condition.Operator}) - {c.Message ?? "passed"}");
    }
}

static void PrintIssue(Issue issue, bool showFix)
{
    Console.WriteLine($"  ISSUE {issue.RuleKey} {issue.Severity}: {issue.Message} ({issue.File}:{issue.Line})");
    if (issue.Flow is { Count: > 1 } flow)
    {
        foreach (var step in flow)
            Console.WriteLine($"      flow  line {step.Line}: {step.Description}");
    }
    if (showFix && issue.HowToFix is { Length: > 0 } fix)
    {
        foreach (var line in fix.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            Console.WriteLine($"      fix   {line.Trim()}");
    }
}

static void DumpTree(string filePath)
{
    var language = BuiltInLanguages.Recognizer.Recognize(filePath);
    if (language == null)
    {
        Console.Error.WriteLine($"ERROR: unknown language for {filePath}");
        return;
    }
    var tokens = new QualityGuard.Core.Tokenization.SourceTokenizer(File.ReadAllText(filePath), language).Tokenize();
    var tree = QualityGuard.Core.Syntax.SyntaxTree.Build(tokens, language);
    Print(tree.Root, 0);

    static void Print(QualityGuard.Core.Syntax.SyntaxNode node, int depth)
    {
        Console.WriteLine($"{new string(' ', depth * 2)}{node.Kind} '{node.Text}' [{node.Range.StartLine}-{node.Range.EndLine}]");
        foreach (var child in node.Children)
            Print(child, depth + 1);
    }
}

static void PrintRuleCatalog()
{
    var rules = RuleRepository.GetBuiltInRules().OrderBy(r => r.Key, StringComparer.Ordinal).ToList();
    Console.WriteLine($"{rules.Count} rules loaded ({QualityGuard.Core.Rules.Catalog.RuleCatalog.Entries.Count} catalog entries)");
    foreach (var group in rules.GroupBy(r => r.Key.Split('-') is { Length: >= 2 } p ? p[1] : "?")
                 .OrderBy(g => g.Key, StringComparer.Ordinal))
    {
        var documented = group.Count(r => QualityGuard.Core.Rules.Catalog.RuleDocs.IsCurated(r.Key));
        Console.WriteLine($"  {group.Key,-5} {group.Count(),4} rules, {documented,4} with a curated description");
    }
}

static string FormatNoUnits(double v)
    => double.IsNaN(v) ? "N/A" : v.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture);

/// <summary>
/// Every value given for an option, whether repeated (--path a --path b) or listed once
/// (--path a,b). Scanning several trees in one run is the normal case in a monorepo.
/// </summary>
static List<string> ExtractAll(string[] args, params string[] names)
{
    var values = new List<string>();
    for (var i = 0; i < args.Length; i++)
    {
        if (!names.Contains(args[i]) || i + 1 >= args.Length)
            continue;
        foreach (var value in args[i + 1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            values.Add(value);
    }
    return values;
}

static string? ExtractArg(string[] args, params string[] names)
{
    for (var i = 0; i < args.Length; i++)
    {
        if (names.Contains(args[i]) && i + 1 < args.Length)
            return args[i + 1];
    }
    return null;
}

static void PrintUsage()
{
    Console.WriteLine("""
        QualityGuard CLI
        Usage:
          QualityGuard.Cli --path <dir|file> [--path <more>] [--gate <json>] [--sarif <out.json>]
                           [--include <glob>] [--exclude <glob>] [--by-folder] [--verbose] [--new-code]
          QualityGuard.Cli --sarif-in <report.json> [--gate <json>]
          QualityGuard.Cli --rules

        Input
          --path        file or directory; directories are scanned to the bottom, including every
                        subfolder. Repeat the option or separate values with commas to scan several.
          --include     only scan files matching this glob (repeatable, e.g. --include "src/**/*.cs").
          --exclude     skip files or directories matching this glob (repeatable).
          --max-file-kb skip files larger than this (default 2048).
          --all-files   keep the build, dependency and generated files that are skipped by default
                        (bin, obj, node_modules, vendor, dist, *.min.js, *.designer.cs, …).
          --coverage    coverage report from the test runner (LCOV, Cobertura or JaCoCo). Repeatable:
                        reports from every test shard are merged. Test files are excluded by default.
          --base        base branch/commit/tag that new code is measured against. When given with
                        --coverage, the new_* coverage metrics are computed from git on the lines the
                        current branch actually changed, instead of being left empty.

        Output
          --by-folder   summary table of files, ncloc and issues per directory.
          --new-code    derive the new_* rating metrics from the issues and evaluate them in the gate.
          --fix-hints   print the fix guidance of every reported rule.
          --verbose     per-file metrics, flow steps and what the scan skipped.
          --rules       list loaded rules and description coverage.
        Exit codes: 0 = PASSED, 1 = FAILED, 2 = error.
        """);
}
