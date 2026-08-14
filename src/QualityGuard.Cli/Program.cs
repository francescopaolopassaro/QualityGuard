using QualityGuard.Cli;
using QualityGuard.Core.Analysis;
using QualityGuard.Core.Evaluation;
using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Tokenization;
using QualityGuard.Sources.Sarif;

if (args.Length == 0)
{
    PrintUsage();
    return 2;
}

var path = ExtractArg(args, "--path", "--dir", "--input");
var gateFile = ExtractArg(args, "--gate", "--config");
var sarifOut = ExtractArg(args, "--sarif", "--sarif-out");
var sarifIn = ExtractArg(args, "--sarif-in", "--report");
var verbose = args.Any(a => a is "--verbose" or "-v");
var newCodeMode = args.Any(a => a is "--new-code");
var showFixes = args.Any(a => a is "--fix-hints" or "--how-to-fix") || verbose;

if (args.Any(a => a is "--rules"))
{
    PrintRuleCatalog();
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

    var analyses = AnalyzeAndScan(path);
    var metrics = AggregateMetrics(analyses);

    if (newCodeMode)
        ApplyNewCodeMetrics(metrics, analyses);

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

    if (sarifOut != null)
        SarifWriter.Write(sarifOut, analyses, gateResult);

    return gateResult.Status == QualityGateStatus.Failed ? 1 : 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"ERROR: {ex.Message}");
    if (verbose)
        Console.Error.WriteLine(ex);
    return 2;
}

static List<FileAnalysis> AnalyzeAndScan(string path)
{
    var attr = File.GetAttributes(path);
    IEnumerable<string> filePaths = (attr & FileAttributes.Directory) == FileAttributes.Directory
        ? Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
            .Where(f => BuiltInLanguages.Recognizer.Recognize(f) != null)
        : [path];

    var files = new List<SourceFile>();
    foreach (var filePath in filePaths)
    {
        if (BuiltInLanguages.Recognizer.Recognize(filePath) is not { } lang)
            continue;
        try
        {
            files.Add(new SourceFile(filePath, File.ReadAllText(filePath), lang));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"WARNING: cannot read {filePath}: {ex.Message}");
        }
    }

    var context = new AnalysisContext(files, new AnalysisOptions());
    var all = new AnalysisEngine().Run(context).ToList();

    var rules = RuleRepository.GetBuiltInRules();
    foreach (var analysis in all)
        RuleEngine.Run(analysis, rules);

    return all;
}

static Dictionary<string, double> AggregateMetrics(List<FileAnalysis> all)
{
    var metrics = new Dictionary<string, double>();
    foreach (var a in all)
    {
        var dupLines = a.Duplicates.Sum(d => d.Lines);
        a.Metrics[CoreMetrics.DuplicatedLinesDensity] =
            a.Metrics.GetValueOrDefault(CoreMetrics.Ncloc) > 0
                ? dupLines / Math.Max(1, a.Metrics[CoreMetrics.Ncloc]) * 100.0
                : 0;
        foreach (var (k, v) in a.Metrics)
            metrics[k] = metrics.GetValueOrDefault(k) + v;
    }

    metrics[CoreMetrics.Bugs] = all.Sum(a => a.IssuesOf(IssueKind.Bug).Count());
    metrics[CoreMetrics.Vulnerabilities] = all.Sum(a => a.IssuesOf(IssueKind.Vulnerability).Count());
    metrics[CoreMetrics.CodeSmells] = all.Sum(a => a.IssuesOf(IssueKind.CodeSmell).Count());
    metrics[CoreMetrics.NewLines] = metrics.GetValueOrDefault(CoreMetrics.Ncloc);
    return metrics;
}

static void ApplyNewCodeMetrics(Dictionary<string, double> metrics, List<FileAnalysis> all)
{
    var bugs = all.Sum(a => a.IssuesOf(IssueKind.Bug).Count());
    var vulns = all.Sum(a => a.IssuesOf(IssueKind.Vulnerability).Count());
    var smells = all.Sum(a => a.IssuesOf(IssueKind.CodeSmell).Count());
    var hotspots = all.Sum(a => a.IssuesOf(IssueKind.SecurityHotspot).Count());
    foreach (var (k, v) in QualityRatings.ComputeNewCodeMetrics(bugs, vulns, smells, hotspots,
                 metrics.GetValueOrDefault(CoreMetrics.NewLines)))
    {
        metrics[k] = v;
    }
    metrics[CoreMetrics.NewDuplicatedLinesDensity] = metrics.GetValueOrDefault(CoreMetrics.DuplicatedLinesDensity);
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
          QualityGuard.Cli --path <dir|file> [--gate <json>] [--sarif <out.json>] [--verbose] [--new-code]
          QualityGuard.Cli --sarif-in <report.json> [--gate <json>]
          QualityGuard.Cli --rules

        --new-code    derive the new_* rating metrics from the issues and evaluate them in the gate.
        --fix-hints   print the fix guidance of every reported rule.
        --rules       list loaded rules and description coverage.
        Exit codes: 0 = PASSED, 1 = FAILED, 2 = error.
        """);
}