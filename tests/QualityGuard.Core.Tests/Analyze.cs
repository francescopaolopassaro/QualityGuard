using QualityGuard.Core.Analysis;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Tests;

/// <summary>Runs the full pipeline on an in-memory file, the way the CLI does.</summary>
internal static class Analyze
{
    public static FileAnalysis File(string fileName, string content)
    {
        var language = BuiltInLanguages.Recognizer.Recognize(fileName)
                       ?? throw new InvalidOperationException($"no language for {fileName}");
        var source = new SourceFile(fileName, content, language);
        var context = new AnalysisContext([source], new AnalysisOptions());
        return new AnalysisEngine().Run(context).Single();
    }

    public static FileAnalysis WithRules(string fileName, string content, params string[] ruleKeys)
    {
        var analysis = File(fileName, content);
        var rules = ruleKeys.Length == 0
            ? RuleRepository.GetBuiltInRules()
            : new HashSet<IRule>(ruleKeys.Select(k => RuleRepository.Find(k)
                                                      ?? throw new InvalidOperationException($"unknown rule {k}")));
        RuleEngine.Run(analysis, rules);
        return analysis;
    }

    public static IReadOnlyList<int> LinesOf(FileAnalysis analysis, string ruleKey)
        => analysis.Issues.Where(i => i.RuleKey == ruleKey).Select(i => i.Line ?? 0).ToList();
}
