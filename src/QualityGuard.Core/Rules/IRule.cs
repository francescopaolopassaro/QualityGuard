using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;
using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules;

public interface IRule
{
    /// <summary>Proprietary identifier, <c>QG-&lt;LANG&gt;-&lt;CAT&gt;-&lt;NNNN&gt;</c>.</summary>
    string Key { get; }

    /// <summary>Short English title, phrased as the expectation the code breaks.</summary>
    string Name { get; }

    Severity Severity { get; }
    IssueKind Kind { get; }

    /// <summary>Estimated fix effort, e.g. <c>10min</c>.</summary>
    string RemediationEffort { get; }

    string[] Languages { get; }

    /// <summary>English explanation plus the steps that fix the finding. Mandatory for every rule.</summary>
    RuleDescription Description { get; }

    string[] Tags { get; }

    /// <summary>CWE identifiers, used for SARIF taxonomies and security reports.</summary>
    int[] Cwe { get; }

    string[] Owasp { get; }

    void Execute(IRuleContext context);
}

public interface IRuleContext
{
    SourceFile File { get; }
    IReadOnlyList<Token> Tokens { get; }
    Dictionary<string, double> Metrics { get; }
    LanguageInfo Language { get; }

    /// <summary>Root of the syntax tree for the file under analysis.</summary>
    SyntaxNode Root { get; }

    SyntaxTree Tree { get; }

    /// <summary>Scopes, symbols and resolved values.</summary>
    SemanticModel Semantics { get; }

    /// <summary>
    /// Cross-file view of the code being analysed: declared types, their hierarchy and the names used
    /// anywhere. Empty when a single file is analysed on its own.
    /// </summary>
    ProjectIndex Project { get; }

    TaintResult? Taint { get; }

    bool IsTainted(string identifier);
    bool IsTaintedLine(int line);

    /// <summary>Data-flow check on a parsed expression; preferred over the name-based overloads.</summary>
    bool IsTainted(SyntaxNode? expression);

    void Report(string message, int? line = null);

    /// <summary>Reports on a node, attaching the taint flow when the finding is data-flow driven.</summary>
    void Report(SyntaxNode node, string message, bool withFlow = false);
}

internal sealed class RuleContext(SourceFile file, FileAnalysis analysis) : IRuleContext
{
    private readonly FileAnalysis _analysis = analysis;

    public SourceFile File { get; } = file;
    public IReadOnlyList<Token> Tokens => _analysis.Tokens;
    public Dictionary<string, double> Metrics => _analysis.Metrics;
    public LanguageInfo Language => File.Language!;
    public SyntaxTree Tree => _analysis.Tree;
    public SyntaxNode Root => _analysis.Tree.Root;
    public SemanticModel Semantics => _analysis.Semantics;
    public ProjectIndex Project => _analysis.Project ?? ProjectIndex.Empty;
    public TaintResult? Taint => _analysis.Taint;

    public IRule CurrentRule { get; set; } = null!;

    public bool IsTainted(string identifier) => _analysis.Taint?.IsTainted(identifier) ?? false;

    public bool IsTaintedLine(int line) => _analysis.Taint?.IsTaintedLine(line) ?? false;

    public bool IsTainted(SyntaxNode? expression) => _analysis.Taint?.IsTainted(expression) ?? false;

    public void Report(string message, int? line = null) => Add(message, line, null);

    public void Report(SyntaxNode node, string message, bool withFlow = false)
        => Add(message, node.Line, withFlow ? _analysis.Taint?.FlowTo(node) : null);

    private readonly HashSet<(string Rule, int Line)> _reported = [];

    private void Add(string message, int? line, IReadOnlyList<FlowStep>? flow)
    {
        // several clauses of the same rule can match one line; report it once
        if (!_reported.Add((CurrentRule.Key, line ?? 0)))
            return;
        _analysis.Issues.Add(new Issue(CurrentRule.Key, message, CurrentRule.Severity, CurrentRule.Kind,
            File.Path, line, CurrentRule.RemediationEffort, howToFix: CurrentRule.Description.HowToFix,
            flow: flow));
    }
}

public static class RuleRepository
{
    public static void RegisterRules(ISet<IRule> target, IEnumerable<IRule>? source = null)
    {
        foreach (var rule in source ?? BuiltInRuleRegistrar.All)
            target.Add(rule);
    }

    public static ISet<IRule> GetBuiltInRules() => new HashSet<IRule>(BuiltInRuleRegistrar.All);

    public static IRule? Find(string key)
        => BuiltInRuleRegistrar.All.FirstOrDefault(r => r.Key == key);
}

public static class RuleEngine
{
    public static void Run(FileAnalysis analysis, IEnumerable<IRule> rules)
    {
        var file = analysis.File;
        if (file.Language == null)
            return;

        var context = new RuleContext(file, analysis);
        foreach (var rule in rules)
        {
            if (rule.Languages.Length > 0 && !rule.Languages.Contains(file.Language.LanguageKey))
                continue;
            context.CurrentRule = rule;
            try
            {
                rule.Execute(context);
            }
            catch (Exception)
            {
                // a single failing rule must never abort the analysis of a file
            }
        }
    }
}
