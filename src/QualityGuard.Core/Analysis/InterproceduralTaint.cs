using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Analysis;

/// <summary>
/// Carries untrusted data across function and file boundaries.
///
/// The per-file pass answers "what is tainted inside this file". This one closes the loop over the
/// whole scan: a function that returns attacker-controlled data becomes a source everywhere it is
/// called, and an argument that is tainted at any call site taints the matching parameter of the
/// callee, wherever it is declared. Both facts feed back into the per-file pass until nothing changes.
/// </summary>
public static class InterproceduralTaint
{
    private const int MaxRounds = 5;

    public static TaintContext Run(IReadOnlyList<FileAnalysis> analyses)
    {
        var context = new TaintContext();
        if (analyses.Count == 0)
            return context;

        var functions = CollectFunctions(analyses);

        for (var round = 0; round < MaxRounds; round++)
        {
            var changed = false;

            // 1. a call that passes tainted data taints the parameter of the callee, in any file
            foreach (var analysis in analyses)
            {
                var taint = analysis.Taint;
                if (taint == null)
                    continue;

                foreach (var call in analysis.Tree.Root.OfKind(NodeKind.Invocation))
                {
                    var name = SyntaxQuery.InvokedName(call);
                    if (!functions.TryGetValue(name, out var callee))
                        continue;
                    var arguments = SyntaxQuery.Arguments(call);
                    var parameters = SyntaxQuery.Parameters(callee.Node).ToList();

                    for (var i = 0; i < parameters.Count && i < arguments.Count; i++)
                    {
                        if (!taint.IsTainted(arguments[i]))
                            continue;
                        var symbol = callee.Analysis.Semantics.ScopeOf(callee.Node).Lookup(parameters[i].Text);
                        if (symbol is null or { IsTainted: true })
                            continue;
                        symbol.IsTainted = true;
                        symbol.TaintSource = arguments[i];
                        changed = true;
                    }
                }
            }

            // 2. a function whose result derives from untrusted data is a source for its callers
            foreach (var (name, function) in functions)
            {
                if (context.ReturnsTainted(name))
                    continue;
                var returned = function.Node.OfKind(NodeKind.Jump)
                    .Where(j => j.Text.StartsWith("return", StringComparison.Ordinal))
                    .SelectMany(j => j.Children)
                    .FirstOrDefault(value => function.Analysis.Taint?.IsTainted(value) == true);
                if (returned == null)
                    continue;
                if (context.Remember(name, function.Analysis.File.Path, returned.Line))
                    changed = true;
            }

            if (!changed)
                break;

            // 3. replay the per-file pass with what was just learned, keeping the marks already set
            foreach (var analysis in analyses)
            {
                analysis.Taint = TaintEngine.Analyze(analysis.Tree, analysis.Semantics, context,
                    keepExistingMarks: true);
            }
        }

        return context;
    }

    private sealed record FunctionEntry(FileAnalysis Analysis, SyntaxNode Node);

    /// <summary>
    /// Functions by name. A name declared more than once is dropped: without overload resolution,
    /// propagating into the wrong body would invent flows that do not exist.
    /// </summary>
    private static Dictionary<string, FunctionEntry> CollectFunctions(IReadOnlyList<FileAnalysis> analyses)
    {
        var functions = new Dictionary<string, FunctionEntry>(StringComparer.Ordinal);
        var ambiguous = new HashSet<string>(StringComparer.Ordinal);

        foreach (var analysis in analyses)
        {
            foreach (var function in SyntaxQuery.Functions(analysis.Tree.Root))
            {
                if (function.Text.Length == 0)
                    continue;
                if (!functions.TryAdd(function.Text, new FunctionEntry(analysis, function)))
                    ambiguous.Add(function.Text);
            }
        }

        foreach (var name in ambiguous)
            functions.Remove(name);
        return functions;
    }
}
