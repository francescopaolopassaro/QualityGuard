using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Analysis;

public sealed class AnalysisEngine
{
    private readonly DuplicationDetector _duplicator = new();

    public IReadOnlyList<FileAnalysis> Run(AnalysisContext context)
    {
        foreach (var file in context.Files)
        {
            if (file.Language == null)
                continue;

            var tokens = new Tokenization.SourceTokenizer(file.Content, file.Language).Tokenize();
            var tree = SyntaxTree.Build(tokens, file.Language);
            var semantics = SemanticModel.Build(tree);

            var analysis = new FileAnalysis
            {
                File = file,
                Tokens = tokens,
                Tree = tree,
                Semantics = semantics,
                Taint = TaintEngine.Analyze(tree, semantics)
            };

            foreach (var (key, value) in MetricCalculator.Compute(file, tokens, tree))
                analysis.Metrics[key] = value;

            foreach (var duplicate in _duplicator.FindDuplicates(file, tokens))
                analysis.Duplicates.Add(duplicate);

            context.Results.Add(analysis);
        }

        // the index needs every file, so it is attached once the whole scan is parsed
        var index = ProjectIndex.Build(context.Results);
        foreach (var analysis in context.Results)
            analysis.Project = index;

        // untrusted data crosses files: close the loop once every file has its own result
        InterproceduralTaint.Run(context.Results);

        return context.Results;
    }
}
