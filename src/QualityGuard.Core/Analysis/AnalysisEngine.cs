using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Analysis;

public sealed class AnalysisEngine
{
    private readonly DuplicationDetector _duplicator = new();

    /// <summary>
    /// Files the engine could not read, with the reason. They are reported rather than swallowed: a
    /// quality gate that silently skipped a file would be worse than one that says it did.
    /// </summary>
    public List<(string Path, string Reason)> Unreadable { get; } = [];

    public IReadOnlyList<FileAnalysis> Run(AnalysisContext context)
    {
        // third-party code is marked before anything runs: the files keep their metrics and stay
        // in the project index, but rules will not speak about code nobody here can change
        if (context.Options.VendorPaths.Count > 0)
        {
            var vendorPatterns = SourceScanner.Compile(
                context.Options.VendorPaths.Where(g => !string.IsNullOrWhiteSpace(g)).ToList());
            foreach (var file in context.Files)
            {
                var normalized = file.Path.Replace('\\', '/');
                file.IsVendor = vendorPatterns.Any(p => p.IsMatch(normalized));
            }
        }

        foreach (var file in context.Files)
        {
            if (file.Language == null)
                continue;

            // One unreadable file must not end the scan. A source that is being edited, generated
            // half-way or written in a dialect the parser does not know is a normal thing to meet in
            // a repository, and the answer to it is to say so and carry on with the other files.
            FileAnalysis analysis;
            try
            {
                var tokens = new Tokenization.SourceTokenizer(file.Content, file.Language).Tokenize();
                var tree = SyntaxTree.Build(tokens, file.Language);
                var semantics = SemanticModel.Build(tree);

                analysis = new FileAnalysis
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
            }
            catch (Exception failure)
            {
                Unreadable.Add((file.Path, failure.Message));
                continue;
            }

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
