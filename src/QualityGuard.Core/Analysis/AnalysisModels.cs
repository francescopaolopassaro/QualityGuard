using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Analysis;

public sealed class SourceFile
{
    public SourceFile(string path, string content, LanguageInfo? language)
    {
        Path = path;
        Content = content;
        Language = language;
    }

    public string Path { get; }
    public string Content { get; }
    public LanguageInfo? Language { get; }
    public string FileName => System.IO.Path.GetFileName(Path);
}

public sealed class FileAnalysis
{
    public required SourceFile File { get; init; }
    public required IReadOnlyList<Token> Tokens { get; init; }
    public required Syntax.SyntaxTree Tree { get; init; }
    public required Semantics.SemanticModel Semantics { get; init; }
    public TaintResult? Taint { get; internal set; }

    /// <summary>Set once every file has been parsed, so rules can look across the code base.</summary>
    public ProjectIndex? Project { get; internal set; }
    public Dictionary<string, double> Metrics { get; } = new();
    public List<Issue> Issues { get; } = [];
    public List<DuplicateBlock> Duplicates { get; } = [];

    public IEnumerable<Issue> IssuesOf(IssueKind kind) => Issues.Where(i => i.Kind == kind);
}

public sealed record DuplicateBlock(int StartLine, int EndLine, int TokensCount, int Occurrences)
{
    public int Lines => EndLine - StartLine + 1;
}

public sealed class AnalysisOptions
{
    public IReadOnlyList<string> IncludedExtensions { get; init; } = [];
    public IReadOnlyList<string> ExcludedPaths { get; init; } = [];
}

public sealed class AnalysisContext
{
    private readonly List<SourceFile> _files = [];

    public AnalysisContext(IEnumerable<SourceFile> files, AnalysisOptions options)
    {
        _files.AddRange(files);
        Options = options;
    }

    public AnalysisOptions Options { get; }
    public IReadOnlyList<SourceFile> Files => _files;
    public List<FileAnalysis> Results { get; } = [];
}