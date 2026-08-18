using System.Text.RegularExpressions;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Analysis;

/// <summary>
/// The lines of one source file that its authors have told the coverage tooling to skip. A whole
/// file can be dropped (the marker sits at the top and means "do not measure this file at all"), or
/// individual lines can be removed.
/// </summary>
public sealed class FileExclusions
{
    /// <summary>Whether the whole file was marked as not to be measured.</summary>
    public bool ExcludeFile { get; init; }

    /// <summary>The explicit line numbers the team asked to skip.</summary>
    public IReadOnlySet<int> Lines { get; init; } = new HashSet<int>();

    /// <summary>Whether this entry removes anything from a report.</summary>
    public bool IsEmpty => !ExcludeFile && Lines.Count == 0;
}

/// <summary>
/// Reads the exclusion markers the coverage tools themselves understand, so the report QualityGuard
/// produces is the one everyone else already sees. Every instrumented platform has a way to say "this
/// is not code we measure": an attribute on the member (C# <c>[ExcludeFromCodeCoverage]</c>, Java and
/// Kotlin <c>@Generated</c>), or a marker comment in the source, spelled differently per language.
///
/// Once a line is excluded it stops counting both among the lines to cover and among the covered
/// ones, which is exactly what the runner would have done had it known the marker.
/// </summary>
public sealed class CoverageExclusions
{
    // Qualified names are read whole ('System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage' or
    // 'javax.annotation.Generated'), so the match looks at the last segment only and ignores the
    // 'Attribute' suffix C# allows in the source.
    private static readonly string[] CSharpAttributeNames =
        ["ExcludeFromCodeCoverage", "GeneratedCode"];

    // JaCoCo and its friends do not measure code annotated '@Generated': the annotation is the
    // platform's own "skip this" gesture for generated sources, so honoring it keeps the numbers
    // aligned with the tooling that wrote the report.
    private static readonly string[] GeneratedAttributeNames = ["Generated"];

    // The comment markers are separated by intent, because each intent has its own geometry: a
    // 'line' marker removes just its own line, 'next' the line after the comment, and a START/STOP
    // pair a whole region. A 'file' marker removes the file altogether. 'LCOV_EXCL_*' and
    // 'GCOVR_EXCL_*' come from the lcov and gcovr families and work in any language; the others are
    // the dialects of the JavaScript tooling (istanbul, c8, v8), Python's pragma, PHP's doc-block
    // annotations and Ruby's :nocov: pairs.
    private static readonly Regex WholeFileMarkers = new(
        @"\b(?:coverage:ignore-file)\b|\b(?:istanbul|c8|v8)\s+ignore\s+file\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex LineMarkers = new(
        @"\b(?:LCOV_EXCL_LINE|GCOVR_EXCL_LINE|coverage:ignore-line)\b|"
        + @"\bpragma:\s*no\s+cover\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // php-code-coverage attaches '@codeCoverageIgnore' to the declaration the doc block precedes, so
    // the marker sits above the code it protects: like the JavaScript 'ignore next' family it removes
    // the line after the comment. The first line is where the element begins; the rest of a multi-line
    // body is beyond what a line-based reading can promise.
    private static readonly Regex NextMarkers = new(
        @"\b(?:istanbul|c8|v8)\s+ignore\s+next\b|"
        + @"@codeCoverageIgnore\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex StartMarkers = new(
        @"\b(?:LCOV_EXCL_START|GCOVR_EXCL_START|coverage:ignore-start)\b|"
        + @"\b(?:istanbul|c8|v8)\s+ignore\s+start\b|"
        + @"@codeCoverageIgnoreStart\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex StopMarkers = new(
        @"\b(?:LCOV_EXCL_STOP|GCOVR_EXCL_STOP|coverage:ignore-stop)\b|"
        + @"\b(?:istanbul|c8|v8)\s+ignore\s+stop\b|"
        + @"@codeCoverageIgnoreEnd\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // SimpleCov's :nocov: is unusual: the same marker opens and closes a region, so the pair has to
    // be matched in order rather than by text.
    private static readonly Regex PairedRegionMarkers = new(
        @":nocov:",
        RegexOptions.Compiled);

    /// <summary>
    /// Finds the exclusions each scanned file declares, keyed by the absolute path so callers can
    /// resolve the report's own paths against them with a <see cref="CoveragePathResolver"/>.
    /// </summary>
    public static IReadOnlyDictionary<string, FileExclusions> Compute(
        IEnumerable<FileAnalysis> analyses)
    {
        var result = new Dictionary<string, FileExclusions>(StringComparer.OrdinalIgnoreCase);
        foreach (var analysis in analyses)
        {
            if (ComputeFile(analysis) is { IsEmpty: false } excluded)
                result[CoveragePathResolver.Normalize(
                    System.IO.Path.GetFullPath(analysis.File.Path))] = excluded;
        }
        return result;
    }

    private static FileExclusions? ComputeFile(FileAnalysis analysis)
    {
        var lines = new HashSet<int>();
        var openRanges = new Stack<int>();
        var excludeFile = false;

        ApplyAttributeMarkers(analysis, lines);
        ApplyCommentMarkers(analysis, lines, ref excludeFile, openRanges);

        // a START whose STOP never came swallows the rest of the file, as the tools define it
        while (openRanges.Count > 0)
            FillRange(lines, openRanges.Pop(), LineCount(analysis.File.Content));

        if (excludeFile)
            return new FileExclusions { ExcludeFile = true };
        return lines.Count == 0 ? null : new FileExclusions { Lines = lines };
    }

    /// <summary>
    /// The attribute form of an exclusion. The parser attaches each attribute directly to the member
    /// it decorates and the member's range covers everything up to the end of its body, so excluding
    /// the member means excluding its whole range — exactly the geometry the tools use.
    /// </summary>
    private static void ApplyAttributeMarkers(FileAnalysis analysis, HashSet<int> lines)
    {
        var names = analysis.File.Language?.LanguageKey switch
        {
            LanguageKeys.CSharp => CSharpAttributeNames,
            LanguageKeys.Java or LanguageKeys.Kotlin or LanguageKeys.Dart => GeneratedAttributeNames,
            _ => null
        };
        if (names is null || !analysis.Tree.HasDedicatedParser)
            return;

        foreach (var node in analysis.Tree.Root.DescendantsAndSelf())
        {
            if (node.Kind != NodeKind.Attribute)
                continue;
            if (!IsExcludedName(node.Text, names))
                continue;
            var member = node.Parent;
            if (member is null || member.Range.Equals(TextRange.Empty))
                continue;
            FillRange(lines, member.Range.StartLine, member.Range.EndLine);
        }
    }

    private static bool IsExcludedName(string text, string[] names)
    {
        var name = text[(text.LastIndexOf('.') + 1)..];
        foreach (var marker in names)
        {
            if (name == marker || name == marker + "Attribute")
                return true;
        }
        return false;
    }

    private static void ApplyCommentMarkers(FileAnalysis analysis, HashSet<int> lines,
        ref bool excludeFile, Stack<int> openRanges)
    {
        // a :nocov: line starts a region on the line after the comment; its match closes it
        // the line before. Two of them can never be on the same comment, so a single slot is enough.
        var regionStart = 0;
        foreach (var token in analysis.Tokens)
        {
            if (token.Kind != TokenKind.Comment)
                continue;
            var text = token.Text;

            if (PairedRegionMarkers.IsMatch(text))
            {
                if (regionStart == 0)
                    regionStart = token.Line + 1;
                else
                {
                    FillRange(lines, regionStart, token.Line - 1);
                    regionStart = 0;
                }
            }
            if (WholeFileMarkers.IsMatch(text))
                excludeFile = true;
            if (LineMarkers.IsMatch(text))
                lines.Add(token.Line);
            if (NextMarkers.IsMatch(text))
                lines.Add(token.Line + 1);
            if (StartMarkers.IsMatch(text))
                openRanges.Push(token.Line);
            if (StopMarkers.IsMatch(text))
            {
                var start = openRanges.Count > 0 ? openRanges.Pop() : token.Line;
                FillRange(lines, start, token.Line);
            }
        }

        if (regionStart != 0)
            FillRange(lines, regionStart, LineCount(analysis.File.Content));
    }

    private static void FillRange(HashSet<int> lines, int start, int end)
    {
        if (end < start)
            return;
        for (var line = start; line <= end; line++)
            lines.Add(line);
    }

    private static int LineCount(string content)
    {
        if (content.Length == 0)
            return 0;
        var count = 1;
        foreach (var c in content)
        {
            if (c == '\n')
                count++;
        }
        return count;
    }
}