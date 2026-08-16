using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Analysis;

public sealed class DuplicationDetector
{
    private const int WindowSize = 20;

    /// <summary>
    /// A block has to be long enough that copying it was a decision, not a coincidence. Twelve tokens
    /// matched anything — a property, a guard clause, two lines of boilerplate — and reported almost
    /// every file as duplicated. A hundred tokens over at least six lines is a block a reviewer would
    /// also call a copy.
    /// </summary>
    private const int MinTokens = 100;

    private const int MinLines = 6;
    private const uint Base = 31;
    private const uint Prime = 1_000_000_007;

    /// <summary>
    /// Languages whose files are data, not code. A catalog, a manifest or a configuration repeats the
    /// same field skeleton on purpose; measuring that as duplication says nothing about quality and
    /// drowns the number that does.
    /// </summary>
    private static readonly string[] DataLanguages = ["yaml", "yml", "json", "xml", "k8", "cf", "ar", "tf", "md"];

    public IReadOnlyList<DuplicateBlock> FindDuplicates(SourceFile file, IReadOnlyList<Token> tokens)
    {
        if (file.Language is { } language
            && DataLanguages.Contains(language.LanguageKey, StringComparer.OrdinalIgnoreCase))
            return [];

        // normalized token sequence — ignore comments and maps each symbol/ident to normalized form
        // literals are normalised because a copy usually changes them; identifiers are kept, since
        // two blocks that differ in every name are two different pieces of code, however alike their
        // shape is. Normalising them too turned "same structure" into "duplicate".
        var normalized = tokens
            .Where(t => t.Kind != TokenKind.Comment)
            .Select(t => t.Kind == TokenKind.String ? "STR" : t.Kind == TokenKind.Number ? "NUM" : t.Text)
            .ToArray();

        if (normalized.Length < WindowSize * 2)
            return [];

        // rolling hash over sliding windows
        var hashes = new ulong[normalized.Length - WindowSize + 1];
        ulong windowHash = 0;
        ulong power = 1;
        for (var i = 0; i < WindowSize; i++)
            power *= Base;
        for (var i = 0; i < WindowSize; i++)
            windowHash = windowHash * Base + (ulong)normalized[i].GetHashCode();

        var map = new Dictionary<ulong, List<int>>();
        for (var i = 0; i < normalized.Length - WindowSize + 1; i++)
        {
            if (i > 0)
            {
                windowHash = windowHash * Base
                             - (ulong)normalized[i - 1].GetHashCode() * power
                             + (ulong)normalized[i + WindowSize - 1].GetHashCode();
            }
            hashes[i] = windowHash;
            if (!map.TryGetValue(windowHash, out var list))
                map[windowHash] = list = [];
            list.Add(i);
        }

        // find maximal duplicate regions
        var duplicatedPositions = new HashSet<int>();
        foreach (var (_, positions) in map)
        {
            if (positions.Count < 2)
                continue;
            // Only consecutive occurrences are compared. Comparing every pair is quadratic in the
            // number of occurrences, and a file that repeats one short sequence hundreds of times —
            // a long chain of concatenations, a generated table — then costs more than the whole
            // rest of the analysis. The regions found are the same: an occurrence that matches a
            // distant one also matches the one in between, and maximal extension merges them.
            for (var i = 0; i + 1 < positions.Count; i++)
            {
                var p1 = positions[i];
                var p2 = positions[i + 1];
                if (p2 - p1 < WindowSize)
                    continue;
                var len = ExtendMatch(normalized, p1, p2, WindowSize);
                if (len < MinTokens)
                    continue;
                for (var k = p1; k < p1 + len; k++)
                    duplicatedPositions.Add(k);
                for (var k = p2; k < p2 + len; k++)
                    duplicatedPositions.Add(k);
            }
        }

        if (duplicatedPositions.Count == 0)
            return [];

        // group contiguous duplicated token positions into blocks
        var sorted = duplicatedPositions.OrderBy(p => p).ToList();
        var blocks = new List<DuplicateBlock>();
        var groupStart = sorted[0];
        var prev = sorted[0];
        var maxOccurrences = 1;
        var currentOccurrences = 1;
        for (var i = 1; i < sorted.Count; i++)
        {
            if (sorted[i] == prev + 1)
            {
                prev = sorted[i];
                currentOccurrences++;
                if (currentOccurrences > maxOccurrences)
                    maxOccurrences = currentOccurrences;
                continue;
            }
            blocks.Add(BuildBlock(file, tokens, groupStart, prev, maxOccurrences));
            groupStart = sorted[i];
            prev = sorted[i];
            currentOccurrences = 1;
            maxOccurrences = 1;
        }
        blocks.Add(BuildBlock(file, tokens, groupStart, prev, maxOccurrences));

        return blocks.Where(b => b.TokensCount >= MinTokens && b.Lines >= MinLines).ToList();
    }

    private static int ExtendMatch(string[] normalized, int p1, int p2, int len)
    {
        var max = normalized.Length - Math.Max(p1, p2);
        while (len < max && normalized[p1 + len] == normalized[p2 + len])
            len++;
        return len;
    }

    private static DuplicateBlock BuildBlock(SourceFile file, IReadOnlyList<Token> tokens, int startPos, int endPos, int maxOccurrences)
    {
        var startLine = tokens[startPos].Line;
        var endLine = tokens[endPos].Line;
        return new DuplicateBlock(startLine, endLine, endPos - startPos + 1, maxOccurrences);
    }
}