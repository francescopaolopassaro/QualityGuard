using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Analysis;

public sealed class DuplicationDetector
{
    private const int WindowSize = 6;
    private const int MinTokens = 12;
    private const uint Base = 31;
    private const uint Prime = 1_000_000_007;

    public IReadOnlyList<DuplicateBlock> FindDuplicates(SourceFile file, IReadOnlyList<Token> tokens)
    {
        // normalized token sequence — ignore comments and maps each symbol/ident to normalized form
        var normalized = tokens
            .Where(t => t.Kind != TokenKind.Comment)
            .Select(t => t.Kind == TokenKind.Identifier ? "ID" : t.Kind == TokenKind.String ? "STR" : t.Kind == TokenKind.Number ? "NUM" : t.Text)
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
            for (var i = 0; i < positions.Count; i++)
            {
                for (var j = i + 1; j < positions.Count; j++)
                {
                    var p1 = positions[i];
                    var p2 = positions[j];
                    if (p2 - p1 < WindowSize)
                        continue;
                    var len = ExtendMatch(normalized, p1, p2, WindowSize);
                    if (len >= MinTokens)
                    {
                        for (var k = p1; k < p1 + len; k++)
                            duplicatedPositions.Add(k);
                        for (var k = p2; k < p2 + len; k++)
                            duplicatedPositions.Add(k);
                    }
                }
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

        return blocks.Where(b => b.TokensCount >= MinTokens).ToList();
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