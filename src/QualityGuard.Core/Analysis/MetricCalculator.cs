using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Analysis;

public static class MetricCalculator
{
    public static Dictionary<string, double> Compute(SourceFile file, IReadOnlyList<Token> tokens,
        SyntaxTree? tree = null)
    {
        var metrics = new Dictionary<string, double>();
        var lines = file.Content.Split('\n');
        var lineCount = lines.Length;
        var codeLines = 0;
        var commentLines = new HashSet<int>();
        var tokenCount = 0;

        var tokensByLine = tokens.ToLookup(t => t.Line);
        for (var idx = 0; idx < lineCount; idx++)
        {
            if (lines[idx].Trim().Length == 0)
                continue;
            var lineTokens = tokensByLine[idx + 1].ToArray();
            if (lineTokens.Length > 0 && lineTokens.All(t => t.Kind == TokenKind.Comment))
            {
                commentLines.Add(idx + 1);
                continue;
            }
            codeLines++;
        }

        foreach (var token in tokens)
        {
            if (token.Kind == TokenKind.Comment)
            {
                for (var line = token.Line; line <= token.Line + token.Text.Count(c => c == '\n'); line++)
                    commentLines.Add(line);
                continue;
            }
            tokenCount++;
        }

        metrics[CoreMetrics.Lines] = lineCount;
        metrics[CoreMetrics.Ncloc] = codeLines;
        metrics[CoreMetrics.CommentLines] = commentLines.Count;
        metrics[CoreMetrics.Files] = 1;
        metrics["tokens"] = tokenCount;

        if (tree != null)
        {
            var structure = ComputeStructural(tree.Root);
            foreach (var (key, value) in structure)
                metrics[key] = value;
        }
        else
        {
            metrics[CoreMetrics.Complexity] = 1;
            metrics[CoreMetrics.CognitiveComplexity] = 0;
            metrics[CoreMetrics.Functions] = 0;
        }

        return metrics;
    }

    private static Dictionary<string, double> ComputeStructural(SyntaxNode root)
    {
        var functions = root.OfKind(NodeKind.FunctionDeclaration).ToList();
        var classes = root.OfKind(NodeKind.ClassDeclaration).Count();
        var statements = root.OfKind(NodeKind.ExpressionStatement, NodeKind.VariableDeclaration, NodeKind.Jump,
            NodeKind.If, NodeKind.Loop, NodeKind.Match).Count();

        return new Dictionary<string, double>
        {
            [CoreMetrics.Complexity] = CyclomaticComplexity(root),
            [CoreMetrics.CognitiveComplexity] = CognitiveComplexity(root, 0),
            [CoreMetrics.Functions] = functions.Count,
            ["classes"] = classes,
            ["statements"] = statements,
            ["max_nesting"] = functions.Count == 0 ? 0 : functions.Max(MaxNesting)
        };
    }

    /// <summary>One point per function plus one per branching construct and short-circuit operator.</summary>
    public static int CyclomaticComplexity(SyntaxNode node)
    {
        var complexity = 1;
        foreach (var descendant in node.DescendantsAndSelf())
        {
            switch (descendant.Kind)
            {
                case NodeKind.FunctionDeclaration:
                case NodeKind.If:
                case NodeKind.Loop:
                case NodeKind.MatchCase:
                case NodeKind.Catch:
                case NodeKind.Conditional:
                    complexity++;
                    break;
                case NodeKind.Binary when descendant.Text is "&&" or "||" or "and" or "or" or "??":
                    complexity++;
                    break;
            }
        }
        return complexity;
    }

    /// <summary>
    /// Nesting-aware complexity: each control structure costs one point plus the depth it sits at,
    /// so deeply nested logic scores higher than the same number of flat branches.
    /// </summary>
    public static int CognitiveComplexity(SyntaxNode node, int nesting)
    {
        var score = 0;
        var pending = new Stack<(SyntaxNode Node, int Nesting)>();
        PushChildren(pending, node, nesting);

        while (pending.Count > 0)
        {
            var (child, level) = pending.Pop();
            var increment = 0;
            var nested = level;
            switch (child.Kind)
            {
                case NodeKind.If:
                case NodeKind.Loop:
                case NodeKind.Match:
                case NodeKind.Catch:
                    increment = 1 + level;
                    nested = level + 1;
                    break;
                case NodeKind.Else when IsElseIf(child):
                    // an else-if is one decision, not a nested branch
                    break;
                case NodeKind.Else:
                    increment = 1;
                    nested = level + 1;
                    break;
                case NodeKind.Lambda:
                case NodeKind.FunctionDeclaration:
                    nested = level + 1;
                    break;
                case NodeKind.Binary when child.Text is "&&" or "||" or "and" or "or":
                    increment = 1;
                    break;
                case NodeKind.Jump when child.Text is "goto" or "break" or "continue" && level > 0:
                    increment = 1;
                    break;
            }
            score += increment;
            PushChildren(pending, child, nested);
        }
        return score;
    }

    private static void PushChildren(Stack<(SyntaxNode, int)> pending, SyntaxNode node, int nesting)
    {
        var children = node.Children;
        for (var i = children.Count - 1; i >= 0; i--)
            pending.Push((children[i], nesting));
    }

    private static bool IsElseIf(SyntaxNode elseNode)
    {
        var body = elseNode.FirstChild(NodeKind.Block);
        return body is { Children.Count: 1 } && body.Children[0].Kind == NodeKind.If;
    }

    public static int MaxNesting(SyntaxNode function)
    {
        var max = 0;
        foreach (var node in function.Descendants())
        {
            if (node.Kind is NodeKind.If or NodeKind.Loop or NodeKind.Match or NodeKind.Try or NodeKind.Catch)
                max = Math.Max(max, SyntaxQuery.NestingDepth(node) + 1);
        }
        return max;
    }
}
