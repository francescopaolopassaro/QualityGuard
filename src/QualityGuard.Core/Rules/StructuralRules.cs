using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;
using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Rules that need the syntax tree: they reason about statements, branches and functions rather than
/// about lines or single tokens, and therefore apply to every language the parser understands.
/// </summary>
public static class StructuralRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new UnreachableCodeAfterJumpRule(),
        new DuplicateConditionRule(),
        new ConstantConditionRule(),
        new SelfAssignmentRule(),
        new IdenticalOperandsRule(),
        new IdenticalBranchesRule(),
        new TooManyParametersRule(),
        new FunctionTooLongRule(),
        new CognitiveComplexityRule(),
        new DeepNestingRule(),
        new MatchWithoutDefaultRule(),
        new DuplicatedStringLiteralRule(),
        new UnusedLocalVariableRule(),
        new EmptyFunctionRule(),
        new MultipleStatementsPerLineRule(),
        new StringConcatenationInLoopRule(),
        new InvalidRegexRule(),
        new FileTooLongRule(),
        new UnusedParameterRule(),
        new MergeableIfRule(),
        new RedundantNestedBlockRule(),
        new IfChainWithoutElseRule(),
        new ComplexConditionRule(),
        new NestedMatchRule(),
        new MissingBracesRule()
    ];

    internal static string Normalized(SyntaxNode node)
        => string.Join(' ', node.Tokens.Where(t => t.Kind != TokenKind.Comment).Select(t => t.Text));
}

public abstract class StructuralRuleBase : RuleBase
{
    public override string[] Languages => [];

    protected static IEnumerable<SyntaxNode> Blocks(IRuleContext context)
        => context.Root.OfKind(NodeKind.Block);

    protected static SyntaxNode? Condition(SyntaxNode branch)
        => branch.Children.FirstOrDefault(c => c.Kind is not (NodeKind.Block or NodeKind.ParameterList));
}

public sealed class UnreachableCodeAfterJumpRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-BUG-0001";
    public override string Name => "Statements after a jump are never executed";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var block in Blocks(context))
        {
            var children = block.Children;
            for (var i = 0; i < children.Count - 1; i++)
            {
                if (children[i].Kind != NodeKind.Jump)
                    continue;
                var next = children[i + 1];
                if (next.Kind is NodeKind.MatchCase or NodeKind.Else or NodeKind.Catch or NodeKind.Finally)
                    continue;
                context.Report(next, $"This code is unreachable: '{children[i].Text}' on line "
                                     + $"{children[i].Line} always leaves the block first.");
                break;
            }
        }
    }
}

public sealed class DuplicateConditionRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-BUG-0002";
    public override string Name => "A condition should not be repeated in the same branch chain";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var head in context.Root.OfKind(NodeKind.If))
        {
            if (head.Parent?.Kind == NodeKind.Else || IsElseIf(head))
                continue; // only the head of a chain drives the comparison

            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var branch in Chain(head))
            {
                if (Condition(branch) is not { } condition)
                    continue;
                var text = StructuralRuleSet.Normalized(condition);
                if (text.Length == 0)
                    continue;
                if (seen.TryGetValue(text, out var firstLine))
                    context.Report(condition, $"This condition repeats the one on line {firstLine}, "
                                              + "so this branch can never run.");
                else
                    seen[text] = condition.Line;
            }
        }
    }

    internal static bool IsElseIf(SyntaxNode branch)
        => branch.Ancestors().Take(2).Any(a => a.Kind == NodeKind.Else);

    /// <summary>The if and every else-if that continues it.</summary>
    internal static IEnumerable<SyntaxNode> Chain(SyntaxNode head)
    {
        var current = head;
        while (current != null)
        {
            yield return current;
            current = NextBranch(current);
        }
    }

    internal static SyntaxNode? NextBranch(SyntaxNode branch)
    {
        var elseNode = branch.FirstChild(NodeKind.Else);
        if (elseNode == null)
            return null;
        var body = elseNode.FirstChild(NodeKind.Block);
        if (body is { Children.Count: 1 } && body.Children[0].Kind == NodeKind.If)
            return body.Children[0];
        return null;
    }

    internal static SyntaxNode? FinalElse(SyntaxNode head)
    {
        var last = Chain(head).Last();
        var elseNode = last.FirstChild(NodeKind.Else);
        return elseNode;
    }
}

public sealed class ConstantConditionRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-BUG-0003";
    public override string Name => "Conditions should not always evaluate to the same result";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var branch in context.Root.OfKind(NodeKind.If, NodeKind.Loop))
        {
            if (Condition(branch) is not { } condition)
                continue;
            var expression = Unwrap(condition);
            if (expression.Kind == NodeKind.BooleanLiteral)
            {
                if (branch.Kind == NodeKind.Loop && expression.Text is "true" or "True")
                    continue; // an intentional infinite loop
                context.Report(condition, $"This condition is always {expression.Text.ToLowerInvariant()}, "
                                          + "so the branch it guards is not a decision.");
                continue;
            }
            if (expression.Kind == NodeKind.Binary && expression.Text is "&&" or "||" or "and" or "or"
                && expression.Children.Any(c => Unwrap(c).Kind == NodeKind.BooleanLiteral))
                context.Report(condition, "A boolean literal in this condition fixes its result: "
                                          + "the other operand is never taken into account.");
        }
    }

    private static SyntaxNode Unwrap(SyntaxNode node)
        => node.Kind is NodeKind.Parenthesized && node.Children.Count == 1 ? Unwrap(node.Children[0]) : node;
}

public sealed class SelfAssignmentRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-BUG-0004";
    public override string Name => "A variable should not be assigned to itself";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            if (assignment.Text != "=")
                continue;
            var left = SyntaxQuery.DottedName(assignment.ChildAt(0));
            var right = SyntaxQuery.DottedName(assignment.ChildAt(1));
            if (left.Length > 0 && left == right)
                context.Report(assignment, $"Assigning '{left}' to itself has no effect; "
                                           + "the intended target or source is probably a different name.");
        }
    }
}

public sealed class IdenticalOperandsRule : StructuralRuleBase
{
    private static readonly string[] Operators =
        ["==", "!=", "===", "!==", "<", ">", "<=", ">=", "&&", "||", "and", "or", "-", "/", "%"];

    public override string Key => "QG-ALL-BUG-0005";
    public override string Name => "Both operands of an operator should not be identical";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (!Operators.Contains(binary.Text, StringComparer.Ordinal))
                continue;
            var left = binary.ChildAt(0);
            var right = binary.ChildAt(1);
            if (left == null || right == null)
                continue;
            var leftText = StructuralRuleSet.Normalized(left);
            if (leftText.Length == 0 || leftText != StructuralRuleSet.Normalized(right))
                continue;
            if (leftText.Contains('(')) // a repeated call may legitimately return different values
                continue;
            context.Report(binary, $"'{leftText}' appears on both sides of '{binary.Text}', "
                                   + "which makes the result constant.");
        }
    }
}

public sealed class IdenticalBranchesRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-BUG-0006";
    public override string Name => "Branches of a conditional should not have the same body";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var branch in context.Root.OfKind(NodeKind.If))
        {
            var body = branch.FirstChild(NodeKind.Block);
            var otherwise = branch.FirstChild(NodeKind.Else)?.FirstChild(NodeKind.Block);
            if (body == null || otherwise == null || body.Children.Count == 0)
                continue;
            if (otherwise.Children.Count == 1 && otherwise.Children[0].Kind == NodeKind.If)
                continue; // an else-if chain, not a duplicated branch
            if (StructuralRuleSet.Normalized(body) != StructuralRuleSet.Normalized(otherwise))
                continue;
            context.Report(otherwise, $"This branch does exactly what the branch on line {body.Line} does, "
                                      + "so the condition changes nothing.");
        }
    }
}

public sealed class TooManyParametersRule : StructuralRuleBase
{
    private const int Max = 7;

    public override string Key => "QG-ALL-SML-0003";
    public override string Name => "Functions should not take too many parameters";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var count = SyntaxQuery.Parameters(function).Count();
            if (count > Max)
                context.Report(function, $"'{function.Text}' takes {count} parameters (limit is {Max}); "
                                         + "group the related ones into an object.");
        }
    }
}

public sealed class FunctionTooLongRule : StructuralRuleBase
{
    private const int MaxLines = 120;

    public override string Key => "QG-ALL-SML-0004";
    public override string Name => "Functions should not be too long";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var body = SyntaxQuery.Body(function);
            var length = (body ?? function).Range.LineCount;
            if (length > MaxLines)
                context.Report(function, $"'{function.Text}' is {length} lines long (limit is {MaxLines}); "
                                         + "split the steps it performs into separate functions.");
        }
    }
}

public sealed class CognitiveComplexityRule : StructuralRuleBase
{
    private const int Max = 15;

    public override string Key => "QG-ALL-SML-0005";
    public override string Name => "Functions should not be too hard to follow";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var score = MetricCalculator.CognitiveComplexity(function, 0);
            if (score > Max)
                context.Report(function, $"'{function.Text}' scores {score} on nesting-aware complexity "
                                         + $"(limit is {Max}); flatten the branches or extract the inner logic.");
        }
    }
}

public sealed class DeepNestingRule : StructuralRuleBase
{
    private const int Max = 4;

    public override string Key => "QG-ALL-SML-0006";
    public override string Name => "Control structures should not be nested too deeply";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var deepest = function.Descendants()
                .Where(n => n.Kind is NodeKind.If or NodeKind.Loop or NodeKind.Match or NodeKind.Try)
                .Select(n => (Node: n, Depth: SyntaxQuery.NestingDepth(n) + 1))
                .Where(x => x.Depth > Max)
                .OrderByDescending(x => x.Depth)
                .FirstOrDefault();
            if (deepest.Node != null)
                context.Report(deepest.Node, $"This block sits {deepest.Depth} levels deep (limit is {Max}); "
                                             + "return early or extract the inner levels into a function.");
        }
    }
}

public sealed class MatchWithoutDefaultRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0007";
    public override string Name => "Multi-way branches should handle the unexpected value";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var match in context.Root.OfKind(NodeKind.Match))
        {
            var body = match.FirstChild(NodeKind.Block);
            if (body == null || body.Children.Count == 0)
                continue;
            var hasDefault = body.DescendantsAndSelf()
                .Any(n => n.Tokens.Count > 0 && n.Tokens[0].Text is "default" or "else" or "_");
            if (!hasDefault)
                context.Report(match, "No branch handles the values that are not listed; add a default case "
                                      + "so an unexpected value is not silently ignored.");
        }
    }
}

public sealed class DuplicatedStringLiteralRule : StructuralRuleBase
{
    private const int Threshold = 3;
    private const int MinLength = 6;

    public override string Key => "QG-ALL-SML-0008";
    public override string Name => "String literals should not be duplicated";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        var groups = context.Root.OfKind(NodeKind.StringLiteral)
            .Where(l => l.Text.Trim().Length >= MinLength)
            .GroupBy(l => l.Text, StringComparer.Ordinal)
            .Where(g => g.Count() >= Threshold);

        foreach (var group in groups)
        {
            var first = group.First();
            context.Report(first, $"This literal is repeated {group.Count()} times; "
                                  + "declare it once as a constant and reference it.");
        }
    }
}

public sealed class UnusedLocalVariableRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0009";
    public override string Name => "Local variables should be used";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var symbol in context.Semantics.AllSymbols())
        {
            if (symbol.Scope.Kind is not (ScopeKind.Function or ScopeKind.Block) || symbol.IsParameter)
                continue;
            if (!symbol.IsExplicitlyDeclared || symbol.Name.Contains('.'))
                continue;
            if (symbol.Usages.Any(u => u.Kind == UsageKind.Reference))
                continue;
            var declaration = symbol.Usages.FirstOrDefault(u => u.Kind == UsageKind.Declaration);
            if (declaration == null || symbol.Name.StartsWith('_'))
                continue;
            context.Report(declaration.Identifier, $"'{symbol.Name}' is assigned but never read; "
                                                   + "remove it or use the value it holds.");
        }
    }
}

public sealed class EmptyFunctionRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0010";
    public override string Name => "Function bodies should not be empty";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var body = SyntaxQuery.Body(function);
            if (body is { Children.Count: 0 })
                context.Report(function, $"'{function.Text}' has an empty body; implement it, "
                                         + "or document why doing nothing is the intended behaviour.");
        }
    }
}

public sealed class MultipleStatementsPerLineRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-CNV-0004";
    public override string Name => "One statement per line";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (context.Tree.Profile.Style is not StructureStyle.Braces)
            return;

        foreach (var parent in context.Root.DescendantsAndSelf())
        {
            if (parent.Kind is not (NodeKind.Block or NodeKind.TopLevel))
                continue;
            var statements = parent.Children
                .Where(c => c.Kind is NodeKind.ExpressionStatement or NodeKind.VariableDeclaration or NodeKind.Jump)
                .ToList();
            for (var i = 1; i < statements.Count; i++)
            {
                if (statements[i].Line == statements[i - 1].Line && statements[i].Line != 0)
                    context.Report(statements[i], "This line holds more than one statement; "
                                                  + "put each statement on its own line.");
            }
        }
    }
}

public sealed class StringConcatenationInLoopRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-PRF-0001";
    public override string Name => "Strings should not be built by concatenation inside a loop";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            foreach (var assignment in loop.OfKind(NodeKind.Assignment))
            {
                var target = assignment.ChildAt(0);
                var isStringTarget = target?.Symbol?.DeclaredType is "string" or "String" or "str"
                                     || SyntaxQuery.ConstantString(assignment.ChildAt(1)) != null;
                var concatenates = assignment.Text == "+=" && isStringTarget
                                   || assignment.Text == "=" && assignment.ChildAt(1) is { Kind: NodeKind.Binary, Text: "+" } value
                                   && SyntaxQuery.MentionsIdentifier(value, SyntaxQuery.DottedName(target));
                if (!concatenates)
                    continue;
                context.Report(assignment, "Each concatenation allocates a new string; accumulate the parts in "
                                           + "a string builder or a list and join them once after the loop.");
            }
        }
    }
}

public sealed class InvalidRegexRule : StructuralRuleBase
{
    private static readonly string[] RegexEntryPoints =
    [
        "Match", "Matches", "IsMatch", "Replace", "Split", "compile", "match", "search", "findall",
        "fullmatch", "test", "exec", "matches", "Pattern", "Regex", "RegExp", "new_regex", "MustCompile"
    ];

    public override string Key => "QG-ALL-BUG-0007";
    public override string Name => "Regular expressions should be syntactically valid";
    public override Severity Severity => Severity.Blocker;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!RegexEntryPoints.Contains(name, StringComparer.Ordinal))
                continue;

            foreach (var argument in SyntaxQuery.Arguments(call).Where(SyntaxQuery.IsStringLiteral))
            {
                var pattern = argument.Text;
                if (pattern.Length == 0 || !LooksLikePattern(pattern) || IsValid(pattern))
                    continue;
                context.Report(argument, "This pattern does not compile, so the call throws the first "
                                         + "time it runs; fix the escaping or the unbalanced group.");
                break;
            }
        }
    }

    private static bool LooksLikePattern(string text)
        => text.IndexOfAny(['(', '[', '\\', '{', '|', '+', '*', '?', '^', '$']) >= 0;

    private static bool IsValid(string pattern)
    {
        try
        {
            _ = System.Text.RegularExpressions.Regex.Match(string.Empty, pattern);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}

public sealed class FileTooLongRule : StructuralRuleBase
{
    private const int MaxLines = 1000;

    public override string Key => "QG-ALL-SML-0011";
    public override string Name => "Files should not grow beyond a readable size";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "60min";

    public override void Execute(IRuleContext context)
    {
        var lines = (int)context.Metrics.GetValueOrDefault("lines");
        if (lines > MaxLines)
            context.Report($"This file holds {lines} lines (limit is {MaxLines}); split it along the "
                           + "responsibilities it has accumulated.", 1);
    }
}

public sealed class UnusedParameterRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0012";
    public override string Name => "Function parameters should be used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var symbol in context.Semantics.AllSymbols())
        {
            if (!symbol.IsParameter || symbol.Name.Length <= 1 || symbol.Name[0] == '_')
                continue;
            if (symbol.Usages.Any(u => u.Kind is UsageKind.Reference or UsageKind.Assignment))
                continue;
            var declaration = symbol.Usages.First(u => u.Kind == UsageKind.Parameter);
            context.Report(declaration.Identifier, $"'{symbol.Name}' is never used in the body; "
                                                   + "remove it or use the value the caller passes.");
        }
    }
}

public sealed class MergeableIfRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0013";
    public override string Name => "Nested conditions that can be merged should be merged";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var outer in context.Root.OfKind(NodeKind.If))
        {
            var body = outer.FirstChild(NodeKind.Block);
            if (body is not { Children.Count: 1 })
                continue;
            var inner = body.Children[0];
            if (inner.Kind != NodeKind.If || inner.Children.Any(c => c.Kind == NodeKind.Else))
                continue;
            if (outer.Children.Any(c => c.Kind == NodeKind.Else))
                continue;
            context.Report(inner, "This condition is the only statement of the outer one; combine the two "
                                  + "tests with a logical AND to remove a level of nesting.");
        }
    }
}

public sealed class RedundantNestedBlockRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0014";
    public override string Name => "Blocks should not be nested without a reason";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var block in Blocks(context))
        {
            if (block.Parent?.Kind != NodeKind.Block || block.Children.Count == 0 || block.Text != "free")
                continue;
            context.Report(block, "This block is not attached to any statement, so it only adds "
                                  + "indentation; remove the braces or extract the code into a function.");
        }
    }
}

public sealed class IfChainWithoutElseRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0015";
    public override string Name => "Condition chains should end with a final branch";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var head in context.Root.OfKind(NodeKind.If))
        {
            if (DuplicateConditionRule.IsElseIf(head))
                continue;
            var chain = DuplicateConditionRule.Chain(head).ToList();
            if (chain.Count < 2 || DuplicateConditionRule.FinalElse(chain[^1]) != null)
                continue;
            context.Report(chain[^1], "No branch covers the remaining cases; add a final else that "
                                      + "handles or rejects the values the chain does not list.");
        }
    }
}

public sealed class ComplexConditionRule : StructuralRuleBase
{
    private const int MaxOperators = 4;

    public override string Key => "QG-ALL-SML-0016";
    public override string Name => "Conditions should not combine too many operators";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        foreach (var branch in context.Root.OfKind(NodeKind.If, NodeKind.Loop))
        {
            if (Condition(branch) is not { } condition)
                continue;
            var operators = condition.DescendantsAndSelf()
                .Count(n => n.Kind == NodeKind.Binary && n.Text is "&&" or "||" or "and" or "or");
            if (operators > MaxOperators)
                context.Report(condition, $"This condition combines {operators} logical operators "
                                          + $"(limit is {MaxOperators}); name the parts in well-named "
                                          + "variables or a predicate function.");
        }
    }
}

public sealed class NestedMatchRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0017";
    public override string Name => "Multi-way branches should not be nested";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "25min";

    public override void Execute(IRuleContext context)
    {
        foreach (var match in context.Root.OfKind(NodeKind.Match))
        {
            if (match.Ancestor(NodeKind.Match) == null)
                continue;
            context.Report(match, "A switch inside another switch multiplies the cases a reader has to "
                                  + "track; move the inner one into a function named after its decision.");
        }
    }
}

public sealed class MissingBracesRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-CNV-0005";
    public override string Name => "Control structures should always use a block";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (context.Tree.Profile.Style != StructureStyle.Braces)
            return;

        foreach (var branch in context.Root.OfKind(NodeKind.If, NodeKind.Loop, NodeKind.Else))
        {
            if (branch.FirstChild(NodeKind.Block) != null || branch.Children.Count == 0)
                continue;
            if (branch.Children.All(c => c.Kind is not (NodeKind.ExpressionStatement or NodeKind.Jump
                    or NodeKind.VariableDeclaration)))
                continue;
            context.Report(branch, "The body of this statement is not wrapped in braces; adding a second "
                                   + "line later then silently leaves it outside the branch.");
        }
    }
}
