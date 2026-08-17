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
        new DeadStoreRule(),
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
        new MissingBracesRule(),
        new TooManyReturnsRule(),
        new EmptyCatchRule(),
        new BooleanLiteralComparisonRule(),
        new MagicNumberRule(),
        new NestedTernaryRule(),
        new TooManyMembersRule(),
        new TestWithoutAssertionRule(),
        new GenericExceptionCaughtRule(),
        new GenericExceptionThrownRule(),
        new RethrowLosingStackRule(),
        new JumpInFinallyRule(),
        new LockOnSharedObjectRule(),
        new IgnoredTestRule(),
        new UnusedPrivateFunctionRule(),
        new RedundantJumpRule(),
        new CommentedOutCodeRule(),
        new DeepInheritanceRule(),
        new HiddenBaseMemberRule(),
        new UnusedInternalMemberRule(),
        new DuplicateTypeNameRule(),
        new EqualityContractRule(),
        new OverrideOnlyCallsBaseRule(),
        new EmptyTypeRule(),
        new FieldCouldBeReadOnlyRule(),
        new MethodCouldBeStaticRule(),
        new MutableStaticStateRule(),
        new UnreleasedResourceRule(),
        new MismatchedComparisonRule()
    ];

    internal static string Normalized(SyntaxNode node)
        => string.Join(' ', node.Tokens.Where(t => t.Kind != TokenKind.Comment).Select(t => t.Text));
}

public abstract class StructuralRuleBase : RuleBase
{
    public override string[] Languages => [];

    /// <summary>Rules that depend on exact statement boundaries opt into this guard.</summary>
    protected static bool HasPreciseTree(IRuleContext context) => context.Tree.HasDedicatedParser;

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
                // A block opening on the same line as the jump is its argument, not code stranded
                // behind it: 'return withSession { ... }' in Kotlin, and every trailing lambda.
                if (next.Kind == NodeKind.Block && next.Range.StartLine == children[i].Range.StartLine)
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
            // a declaration is not a self-assignment, whatever its initializer is called
            // 'new Thing { Id = Id }' sets a member of the object being built from a variable that
            // happens to share its name. The two sides are different things, and reading them as one
            // reported every object initialiser written against a matching parameter name.
            if (assignment.Ancestor(NodeKind.ObjectCreation, NodeKind.ListLiteral,
                    NodeKind.ArrayCreation, NodeKind.Attribute) != null)
                continue;
            if (assignment.Parent is { Kind: NodeKind.VariableDeclaration or NodeKind.FieldDeclaration })
                continue;

            var left = PlainName(assignment.ChildAt(0));
            var right = PlainName(assignment.ChildAt(1));
            if (left.Length > 0 && left == right)
                context.Report(assignment, $"Assigning '{left}' to itself has no effect; "
                                           + "the intended target or source is probably a different name.");
        }
    }

    /// <summary>
    /// The dotted name of a node when it is nothing but identifiers joined by dots. A call, a cast
    /// or an index gives an empty answer: 'boolean isSubscribed = isSubscribed(tree)' names the same
    /// thing on both sides and is not an assignment to itself.
    /// </summary>
    private static string PlainName(SyntaxNode? node)
    {
        if (node == null)
            return string.Empty;
        if (node.Kind == NodeKind.Identifier)
            return node.Text;
        if (node.Kind != NodeKind.MemberSelect)
            return string.Empty;

        foreach (var part in node.DescendantsAndSelf())
        {
            if (part.Kind is not (NodeKind.MemberSelect or NodeKind.Identifier))
                return string.Empty;
        }
        return SyntaxQuery.DottedName(node);
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
            if (count <= Max)
                continue;

            // the cost follows the size of the problem: every parameter past the limit is another
            // one to find a home for, and every caller has to be changed with it
            context.ReportCosting($"'{function.Text}' takes {count} parameters (limit is {Max}); "
                                  + "group the related ones into an object.",
                20 + (count - Max) * 10, function.Line);
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
            if (length <= MaxLines)
                continue;

            context.ReportCosting($"'{function.Text}' is {length} lines long (limit is {MaxLines}); "
                                  + "split the steps it performs into separate functions.",
                30 + (length - MaxLines) / 20 * 10, function.Line);
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
            if (score <= Max)
                continue;

            // a function three times over the limit is not three times the work of one a point over
            // it, but it is not the same work either: the cost grows with the distance
            context.ReportCosting($"'{function.Text}' scores {score} on nesting-aware complexity "
                                  + $"(limit is {Max}); flatten the branches or extract the inner logic.",
                30 + (score - Max), function.Line);
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

    /// <summary>
    /// Short strings are repeated everywhere and naming them buys nothing: a constant called
    /// SLASH holding "/" is worse than the slash. The advice starts paying at about this length.
    /// </summary>
    private const int MinLength = 10;

    /// <summary>Calls whose string argument names a module, not a value that could be a constant.</summary>
    private static readonly string[] ModuleReferences =
        ["require", "import", "define", "mock", "unmock", "doMock", "jest.mock", "importScripts"];

    public override string Key => "QG-ALL-SML-0008";
    public override string Name => "String literals should not be duplicated";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    /// <summary>
    /// Formats with nowhere to put a constant. A repeated value in JSON, in a template or in a
    /// stylesheet is how those files are written, and there is no declaration to move it to.
    /// </summary>
    private static readonly string[] NoConstants =
        ["json", "yaml", "yml", "xml", "csv", "html", "raz", "razor", "cshtml", "vbhtml", "vue",
         "css", "scss", "sass", "less", "md", "txt", "resx", "config", "sql"];

    public override void Execute(IRuleContext context)
    {
        if (NoConstants.Contains(context.Language.LanguageKey, StringComparer.OrdinalIgnoreCase))
            return;

        var modules = ModuleNames(context);
        var groups = context.Root.OfKind(NodeKind.StringLiteral)
            .Where(l => Nameable(l.Text) && !modules.Contains(l.Text))
            .GroupBy(l => l.Text, StringComparer.Ordinal)
            .Where(g => g.Count() >= Threshold);

        foreach (var group in groups)
        {
            var first = group.First();
            context.Report(first, $"This literal is repeated {group.Count()} times; "
                                  + "declare it once as a constant and reference it.");
        }
    }

    /// <summary>
    /// Whether a literal is the kind of thing a constant can be given a name for: long enough to be
    /// worth naming, and made of words rather than punctuation or a number.
    /// </summary>
    private static bool Nameable(string text)
    {
        var trimmed = text.Trim();
        return trimmed.Length >= MinLength && trimmed.Any(char.IsLetter);
    }

    /// <summary>
    /// The module names the file mentions. Repeating one is how imports are written, and replacing it
    /// with a constant would break the tools that read those calls statically.
    /// </summary>
    private static HashSet<string> ModuleNames(IRuleContext context)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var invoked = SyntaxQuery.InvokedName(call);
            var dotted = SyntaxQuery.InvokedDottedName(call);
            if (!ModuleReferences.Contains(invoked, StringComparer.Ordinal)
                && !ModuleReferences.Contains(dotted, StringComparer.Ordinal))
                continue;
            if (SyntaxQuery.ArgumentAt(call, 0) is { Kind: NodeKind.StringLiteral } module)
                names.Add(module.Text);
        }
        return names;
    }
}

public sealed class DeadStoreRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-BUG-0041";
    public override string Name => "A value should be read before it is replaced";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var symbol in context.Semantics.AllSymbols())
        {
            if (symbol.Scope.Kind is not (ScopeKind.Function or ScopeKind.Block) || symbol.IsParameter)
                continue;
            // a dotted name is a member of another object: it outlives the statement and is read
            // through the name of the object, which this rule cannot follow
            if (symbol.Name.StartsWith('_') || symbol.Name.Contains('.'))
                continue;

            var usages = symbol.Usages
                .Where(u => u.Kind is UsageKind.Declaration or UsageKind.Assignment or UsageKind.Reference)
                .OrderBy(u => u.Line)
                .ToList();

            for (var i = 0; i < usages.Count - 1; i++)
            {
                var write = usages[i];
                if (write.Kind == UsageKind.Reference)
                    continue;
                var next = usages[i + 1];
                if (next.Kind == UsageKind.Reference)
                    continue;

                // Two writes with no read between them mean the first value never mattered — but
                // only when both are on the same straight line of code. Across a branch the earlier
                // write is the value the other path uses, and reporting it would be wrong.
                if (!SameStraightLine(write.Identifier, next.Identifier))
                    continue;
                // a declaration with no value written is not a store
                if (write.Kind == UsageKind.Declaration && write.Value == null)
                    continue;
                // 'new Thing { Name = "a" }' assigns a member of the object being built, not a
                // variable: two initialisers naming the same member are two different objects
                if (InsideInitializer(write.Identifier) || InsideInitializer(next.Identifier))
                    continue;
                if (SetsAMember(write.Identifier) || SetsAMember(next.Identifier))
                    continue;
                // 'ret = ret.Where(...)' reads the value it replaces, so the first store mattered
                if (next.Value != null && next.Value.DescendantsAndSelf()
                        .Any(n => n.Kind == NodeKind.Identifier && n.Text == symbol.Name))
                    continue;

                context.Report(write.Identifier, $"The value put in '{symbol.Name}' here is replaced on "
                                                 + $"line {next.Line} without ever being read. Either "
                                                 + "this assignment is left over, or the one that "
                                                 + "reads it was lost.");
                break;
            }
        }
    }

    /// <summary>
    /// Whether the write sets a member of another object — 'filter.Page = 2' — rather than a local.
    /// The object outlives the statement and is read through its own name, which this rule cannot
    /// follow.
    /// </summary>
    private static bool SetsAMember(SyntaxNode identifier)
        => identifier.Parent?.Kind == NodeKind.MemberSelect;

    /// <summary>Whether the write sets a member of an object being constructed.</summary>
    private static bool InsideInitializer(SyntaxNode node)
    {
        for (var parent = node.Parent; parent != null; parent = parent.Parent)
        {
            // an object initialiser, a collection literal, and the named argument of an attribute:
            // in none of them is the left-hand side a variable with a lifetime of its own
            if (parent.Kind is NodeKind.ObjectCreation or NodeKind.ListLiteral or NodeKind.ArrayCreation
                or NodeKind.Attribute or NodeKind.AttributeList or NodeKind.ArgumentList)
                return true;
            if (parent.Kind is NodeKind.Block or NodeKind.FunctionDeclaration)
                return false;
        }
        return false;
    }

    /// <summary>
    /// Whether two writes run one after the other with nothing choosing between them: same block, and
    /// no branch or loop in between that either of them sits inside.
    /// </summary>
    private static bool SameStraightLine(SyntaxNode first, SyntaxNode second)
    {
        var firstBlock = first.Ancestor(NodeKind.Block);
        var secondBlock = second.Ancestor(NodeKind.Block);
        if (firstBlock == null || firstBlock != secondBlock)
            return false;
        return first.Ancestor(NodeKind.If, NodeKind.Else, NodeKind.Loop, NodeKind.Match,
                   NodeKind.Try, NodeKind.Catch, NodeKind.Lambda)
               == second.Ancestor(NodeKind.If, NodeKind.Else, NodeKind.Loop, NodeKind.Match,
                   NodeKind.Try, NodeKind.Catch, NodeKind.Lambda);
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
        if (!HasPreciseTree(context))
            return;

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
            if (function.Kind == NodeKind.ConstructorDeclaration)
                continue; // an empty constructor is how a class says it takes no setup
            var body = SyntaxQuery.Body(function);
            if (body is not { Children.Count: 0 })
                continue;
            // the rule asks for the emptiness to be documented, so a comment inside the body is the
            // answer to it — and the tree does not keep comments, which is why the tokens are read
            // strictly inside: a comment on the closing line is a note about the method, not in it
            if (context.Tokens.Any(t => t.Kind == Tokenization.TokenKind.Comment
                                        && t.Line > body.Range.StartLine && t.Line < body.Range.EndLine))
                continue;

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
        if (!HasPreciseTree(context))
            return;

        // a real separator must exist on the line: this keeps generated terminators out of the result
        var separators = context.Tokens
            .Where(t => t.Kind == Tokenization.TokenKind.Symbol && t.Text == ";")
            .Select(t => t.Line)
            .ToHashSet();

        foreach (var parent in context.Root.DescendantsAndSelf())
        {
            if (parent.Kind is not (NodeKind.Block or NodeKind.TopLevel))
                continue;
            var statements = parent.Children
                .Where(c => c.Kind is NodeKind.ExpressionStatement or NodeKind.VariableDeclaration or NodeKind.Jump)
                .ToList();
            for (var i = 1; i < statements.Count; i++)
            {
                var line = statements[i].Line;
                if (line == 0 || line != statements[i - 1].Line || !separators.Contains(line))
                    continue;
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
    /// <summary>Calls whose first string argument is a pattern whatever the receiver is.</summary>
    private static readonly string[] RegexEntryPoints =
    [
        "MustCompile", "MustCompilePOSIX", "new_regex", "RegExp", "Regex", "compile", "findall",
        "fullmatch", "IsMatch", "Matches"
    ];

    /// <summary>
    /// The same names exist on strings and on collections, where the argument is plain text:
    /// "path".Replace("\\", "/") is not a broken pattern. They only count when the receiver says
    /// the call goes through a regular expression engine.
    /// </summary>
    private static readonly string[] AmbiguousEntryPoints =
        ["Match", "Replace", "Split", "match", "search", "test", "exec", "matches", "sub", "subn"];

    private static readonly string[] RegexReceivers =
        ["Regex", "RegExp", "re", "Pattern", "regexp", "System.Text.RegularExpressions.Regex"];

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
            var known = RegexEntryPoints.Contains(name, StringComparer.Ordinal);
            if (!known && !(AmbiguousEntryPoints.Contains(name, StringComparer.Ordinal)
                            && RegexReceivers.Contains(SyntaxQuery.Receiver(call), StringComparer.Ordinal)))
                continue;

            foreach (var argument in SyntaxQuery.Arguments(call).Where(SyntaxQuery.IsStringLiteral))
            {
                var pattern = argument.Text;
                // a single character is a separator, never a pattern worth compiling
                if (pattern.Length <= 1 || !LooksLikePattern(pattern) || IsValid(pattern))
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
        if (!HasPreciseTree(context))
            return;

        foreach (var symbol in context.Semantics.AllSymbols())
        {
            if (!symbol.IsParameter || symbol.Name.Length <= 1 || symbol.Name[0] == '_')
                continue;
            if (symbol.Usages.Any(u => u.Kind is UsageKind.Reference or UsageKind.Assignment))
                continue;
            // an initialising formal (this.x, super.x) is consumed by the constructor itself
            if (symbol.Name.StartsWith("this.", StringComparison.Ordinal)
                || symbol.Name.StartsWith("super.", StringComparison.Ordinal))
                continue;
            var declaration = symbol.Usages.First(u => u.Kind == UsageKind.Parameter);
            // an override cannot change the signature it implements, so an unused parameter there is
            // imposed by the base type and not a decision the author can revisit
            var owner = SyntaxQuery.EnclosingFunction(declaration.Identifier);
            if (owner != null
                && owner.ChildrenOf(NodeKind.Attribute).Concat(owner.ChildrenOf(NodeKind.Modifier))
                    .Any(m => m.Text is "override" or "Override"))
                continue;
            // A method with no body — abstract, native, an interface member — declares a contract:
            // its parameters cannot be used because there is nothing to use them in. A method with
            // an empty body is the same idea written as a default hook.
            if (owner != null && SyntaxQuery.Body(owner) is not { Children.Count: > 0 })
                continue;
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
        if (!HasPreciseTree(context))
            return;

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
        if (!HasPreciseTree(context))
            return;

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
        if (!HasPreciseTree(context))
            return;

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
        if (!HasPreciseTree(context))
            return;

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


public sealed class TooManyReturnsRule : StructuralRuleBase
{
    private const int Max = 6;

    public override string Key => "QG-ALL-SML-0018";
    public override string Name => "Functions should not have too many exit points";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var returns = function.OfKind(NodeKind.Jump)
                .Count(j => j.Text.StartsWith("return", StringComparison.Ordinal)
                            && SyntaxQuery.EnclosingFunction(j) == function);
            if (returns > Max)
                context.Report(function, $"'{function.Text}' returns from {returns} places (limit is {Max}); "
                                         + "compute one result and return it once.");
        }
    }
}

public sealed class EmptyCatchRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0020";
    public override string Name => "Caught exceptions should not be ignored";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var handler in context.Root.OfKind(NodeKind.Catch))
        {
            var body = handler.FirstChild(NodeKind.Block);
            if (body is not { Children.Count: 0 })
                continue;
            // a comment inside the block is an explicit decision, and the tokenizer keeps it
            var hasComment = context.Tokens.Any(t => t.Kind == Tokenization.TokenKind.Comment
                                                     && t.Line >= handler.Line && t.Line <= handler.EndLine);
            if (hasComment)
                continue;
            context.Report(handler, "This handler discards the failure without recording it; "
                                    + "log it with context or let it propagate.");
        }
    }
}

public sealed class BooleanLiteralComparisonRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0021";
    public override string Name => "Boolean values should not be compared with literals";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!=" or "===" or "!=="))
                continue;
            if (!comparison.Children.Any(c => c.Kind == NodeKind.BooleanLiteral))
                continue;

            // A nullable boolean has three values, and 'x != true' is the only short way to say
            // "false or missing". Replacing it with '!x' changes the answer when x is null, so the
            // comparison is kept wherever the operand can be null.
            var other = comparison.Children.FirstOrDefault(c => c.Kind != NodeKind.BooleanLiteral);
            if (other != null && MayBeNull(context, other))
                continue;

            context.Report(comparison, "Comparing with a boolean literal restates the value; "
                                       + "use the expression itself, negated when needed.");
        }
    }

    /// <summary>
    /// Whether the compared value can be null, which makes the comparison say something the plain
    /// expression cannot. The declared type answers it when it is in reach; when it is not, the rule
    /// stays quiet rather than change what the code means.
    /// </summary>
    private static bool MayBeNull(IRuleContext context, SyntaxNode expression)
    {
        var type = context.Types.TypeOf(expression);
        if (type is { Length: > 0 })
            return type.EndsWith('?') || type.StartsWith("Nullable", StringComparison.Ordinal);
        return true;
    }
}

public sealed class MagicNumberRule : StructuralRuleBase
{
    private static readonly string[] Accepted = ["0", "1", "2", "-1", "100", "1000"];

    public override string Key => "QG-ALL-SML-0022";
    public override string Name => "Numbers should be named when their meaning is not obvious";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var number in context.Root.OfKind(NodeKind.NumberLiteral))
        {
            var text = number.Text.TrimEnd('L', 'l', 'f', 'F', 'd', 'D', 'm', 'M', 'u', 'U');
            if (Accepted.Contains(text, StringComparer.Ordinal) || text.Length < 2)
                continue;
            // a literal that initialises a constant is already named
            if (number.Ancestor(NodeKind.FieldDeclaration, NodeKind.EnumMember) != null)
                continue;
            if (number.Ancestor(NodeKind.Invocation, NodeKind.If, NodeKind.Loop, NodeKind.Binary) == null)
                continue;
            context.Report(number, $"The meaning of {number.Text} is not visible here; "
                                   + "give it a name through a constant.");
            break; // one reminder per file is enough
        }
    }
}

public sealed class NestedTernaryRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0023";
    public override string Name => "Conditional expressions should not be nested";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var conditional in context.Root.OfKind(NodeKind.Conditional))
        {
            if (conditional.Ancestor(NodeKind.Conditional) == null)
                continue;
            context.Report(conditional, "A conditional inside another one hides which case applies; "
                                        + "use a statement form or extract a named helper.");
        }
    }
}

public sealed class TooManyMembersRule : StructuralRuleBase
{
    private const int MaxMethods = 25;
    private const int MaxFields = 20;

    public override string Key => "QG-ALL-SML-0024";
    public override string Name => "Types should not accumulate too many members";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "45min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var methods = type.OfKind(NodeKind.FunctionDeclaration)
                .Count(m => m.Ancestor(NodeKind.ClassDeclaration) == type);
            var fields = type.OfKind(NodeKind.FieldDeclaration, NodeKind.PropertyDeclaration)
                .Count(f => f.Ancestor(NodeKind.ClassDeclaration) == type);
            if (methods <= MaxMethods && fields <= MaxFields)
                continue;
            context.Report(type, $"'{type.Text}' declares {methods} methods and {fields} fields; "
                                 + "split the responsibilities it has accumulated.");
        }
    }
}

public sealed class TestWithoutAssertionRule : StructuralRuleBase
{
    private static readonly string[] AssertionNames =
    [
        "assert", "assertthat", "assertequals", "asserttrue", "assertfalse", "assertnull",
        "assertnotnull", "expect", "should", "verify", "check", "mustbe", "throws", "assertion",
        // a test can state its expectation without the word: these throw when it does not hold
        "ensuresuccessstatuscode", "received", "musthavehappened", "shouldbe", "shouldsatisfy",
        "matchsnapshot", "approve", "isvalid", "haveoccurred"
    ];

    public override string Key => "QG-ALL-BUG-0008";
    public override string Name => "Tests should verify something";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || !LooksLikeTestFile(context))
            return;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var body = SyntaxQuery.Body(function);
            if (body is null or { Children.Count: 0 })
                continue;
            if (!IsTestName(function))
                continue;
            // The assertion is often the receiver, not the method: NUnit writes 'Assert.That',
            // xUnit 'Assert.Equal', FluentAssertions 'value.Should().Be'. Reading only the method
            // name saw 'That' and 'Be' and reported tests that assert on every line.
            var asserts = function.OfKind(NodeKind.Invocation).Any(call =>
            {
                var chain = SyntaxQuery.InvokedDottedName(call);
                if (chain.Length == 0)
                    chain = SyntaxQuery.InvokedName(call);
                var lowered = chain.ToLowerInvariant();
                return AssertionNames.Any(name => lowered.Contains(name));
            });
            if (asserts)
                continue;
            context.Report(function, $"'{function.Text}' runs code but asserts nothing, "
                                     + "so it passes whatever the behaviour does.");
        }
    }

    /// <summary>
    /// Whether the file is a test. It shares the judgement with the rest of the engine rather than
    /// asking whether the name contains "test": a sample under src/test/resources is data a test
    /// reads, and every one of those was being reported as a test that verifies nothing.
    /// </summary>
    private static bool LooksLikeTestFile(IRuleContext context)
        => Rules.Languages.LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName);

    private static bool IsTestName(SyntaxNode function)
    {
        var name = function.Text.ToLowerInvariant();
        if (name.StartsWith("test", StringComparison.Ordinal) || name.EndsWith("test", StringComparison.Ordinal))
            return true;
        return function.ChildrenOf(NodeKind.Attribute)
            .Any(a => a.Text.Contains("Test", StringComparison.OrdinalIgnoreCase)
                      || a.Text.Contains("Fact", StringComparison.OrdinalIgnoreCase)
                      || a.Text.Contains("Theory", StringComparison.OrdinalIgnoreCase));
    }
}

public sealed class GenericExceptionCaughtRule : StructuralRuleBase
{
    private static readonly string[] BaseTypes =
        ["Exception", "SystemException", "Throwable", "Error", "BaseException", "RuntimeException"];

    public override string Key => "QG-ALL-SML-0025";
    public override string Name => "Catch clauses should name the failures they handle";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var handler in context.Root.OfKind(NodeKind.Catch))
        {
            var type = handler.FirstChild(NodeKind.TypeReference)?.Text
                       ?? handler.FirstChild(NodeKind.Pattern)?.Text;
            if (type == null || !BaseTypes.Contains(type, StringComparer.Ordinal))
                continue;
            if (handler.Ancestor(NodeKind.FunctionDeclaration) is { Text: "Main" or "main" })
                continue; // the process boundary may legitimately catch everything
            context.Report(handler, $"Catching '{type}' also swallows the failures this code cannot "
                                    + "handle; catch the specific ones and let the rest reach the boundary.");
        }
    }
}

public sealed class GenericExceptionThrownRule : StructuralRuleBase
{
    private static readonly string[] BaseTypes =
        ["Exception", "SystemException", "Throwable", "Error", "RuntimeException", "BaseException"];

    public override string Key => "QG-ALL-SML-0026";
    public override string Name => "Thrown exceptions should be specific";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var jump in context.Root.OfKind(NodeKind.Jump))
        {
            if (jump.Text is not ("throw" or "raise"))
                continue;
            var created = jump.OfKind(NodeKind.ObjectCreation).FirstOrDefault()
                          ?? jump.OfKind(NodeKind.Invocation).FirstOrDefault();
            var type = created?.Text ?? string.Empty;
            if (!BaseTypes.Contains(type, StringComparer.Ordinal))
                continue;
            context.Report(jump, $"'{type}' tells the caller nothing about the failure; "
                                 + "throw a specific type it can act on.");
        }
    }
}

public sealed class RethrowLosingStackRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-BUG-0009";
    public override string Name => "Rethrowing should preserve the original trace";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("cs" or "vb"))
            return;

        foreach (var handler in context.Root.OfKind(NodeKind.Catch))
        {
            var caught = handler.FirstChild(NodeKind.VariableDeclaration)?.Text;
            if (string.IsNullOrEmpty(caught))
                continue;
            foreach (var jump in handler.OfKind(NodeKind.Jump).Where(j => j.Text == "throw"))
            {
                var thrown = SyntaxQuery.DottedName(jump.ChildAt(0));
                if (thrown != caught)
                    continue;
                context.Report(jump, $"Throwing '{caught}' again restarts the stack trace here; "
                                     + "use a bare throw, or wrap it as the inner exception.");
            }
        }
    }
}

public sealed class JumpInFinallyRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-BUG-0010";
    public override string Name => "Cleanup blocks should not change the control flow";
    public override Severity Severity => Severity.Blocker;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var cleanup in context.Root.OfKind(NodeKind.Finally))
        {
            foreach (var jump in cleanup.OfKind(NodeKind.Jump))
            {
                if (jump.Text is not ("return" or "break" or "continue" or "throw" or "raise"))
                    continue;
                if (jump.Ancestor(NodeKind.Lambda, NodeKind.FunctionDeclaration) is { } inner
                    && inner.Ancestor(NodeKind.Finally) == null)
                    continue; // belongs to a nested function, not to the cleanup itself
                context.Report(jump, $"'{jump.Text}' inside cleanup discards whatever was in flight, "
                                     + "including an exception on its way to the caller.");
                break;
            }
        }
    }
}

public sealed class LockOnSharedObjectRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-BUG-0011";
    public override string Name => "Locks should be taken on a private object";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var lockStatement in context.Root.OfKind(NodeKind.Lock))
        {
            var subject = lockStatement.Children.FirstOrDefault(c => c.Kind is not NodeKind.Block);
            if (subject == null)
                continue;
            var text = SyntaxQuery.DottedName(subject);
            var isShared = subject.Kind == NodeKind.StringLiteral
                           || text is "this" or "self"
                           || text.StartsWith("typeof", StringComparison.Ordinal)
                           || subject.OfKind(NodeKind.Invocation).Any(i =>
                               SyntaxQuery.InvokedName(i) is "getClass" or "typeof" or "GetType");
            if (!isShared)
                continue;
            context.Report(lockStatement, "Anything reachable from outside can lock this monitor too, "
                                          + "so unrelated code can block or deadlock this section; "
                                          + "use a private object dedicated to the state it protects.");
        }
    }
}

public sealed class IgnoredTestRule : StructuralRuleBase
{
    private static readonly string[] Markers =
        ["Ignore", "Skip", "Skipped", "Disabled", "Pending", "Xfail", "Todo"];

    public override string Key => "QG-ALL-SML-0027";
    public override string Name => "Disabled tests should not stay in the suite";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var marker = function.ChildrenOf(NodeKind.Attribute)
                .FirstOrDefault(a => Markers.Any(m => a.Text.Contains(m, StringComparison.OrdinalIgnoreCase)));
            if (marker == null)
                continue;
            context.Report(function, $"'{function.Text}' is disabled, so the behaviour it covers is "
                                     + "unverified while the suite still reports green.");
        }
    }
}

public sealed class UnusedPrivateFunctionRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0028";
    public override string Name => "Private functions should be called";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        var called = context.Root.OfKind(NodeKind.Invocation)
            .Select(SyntaxQuery.InvokedName)
            .ToHashSet(StringComparer.Ordinal);

        // when the whole project was indexed, QG-ALL-SML-0032 answers the same question with more
        // evidence; running both would report one declaration twice
        var projectWideRuleApplies = context.Project.Types.Count > 0;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var declaredPrivate = function.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "private");
            var privateByConvention = context.Language.LanguageKey == "py" && function.Text.StartsWith('_')
                                      && !function.Text.StartsWith("__", StringComparison.Ordinal);
            if (declaredPrivate && projectWideRuleApplies)
                continue;
            var isPrivate = declaredPrivate || privateByConvention;
            if (!isPrivate || function.Text.Length == 0 || called.Contains(function.Text))
                continue;
            // a member referenced without a call, for instance as a delegate, still counts as used
            var referenced = context.Root.OfKind(NodeKind.Identifier)
                .Count(i => i.Text == function.Text) > 0;
            if (referenced)
                continue;
            context.Report(function, $"Nothing in this file calls '{function.Text}'; "
                                     + "remove it or make the caller explicit.");
        }
    }
}

public sealed class RedundantJumpRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0029";
    public override string Name => "Jumps that change nothing should be removed";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var block in Blocks(context))
        {
            if (block.Children.Count == 0)
                continue;
            var last = block.Children[^1];
            if (last.Kind != NodeKind.Jump || last.Children.Count > 0)
                continue;

            var owner = block.Parent;
            var redundant = last.Text switch
            {
                "return" => owner?.Kind == NodeKind.FunctionDeclaration,
                "continue" => owner?.Kind == NodeKind.Loop,
                _ => false
            };
            if (!redundant)
                continue;
            context.Report(last, $"Control leaves the block here anyway, so this '{last.Text}' "
                                 + "only adds a line to read.");
        }
    }
}

public sealed class CommentedOutCodeRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0030";
    public override string Name => "Commented-out code should be deleted";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var comment in context.Tokens.Where(t => t.Kind == Tokenization.TokenKind.Comment))
        {
            var text = comment.Text.TrimStart('/', '*', '#', '-', ' ', '\t');
            if (text.Length < 12 || text.Length > 200)
                continue;
            var looksLikeCode = (text.EndsWith(';') || text.EndsWith('{') || text.EndsWith('}'))
                                && (text.Contains('=') || text.Contains('(') || text.Contains("return"));
            if (!looksLikeCode)
                continue;
            context.Report("This comment holds code that no longer runs; delete it — "
                           + "version control already keeps the history.", comment.Line);
        }
    }
}

public sealed class DeepInheritanceRule : StructuralRuleBase
{
    private const int MaxDepth = 4;

    public override string Key => "QG-ALL-SML-0031";
    public override string Name => "Inheritance chains should stay shallow";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "45min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var info = context.Project.FindTypes(type.Text).FirstOrDefault(t => t.Node == type);
            if (info == null)
                continue;
            var depth = context.Project.InheritanceDepth(info);
            if (depth <= MaxDepth)
                continue;
            context.Report(type, $"'{type.Text}' sits {depth} levels down its hierarchy; "
                                 + "understanding one method means opening every ancestor.");
        }
    }
}

public sealed class HiddenBaseMemberRule : StructuralRuleBase
{
    private static readonly string[] IntentionalMarkers = ["override", "new", "virtual", "abstract", "partial"];

    public override string Key => "QG-ALL-BUG-0012";
    public override string Name => "Members should not hide a base member by accident";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("cs" or "java" or "kt" or "vb"))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var info = context.Project.FindTypes(type.Text).FirstOrDefault(t => t.Node == type);
            if (info == null || info.BaseNames.Count == 0)
                continue;
            var inherited = context.Project.InheritedMembers(info);
            if (inherited.Count == 0)
                continue;

            foreach (var member in type.OfKind(NodeKind.FunctionDeclaration, NodeKind.PropertyDeclaration))
            {
                if (member.Ancestor(NodeKind.ClassDeclaration) != type || member.Text.Length == 0)
                    continue;
                if (!inherited.Contains(member.Text))
                    continue;
                var modifiers = member.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
                if (modifiers.Any(m => IntentionalMarkers.Contains(m, StringComparer.Ordinal)))
                    continue;
                if (member.ChildrenOf(NodeKind.Attribute).Any(a => a.Text.Contains("Override", StringComparison.OrdinalIgnoreCase)))
                    continue;
                context.Report(member, $"'{member.Text}' already exists in a base type; "
                                       + "mark the intent with override, or rename it so the two do not clash.");
            }
        }
    }
}

public sealed class UnusedInternalMemberRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0032";
    public override string Name => "Non-public members should be reachable";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Project.Types.Count == 0)
            return;

        // A code-behind is reached from the markup beside it. When the scan did not include the
        // templates the engine cannot see those callers, and saying "nothing reaches this" would be
        // a statement about the scan rather than about the code.
        var fileName = System.IO.Path.GetFileName(context.File.Path);
        var isCodeBehind = fileName.EndsWith(".razor.cs", StringComparison.OrdinalIgnoreCase)
                           || fileName.EndsWith(".cshtml.cs", StringComparison.OrdinalIgnoreCase)
                           || fileName.EndsWith(".xaml.cs", StringComparison.OrdinalIgnoreCase)
                           || fileName.EndsWith(".aspx.cs", StringComparison.OrdinalIgnoreCase);
        if (isCodeBehind && !context.Project.SawTemplates)
            return;

        foreach (var member in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var modifiers = member.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (!modifiers.Contains("internal") && !modifiers.Contains("private"))
                continue;
            if (member.Text.Length == 0 || context.Project.IsCalledAnywhere(member.Text))
                continue;
            // A method group is a reference without a call: '.Select(MapDocumento)' uses the method
            // as a value. Only the identifiers the declaration itself contributes are discounted,
            // and in most languages that is none of them.
            var own = member.OfKind(NodeKind.Identifier).Count(i => i.Text == member.Text);
            if (context.Project.ReferenceCount(member.Text) > own)
                continue;
            context.Report(member, $"Nothing in the scanned code reaches '{member.Text}'; "
                                   + "remove it or make the caller explicit.");
        }
    }
}

public sealed class DuplicateTypeNameRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0033";
    public override string Name => "Type names should be unique across the code base";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (type.Text.Length < 3 || !context.Project.IsDeclaredMoreThanOnce(type.Text))
                continue;
            // The same simple name in two namespaces is ordinary — Settings, Options and Handler
            // exist once per module by design, and the language keeps them apart. It only confuses a
            // reader when the two answer to the same qualified name, so that is what is compared;
            // where no namespace is declared, the folder stands in for it.
            // without a declared namespace the language itself cannot tell the two apart, which is
            // what the rule about declaring types in a namespace is for
            var here = Container(type, context.File.Path);
            if (here.Length == 0)
                continue;
            var others = context.Project.FindTypes(type.Text)
                .Where(t => t.File != context.File.Path
                            && string.Equals(Container(t.Node, t.File), here, StringComparison.OrdinalIgnoreCase))
                .Select(t => System.IO.Path.GetFileName(t.File))
                .Distinct()
                .ToArray();
            if (others.Length == 0)
                continue;
            // the message names a few of them: a list of ninety file names is not a message
            var named = string.Join(", ", others.Take(3));
            var rest = others.Length > 3 ? $" and {others.Length - 3} more files" : string.Empty;
            context.Report(type, $"'{type.Text}' is also declared in {named}{rest}, under the same "
                                 + "namespace; a reader cannot tell which one an import refers to.");
        }
    }
    /// <summary>
    /// What a type is qualified by: the namespace or package it is declared in, and the folder when
    /// the language does not declare one.
    /// </summary>
    private static string Container(SyntaxNode type, string path)
    {
        for (var node = type.Parent; node != null; node = node.Parent)
        {
            if (node.Kind == NodeKind.PackageDeclaration && node.Text.Length > 0)
                return node.Text;
        }
        // a file-scoped namespace is a sibling of the type, not its parent: it covers everything
        // written after it, so the last one declared before this type is the one it belongs to
        var root = type;
        while (root.Parent != null)
            root = root.Parent;
        var declared = root.ChildrenOf(NodeKind.PackageDeclaration)
            .Where(n => n.Range.StartLine <= type.Range.StartLine && n.Text.Length > 0)
            .Select(n => n.Text)
            .LastOrDefault();
        _ = path;
        return declared ?? string.Empty;
    }

}

public sealed class EqualityContractRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-BUG-0013";
    public override string Name => "Equality and hashing should be overridden together";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var members = type.OfKind(NodeKind.FunctionDeclaration)
                .Where(m => m.Ancestor(NodeKind.ClassDeclaration) == type)
                .Select(m => m.Text)
                .ToArray();
            var hasEquals = members.Any(m => m is "Equals" or "equals" or "__eq__");
            var hasHash = members.Any(m => m is "GetHashCode" or "hashCode" or "__hash__");
            if (hasEquals == hasHash)
                continue;
            var present = hasEquals ? "equality" : "hashing";
            var missing = hasEquals ? "hashing" : "equality";
            context.Report(type, $"'{type.Text}' overrides {present} but not {missing}; "
                                 + "hash-based collections then fail to find items that compare equal.");
        }
    }
}

public sealed class OverrideOnlyCallsBaseRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0034";
    public override string Name => "Overrides should add something";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var member in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var isOverride = member.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "override")
                             || member.ChildrenOf(NodeKind.Attribute).Any(a => a.Text == "Override");
            if (!isOverride)
                continue;
            var body = SyntaxQuery.Body(member);
            if (body is not { Children.Count: 1 })
                continue;

            var only = body.Children[0];
            var call = only.OfKind(NodeKind.Invocation).FirstOrDefault();
            if (call == null)
                continue;
            var callee = SyntaxQuery.InvokedDottedName(call);
            if (!callee.StartsWith("base.", StringComparison.Ordinal)
                && !callee.StartsWith("super.", StringComparison.Ordinal))
                continue;
            if (SyntaxQuery.SimpleName(call.ChildAt(0)) != member.Text)
                continue;
            context.Report(member, $"'{member.Text}' only forwards to the base implementation, "
                                   + "so removing it changes nothing.");
        }
    }
}

public sealed class EmptyTypeRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0035";
    public override string Name => "Types should declare something";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body is not { Children.Count: 0 })
                continue;
            if (type.BaseCount(context) > 0)
                continue; // an empty subclass can be a deliberate marker or a specialised exception
            context.Report(type, $"'{type.Text}' declares no members; "
                                 + "give it behaviour or remove it.");
        }
    }
}

internal static class TypeNodeExtensions
{
    /// <summary>Number of base types the declaration names, as seen by the project index.</summary>
    public static int BaseCount(this SyntaxNode type, IRuleContext context)
        => context.Project.FindTypes(type.Text).FirstOrDefault(t => t.Node == type)?.BaseNames.Count ?? 0;
}

public sealed class FieldCouldBeReadOnlyRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0036";
    public override string Name => "Fields set only during construction should be read-only";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("cs" or "java" or "kt"))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            foreach (var field in type.OfKind(NodeKind.FieldDeclaration))
            {
                if (field.Ancestor(NodeKind.ClassDeclaration) != type || field.Text.Length == 0)
                    continue;
                var modifiers = field.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
                if (modifiers.Any(m => m is "readonly" or "const" or "final" or "static" or "volatile"))
                    continue;
                if (!modifiers.Contains("private"))
                    continue;

                var assignments = type.OfKind(NodeKind.Assignment)
                    .Where(a => SyntaxQuery.SimpleName(a.ChildAt(0)) == field.Text)
                    .ToList();
                if (assignments.Count == 0)
                    continue;

                var outsideConstruction = assignments.Any(a =>
                    a.Ancestor(NodeKind.ConstructorDeclaration) == null
                    && a.Ancestor(NodeKind.FieldDeclaration) == null);
                if (outsideConstruction)
                    continue;

                context.Report(field, $"'{field.Text}' never changes after construction; "
                                      + "mark it read-only so the compiler enforces that.");
            }
        }
    }
}

public sealed class MethodCouldBeStaticRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0037";
    public override string Name => "Members that ignore instance state should be static";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("cs" or "java"))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var instanceMembers = type
                .OfKind(NodeKind.FieldDeclaration, NodeKind.PropertyDeclaration, NodeKind.FunctionDeclaration)
                .Where(m => m.Ancestor(NodeKind.ClassDeclaration) == type
                            && !m.ChildrenOf(NodeKind.Modifier).Any(x => x.Text == "static"))
                .Select(m => m.Text)
                .Where(name => name.Length > 0)
                .ToHashSet(StringComparer.Ordinal);

            foreach (var method in type.OfKind(NodeKind.FunctionDeclaration))
            {
                if (method.Ancestor(NodeKind.ClassDeclaration) != type || method.Text.Length == 0)
                    continue;
                var modifiers = method.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
                if (modifiers.Any(m => m is "static" or "override" or "virtual" or "abstract" or "partial"
                        or "default" or "extern" or "async"))
                    continue;
                // Only a private method can be turned static without touching anything outside the
                // class: everything else is somebody's contract — an override, an implementation of
                // an interface, or a member a subclass is expected to be able to replace. The engine
                // cannot see those callers from one file, so it does not guess about them.
                if (!modifiers.Contains("private", StringComparer.Ordinal))
                    continue;
                if (method.ChildrenOf(NodeKind.Attribute).Any() || method.ChildrenOf(NodeKind.Annotation).Any())
                    continue; // a framework may require the instance form
                var body = SyntaxQuery.Body(method);
                if (body is null or { Children.Count: 0 })
                    continue;

                var touchesInstance = body.OfKind(NodeKind.Identifier)
                    .Any(i => i.Text is "this" or "base" or "super" || instanceMembers.Contains(i.Text))
                    || body.OfKind(NodeKind.Invocation)
                        .Any(call => instanceMembers.Contains(SyntaxQuery.InvokedName(call)));
                if (touchesInstance)
                    continue;

                context.Report(method, $"'{method.Text}' never reads the instance; "
                                       + "make it static so callers do not need an object.");
            }
        }
    }
}

public sealed class MutableStaticStateRule : StructuralRuleBase
{
    public override string Key => "QG-ALL-SML-0038";
    public override string Name => "Shared state should not be mutable";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var field in context.Root.OfKind(NodeKind.FieldDeclaration))
        {
            var modifiers = field.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (!modifiers.Contains("static") || modifiers.Any(m => m is "readonly" or "const" or "final"))
                continue;
            if (modifiers.Contains("private"))
                continue;
            context.Report(field, $"'{field.Text}' is shared by the whole process and can be replaced by "
                                  + "any caller, from any thread; make it read-only or move it behind a "
                                  + "scoped service.");
        }
    }
}

public sealed class UnreleasedResourceRule : StructuralRuleBase
{
    private static readonly string[] ResourceTypes =
    [
        "FileStream", "StreamReader", "StreamWriter", "SqlConnection", "SqlCommand", "HttpClient",
        "MemoryStream", "Socket", "TcpClient", "NpgsqlConnection", "MySqlConnection", "FileInputStream",
        "FileOutputStream", "FileReader", "FileWriter", "BufferedReader", "ServerSocket", "Scanner"
    ];

    private static readonly string[] ReleaseNames = ["Dispose", "close", "Close", "DisposeAsync"];

    public override string Key => "QG-ALL-BUG-0014";
    public override string Name => "Resources should be released on every path";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("cs" or "java" or "kt"))
            return;

        foreach (var declaration in context.Root.OfKind(NodeKind.VariableDeclaration))
        {
            var creation = declaration.OfKind(NodeKind.ObjectCreation).FirstOrDefault();
            if (creation == null)
                continue;
            var type = Semantics.TypeResolver.Normalize(creation.Text);
            if (!ResourceTypes.Contains(type, StringComparer.Ordinal))
                continue;
            if (declaration.Ancestor(NodeKind.Using) != null || declaration.Kind == NodeKind.Using)
                continue;
            if (declaration.Parent?.Kind == NodeKind.Using)
                continue;

            var function = SyntaxQuery.EnclosingFunction(declaration);
            var released = function != null && function.OfKind(NodeKind.Invocation)
                .Any(call => ReleaseNames.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal)
                             && SyntaxQuery.Receiver(call) == declaration.Text);
            if (released)
                continue;

            context.Report(declaration, $"'{declaration.Text}' holds a {type} that is never released; "
                                        + "declare it in a using or try-with-resources block so it closes "
                                        + "on every path, including the exceptional ones.");
        }
    }
}

public sealed class MismatchedComparisonRule : StructuralRuleBase
{
    private static readonly string[] Numeric =
        ["int", "long", "short", "byte", "double", "float", "decimal", "number", "Integer", "Double"];

    private static readonly string[] Primitive =
        ["int", "long", "short", "byte", "double", "float", "decimal", "number", "bool", "boolean",
         "string", "str", "char", "object"];

    public override string Key => "QG-ALL-BUG-0015";
    public override string Name => "Values of unrelated types should not be compared";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!=" or "===" or "!=="))
                continue;
            var left = context.Types.TypeOf(comparison.ChildAt(0));
            var right = context.Types.TypeOf(comparison.ChildAt(1));
            if (left == null || right == null || left == right)
                continue;
            // only compare names that are really types: anything else is an expression the resolver
            // could not follow, and two unknowns never prove that a comparison is impossible
            if (!context.Types.IsKnownType(left) || !context.Types.IsKnownType(right))
                continue;
            if (Numeric.Contains(left, StringComparer.Ordinal) && Numeric.Contains(right, StringComparer.Ordinal))
                continue;
            // TypeScript names a union of literals with `type X = 'a' | 'b'`, which the index sees as
            // a declaration with no shape. Comparing such a name with a primitive proves nothing, so
            // the pair is only reported where a named type cannot be an alias for a primitive.
            if (context.Language.LanguageKey is "ts" or "js"
                && (Primitive.Contains(left, StringComparer.Ordinal)
                    || Primitive.Contains(right, StringComparer.Ordinal)))
                continue;
            if (context.Types.IsOrDerivesFrom(left, right) || context.Types.IsOrDerivesFrom(right, left))
                continue;
            context.Report(comparison, $"A value of type {left} can never equal one of type {right}, "
                                       + "so this comparison is constant.");
        }
    }
}
