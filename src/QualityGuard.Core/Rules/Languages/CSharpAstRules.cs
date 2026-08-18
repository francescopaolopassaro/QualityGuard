using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// C# rules that need the real syntax tree. They replace earlier line-based approximations, which is
/// what keeps the false positive rate low enough to run the engine on a whole repository.
/// </summary>
public static class CSharpAstRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CsEmptyStatementRule(),
        new CsLoopDirectionRule(),
        new CsUnusedPrivateFieldRule(),
        new CsAssignmentInConditionRule(),
        new CsEmptyStringComparisonRule()
    ];

    internal static bool IsCSharp(IRuleContext context) => context.Language.LanguageKey == "cs";
}

public abstract class CSharpAstRuleBase : RuleBase
{
    public override string[] Languages => ["cs"];
}

public sealed class CsOneDeclarationPerStatementRule : CSharpAstRuleBase
{
    public override string Key => "QG-CS-SML-0037";
    public override string Name => "One declaration per line";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var declaration in context.Root.OfKind(NodeKind.VariableDeclaration, NodeKind.FieldDeclaration))
        {
            // a foreach header may bind several names through deconstruction, which is one declaration
            if (declaration.Parent?.Kind is NodeKind.Loop or NodeKind.Using)
                continue;
            var declarators = declaration.Children
                .Count(c => c.Kind == NodeKind.Identifier
                            || (c.Kind == NodeKind.Assignment && c.Text == "="));
            if (declarators > 1)
                context.Report(declaration, $"This statement declares {declarators} variables; "
                                            + "give each one its own line.");
        }
    }
}

public sealed class CsEmptyStatementRule : CSharpAstRuleBase
{
    public override string Key => "QG-CS-SML-0032";
    public override string Name => "Empty statements should be removed";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var statement in context.Root.OfKind(NodeKind.ExpressionStatement))
        {
            if (statement.Text != ";" || statement.Children.Count != 0)
                continue;
            var owner = statement.Parent?.Parent;
            var message = owner?.Kind is NodeKind.If or NodeKind.Loop
                ? $"The body of this '{owner.Text}' is an empty statement, so the block below always runs."
                : "This stray semicolon is an empty statement; remove it.";
            context.Report(statement, message);
        }
    }
}

public sealed class CsLoopDirectionRule : CSharpAstRuleBase
{
    public override string Key => "QG-CS-BUG-0020";
    public override string Name => "Loop counters should move towards the loop condition";
    public override Severity Severity => Severity.Blocker;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (loop.Text != "for")
                continue;

            var condition = loop.Children.FirstOrDefault(c => c.Kind == NodeKind.Binary
                                                              && c.Text is "<" or "<=" or ">" or ">=");
            if (condition == null)
                continue;

            var counter = SyntaxQuery.DottedName(condition.ChildAt(0));
            if (counter.Length == 0)
                continue;

            foreach (var update in loop.Children.Where(c => c.Kind is NodeKind.Unary or NodeKind.Assignment))
            {
                var target = SyntaxQuery.DottedName(update.ChildAt(0));
                if (target != counter)
                    continue;

                var goesUp = update.Text is "++" or "+=";
                var goesDown = update.Text is "--" or "-=";
                var wantsUp = condition.Text is "<" or "<=";
                if ((wantsUp && goesDown) || (!wantsUp && goesUp))
                {
                    context.Report(loop, $"'{counter}' moves away from the condition on every iteration, "
                                         + "so the loop never ends.");
                }
            }
        }
    }
}

public sealed class CsUnusedPrivateFieldRule : CSharpAstRuleBase
{
    public override string Key => "QG-CS-SML-0012";
    public override string Name => "Unused private field";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        var references = context.Root.OfKind(NodeKind.Identifier)
            .GroupBy(n => n.Text, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

        foreach (var field in context.Root.OfKind(NodeKind.FieldDeclaration))
        {
            var modifiers = field.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (!modifiers.Contains("private") && modifiers.Length != 0)
                continue;
            if (modifiers.Contains("const"))
                continue;

            var name = field.Text;
            if (name.Length == 0)
                continue;
            // one occurrence is the declaration itself
            if (references.GetValueOrDefault(name) > 1)
                continue;
            context.Report(field, $"'{name}' is never read; remove the field or use the value it holds.");
        }
    }
}

public sealed class CsAssignmentInConditionRule : CSharpAstRuleBase
{
    public override string Key => "QG-CS-SML-0030";
    public override string Name => "Conditions should not contain assignments";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var branch in context.Root.OfKind(NodeKind.If, NodeKind.Loop, NodeKind.Match))
        {
            foreach (var condition in Conditions(branch))
            {
                var assignment = condition.DescendantsAndSelf()
                    .FirstOrDefault(n => n.Kind == NodeKind.Assignment && n.Text == "="
                                         && n.Ancestor(NodeKind.Lambda) == null);
                if (assignment != null)
                    context.Report(assignment, "This condition assigns a value instead of comparing it.");
            }
        }
    }

    /// <summary>
    /// The tested expression only: the initializer and the update clause of a for loop legitimately
    /// assign, and so does a foreach variable.
    /// </summary>
    private static IEnumerable<SyntaxNode> Conditions(SyntaxNode branch)
    {
        if (branch.Kind == NodeKind.Loop && branch.Text == "for")
        {
            return branch.Children.Where(c => c.Kind == NodeKind.Binary
                                              && c.Text is "<" or "<=" or ">" or ">=" or "==" or "!=");
        }
        return branch.Children.Where(c => c.Kind is not (NodeKind.Block or NodeKind.Else
            or NodeKind.VariableDeclaration or NodeKind.Unary));
    }
}

public sealed class CsEmptyStringComparisonRule : CSharpAstRuleBase
{
    public override string Key => "QG-CS-SML-0049";
    public override string Name => "Emptiness of a string should be tested with the dedicated helper";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!="))
                continue;
            var isEmptyLiteral = comparison.Children.Any(c =>
                (c.Kind == NodeKind.StringLiteral && c.Text.Length == 0)
                || (c.Kind == NodeKind.MemberSelect && c.Text is "string.Empty" or "String.Empty"));
            if (isEmptyLiteral)
                context.Report(comparison, "Use string.IsNullOrEmpty instead of comparing with an empty literal.");
        }
    }
}
