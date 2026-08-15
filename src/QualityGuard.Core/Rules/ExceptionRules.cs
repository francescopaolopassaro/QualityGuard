using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules;

/// <summary>
/// How failures are declared, thrown and caught. These rules are about the paths nobody exercises
/// until production: a handler that hides the cause, a throw that replaces the exception already on
/// its way out, a type that says "exception" and is not one.
/// </summary>
public static class ExceptionRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CatchThatOnlyRethrowsRule(),
        new ExceptionTypeWithoutExceptionBaseRule(),
        new ThrowInsideFinallyRule(),
        new LocalReturnedImmediatelyRule(),
        new CatchingUnrecoverableTypeRule(),
        new EmptyCommentRule()
    ];
}

public abstract class ExceptionRuleBase : RuleBase
{
    public override string[] Languages => [];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "10min";

    protected static bool HasPreciseTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static bool IsThrow(SyntaxNode node)
        => node.Text.StartsWith("throw", StringComparison.Ordinal)
           || node.Text.StartsWith("raise", StringComparison.Ordinal);
}

public sealed class CatchThatOnlyRethrowsRule : ExceptionRuleBase
{
    public override string Key => "QG-ALL-SML-0048";
    public override string Name => "A catch clause should do more than rethrow";
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var handler in context.Root.OfKind(NodeKind.Catch))
        {
            var body = handler.FirstChild(NodeKind.Block);
            if (body == null || body.Children.Count != 1)
                continue;
            var only = body.Children[0];
            if (!IsThrow(only))
                continue;
            // `throw new WrappedException(e)` adds context; a bare rethrow does not
            if (only.OfKind(NodeKind.ObjectCreation).Any())
                continue;

            context.Report(handler, "This handler catches the exception and throws it straight back, so it "
                                    + "changes nothing except the stack trace it may reset. Remove the "
                                    + "try/catch, or add what the caller cannot know — context, cleanup, "
                                    + "or an exception that names the operation that failed.");
        }
    }
}

public sealed class ExceptionTypeWithoutExceptionBaseRule : ExceptionRuleBase
{
    public override string Key => "QG-ALL-SML-0049";
    public override string Name => "A type named like an exception should be one";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Language.LanguageKey is not ("cs" or "java" or "kt" or "vb"))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!type.Text.EndsWith("Exception", StringComparison.Ordinal))
                continue;
            var info = context.Project.FindType(type.Text);
            if (info == null)
                continue;
            if (info.BaseNames.Any(b => b.Contains("Exception", StringComparison.Ordinal)
                                        || b.Contains("Throwable", StringComparison.Ordinal)
                                        || b.Contains("Error", StringComparison.Ordinal)))
                continue;
            if (info.BaseNames.Count > 0 && info.BaseNames.Any(b => context.Project.FindType(b) != null))
                continue; // it derives from something the scan knows: follow that chain instead

            context.Report(type, $"'{type.Text}' is named like an exception but derives from nothing that "
                                 + "can be thrown. Either derive it from the exception type of the "
                                 + "platform, or give it a name that does not promise it can be caught.");
        }
    }
}

public sealed class ThrowInsideFinallyRule : ExceptionRuleBase
{
    public override string Key => "QG-ALL-BUG-0037";
    public override string Name => "A finally block should not throw";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var block in context.Root.OfKind(NodeKind.Finally))
        {
            foreach (var thrown in block.DescendantsAndSelf().Where(IsThrow))
            {
                // a throw inside a nested try of the finally block is handled there
                if (thrown.Ancestor(NodeKind.Try) is { } inner && inner.Ancestor(NodeKind.Finally) == block)
                    continue;

                context.Report(thrown, "A throw in a finally block replaces the exception that was already "
                                       + "on its way out, so the original failure — the one that explains "
                                       + "what went wrong — is lost. Handle the error here, or let the "
                                       + "cleanup fail silently and log it.");
                break;
            }
        }
    }
}

public sealed class LocalReturnedImmediatelyRule : ExceptionRuleBase
{
    public override string Key => "QG-ALL-SML-0050";
    public override string Name => "A local should not be declared only to be returned on the next line";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var block in context.Root.OfKind(NodeKind.Block))
        {
            var children = block.Children;
            for (var i = 0; i < children.Count - 1; i++)
            {
                if (children[i].Kind != NodeKind.VariableDeclaration)
                    continue;
                var next = children[i + 1];
                if (next.Kind != NodeKind.Jump || !(next.Text.StartsWith("return", StringComparison.Ordinal)
                                                    || IsThrow(next)))
                    continue;
                var name = children[i].Text;
                if (name.Length == 0)
                    continue;
                var returned = next.Children.Count == 1 && next.ChildAt(0) is { Kind: NodeKind.Identifier } id
                               && id.Text == name;
                if (!returned)
                    continue;

                context.Report(children[i], $"'{name}' exists only to be handed straight back. Return the "
                                            + "expression, unless the name is what explains it — in which "
                                            + "case the name should say more than the expression does.");
            }
        }
    }
}

public sealed class CatchingUnrecoverableTypeRule : ExceptionRuleBase
{
    private static readonly string[] Unrecoverable =
    [
        "Throwable", "Error", "StackOverflowError", "OutOfMemoryError", "NullReferenceException",
        "NullPointerException", "AccessViolationException", "StackOverflowException",
        "OutOfMemoryException", "SystemExit", "KeyboardInterrupt", "BaseException"
    ];

    public override string Key => "QG-ALL-BUG-0038";
    public override string Name => "A failure the program cannot recover from should not be caught";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var handler in context.Root.OfKind(NodeKind.Catch))
        {
            var caught = handler.Children
                .Where(c => c.Kind is NodeKind.TypeReference or NodeKind.Parameter or NodeKind.Identifier)
                .SelectMany(c => c.DescendantsAndSelf())
                .Select(c => TypeResolverName(c.Text))
                .FirstOrDefault(name => Unrecoverable.Contains(name, StringComparer.Ordinal));
            if (caught == null)
                continue;

            context.Report(handler, $"Catching '{caught}' hides a failure the program cannot continue "
                                    + "from: the process keeps running with a broken state, and the real "
                                    + "cause disappears. Catch the exception the operation can actually "
                                    + "produce, and let the rest travel.");
        }
    }

    private static string TypeResolverName(string text)
    {
        var dot = text.LastIndexOf('.');
        return dot >= 0 && dot < text.Length - 1 ? text[(dot + 1)..] : text;
    }
}

public sealed class EmptyCommentRule : ExceptionRuleBase
{
    public override string Key => "QG-ALL-SML-0051";
    public override string Name => "A comment should say something";
    public override Severity Severity => Severity.Info;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        var comments = context.Tokens.Where(t => t.Kind == Tokenization.TokenKind.Comment).ToList();
        var withContent = comments.Where(c => HasContent(c.Text)).Select(c => c.Line).ToHashSet();

        foreach (var comment in comments)
        {
            if (HasContent(comment.Text))
                continue;
            // a blank line inside a documentation block is spacing, not an empty comment: only a
            // comment that stands alone with nothing in it is worth a line in the report
            if (withContent.Contains(comment.Line - 1) || withContent.Contains(comment.Line + 1))
                continue;

            context.Report("This comment is empty: it takes a line and a reader's attention and gives "
                           + "nothing back. Write what it was meant to say, or remove it.", comment.Line);
        }

        static bool HasContent(string text)
            => text.Trim().Trim('/', '*', '#', '-', '<', '>', '!', '=').Trim().Length > 0;
    }
}
