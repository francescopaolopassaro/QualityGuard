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
        new CatchThatOnlyRethrowsRuleCs(),
        new CatchThatOnlyRethrowsRuleJava(),
        new CatchThatOnlyRethrowsRuleKotlin(),
        new CatchThatOnlyRethrowsRuleJs(),
        new CatchThatOnlyRethrowsRulePython(),
        new CatchThatOnlyRethrowsRulePhp(),
        new CatchThatOnlyRethrowsRuleGo(),
        new CatchThatOnlyRethrowsRuleDart(),
        new CatchThatOnlyRethrowsRuleRuby(),
        new CatchThatOnlyRethrowsRuleSwift(),
        new CatchThatOnlyRethrowsRuleCss(),
        new CatchThatOnlyRethrowsRuleHtml(),
        new CatchThatOnlyRethrowsRuleXml(),
        new CatchThatOnlyRethrowsRuleTerraform(),
        new CatchThatOnlyRethrowsRuleDockerfile(),
        new CatchThatOnlyRethrowsRuleKubernetes(),
        new CatchThatOnlyRethrowsRuleCloudFormation(),
        new CatchThatOnlyRethrowsRuleJson(),
        new ExceptionTypeWithoutExceptionBaseRuleCs(),
        new ExceptionTypeWithoutExceptionBaseRuleJava(),
        new ExceptionTypeWithoutExceptionBaseRuleKotlin(),
        new ExceptionTypeWithoutExceptionBaseRuleJs(),
        new ExceptionTypeWithoutExceptionBaseRulePython(),
        new ExceptionTypeWithoutExceptionBaseRulePhp(),
        new ExceptionTypeWithoutExceptionBaseRuleGo(),
        new ExceptionTypeWithoutExceptionBaseRuleDart(),
        new ExceptionTypeWithoutExceptionBaseRuleRuby(),
        new ExceptionTypeWithoutExceptionBaseRuleSwift(),
        new ExceptionTypeWithoutExceptionBaseRuleCss(),
        new ExceptionTypeWithoutExceptionBaseRuleHtml(),
        new ExceptionTypeWithoutExceptionBaseRuleXml(),
        new ExceptionTypeWithoutExceptionBaseRuleTerraform(),
        new ExceptionTypeWithoutExceptionBaseRuleDockerfile(),
        new ExceptionTypeWithoutExceptionBaseRuleKubernetes(),
        new ExceptionTypeWithoutExceptionBaseRuleCloudFormation(),
        new ExceptionTypeWithoutExceptionBaseRuleJson(),
        new ThrowInsideFinallyRuleCs(),
        new ThrowInsideFinallyRuleJava(),
        new ThrowInsideFinallyRuleKotlin(),
        new ThrowInsideFinallyRuleJs(),
        new ThrowInsideFinallyRulePython(),
        new ThrowInsideFinallyRulePhp(),
        new ThrowInsideFinallyRuleGo(),
        new ThrowInsideFinallyRuleDart(),
        new ThrowInsideFinallyRuleRuby(),
        new ThrowInsideFinallyRuleSwift(),
        new ThrowInsideFinallyRuleCss(),
        new ThrowInsideFinallyRuleHtml(),
        new ThrowInsideFinallyRuleXml(),
        new ThrowInsideFinallyRuleTerraform(),
        new ThrowInsideFinallyRuleDockerfile(),
        new ThrowInsideFinallyRuleKubernetes(),
        new ThrowInsideFinallyRuleCloudFormation(),
        new ThrowInsideFinallyRuleJson(),
        new LocalReturnedImmediatelyRuleCs(),
        new LocalReturnedImmediatelyRuleJava(),
        new LocalReturnedImmediatelyRuleKotlin(),
        new LocalReturnedImmediatelyRulePython(),
        new LocalReturnedImmediatelyRulePhp(),
        new LocalReturnedImmediatelyRuleGo(),
        new LocalReturnedImmediatelyRuleDart(),
        new LocalReturnedImmediatelyRuleRuby(),
        new LocalReturnedImmediatelyRuleSwift(),
        new LocalReturnedImmediatelyRuleCss(),
        new LocalReturnedImmediatelyRuleHtml(),
        new LocalReturnedImmediatelyRuleXml(),
        new LocalReturnedImmediatelyRuleTerraform(),
        new LocalReturnedImmediatelyRuleDockerfile(),
        new LocalReturnedImmediatelyRuleKubernetes(),
        new LocalReturnedImmediatelyRuleCloudFormation(),
        new LocalReturnedImmediatelyRuleJson(),
        new CatchingUnrecoverableTypeRuleCs(),
        new CatchingUnrecoverableTypeRuleJava(),
        new CatchingUnrecoverableTypeRuleKotlin(),
        new CatchingUnrecoverableTypeRuleJs(),
        new CatchingUnrecoverableTypeRulePython(),
        new CatchingUnrecoverableTypeRulePhp(),
        new CatchingUnrecoverableTypeRuleGo(),
        new CatchingUnrecoverableTypeRuleDart(),
        new CatchingUnrecoverableTypeRuleRuby(),
        new CatchingUnrecoverableTypeRuleSwift(),
        new CatchingUnrecoverableTypeRuleCss(),
        new CatchingUnrecoverableTypeRuleHtml(),
        new CatchingUnrecoverableTypeRuleXml(),
        new CatchingUnrecoverableTypeRuleTerraform(),
        new CatchingUnrecoverableTypeRuleDockerfile(),
        new CatchingUnrecoverableTypeRuleKubernetes(),
        new CatchingUnrecoverableTypeRuleCloudFormation(),
        new CatchingUnrecoverableTypeRuleJson(),
        new EmptyCommentRuleCs(),
        new EmptyCommentRuleRuby(),
        new EmptyCommentRuleSwift(),
        new EmptyCommentRuleCss(),
        new EmptyCommentRuleHtml(),
        new EmptyCommentRuleXml(),
        new EmptyCommentRuleTerraform(),
        new EmptyCommentRuleDockerfile(),
        new EmptyCommentRuleKubernetes(),
        new EmptyCommentRuleCloudFormation(),
        new EmptyCommentRuleJson(),
        new EmptyCommentRuleJava(),
        new EmptyCommentRuleKotlin(),
        new EmptyCommentRuleJs(),
        new EmptyCommentRulePython(),
        new EmptyCommentRulePhp(),
        new EmptyCommentRuleGo(),
        new EmptyCommentRuleDart()
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

public abstract class CatchThatOnlyRethrowsRule : ExceptionRuleBase
{
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
            // 'throw new WrappedException(e)' adds context; a bare rethrow does not. Python and
            // Ruby build the replacement without a keyword — 'raise ConnectionError(err)' is a call
            // — so the wrapping was invisible here and the most careful handlers were reported.
            if (only.OfKind(NodeKind.ObjectCreation).Any() || only.OfKind(NodeKind.Invocation).Any())
                continue;

            context.Report(handler, "This handler catches the exception and throws it straight back, so it "
                                    + "changes nothing except the stack trace it may reset. Remove the "
                                    + "try/catch, or add what the caller cannot know — context, cleanup, "
                                    + "or an exception that names the operation that failed.");
        }
    }
}

public sealed class CatchThatOnlyRethrowsRuleCs : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-CS-SML-0541";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class CatchThatOnlyRethrowsRuleJava : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-JV-SML-0502";
    public override string[] Languages => ["java"];
}

public sealed class CatchThatOnlyRethrowsRuleKotlin : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-KT-SML-0124";
    public override string[] Languages => ["kt"];
}

public sealed class CatchThatOnlyRethrowsRuleJs : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-JS-SML-0418";
    public override string[] Languages => ["js", "ts"];
}

public sealed class CatchThatOnlyRethrowsRulePython : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-PY-SML-0297";
    public override string[] Languages => ["py"];
}

public sealed class CatchThatOnlyRethrowsRulePhp : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-PP-SML-0162";
    public override string[] Languages => ["php"];
}

public sealed class CatchThatOnlyRethrowsRuleGo : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-GO-SML-0076";
    public override string[] Languages => ["go"];
}

public sealed class CatchThatOnlyRethrowsRuleDart : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-DART-SML-0041";
    public override string[] Languages => ["dart"];
}

public sealed class CatchThatOnlyRethrowsRuleRuby : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-RB-SML-0024";
    public override string[] Languages => ["rb"];
}

public sealed class CatchThatOnlyRethrowsRuleSwift : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-SW-SML-0008";
    public override string[] Languages => ["swift"];
}

public sealed class CatchThatOnlyRethrowsRuleCss : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-CSS-SML-0029";
    public override string[] Languages => ["css"];
}

public sealed class CatchThatOnlyRethrowsRuleHtml : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-HTML-SML-0101";
    public override string[] Languages => ["html"];
}

public sealed class CatchThatOnlyRethrowsRuleXml : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-XML-SML-0016";
    public override string[] Languages => ["xml"];
}

public sealed class CatchThatOnlyRethrowsRuleTerraform : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-TF-SML-0008";
    public override string[] Languages => ["tf"];
}

public sealed class CatchThatOnlyRethrowsRuleDockerfile : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-DK-SML-0022";
    public override string[] Languages => ["dk"];
}

public sealed class CatchThatOnlyRethrowsRuleKubernetes : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-K8-SML-0016";
    public override string[] Languages => ["k8"];
}

public sealed class CatchThatOnlyRethrowsRuleCloudFormation : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-CF-SML-0009";
    public override string[] Languages => ["cf"];
}

public sealed class CatchThatOnlyRethrowsRuleJson : CatchThatOnlyRethrowsRule
{
    public override string Key => "QG-JSON-SML-0004";
    public override string[] Languages => ["json"];
}

public abstract class ExceptionTypeWithoutExceptionBaseRule : ExceptionRuleBase
{
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

public sealed class ExceptionTypeWithoutExceptionBaseRuleCs : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-CS-SML-0542";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleJava : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-JV-SML-0503";
    public override string[] Languages => ["java"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleKotlin : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-KT-SML-0125";
    public override string[] Languages => ["kt"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleJs : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-JS-SML-0419";
    public override string[] Languages => ["js", "ts"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRulePython : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-PY-SML-0298";
    public override string[] Languages => ["py"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRulePhp : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-PP-SML-0163";
    public override string[] Languages => ["php"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleGo : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-GO-SML-0077";
    public override string[] Languages => ["go"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleDart : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-DART-SML-0042";
    public override string[] Languages => ["dart"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleRuby : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-RB-SML-0025";
    public override string[] Languages => ["rb"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleSwift : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-SW-SML-0009";
    public override string[] Languages => ["swift"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleCss : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-CSS-SML-0030";
    public override string[] Languages => ["css"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleHtml : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-HTML-SML-0102";
    public override string[] Languages => ["html"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleXml : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-XML-SML-0017";
    public override string[] Languages => ["xml"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleTerraform : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-TF-SML-0009";
    public override string[] Languages => ["tf"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleDockerfile : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-DK-SML-0023";
    public override string[] Languages => ["dk"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleKubernetes : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-K8-SML-0017";
    public override string[] Languages => ["k8"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleCloudFormation : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-CF-SML-0010";
    public override string[] Languages => ["cf"];
}

public sealed class ExceptionTypeWithoutExceptionBaseRuleJson : ExceptionTypeWithoutExceptionBaseRule
{
    public override string Key => "QG-JSON-SML-0005";
    public override string[] Languages => ["json"];
}

public abstract class ThrowInsideFinallyRule : ExceptionRuleBase
{
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

public sealed class ThrowInsideFinallyRuleCs : ThrowInsideFinallyRule
{
    public override string Key => "QG-CS-BUG-0186";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class ThrowInsideFinallyRuleJava : ThrowInsideFinallyRule
{
    public override string Key => "QG-JV-BUG-0240";
    public override string[] Languages => ["java"];
}

public sealed class ThrowInsideFinallyRuleKotlin : ThrowInsideFinallyRule
{
    public override string Key => "QG-KT-BUG-0067";
    public override string[] Languages => ["kt"];
}

public sealed class ThrowInsideFinallyRuleJs : ThrowInsideFinallyRule
{
    public override string Key => "QG-JS-BUG-0184";
    public override string[] Languages => ["js", "ts"];
}

public sealed class ThrowInsideFinallyRulePython : ThrowInsideFinallyRule
{
    public override string Key => "QG-PY-BUG-0190";
    public override string[] Languages => ["py"];
}

public sealed class ThrowInsideFinallyRulePhp : ThrowInsideFinallyRule
{
    public override string Key => "QG-PP-BUG-0087";
    public override string[] Languages => ["php"];
}

public sealed class ThrowInsideFinallyRuleGo : ThrowInsideFinallyRule
{
    public override string Key => "QG-GO-BUG-0043";
    public override string[] Languages => ["go"];
}

public sealed class ThrowInsideFinallyRuleDart : ThrowInsideFinallyRule
{
    public override string Key => "QG-DART-BUG-0041";
    public override string[] Languages => ["dart"];
}

public sealed class ThrowInsideFinallyRuleRuby : ThrowInsideFinallyRule
{
    public override string Key => "QG-RB-BUG-0015";
    public override string[] Languages => ["rb"];
}

public sealed class ThrowInsideFinallyRuleSwift : ThrowInsideFinallyRule
{
    public override string Key => "QG-SW-BUG-0019";
    public override string[] Languages => ["swift"];
}

public sealed class ThrowInsideFinallyRuleCss : ThrowInsideFinallyRule
{
    public override string Key => "QG-CSS-BUG-0044";
    public override string[] Languages => ["css"];
}

public sealed class ThrowInsideFinallyRuleHtml : ThrowInsideFinallyRule
{
    public override string Key => "QG-HTML-BUG-0044";
    public override string[] Languages => ["html"];
}

public sealed class ThrowInsideFinallyRuleXml : ThrowInsideFinallyRule
{
    public override string Key => "QG-XML-BUG-0019";
    public override string[] Languages => ["xml"];
}

public sealed class ThrowInsideFinallyRuleTerraform : ThrowInsideFinallyRule
{
    public override string Key => "QG-TF-BUG-0014";
    public override string[] Languages => ["tf"];
}

public sealed class ThrowInsideFinallyRuleDockerfile : ThrowInsideFinallyRule
{
    public override string Key => "QG-DK-BUG-0021";
    public override string[] Languages => ["dk"];
}

public sealed class ThrowInsideFinallyRuleKubernetes : ThrowInsideFinallyRule
{
    public override string Key => "QG-K8-BUG-0014";
    public override string[] Languages => ["k8"];
}

public sealed class ThrowInsideFinallyRuleCloudFormation : ThrowInsideFinallyRule
{
    public override string Key => "QG-CF-BUG-0014";
    public override string[] Languages => ["cf"];
}

public sealed class ThrowInsideFinallyRuleJson : ThrowInsideFinallyRule
{
    public override string Key => "QG-JSON-BUG-0015";
    public override string[] Languages => ["json"];
}

public abstract class LocalReturnedImmediatelyRule : ExceptionRuleBase
{
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

public sealed class LocalReturnedImmediatelyRuleCs : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-CS-SML-0543";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class LocalReturnedImmediatelyRuleJava : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-JV-SML-0504";
    public override string[] Languages => ["java"];
}

public sealed class LocalReturnedImmediatelyRuleKotlin : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-KT-SML-0126";
    public override string[] Languages => ["kt"];
}

public sealed class LocalReturnedImmediatelyRuleJs : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-JS-SML-0420";
    public override string[] Languages => ["js", "ts"];
}

public sealed class LocalReturnedImmediatelyRulePython : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-PY-SML-0299";
    public override string[] Languages => ["py"];
}

public sealed class LocalReturnedImmediatelyRulePhp : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-PP-SML-0164";
    public override string[] Languages => ["php"];
}

public sealed class LocalReturnedImmediatelyRuleGo : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-GO-SML-0078";
    public override string[] Languages => ["go"];
}

public sealed class LocalReturnedImmediatelyRuleDart : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-DART-SML-0043";
    public override string[] Languages => ["dart"];
}

public sealed class LocalReturnedImmediatelyRuleRuby : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-RB-SML-0026";
    public override string[] Languages => ["rb"];
}

public sealed class LocalReturnedImmediatelyRuleSwift : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-SW-SML-0010";
    public override string[] Languages => ["swift"];
}

public sealed class LocalReturnedImmediatelyRuleCss : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-CSS-SML-0031";
    public override string[] Languages => ["css"];
}

public sealed class LocalReturnedImmediatelyRuleHtml : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-HTML-SML-0103";
    public override string[] Languages => ["html"];
}

public sealed class LocalReturnedImmediatelyRuleXml : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-XML-SML-0018";
    public override string[] Languages => ["xml"];
}

public sealed class LocalReturnedImmediatelyRuleTerraform : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-TF-SML-0010";
    public override string[] Languages => ["tf"];
}

public sealed class LocalReturnedImmediatelyRuleDockerfile : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-DK-SML-0024";
    public override string[] Languages => ["dk"];
}

public sealed class LocalReturnedImmediatelyRuleKubernetes : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-K8-SML-0018";
    public override string[] Languages => ["k8"];
}

public sealed class LocalReturnedImmediatelyRuleCloudFormation : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-CF-SML-0011";
    public override string[] Languages => ["cf"];
}

public sealed class LocalReturnedImmediatelyRuleJson : LocalReturnedImmediatelyRule
{
    public override string Key => "QG-JSON-SML-0006";
    public override string[] Languages => ["json"];
}

public abstract class CatchingUnrecoverableTypeRule : ExceptionRuleBase
{
    private static readonly string[] Unrecoverable =
    [
        "Throwable", "Error", "StackOverflowError", "OutOfMemoryError", "NullReferenceException",
        "NullPointerException", "AccessViolationException", "StackOverflowException",
        "OutOfMemoryException", "SystemExit", "KeyboardInterrupt", "BaseException"
    ];
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

public sealed class CatchingUnrecoverableTypeRuleCs : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-CS-BUG-0187";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class CatchingUnrecoverableTypeRuleJava : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-JV-BUG-0241";
    public override string[] Languages => ["java"];
}

public sealed class CatchingUnrecoverableTypeRuleKotlin : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-KT-BUG-0068";
    public override string[] Languages => ["kt"];
}

public sealed class CatchingUnrecoverableTypeRuleJs : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-JS-BUG-0185";
    public override string[] Languages => ["js", "ts"];
}

public sealed class CatchingUnrecoverableTypeRulePython : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-PY-BUG-0191";
    public override string[] Languages => ["py"];
}

public sealed class CatchingUnrecoverableTypeRulePhp : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-PP-BUG-0088";
    public override string[] Languages => ["php"];
}

public sealed class CatchingUnrecoverableTypeRuleGo : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-GO-BUG-0044";
    public override string[] Languages => ["go"];
}

public sealed class CatchingUnrecoverableTypeRuleDart : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-DART-BUG-0042";
    public override string[] Languages => ["dart"];
}

public sealed class CatchingUnrecoverableTypeRuleRuby : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-RB-BUG-0016";
    public override string[] Languages => ["rb"];
}

public sealed class CatchingUnrecoverableTypeRuleSwift : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-SW-BUG-0020";
    public override string[] Languages => ["swift"];
}

public sealed class CatchingUnrecoverableTypeRuleCss : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-CSS-BUG-0045";
    public override string[] Languages => ["css"];
}

public sealed class CatchingUnrecoverableTypeRuleHtml : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-HTML-BUG-0045";
    public override string[] Languages => ["html"];
}

public sealed class CatchingUnrecoverableTypeRuleXml : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-XML-BUG-0020";
    public override string[] Languages => ["xml"];
}

public sealed class CatchingUnrecoverableTypeRuleTerraform : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-TF-BUG-0015";
    public override string[] Languages => ["tf"];
}

public sealed class CatchingUnrecoverableTypeRuleDockerfile : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-DK-BUG-0022";
    public override string[] Languages => ["dk"];
}

public sealed class CatchingUnrecoverableTypeRuleKubernetes : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-K8-BUG-0015";
    public override string[] Languages => ["k8"];
}

public sealed class CatchingUnrecoverableTypeRuleCloudFormation : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-CF-BUG-0015";
    public override string[] Languages => ["cf"];
}

public sealed class CatchingUnrecoverableTypeRuleJson : CatchingUnrecoverableTypeRule
{
    public override string Key => "QG-JSON-BUG-0016";
    public override string[] Languages => ["json"];
}

public abstract class EmptyCommentRule : ExceptionRuleBase
{
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

public sealed class EmptyCommentRuleCs : EmptyCommentRule
{
    public override string Key => "QG-CS-SML-0544";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class EmptyCommentRuleJava : EmptyCommentRule
{
    public override string Key => "QG-JV-SML-0505";
    public override string[] Languages => ["java"];
}

public sealed class EmptyCommentRuleKotlin : EmptyCommentRule
{
    public override string Key => "QG-KT-SML-0127";
    public override string[] Languages => ["kt"];
}

public sealed class EmptyCommentRuleJs : EmptyCommentRule
{
    public override string Key => "QG-JS-SML-0421";
    public override string[] Languages => ["js", "ts"];
}

public sealed class EmptyCommentRulePython : EmptyCommentRule
{
    public override string Key => "QG-PY-SML-0300";
    public override string[] Languages => ["py"];
}

public sealed class EmptyCommentRulePhp : EmptyCommentRule
{
    public override string Key => "QG-PP-SML-0165";
    public override string[] Languages => ["php"];
}

public sealed class EmptyCommentRuleGo : EmptyCommentRule
{
    public override string Key => "QG-GO-SML-0079";
    public override string[] Languages => ["go"];
}

public sealed class EmptyCommentRuleDart : EmptyCommentRule
{
    public override string Key => "QG-DART-SML-0044";
    public override string[] Languages => ["dart"];
}

public sealed class EmptyCommentRuleRuby : EmptyCommentRule
{
    public override string Key => "QG-RB-SML-0027";
    public override string[] Languages => ["rb"];
}

public sealed class EmptyCommentRuleSwift : EmptyCommentRule
{
    public override string Key => "QG-SW-SML-0011";
    public override string[] Languages => ["swift"];
}

public sealed class EmptyCommentRuleCss : EmptyCommentRule
{
    public override string Key => "QG-CSS-SML-0032";
    public override string[] Languages => ["css"];
}

public sealed class EmptyCommentRuleHtml : EmptyCommentRule
{
    public override string Key => "QG-HTML-SML-0104";
    public override string[] Languages => ["html"];
}

public sealed class EmptyCommentRuleXml : EmptyCommentRule
{
    public override string Key => "QG-XML-SML-0019";
    public override string[] Languages => ["xml"];
}

public sealed class EmptyCommentRuleTerraform : EmptyCommentRule
{
    public override string Key => "QG-TF-SML-0011";
    public override string[] Languages => ["tf"];
}

public sealed class EmptyCommentRuleDockerfile : EmptyCommentRule
{
    public override string Key => "QG-DK-SML-0025";
    public override string[] Languages => ["dk"];
}

public sealed class EmptyCommentRuleKubernetes : EmptyCommentRule
{
    public override string Key => "QG-K8-SML-0019";
    public override string[] Languages => ["k8"];
}

public sealed class EmptyCommentRuleCloudFormation : EmptyCommentRule
{
    public override string Key => "QG-CF-SML-0012";
    public override string[] Languages => ["cf"];
}

public sealed class EmptyCommentRuleJson : EmptyCommentRule
{
    public override string Key => "QG-JSON-SML-0007";
    public override string[] Languages => ["json"];
}
