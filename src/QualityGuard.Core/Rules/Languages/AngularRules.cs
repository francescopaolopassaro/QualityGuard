using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class AngularRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new AngularBypassSecurityTrustRule(),
        new AngularMissingOnDestroyRule(),
        new AngularElementRefNativeElementRule(),
        new AngularEvalUsageRule(),
    ];
}

public abstract class AngularRuleBase : RuleBase
{
    public override string[] Languages => ["js", "ts"];
    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;
}

/// <summary>
/// bypassSecurityTrust* methods disable Angular's built-in XSS sanitization.
/// </summary>
public sealed class AngularBypassSecurityTrustRule : AngularRuleBase
{
    public override string Key => "QG-TS-SEC-0006";
    public override string Name => "Angular bypassSecurityTrust disables XSS protection";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min"; public override string FixAdvice => "Use DomSanitizer.bypassSecurityTrustUrl() only for known-safe URLs, or sanitize server-side.";

    private static readonly string[] UnsafeMethods =
    [
        "bypassSecurityTrustHtml", "bypassSecurityTrustScript",
        "bypassSecurityTrustStyle", "bypassSecurityTrustUrl",
        "bypassSecurityTrustResourceUrl", "bypassSecurityTrustMap",
        "bypassSecurityTrustStyle"
    ];

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var invocation in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(invocation);
            if (!UnsafeMethods.Contains(name))
                continue;
            context.Report($"'{name}' disables Angular's built-in XSS sanitization. Any value "
                           + "passed to it will be rendered as-is, so an attacker-controlled "
                           + "value would allow script injection. Restrict the input or "
                           + "sanitize on the server.",
                invocation.Range.StartLine);
        }
    }
}

/// <summary>
/// Components that subscribe to Observables in ngOnInit should unsubscribe in ngOnDestroy
/// to prevent memory leaks.
/// </summary>
public sealed class AngularMissingOnDestroyRule : AngularRuleBase
{
    public override string Key => "QG-TS-SML-0007";
    public override string Name => "Missing ngOnDestroy to clean up subscriptions";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min"; public override string FixAdvice => "Store subscriptions and unsubscribe in ngOnDestroy, or use async pipe.";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        // check if file has .subscribe( but no ngOnDestroy
        var content = context.File.Content;
        if (!content.Contains(".subscribe("))
            return;
        if (content.Contains("ngOnDestroy"))
            return;
        if (!content.Contains("@Component") && !content.Contains("@Injectable"))
            return;

        var lines = content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (lines[i].Contains(".subscribe(", StringComparison.Ordinal))
            {
                context.Report("This Observable subscription has no corresponding unsubscribe in "
                               + "ngOnDestroy, which will cause a memory leak. Use async pipe, "
                               + "takeUntil, or store the subscription and unsubscribe.",
                    i + 1);
                return; // report once per file
            }
        }
    }
}

/// <summary>
/// Direct access to ElementRef.nativeElement exposes the raw DOM and bypasses Angular's
/// sanitization. Use renderer2 or the TemplateRef API instead.
/// </summary>
public sealed class AngularElementRefNativeElementRule : AngularRuleBase
{
    public override string Key => "QG-TS-SML-0008";
    public override string Name => "Direct DOM access via ElementRef.nativeElement";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "10min"; public override string FixAdvice => "Use Renderer2 or TemplateRef for safe DOM manipulation.";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var invocation in SyntaxQuery.Invocations(context.Root))
        {
            var dotted = SyntaxQuery.InvokedDottedName(invocation);
            if (dotted == "elementRef.nativeElement" || dotted == "el.nativeElement")
            {
                context.Report("Direct access to.nativeElement bypasses Angular's abstraction "
                               + "layer. Use Renderer2 for DOM manipulation to ensure "
                               + "portability and security.",
                    invocation.Range.StartLine);
            }
        }
    }
}

/// <summary>
/// eval() or new Function() in Angular components enables arbitrary code execution.
/// </summary>
public sealed class AngularEvalUsageRule : AngularRuleBase
{
    public override string Key => "QG-TS-SEC-0007";
    public override string Name => "eval() in Angular enables code injection";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "10min"; public override string FixAdvice => "Remove eval() and use safe alternatives.";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var invocation in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(invocation);
            if (name is "eval" or "Function")
            {
                // skip if it's a string literal pattern like "eval" or typeof
                context.Report($"Call to '{name}' enables arbitrary code execution and is a "
                               + "security vulnerability. Remove it.",
                    invocation.Range.StartLine);
            }
        }
    }
}

