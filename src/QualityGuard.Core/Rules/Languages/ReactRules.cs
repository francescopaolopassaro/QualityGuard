using System.Text.RegularExpressions;
using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class ReactRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new ReactDangerouslySetInnerHtmlRule(),
        new ReactMissingKeyPropRule(),
        new ReactDirectDomAccessRule(),
        new ReactWindowStateOpenRule(),
        new ReactHookArrayDependencyRule(),
        new ReactUseEffectMissingCleanupRule(),
    ];
}

public abstract class ReactRuleBase : RuleBase
{
    public override string[] Languages => ["js", "ts"];
    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;
}

/// <summary>
/// dangerouslySetInnerHTML bypasses React's XSS protection and should be avoided.
/// </summary>
public sealed class ReactDangerouslySetInnerHtmlRule : ReactRuleBase
{
    public override string Key => "QG-JS-SEC-0100";
    public override string Name => "dangerouslySetInnerHTML bypasses XSS protection";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min"; public override string FixAdvice => "Use a sanitizing library (e.g. DOMPurify) before passing HTML.";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var invocation in SyntaxQuery.Invocations(context.Root))
        {
            if (SyntaxQuery.InvokedName(invocation) != "createElement")
                continue;
            var args = SyntaxQuery.Arguments(invocation);
            if (args.Count < 2)
                continue;
            // the second arg (or later) may contain dangerouslySetInnerHTML
            foreach (var arg in args.Skip(1))
            {
                foreach (var desc in arg.DescendantsAndSelf())
                {
                    if (desc.Kind != NodeKind.MemberSelect)
                        continue;
                    var dotted = SyntaxQuery.DottedName(desc);
                    if (dotted == "dangerouslySetInnerHTML")
                    {
                        context.Report("dangerouslySetInnerHTML bypasses React's built-in XSS "
                                       + "sanitization. Any unsanitized HTML will be rendered as-is, "
                                       + "opening the door to script injection. Sanitize the HTML "
                                       + "first.",
                            invocation.Range.StartLine);
                    }
                }
            }
        }

        // also: <div dangerouslySetInnerHTML={...} />
        foreach (var token in context.Tokens)
        {
            if (token.Kind != TokenKind.Identifier || token.Text != "dangerouslySetInnerHTML")
                continue;
            // should already be caught by the AST path above, but as a fallback
            context.Report("dangerouslySetInnerHTML bypasses React's built-in XSS sanitization.",
                token.Line);
        }
    }
}

/// <summary>
/// React lists rendered with .map() should provide a stable, unique key prop for each item.
/// key={index} is anti-pattern because it breaks reordering and state preservation.
/// </summary>
public sealed class ReactMissingKeyPropRule : ReactRuleBase
{
    public override string Key => "QG-JS-SML-0639";
    public override string Name => "List items should use a stable, unique key";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "10min"; public override string FixAdvice => "Use a unique identifier (e.g. item.id) instead of the array index.";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!line.Contains("key=", StringComparison.Ordinal))
                continue;
            // key={index} or key={i} â€” array index as key
            if (line.Contains("key={index}", StringComparison.Ordinal)
                || line.Contains("key={i}", StringComparison.Ordinal)
                || Regex.IsMatch(line, @"key=\{\w+\.index\}"))
            {
                context.Report("Using the array index as a key causes components to reuse state "
                               + "incorrectly when the list is reordered or filtered. Use a "
                               + "unique, stable identifier.",
                    i + 1);
            }
        }
    }
}

/// <summary>
/// Direct DOM access via document.querySelector/getElementById breaks React's virtual DOM.
/// </summary>
public sealed class ReactDirectDomAccessRule : ReactRuleBase
{
    public override string Key => "QG-JS-SML-0432";
    public override string Name => "Direct DOM access breaks React's virtual DOM";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "10min"; public override string FixAdvice => "Use refs (useRef) or React state to manage DOM interactions.";

    private static readonly string[] DomMethods =
    [
        "document.getElementById", "document.querySelector", "document.querySelectorAll",
        "document.getElementsByClassName", "document.getElementsByTagName",
        "document.createElement", "document.write"
    ];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var comment = line.IndexOf("//", StringComparison.Ordinal);
            if (comment >= 0)
                line = line[..comment];

            foreach (var method in DomMethods)
            {
                if (!line.Contains(method, StringComparison.Ordinal))
                    continue;
                // exclude type declarations and string literals
                var idx = line.IndexOf(method, StringComparison.Ordinal);
                if (idx > 0 && line[idx - 1] == '"')
                    continue;
                context.Report($"Direct DOM access via '{method}' bypasses React's virtual DOM. "
                               + "Use refs or state instead.",
                    i + 1);
                break;
            }
        }
    }
}

/// <summary>
/// window.open without security args may open a new window with full access to the parent.
/// </summary>
public sealed class ReactWindowStateOpenRule : ReactRuleBase
{
    public override string Key => "QG-JS-SEC-0101";
    public override string Name => "window.open without restrictive features";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "10min"; public override string FixAdvice => "Pass 'noopener,noreferrer' as the window features argument.";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var invocation in SyntaxQuery.Invocations(context.Root))
        {
            var dotted = SyntaxQuery.InvokedDottedName(invocation);
            if (dotted != "window.open")
                continue;
            var args = SyntaxQuery.Arguments(invocation);
            if (args.Count < 3)
            {
                context.Report("window.open without a features string leaves the opened window "
                               + "with full access to the parent. Pass 'noopener,noreferrer' "
                               + "to prevent reverse tabnabbing.",
                    invocation.Range.StartLine);
            }
        }
    }
}

/// <summary>
/// Arrays and objects as useEffect dependencies cause infinite re-renders because new references
/// are created on every render.
/// </summary>
public sealed class ReactHookArrayDependencyRule : ReactRuleBase
{
    public override string Key => "QG-JS-BUG-0220";
    public override string Name => "Inline array/object in hook dependency causes re-render loop";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min"; public override string FixAdvice => "Move the dependency to a useMemo/useCallback or state variable.";

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            // useEffect(() => { ... }, [dep1, dep2]) where deps are computed inline
            if (!line.Contains("useEffect", StringComparison.Ordinal)
                && !line.Contains("useCallback", StringComparison.Ordinal)
                && !line.Contains("useMemo", StringComparison.Ordinal))
                continue;
            // detect inline array literal as second arg: [...]
            if (Regex.IsMatch(line, @"\[[\s\S]*\]\s*\)\s*;?\s*$"))
            {
                context.Report("An inline array as a hook dependency is a new reference on every "
                               + "render, causing the hook to run infinitely. Extract the "
                               + "dependency into a stable variable or useMemo.",
                    i + 1);
            }
        }
    }
}

/// <summary>
/// useEffect with an async function as callback cannot return a cleanup function.
/// </summary>
public sealed class ReactUseEffectMissingCleanupRule : ReactRuleBase
{
    public override string Key => "QG-JS-BUG-0221";
    public override string Name => "useEffect with async callback cannot return cleanup";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min"; public override string FixAdvice => "Wrap the async logic inside the useEffect and handle cleanup.";

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (!lines[i].Contains("useEffect", StringComparison.Ordinal))
                continue;
            // useEffect(async () => { ... }, [...]) â€” async callback returns Promise, not cleanup
            if (lines[i].Contains("async", StringComparison.Ordinal))
            {
                context.Report("An async function as useEffect callback returns a Promise, not a "
                               + "cleanup function. Move the async logic inside the effect and "
                               + "handle cleanup with a flag or AbortController.",
                    i + 1);
            }
        }
    }
}

