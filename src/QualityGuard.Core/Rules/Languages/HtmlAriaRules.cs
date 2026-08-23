using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;

namespace QualityGuard.Core.Rules.Languages;

public static class HtmlAriaRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new HtmlLangAttributeGapRule(),
        new HtmlTabIndexNonInteractiveGapRule(),
        new HtmlRedundantAriaRoleGapRule(),
        new HtmlAutocompleteValuesGapRule(),
        new HtmlAnchorAsButtonGapRule(),
    ];
}

internal static class HtmlAriaHelper
{
    public static bool Has(HtmlElement e, string name) => e.Attribute(name) != null;

    public static string? Attr(HtmlElement e, string name) => e.Attribute(name);

    public static readonly HashSet<string> Interactive = new(StringComparer.Ordinal)
    {
        "a", "button", "input", "select", "textarea", "details", "audio", "video", "embed", "label"
    };
}

public sealed class HtmlLangAttributeGapRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-BUG-0014";
    public override string Name => "<html> should carry a lang attribute";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (element.Text is not ("html" or "body")) continue;
            if (HtmlAriaHelper.Has(element, "lang")) return;
            context.Report("Without lang, screen readers guess the pronunciation and translation "
                           + "tools cannot switch. Add lang to <html>.", element.Line);
            return;
        }
    }
}

public sealed class HtmlTabIndexNonInteractiveGapRule : MarkupRuleBase
{
    private static readonly HashSet<string> Interactive = new(StringComparer.Ordinal)
    {
        "a", "button", "input", "select", "textarea", "details", "audio", "video", "label"
    };

    public override string Key => "QG-HTML-SML-0060";
    public override string Name => "tabindex should not force non-interactive elements into tab order";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (Interactive.Contains(element.Text)) continue;
            var value = element.Attribute("tabindex");
            if (value == null || !int.TryParse(value.Trim(), out var idx) || idx <= 0) continue;
            context.Report($"<\" + element.Text + \" tabindex=\" + idx + \"> forces a non-interactive "
                           + "element ahead of interactive ones: screen reader users lose their "
                           + "place. Remove tabindex or use 0.");
        }
    }
}

public sealed class HtmlRedundantAriaRoleGapRule : MarkupRuleBase
{
    private static readonly HashSet<string> Implicit = new(StringComparer.Ordinal)
    {
        "button", "nav", "main", "header", "footer", "form", "article", "aside",
        "h1", "h2", "h3", "h4", "h5", "h6", "img", "ul", "ol", "li"
    };

    public override string Key => "QG-HTML-SML-0050";
    public override string Name => "Do not restate the implicit ARIA role of a semantic tag";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (!Implicit.Contains(element.Text)) continue;
            var role = element.Attribute("role");
            if (role == null || !role.Equals(element.Text, StringComparison.OrdinalIgnoreCase))
                continue;
            context.Report("<" + element.Text + " role=\"" + role + "\"> repeats the implicit role. "
                           + "Remove it: assistive technology already knows.");
        }
    }
}

public sealed class HtmlAutocompleteValuesGapRule : MarkupRuleBase
{
    private static readonly HashSet<string> Valid = new(StringComparer.OrdinalIgnoreCase)
    {
        "on", "off", "name", "email", "username", "new-password", "current-password",
        "one-time-code", "organization", "street-address", "postal-code", "tel", "url"
    };

    public override string Key => "QG-HTML-SML-0055";
    public override string Name => "autocomplete values should be standard tokens";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (element.Text != "input") continue;
            var value = element.Attribute("autocomplete");
            if (value == null || Valid.Contains(value)) continue;
            context.Report("autocomplete=\"" + value + "\" is not a standard token: password managers "
                           + "ignore unknown values.");
        }
    }
}

public sealed class HtmlAnchorAsButtonGapRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0059";
    public override string Name => "Anchors without href are not buttons";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (element.Text != "a") continue;
            if (element.Attribute("href") != null || element.Attribute("role") != null) continue;
            var text = element.Text.ToLowerInvariant();
            // check attributes for click handlers via the element's own text representation
            var hasHandler = false;
            foreach (var key in element.Attributes.Keys)
            {
                if (key.StartsWith("on", StringComparison.Ordinal))
                {
                    hasHandler = true;
                    break;
                }
            }
            if (!hasHandler) continue;
            context.Report("An <a> without href is not focusable and not announced as interactive: "
                           + "use <button> for actions.");
        }
    }
}
