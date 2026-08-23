using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// HTML accessibility checks that read the WAI-ARIA 1.2 dictionaries. Each rule answers a question
/// the dictionaries were built for: is this role real, does it carry what it requires, and does
/// this element already have an implicit version.
/// </summary>
public static class HtmlAriaRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new HtmlLangAttributeGapRule(),
        new HtmlTabIndexNonInteractiveGapRule(),
        new HtmlRedundantAriaRoleGapRule(),
        new HtmlAutocompleteValuesGapRule(),
        new HtmlAnchorAsButtonGapRule(),
        new HtmlAbstractAriaRoleRule(),
        new HtmlNonInteractiveEventHandlerGapRule(),
    ];
}

internal static class HtmlAriaHelper
{
    public static bool Has(HtmlElement e, string name) => e.Attribute(name) != null;

    public static string? Attr(HtmlElement e, string name) => e.Attribute(name);

    public static readonly HashSet<string> Interactive = new(StringComparer.Ordinal)
    {
        "a", "button", "details", "embed", "iframe", "input", "label",
        "select", "summary", "textarea", "audio", "video"
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
            if (element.Attribute("lang") != null) return;
            context.Report("Without lang, screen readers guess the pronunciation and translation "
                           + "tools cannot switch. Add lang to <html>.", element.Line);
            return;
        }
    }
}

public sealed class HtmlTabIndexNonInteractiveGapRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0060";
    public override string Name => "tabindex should not force non-interactive elements into tab order";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (HtmlAriaHelper.Interactive.Contains(element.Text)) continue;
            if (element.Attribute("role") != null) continue;
            var value = element.Attribute("tabindex");
            if (value == null || !int.TryParse(value.Trim(), out var idx) || idx <= 0) continue;
            context.Report("<" + element.Text + " tabindex=\"" + idx + "\"> forces a non-interactive "
                           + "element ahead of interactive ones: screen reader users lose their "
                           + "place. Remove tabindex or use 0.", element.Line);
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

public sealed class HtmlAbstractAriaRoleRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0049";
    public override string Name => "ARIA roles should not be abstract";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            var role = element.Attribute("role");
            if (role == null) continue;
            if (!AriaDictionary.AbstractRoles.Contains(role.Trim())) continue;
            context.Report("'" + role + "' is an abstract ARIA role: it exists to organise "
                                   + "the taxonomy and browsers ignore it. Use one of its concrete "
                                   + "subclasses instead.", element.Line);
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
            if (element.Attribute("href") != null) continue;
            if (element.Attribute("role") != null) continue;
            foreach (var key in element.Attributes.Keys)
            {
                if (key.StartsWith("on", StringComparison.Ordinal))
                {
                    context.Report("An <a> without href is not focusable and not announced as "
                                           + "interactive: use <button> for actions.");
                    break;
                }
            }
        }
    }
}



public sealed class HtmlNonInteractiveEventHandlerGapRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0062";
    public override string Name => "Event handlers on non-interactive elements exclude keyboard users";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (HtmlAriaHelper.Interactive.Contains(element.Text)) continue;
            if (element.Attribute("role") != null || element.Attribute("tabindex") != null)
                continue;
            foreach (var attr in element.Attributes.Keys)
            {
                if (!attr.StartsWith("on", StringComparison.Ordinal)) continue;
                if (attr.EndsWith("focus", StringComparison.Ordinal)
                    || attr.EndsWith("blur", StringComparison.Ordinal))
                    continue;
                context.Report("<" + element.Text + " " + attr + "> carries an event handler but no "
                                       + "role or tabindex: keyboard users can never reach it.",
                    element.Line);
                break;
            }
        }
    }
}
