using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Markup rules that read the document as a tree of elements. Accessibility and markup defects are
/// relationships — an image and its alternative text, a control and the label that names it, a link
/// and the window it opens — so they need the element and its attributes, not a line of text.
/// </summary>
public static class MarkupDocumentRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new ImageWithoutAlternativeTextRule(),
        new DocumentWithoutLanguageRule(),
        new DuplicateElementIdRule(),
        new BlankTargetWithoutRelationRule(),
        new InlineEventHandlerRule(),
        new ControlWithoutLabelRule(),
        new FrameWithoutTitleRule(),
        new DeprecatedElementRule(),
        new TableWithoutHeaderRule()
    ];
}

public abstract class MarkupRuleBase : RuleBase
{
    public override string[] Languages => ["html"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static HtmlElement Document(IRuleContext context) => HtmlDocument.Parse(context.File.Content);

    /// <summary>
    /// True when the attribute is how a component library or a framework binds behaviour to the
    /// element — a data hook, an event binding, a directive. The element then does something, even
    /// though the markup alone does not show what.
    /// </summary>
    protected static bool IsComponentHook(string attribute)
        => attribute.StartsWith("data-", StringComparison.OrdinalIgnoreCase)
           || attribute.StartsWith("ng-", StringComparison.Ordinal)
           || attribute.StartsWith("v-", StringComparison.Ordinal)
           || attribute.StartsWith('@')
           || attribute.StartsWith('(')
           || attribute.StartsWith("on", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the value is written by a template and cannot be judged here.</summary>
    protected static bool IsDynamic(string? value)
        => value != null && (value.Contains("{{", StringComparison.Ordinal)
                             || value.Contains("{%", StringComparison.Ordinal)
                             || value.Contains("<%", StringComparison.Ordinal)
                             || value.Contains("${", StringComparison.Ordinal)
                             || value.Contains("@(", StringComparison.Ordinal));
}

public sealed class ImageWithoutAlternativeTextRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-CNV-0001";
    public override string Name => "An image should carry alternative text";

    public override void Execute(IRuleContext context)
    {
        foreach (var image in Document(context).Named("img"))
        {
            if (image.Has("alt") || image.Has("aria-label") || image.Has("aria-labelledby"))
                continue;
            if (image.Attributes.Keys.Any(k => k.StartsWith(':') || k.StartsWith("v-bind")
                                               || k.StartsWith("[") || k.StartsWith("bind:")))
                continue; // the attribute is bound by a framework and is not visible here

            context.Report("This image has no alternative text, so a screen reader announces its file "
                           + "name or nothing at all. Describe what the image conveys, or set alt=\"\" "
                           + "when it is decoration the reader can ignore.", image.Line);
        }
    }
}

public sealed class DocumentWithoutLanguageRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0002";
    public override string Name => "A document should declare its language";

    public override void Execute(IRuleContext context)
    {
        var root = Document(context);
        var html = root.Named("html").FirstOrDefault();
        if (html == null || html.Has("lang") || html.Has("xml:lang"))
            return;

        context.Report("The document does not say which language it is written in, so a screen reader "
                       + "pronounces it with the wrong voice and the browser offers the wrong "
                       + "translation. Add lang to the html element.", html.Line);
    }
}

public sealed class DuplicateElementIdRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-BUG-0001";
    public override string Name => "An id should identify one element";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        var seen = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var element in Document(context).Descendants())
        {
            var id = element.Attribute("id");
            if (string.IsNullOrWhiteSpace(id) || IsDynamic(id))
                continue;
            if (seen.TryGetValue(id, out var first))
            {
                context.Report($"The id '{id}' is already used on line {first}. Every lookup by that id "
                               + "finds the first element only, so scripts, labels and anchors that point "
                               + "here reach the wrong one.", element.Line);
                continue;
            }
            seen[id] = element.Line;
        }
    }
}

public sealed class BlankTargetWithoutRelationRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SEC-0004";
    public override string Name => "A link opening a new window should cut the reference back";
    public override IssueKind Kind => IssueKind.Vulnerability;

    public override void Execute(IRuleContext context)
    {
        foreach (var link in Document(context).Descendants())
        {
            if (link.Name is not ("a" or "area" or "form"))
                continue;
            if (!string.Equals(link.Attribute("target"), "_blank", StringComparison.OrdinalIgnoreCase))
                continue;
            var relation = link.Attribute("rel") ?? string.Empty;
            if (relation.Contains("noopener", StringComparison.OrdinalIgnoreCase)
                || relation.Contains("noreferrer", StringComparison.OrdinalIgnoreCase))
                continue;
            var href = link.Attribute("href") ?? string.Empty;
            if (href.StartsWith('#') || href.StartsWith('/') || href.Length == 0)
                continue; // a link inside the site opens a page you control

            context.Report("The page opened in the new window keeps a reference to this one and can "
                           + "navigate it somewhere else — a phishing page that looks like the site the "
                           + "user just left. Add rel=\"noopener noreferrer\".", link.Line);
        }
    }
}

public sealed class InlineEventHandlerRule : MarkupRuleBase
{
    /// <summary>
    /// The DOM event attributes. Matching anything that starts with "on" would also flag once, only
    /// and online, which are ordinary attribute names.
    /// </summary>
    private static readonly string[] EventHandlers =
    [
        "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover", "onmousemove", "onmouseout",
        "onmouseenter", "onmouseleave", "onkeypress", "onkeydown", "onkeyup", "onload", "onunload",
        "onbeforeunload", "onerror", "onsubmit", "onreset", "onchange", "oninput", "onfocus", "onblur",
        "onselect", "onscroll", "onresize", "ondrag", "ondrop", "ondragstart", "ondragover", "ontoggle",
        "oncontextmenu", "onwheel", "oncopy", "oncut", "onpaste", "onplay", "onpause", "onended",
        "onanimationend", "ontransitionend", "onpointerdown", "onpointerup", "ontouchstart", "ontouchend"
    ];

    public override string Key => "QG-HTML-SEC-0001";
    public override string Name => "Behaviour should not be written inside the markup";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.SecurityHotspot;

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            var handler = element.Attributes.Keys.FirstOrDefault(
                k => EventHandlers.Contains(k, StringComparer.OrdinalIgnoreCase));
            if (handler == null)
                continue;

            context.Report($"'{handler}' puts behaviour in the markup, where it cannot be tested, reused "
                           + "or covered by a content security policy — the page then needs to allow "
                           + "inline scripts, which is the setting that stops most injection attacks. "
                           + "Bind the handler from a script file.", element.Line);
        }
    }
}

public sealed class ControlWithoutLabelRule : MarkupRuleBase
{
    private static readonly string[] SelfDescribing = ["hidden", "submit", "reset", "button", "image"];

    public override string Key => "QG-HTML-SML-0005";
    public override string Name => "A form control should be named by a label";

    public override void Execute(IRuleContext context)
    {
        var root = Document(context);
        var labelled = root.Named("label")
            .Select(l => l.Attribute("for"))
            .Where(f => !string.IsNullOrEmpty(f))
            .ToHashSet(StringComparer.Ordinal)!;

        foreach (var control in root.Descendants())
        {
            if (control.Name is not ("input" or "select" or "textarea"))
                continue;
            var type = control.Attribute("type") ?? "text";
            if (SelfDescribing.Contains(type, StringComparer.OrdinalIgnoreCase))
                continue;
            if (control.Has("aria-label") || control.Has("aria-labelledby") || control.Has("title"))
                continue;
            if (control.Attribute("id") is { Length: > 0 } id && labelled.Contains(id))
                continue;
            // a control wrapped in its label is labelled without needing the for attribute
            if (control.Parent is { Name: "label" })
                continue;

            context.Report($"This {control.Name} has nothing that names it, so a screen reader announces "
                           + "only its type and a click on the surrounding text does not focus it. Point "
                           + "a label at it with for, or wrap it in one.", control.Line);
        }
    }
}

public sealed class FrameWithoutTitleRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0006";
    public override string Name => "An embedded frame should say what it contains";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        foreach (var frame in Document(context).Descendants())
        {
            if (frame.Name is not ("iframe" or "frame" or "object"))
                continue;
            if (frame.Has("title") || frame.Has("aria-label"))
                continue;

            context.Report($"This {frame.Name} is announced as an unnamed region, so a reader moving "
                           + "through the page by landmarks cannot tell whether to enter it. Give it a "
                           + "title that says what it holds.", frame.Line);
        }
    }
}

public sealed class DeprecatedElementRule : MarkupRuleBase
{
    private static readonly Dictionary<string, string> Replacements = new(StringComparer.OrdinalIgnoreCase)
    {
        ["center"] = "text-align in a stylesheet",
        ["font"] = "font properties in a stylesheet",
        ["big"] = "font-size in a stylesheet",
        ["strike"] = "the del element, or text-decoration",
        ["tt"] = "the code element, or font-family",
        ["marquee"] = "a CSS animation, if the movement is really wanted",
        ["blink"] = "nothing: the effect was removed from every browser",
        ["frame"] = "an iframe, or a layout built with CSS",
        ["frameset"] = "a layout built with CSS",
        ["acronym"] = "the abbr element",
        ["applet"] = "the object element"
    };

    public override string Key => "QG-HTML-SML-0007";
    public override string Name => "A deprecated element should be replaced";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (!Replacements.TryGetValue(element.Name, out var replacement))
                continue;

            context.Report($"'<{element.Name}>' was removed from the standard: browsers still render it "
                           + "today by convention, and nothing guarantees they will tomorrow. Use "
                           + $"{replacement}.", element.Line);
        }
    }
}

public sealed class TableWithoutHeaderRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0008";
    public override string Name => "A data table should have header cells";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        foreach (var table in Document(context).Named("table"))
        {
            if (table.Descendants().Any(e => e.Name == "th"))
                continue;
            // a table with a single row is often used for layout, which the rule has nothing to say about
            if (table.Descendants().Count(e => e.Name == "tr") < 2)
                continue;
            if (string.Equals(table.Attribute("role"), "presentation", StringComparison.OrdinalIgnoreCase))
                continue;

            context.Report("This table has rows but no header cells, so a screen reader reads the values "
                           + "without saying which column they belong to. Mark the heading row with th, "
                           + "or set role=\"presentation\" if the table only arranges the layout.",
                table.Line);
        }
    }
}
