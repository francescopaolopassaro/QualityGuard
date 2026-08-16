using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// The second wave of markup rules: the page as a whole (doctype, title, headings), the elements
/// that only work when a second element is present (fieldset and legend, video and its captions,
/// srcset and its descriptor), and the attributes that quietly take a feature away from the user
/// (a viewport that forbids zoom, aria-hidden on something focusable, a positive tab index).
///
/// All of them read the element tree: an attribute alone never decides, because the same attribute
/// is right or wrong depending on what it sits on and what surrounds it.
/// </summary>
public static class MarkupAccessibilityRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new DocumentWithoutDoctypeRule(),
        new DocumentWithoutTitleRule(),
        new InlineStyleAttributeRule(),
        new MetaRefreshRule(),
        new LinkWithoutDestinationRule(),
        new FieldsetWithoutLegendRule(),
        new LegendOutsideFieldsetRule(),
        new ListItemOutsideListRule(),
        new SkippedHeadingLevelRule(),
        new EmptyHeadingRule(),
        new EmptyAnchorRule(),
        new PositiveTabIndexRule(),
        new AccessKeyRule(),
        new AriaHiddenOnFocusableRule(),
        new AriaRoleAttributeRule(),
        new FormWithoutMethodRule(),
        new SourceSetWithoutDescriptorRule(),
        new ViewportBlocksZoomRule(),
        new AutoplayingMediaRule(),
        new VideoWithoutCaptionsRule(),
        new MouseEventWithoutKeyboardEventRule(),
        new ObjectWithoutFallbackRule(),
        new ImageWithoutDimensionsRule(),
        new DeprecatedAttributeRule(),
        new ServerSideImageMapRule(),
        new NestedScriptRule(),
        new RemoteScriptWithoutIntegrityRule()
    ];
}

public sealed class DocumentWithoutDoctypeRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0076";
    public override string Name => "A page should declare its doctype first";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        var root = Document(context);
        var html = root.Children.FirstOrDefault(e => e.Name == "html");
        if (html == null)
            return; // a fragment, not a page
        if (root.Children.Any(e => e.Name == "!doctype" && e.Line <= html.Line))
            return;

        context.Report("The page does not open with <!DOCTYPE html>, so browsers fall back to quirks "
                       + "mode and lay it out with rules kept for pages written twenty years ago. "
                       + "Widths, margins and line heights then differ from what the stylesheet asks "
                       + "for. Put the declaration on the first line.", html.Line);
    }
}

public sealed class DocumentWithoutTitleRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0077";
    public override string Name => "A page should have a title";

    public override void Execute(IRuleContext context)
    {
        var root = Document(context);
        var head = root.Named("head").FirstOrDefault();
        if (head == null)
            return;
        if (head.Named("title").Any())
            return;

        context.Report("This page has no title, so the browser tab shows its address, a bookmark is "
                       + "saved under the address as well, and a screen reader has nothing to announce "
                       + "when the page opens. Add a title that says which page this is.", head.Line);
    }
}

public sealed class InlineStyleAttributeRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0078";
    public override string Name => "Presentation should live in a stylesheet";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            var style = element.Attribute("style");
            if (string.IsNullOrWhiteSpace(style) || IsDynamic(style))
                continue;

            context.Report($"The style written on this <{element.Name}> beats every selector in the "
                           + "stylesheet, so the theme cannot change it and a content security policy "
                           + "that forbids inline styles drops it. Move the declarations to a class.",
                element.Line);
        }
    }
}

public sealed class MetaRefreshRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0079";
    public override string Name => "A page should not refresh or redirect itself with a meta tag";

    public override void Execute(IRuleContext context)
    {
        foreach (var meta in Document(context).Named("meta"))
        {
            if (!string.Equals(meta.Attribute("http-equiv"), "refresh", StringComparison.OrdinalIgnoreCase))
                continue;

            context.Report("A meta refresh moves the user without warning and without a way to stop it: "
                           + "someone reading slowly loses the page mid-sentence, and the back button "
                           + "returns to a page that immediately leaves again. Redirect from the server "
                           + "with a 3xx response, or update the content with a script the user starts.",
                meta.Line);
        }
    }
}

public sealed class LinkWithoutDestinationRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0080";
    public override string Name => "A link should lead somewhere";

    public override void Execute(IRuleContext context)
    {
        foreach (var link in Document(context).Named("a"))
        {
            var href = (link.Attribute("href") ?? string.Empty).Trim();
            if (href.Length == 0 || IsDynamic(href))
                continue;
            var isEmpty = href == "#"
                          || href.Replace(" ", string.Empty)
                              .StartsWith("javascript:void", StringComparison.OrdinalIgnoreCase)
                          || href.Equals("javascript:;", StringComparison.OrdinalIgnoreCase);
            if (!isEmpty)
                continue;
            // an anchor that carries a role or a component hook is a control the framework drives:
            // the placeholder href is how it stays reachable by keyboard, not a forgotten destination
            if (link.Has("role") || link.Attributes.Keys.Any(IsComponentHook))
                continue;

            context.Report("This link has no destination: it is a button dressed as a link. The browser "
                           + "still offers 'open in a new tab', which lands on the same page, and a "
                           + "screen reader announces a link that goes nowhere. Use a <button> when the "
                           + "element runs a script.", link.Line);
        }
    }
}

public sealed class FieldsetWithoutLegendRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0081";
    public override string Name => "A fieldset should be introduced by a legend";

    public override void Execute(IRuleContext context)
    {
        foreach (var fieldset in Document(context).Named("fieldset"))
        {
            if (fieldset.Children.Any(c => c.Name == "legend"))
                continue;
            if (fieldset.Has("aria-label") || fieldset.Has("aria-labelledby"))
                continue;

            context.Report("A fieldset groups controls that belong together, and the legend is what "
                           + "names the group. Without it a screen reader reads each control on its own, "
                           + "so 'yes' and 'no' arrive with no idea what the question was.",
                fieldset.Line);
        }
    }
}

public sealed class LegendOutsideFieldsetRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0082";
    public override string Name => "A legend should be the first child of its fieldset";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        foreach (var legend in Document(context).Named("legend"))
        {
            var parent = legend.Parent?.Name ?? string.Empty;
            if (parent is "fieldset" or "optgroup" or "figure" or "#document")
                continue;

            context.Report($"This legend sits inside <{parent}>, where it names nothing: only a fieldset "
                           + "or an optgroup turns it into the label of a group. Move it up to the "
                           + "element it is meant to introduce.", legend.Line);
        }
    }
}

public sealed class ListItemOutsideListRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0083";
    public override string Name => "A list item should be inside a list";

    public override void Execute(IRuleContext context)
    {
        foreach (var item in Document(context).Descendants())
        {
            var expected = item.Name switch
            {
                "li" => new[] { "ul", "ol", "menu" },
                "dt" or "dd" => ["dl"],
                _ => null
            };
            if (expected == null)
                continue;
            var parent = item.Parent?.Name ?? "#document";
            if (expected.Contains(parent) || parent == "template")
                continue;
            // a framework component often wraps the items, and the list is built at run time
            if (parent.Contains('-') || item.Parent?.Has("role") == true)
                continue;

            context.Report($"<{item.Name}> is inside <{parent}>, which is not a list. The browser then "
                           + "renders it as loose text and a screen reader never announces how many "
                           + $"items there are. Wrap the items in <{expected[0]}>.", item.Line);
        }
    }
}

public sealed class SkippedHeadingLevelRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0084";
    public override string Name => "Heading levels should not be skipped";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        var previous = 0;
        foreach (var heading in Document(context).Descendants())
        {
            if (heading.Name.Length != 2 || heading.Name[0] != 'h' || !char.IsDigit(heading.Name[1]))
                continue;
            var level = heading.Name[1] - '0';
            if (level is < 1 or > 6)
                continue;
            if (previous != 0 && level > previous + 1)
                context.Report($"This heading is an h{level} but the one before it was an h{previous}. "
                               + "Readers who move through the page by headings hear a section that "
                               + "belongs to a level that was never opened, so the outline of the page "
                               + $"breaks. Use h{previous + 1}, and set the size from the stylesheet.",
                    heading.Line);
            previous = level;
        }
    }
}

public sealed class EmptyHeadingRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0085";
    public override string Name => "A heading should have text";

    public override void Execute(IRuleContext context)
    {
        foreach (var heading in Document(context).Descendants())
        {
            if (heading.Name.Length != 2 || heading.Name[0] != 'h' || !char.IsDigit(heading.Name[1]))
                continue;
            if (MarkupText.HasAccessibleContent(heading))
                continue;

            context.Report($"This <{heading.Name}> is empty, so it appears in the list of headings a "
                           + "screen reader builds with nothing to read out. Give it the text of the "
                           + "section, or remove it and set the spacing from the stylesheet.",
                heading.Line);
        }
    }
}

public sealed class EmptyAnchorRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0086";
    public override string Name => "A link should have text";

    public override void Execute(IRuleContext context)
    {
        foreach (var link in Document(context).Named("a"))
        {
            if (!link.Has("href"))
                continue; // an anchor without href is a target, not a link
            if (MarkupText.HasAccessibleContent(link))
                continue;

            context.Report("This link has no text: an icon or an empty element is all it contains, so a "
                           + "screen reader announces its address instead. Put the text inside it, or "
                           + "name it with aria-label when the label has to stay visual.", link.Line);
        }
    }
}

public sealed class PositiveTabIndexRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0087";
    public override string Name => "A tab index should be 0 or -1";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            var value = element.Attribute("tabindex");
            if (value == null || !int.TryParse(value.Trim(), out var index) || index <= 0)
                continue;

            context.Report($"tabindex=\"{index}\" pulls this element in front of everything that has no "
                           + "explicit index, so the focus order stops following the page. Keeping it "
                           + "right then means renumbering every other element. Use 0 to keep the "
                           + "element in the natural order, or -1 to take it out of the tab sequence.",
                element.Line);
        }
    }
}

public sealed class AccessKeyRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0088";
    public override string Name => "The accesskey attribute should not be used";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (!element.Has("accesskey"))
                continue;

            context.Report("An access key silently takes over a shortcut the browser or the screen "
                           + "reader already uses, and which combination triggers it differs on every "
                           + "platform. The user cannot discover it and cannot change it. Provide the "
                           + "shortcut from a script the user can turn off.", element.Line);
        }
    }
}

public sealed class AriaHiddenOnFocusableRule : MarkupRuleBase
{
    private static readonly string[] Focusable =
        ["a", "button", "input", "select", "textarea", "summary", "details", "audio", "video"];

    public override string Key => "QG-HTML-BUG-0027";
    public override string Name => "A focusable element should not be hidden from assistive technology";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (!string.Equals(element.Attribute("aria-hidden"), "true", StringComparison.OrdinalIgnoreCase))
                continue;
            var focusable = Focusable.Contains(element.Name)
                            || (int.TryParse(element.Attribute("tabindex"), out var index) && index >= 0);
            if (!focusable)
                continue;
            if (element.Has("disabled") || element.Has("hidden"))
                continue;
            if (string.Equals(element.Attribute("tabindex"), "-1", StringComparison.Ordinal))
                continue;

            context.Report($"This <{element.Name}> is hidden from assistive technology but still takes "
                           + "focus, so the keyboard stops on something a screen reader refuses to "
                           + "announce — the user hears silence and cannot tell where they are. Remove "
                           + "aria-hidden, or take the element out of the tab order as well.",
                element.Line);
        }
    }
}

public sealed class AriaRoleAttributeRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-BUG-0028";
    public override string Name => "The role attribute should be spelled role";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (!element.Has("aria-role"))
                continue;

            context.Report("There is no aria-role attribute: the role of an element is written as "
                           + "'role'. Browsers ignore this one, so the element keeps the role it had and "
                           + "the change intended here never happens.", element.Line);
        }
    }
}

public sealed class FormWithoutMethodRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0089";
    public override string Name => "A form should state its method";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        foreach (var form in Document(context).Named("form"))
        {
            var method = form.Attribute("method");
            if (method == null)
            {
                if (!form.Has("action") || form.Attributes.Keys.Any(k => k.StartsWith('@') || k.StartsWith("on")))
                    continue; // a form driven by a script never submits itself
                context.Report("This form has no method, so it submits with GET and puts every field in "
                               + "the address bar — where it is logged by proxies and kept in the "
                               + "history. Say method=\"post\" when the form changes something.",
                    form.Line);
                continue;
            }

            if (IsDynamic(method))
                continue;
            if (method.Trim() is "get" or "post" or "GET" or "POST" or "Get" or "Post" or "dialog")
                continue;

            context.Report($"'{method}' is not a form method: a browser only understands get, post and "
                           + "dialog, and falls back to get for anything else. The request then arrives "
                           + "in a shape the server does not expect.", form.Line);
        }
    }
}

public sealed class SourceSetWithoutDescriptorRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-BUG-0029";
    public override string Name => "Every candidate in a srcset should carry a descriptor";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            var srcset = element.Attribute("srcset");
            if (string.IsNullOrWhiteSpace(srcset) || IsDynamic(srcset))
                continue;
            var candidates = srcset.Split(',', StringSplitOptions.RemoveEmptyEntries
                                               | StringSplitOptions.TrimEntries);
            if (candidates.Length < 2)
                continue;
            var described = candidates.Count(c => c.Contains(' '));
            if (described == candidates.Length || described == 0)
                continue;

            context.Report("Some candidates in this srcset say how wide or how dense they are and "
                           + "others do not. A candidate without a descriptor counts as 1x, so two of "
                           + "them describe the same image and the browser has no way to choose. Give "
                           + "every candidate a w or x descriptor.", element.Line);
        }
    }
}

public sealed class ViewportBlocksZoomRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0090";
    public override string Name => "The viewport should let the user zoom";

    public override void Execute(IRuleContext context)
    {
        foreach (var meta in Document(context).Named("meta"))
        {
            if (!string.Equals(meta.Attribute("name"), "viewport", StringComparison.OrdinalIgnoreCase))
                continue;
            var content = (meta.Attribute("content") ?? string.Empty).Replace(" ", string.Empty);
            var blocked = content.Contains("user-scalable=no", StringComparison.OrdinalIgnoreCase)
                          || content.Contains("user-scalable=0", StringComparison.OrdinalIgnoreCase)
                          || HasSmallMaximum(content);
            if (!blocked)
                continue;

            context.Report("This viewport forbids zooming, so anyone who cannot read text at the size "
                           + "the design chose has no way to enlarge it — on a phone that is the only "
                           + "way. Remove user-scalable=no and let maximum-scale reach at least 5.",
                meta.Line);
        }
    }

    private static bool HasSmallMaximum(string content)
    {
        foreach (var part in content.Split(','))
        {
            if (!part.StartsWith("maximum-scale=", StringComparison.OrdinalIgnoreCase))
                continue;
            var value = part["maximum-scale=".Length..];
            if (double.TryParse(value, System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out var scale) && scale < 2)
                return true;
        }
        return false;
    }
}

public sealed class AutoplayingMediaRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0091";
    public override string Name => "Media should not start playing on its own";

    public override void Execute(IRuleContext context)
    {
        foreach (var media in Document(context).Descendants())
        {
            if (media.Name is not ("audio" or "video"))
                continue;
            if (!media.Has("autoplay"))
                continue;
            // muted video without sound is the accepted background-animation case
            if (media.Name == "video" && media.Has("muted"))
                continue;

            context.Report($"This {media.Name} starts by itself with sound, which covers whatever a "
                           + "screen reader is saying and gives the user no control over it. Browsers "
                           + "block it more often than not, so the behaviour is not even reliable. Let "
                           + "the user press play, or mute the media.", media.Line);
        }
    }
}

public sealed class VideoWithoutCaptionsRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0092";
    public override string Name => "A video should offer captions";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        foreach (var video in Document(context).Named("video"))
        {
            if (video.Has("muted") && !video.Has("controls"))
                continue; // a silent background clip carries nothing to caption
            var tracks = video.Named("track").ToList();
            if (tracks.Any(t => t.Attribute("kind") is "captions" or "subtitles" or null))
                continue;

            context.Report("This video has no captions, so its content is lost to anyone who cannot "
                           + "hear it — and to everyone watching with the sound off, which is most "
                           + "people on a phone. Add a <track kind=\"captions\">.", video.Line);
        }
    }
}

public sealed class MouseEventWithoutKeyboardEventRule : MarkupRuleBase
{
    private static readonly (string Mouse, string Keyboard)[] Pairs =
    [
        ("onmouseover", "onfocus"),
        ("onmouseout", "onblur"),
        ("onmousedown", "onkeydown"),
        ("onmouseup", "onkeyup")
    ];

    public override string Key => "QG-HTML-SML-0093";
    public override string Name => "A mouse handler should have a keyboard equivalent";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            foreach (var (mouse, keyboard) in Pairs)
            {
                if (!element.Has(mouse) || element.Has(keyboard))
                    continue;

                context.Report($"'{mouse}' has no {keyboard} beside it, so whatever it does happens only "
                               + "for a pointer. Someone moving through the page with the keyboard — or "
                               + "with a screen reader, or on a touch screen — never reaches it.",
                    element.Line);
            }
        }
    }
}

public sealed class ObjectWithoutFallbackRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0094";
    public override string Name => "An embedded object should provide alternative content";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            if (element.Name is not ("object" or "embed"))
                continue;
            if (element.Children.Count > 0 || element.Text.Length > 0)
                continue;
            if (element.Has("aria-label") || element.Has("title") || element.Has("alt"))
                continue;

            context.Report($"Nothing inside this <{element.Name}> says what it holds, so a browser that "
                           + "cannot render the object — and every screen reader — shows an empty box. "
                           + "Put a description, a link to the content or an image inside it.",
                element.Line);
        }
    }
}

public sealed class ImageWithoutDimensionsRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0095";
    public override string Name => "An image should declare its size";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var image in Document(context).Named("img"))
        {
            // one dimension, a class or an inline style all mean something already sizes the image
            if (image.Has("width") || image.Has("height") || image.Has("style") || image.Has("class"))
                continue;
            var source = image.Attribute("src") ?? string.Empty;
            if (source.Length == 0 || IsDynamic(source) || source.StartsWith("data:", StringComparison.Ordinal))
                continue;
            if (source.EndsWith(".svg", StringComparison.OrdinalIgnoreCase))
                continue; // a vector scales to whatever the layout gives it

            context.Report("Without width and height the browser cannot reserve room for this image, so "
                           + "the page reflows when it arrives and the text the user was reading jumps "
                           + "away. Declare the intrinsic size; the stylesheet can still scale it.",
                image.Line);
        }
    }
}

public sealed class DeprecatedAttributeRule : MarkupRuleBase
{
    private static readonly Dictionary<string, string> Replacements = new(StringComparer.OrdinalIgnoreCase)
    {
        ["bgcolor"] = "background-color",
        ["background"] = "background-image",
        ["align"] = "text-align, or a flex layout",
        ["valign"] = "vertical-align",
        ["cellpadding"] = "padding on the cells",
        ["cellspacing"] = "border-spacing",
        ["border"] = "border",
        ["hspace"] = "margin",
        ["vspace"] = "margin",
        ["nowrap"] = "white-space: nowrap",
        ["frameborder"] = "border",
        ["marginwidth"] = "margin",
        ["marginheight"] = "margin"
    };

    private static readonly string[] BorderIsFine = ["table", "img", "object"];

    public override string Key => "QG-HTML-SML-0096";
    public override string Name => "An attribute removed from the standard should be replaced";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            foreach (var attribute in element.Attributes.Keys)
            {
                if (!Replacements.TryGetValue(attribute, out var replacement))
                    continue;
                if (attribute.Equals("border", StringComparison.OrdinalIgnoreCase)
                    && !BorderIsFine.Contains(element.Name))
                    continue;
                if (attribute.Equals("align", StringComparison.OrdinalIgnoreCase) && element.Name == "svg")
                    continue;

                context.Report($"'{attribute}' was dropped from the standard: it still renders today "
                               + "because browsers keep old pages working, and it cannot be overridden "
                               + $"from a theme. Set {replacement} in the stylesheet instead.",
                    element.Line);
            }
        }
    }
}

public sealed class ServerSideImageMapRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SML-0097";
    public override string Name => "A server-side image map should not be used";

    public override void Execute(IRuleContext context)
    {
        foreach (var image in Document(context).Named("img"))
        {
            if (!image.Has("ismap"))
                continue;
            if (image.Parent is { Name: "a" } link && link.Has("usemap"))
                continue;

            context.Report("A server-side image map sends the pixel the user clicked, so the regions "
                           + "exist only on the server: they cannot be reached with the keyboard and a "
                           + "screen reader has nothing to announce. Use a client-side map with area "
                           + "elements, each with its own alt text.", image.Line);
        }
    }
}

public sealed class NestedScriptRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-BUG-0030";
    public override string Name => "A script element should not contain another one";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var script in Document(context).Named("script"))
        {
            if (script.Parent is not { Name: "script" })
                continue;

            context.Report("The parser closes a script at the first </script> it reads, whatever it is "
                           + "nested in, so the outer script ends here and the rest of its code is "
                           + "rendered as text on the page. Split the string that contains the closing "
                           + "tag, or write the script from a file.", script.Line);
        }
    }
}

public sealed class RemoteScriptWithoutIntegrityRule : MarkupRuleBase
{
    public override string Key => "QG-HTML-SEC-0010";
    public override string Name => "A remote script should be checked against a hash";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            var source = element.Name switch
            {
                "script" => element.Attribute("src"),
                "link" when (element.Attribute("rel") ?? string.Empty)
                    .Contains("stylesheet", StringComparison.OrdinalIgnoreCase) => element.Attribute("href"),
                _ => null
            };
            if (string.IsNullOrWhiteSpace(source) || IsDynamic(source))
                continue;
            if (!source.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                && !source.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                && !source.StartsWith("//", StringComparison.Ordinal))
                continue; // a file served from this site is already under your control
            if (element.Has("integrity"))
                continue;

            context.Report("This file comes from another host and nothing checks what arrives. Whoever "
                           + "controls that host — or anyone who takes it over — runs code inside your "
                           + "page, with your cookies and your origin. Add an integrity hash and "
                           + "crossorigin, or serve the file yourself.", element.Line);
        }
    }
}

/// <summary>Whether an element carries something a screen reader can announce.</summary>
internal static class MarkupText
{
    private static readonly string[] Naming = ["aria-label", "aria-labelledby", "title"];

    public static bool HasAccessibleContent(HtmlElement element)
    {
        if (Naming.Any(element.Has))
            return true;
        if (element.Text.Trim().Length > 0)
            return true;

        foreach (var child in element.Descendants())
        {
            if (child.Text.Trim().Length > 0)
                return true;
            if (Naming.Any(child.Has))
                return true;
            if (child.Name == "img" && (child.Attribute("alt") ?? string.Empty).Trim().Length > 0)
                return true;
            // a component or a template writes its text at run time
            if (child.Name.Contains('-') || child.Name is "slot" or "template")
                return true;
        }

        return element.Attributes.Keys.Any(k => k.StartsWith('{') || k.StartsWith(':')
                                                || k.StartsWith("v-") || k.StartsWith('['));
    }
}
