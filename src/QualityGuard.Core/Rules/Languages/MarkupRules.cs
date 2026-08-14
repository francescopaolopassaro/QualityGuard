using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class MarkupRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new HtmlInlineEventHandlerRule(),
        new HtmlJavascriptUrlRule(),
        new HtmlIframeSandboxRule(),
        new HtmlBlankTargetNoopenerRule(),
        new HtmlCleartextSourceRule(),
        new HtmlMissingMetaCharsetRule(),
        new HtmlImgMissingAltRule(),
        new XmlExternalEntityRule(),
        new XmlExternalDtdRule(),
        new XmlMissingEncodingRule(),
        new XmlEntityExpansionRule()
    ];
}

internal static class MarkupHelper
{
    public static bool HasInlineEventHandler(string line)
    {
        for (var i = 0; i < line.Length - 2; i++)
        {
            if (char.ToLowerInvariant(line[i]) != 'o' || char.ToLowerInvariant(line[i + 1]) != 'n')
                continue;
            var j = i + 2;
            if (!char.IsLetter(line[j]))
                continue;
            while (j < line.Length && (char.IsLetterOrDigit(line[j]) || line[j] == '_'))
                j++;
            while (j < line.Length && line[j] == ' ')
                j++;
            if (j < line.Length && line[j] == '=')
                return true;
        }
        return false;
    }
}

public sealed class HtmlInlineEventHandlerRule : PatternRuleBase
{
    public override string Key => "QG-HTML-SEC-0001";
    public override string Name => "Avoid inline event handlers";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Attach event listeners from script instead of inline on* attributes.";
    public override string[] Languages => ["html"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
            if (MarkupHelper.HasInlineEventHandler(lines[i]))
                context.Report("Inline event handlers are a vector for XSS; use addEventListener.", i + 1);
    }
}

public sealed class HtmlJavascriptUrlRule : PatternRuleBase
{
    public override string Key => "QG-HTML-SEC-0002";
    public override string Name => "Avoid javascript: URLs";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Replace javascript: URLs with real navigation or event listeners.";
    public override string[] Languages => ["html"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
            if (RuleMatchers.LineContains(lines[i], "javascript:"))
                context.Report("javascript: URLs are a vector for XSS.", i + 1);
    }
}

public sealed class HtmlIframeSandboxRule : PatternRuleBase
{
    public override string Key => "QG-HTML-SEC-0003";
    public override string Name => "Iframe without sandbox";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Add a sandbox attribute (with allow-same-origin only when needed) to the iframe.";
    public override string[] Languages => ["html"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasSandbox = lines.Any(l => RuleMatchers.LineContains(l, "sandbox"));
        if (hasSandbox)
            return;
        for (var i = 0; i < lines.Length; i++)
            if (RuleMatchers.LineContains(lines[i], "<iframe"))
                context.Report("The iframe has no sandbox attribute.", i + 1);
    }
}

public sealed class HtmlBlankTargetNoopenerRule : PatternRuleBase
{
    public override string Key => "QG-HTML-SEC-0004";
    public override string Name => "target=_blank without rel=noopener";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Add rel=\"noopener noreferrer\" to links opening in a new tab.";
    public override string[] Languages => ["html"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasNoopener = lines.Any(l => RuleMatchers.LineContains(l, "noopener"));
        if (hasNoopener)
            return;
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "target") && RuleMatchers.LineContains(line, "_blank"))
                context.Report("Add rel=\"noopener\" when opening links in a new tab.", i + 1);
        }
    }
}

public sealed class HtmlCleartextSourceRule : PatternRuleBase
{
    public override string Key => "QG-HTML-SEC-0005";
    public override string Name => "Resource loaded over cleartext HTTP";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Load scripts and links over HTTPS.";
    public override string[] Languages => ["html"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "http://")
                && (RuleMatchers.LineContains(line, "src") || RuleMatchers.LineContains(line, "href")))
                context.Report("Load resources over HTTPS instead of cleartext HTTP.", i + 1);
        }
    }
}

public sealed class HtmlMissingMetaCharsetRule : PatternRuleBase
{
    public override string Key => "QG-HTML-SML-0001";
    public override string Name => "Declare the document character encoding";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Add a <meta charset=\"utf-8\"> element within the document head.";
    public override string[] Languages => ["html"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasCharset = lines.Any(l => RuleMatchers.LineContains(l, "<meta charset"));
        if (!hasCharset)
            context.Report("Declare the document character encoding with <meta charset>.", 1);
    }
}

public sealed class HtmlImgMissingAltRule : PatternRuleBase
{
    public override string Key => "QG-HTML-CNV-0001";
    public override string Name => "Image without alt text";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Provide an alt attribute describing the image content.";
    public override string[] Languages => ["html"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "<img") && !RuleMatchers.LineContains(line, "alt"))
                context.Report("Add an alt attribute to the image.", i + 1);
        }
    }
}

public sealed class XmlExternalEntityRule : PatternRuleBase
{
    public override string Key => "QG-XML-SEC-0001";
    public override string Name => "External entity declarations";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Disable external entity resolution or reject DOCTYPE declarations.";
    public override string[] Languages => ["xml"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!RuleMatchers.LineContains(line, "SYSTEM"))
                continue;
            if (RuleMatchers.LineContains(line, "<!DOCTYPE") || RuleMatchers.LineContains(line, "<!ENTITY"))
                context.Report("External entities can be exploited for XXE; disable them.", i + 1);
        }
    }
}

public sealed class XmlExternalDtdRule : PatternRuleBase
{
    public override string Key => "QG-XML-SEC-0002";
    public override string Name => "External DTD loaded over HTTP";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Avoid loading external DTDs; embed a local schema.";
    public override string[] Languages => ["xml"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "SYSTEM") && RuleMatchers.LineContains(line, "http"))
                context.Report("Do not load external DTDs over the network.", i + 1);
        }
    }
}

public sealed class XmlMissingEncodingRule : PatternRuleBase
{
    public override string Key => "QG-XML-SML-0001";
    public override string Name => "XML declaration without encoding";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Declare encoding=\"utf-8\" in the XML declaration.";
    public override string[] Languages => ["xml"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasEncoding = lines.Any(l => RuleMatchers.LineContains(l, "<?xml") && RuleMatchers.LineContains(l, "encoding"));
        if (!hasEncoding)
            context.Report("Declare the encoding in the XML declaration.", 1);
    }
}

public sealed class XmlEntityExpansionRule : PatternRuleBase
{
    public override string Key => "QG-XML-SEC-0003";
    public override string Name => "Excessive entity declarations";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not allow nested entity expansion that can exhaust memory (billion laughs).";
    public override string[] Languages => ["xml"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var count = lines.Count(l => RuleMatchers.LineContains(l, "<!ENTITY"));
        if (count >= 3)
            context.Report("Excessive entity declarations may allow entity expansion attacks.", 1);
    }
}
