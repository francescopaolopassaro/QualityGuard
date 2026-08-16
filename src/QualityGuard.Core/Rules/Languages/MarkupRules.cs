using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class MarkupRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new HtmlJavascriptUrlRule(),
        new HtmlIframeSandboxRule(),
        new HtmlCleartextSourceRule(),
        new HtmlMissingMetaCharsetRule(),
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

/// <summary>
/// A URL that runs code instead of naming a destination. Read from the element tree rather than
/// from the lines: the text "javascript:" appears in scripts, in comments and in the placeholder
/// javascript:void(0), none of which executes anything, and reporting those buries the one case
/// that does — an attribute whose value is code.
/// </summary>
public sealed class HtmlJavascriptUrlRule : MarkupRuleBase
{
    private static readonly string[] UrlAttributes =
        ["href", "src", "action", "formaction", "data", "cite", "poster", "background"];

    public override string Key => "QG-HTML-SEC-0002";
    public override string Name => "A URL should not carry code";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Document(context).Descendants())
        {
            foreach (var attribute in UrlAttributes)
            {
                var value = element.Attribute(attribute)?.TrimStart();
                if (value == null || !value.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase))
                    continue;

                var code = value["javascript:".Length..].Trim().TrimEnd(';');
                // the two placeholders that do nothing: they are a style choice, not an injection point
                if (code.Length == 0 || code.Replace(" ", string.Empty)
                        .StartsWith("void(", StringComparison.OrdinalIgnoreCase))
                    continue;

                context.Report($"The {attribute} of this <{element.Name}> runs code instead of pointing "
                               + "somewhere. Whatever the page later writes into that URL becomes script "
                               + "with the privileges of the page, and no content security policy can "
                               + "tell it apart from the code you wrote. Bind a listener from a script "
                               + "file and let the attribute name a destination.", element.Line);
            }
        }
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
