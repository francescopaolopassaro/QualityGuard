using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Defects that live in the descriptors a Java project carries: the build file, the Spring context, the
/// persistence settings. They are read from the document, and each one is tied to the file that gives
/// its elements meaning — a 'scope' element outside a dependency is somebody else's vocabulary.
/// </summary>
public static class XmlDescriptorRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PrologNotFirstRuleXml(),
        new LegacyPomPropertyRuleXml(),
        new SystemScopedDependencyRuleXml(),
        new SingleConnectionFactoryRuleXml(),
        new MessageListenerContainerRuleXml(),
        new SchemaUpdateRuleXml()
    ];
}

public abstract class XmlDescriptorRuleBase : RuleBase
{
    public override string[] Languages => ["xml"];
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    /// <summary>Every element of the document, with the text it holds.</summary>
    protected static IEnumerable<HtmlElement> Elements(IRuleContext context)
        => HtmlDocument.Parse(context.File.Content).Descendants();

    /// <summary>Whether the document is a build file: the elements below only mean something there.</summary>
    protected static bool IsBuildFile(IRuleContext context)
        => context.File.FileName.Equals("pom.xml", StringComparison.OrdinalIgnoreCase);

    protected static bool DeclaresBean(HtmlElement element, string type)
        => element.Name.Equals("bean", StringComparison.OrdinalIgnoreCase)
           && element.Attribute("class") is { } declared
           && declared.EndsWith(type, StringComparison.Ordinal);
}

/// <summary>
/// The declaration has to be the first thing in the file. A comment or a blank line in front of it
/// makes the parser refuse the document, and the failure lands on whoever reads the file, not here.
/// </summary>
public sealed class PrologNotFirstRuleXml : XmlDescriptorRuleBase
{
    public override string Key => "QG-XML-BUG-0001";
    public override Severity Severity => Severity.Critical;
    public override string Name => "The XML declaration should open the file";

    public override void Execute(IRuleContext context)
    {
        var content = context.File.Content;
        var prolog = content.IndexOf("<?xml", StringComparison.Ordinal);
        if (prolog <= 0)
            return; // absent is allowed; first is what this rule is about

        var before = content[..prolog];
        if (before.All(char.IsWhiteSpace) && !before.Contains('﻿'))
            return;

        var line = before.Count(c => c == '\n') + 1;
        context.Report("The XML declaration is not the first thing in this file, so a parser stops at "
                       + "the first character instead of reading the document. Move the declaration to "
                       + "the top, above any comment.", line);
    }
}

/// <summary>
/// The old property prefix has been replaced for years. It still resolves in some builds and silently
/// produces an empty value in others, which reaches artifacts named after nothing.
/// </summary>
public sealed class LegacyPomPropertyRuleXml : XmlDescriptorRuleBase
{
    public override string Key => "QG-XML-SML-0010";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";
    public override string Name => "A build property should use the current prefix";

    public override void Execute(IRuleContext context)
    {
        if (!IsBuildFile(context))
            return;

        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (!lines[i].Contains("${pom.", StringComparison.Ordinal))
                continue;

            context.Report("'${pom.*}' was replaced by '${project.*}' and resolves to nothing in a "
                           + "current build, which produces artifacts named after an empty value. Use "
                           + "the 'project' prefix.", i + 1);
        }
    }
}

/// <summary>
/// A dependency taken from a path on the build machine is not in any repository: the build works here
/// and nowhere else, and the artifact it produces cannot be rebuilt.
/// </summary>
public sealed class SystemScopedDependencyRuleXml : XmlDescriptorRuleBase
{
    public override string Key => "QG-XML-BUG-0002";
    public override Severity Severity => Severity.Critical;
    public override string Name => "A dependency should not be taken from a local path";

    public override void Execute(IRuleContext context)
    {
        if (!IsBuildFile(context))
            return;

        foreach (var element in Elements(context))
        {
            if (!element.Name.Equals("scope", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!element.Text.Trim().Equals("system", StringComparison.OrdinalIgnoreCase))
                continue;

            context.Report("This dependency is read from a path on the machine that runs the build, so "
                           + "it is not in any repository and the build cannot be reproduced anywhere "
                           + "else. Publish the artifact to a repository and depend on it by "
                           + "coordinates.", element.Line);
        }
    }
}

/// <summary>
/// The factory keeps one connection open and hands it to everyone. When the broker drops it, nothing
/// asks for a new one and every consumer stays silent until the application is restarted.
/// </summary>
public sealed class SingleConnectionFactoryRuleXml : XmlDescriptorRuleBase
{
    public override string Key => "QG-XML-BUG-0003";
    public override string Name => "A shared connection should reconnect when it drops";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Elements(context))
        {
            if (!DeclaresBean(element, "SingleConnectionFactory"))
                continue;
            if (element.Attributes.Keys.Any(k => k.Contains("reconnectOnException", StringComparison.Ordinal)))
                continue;
            if (element.Children.Any(c => c.Attribute("name") == "reconnectOnException"))
                continue;

            context.Report("This factory keeps a single connection and hands it to every consumer, and "
                           + "without 'reconnectOnException' nothing reopens it when the broker drops "
                           + "it: the application stops receiving messages until it is restarted. Set "
                           + "the property to true.", element.Line);
        }
    }
}

/// <summary>
/// While the container is stopping, a message taken from the broker is neither processed nor put back.
/// Acknowledging after the work is what keeps that message.
/// </summary>
public sealed class MessageListenerContainerRuleXml : XmlDescriptorRuleBase
{
    public override string Key => "QG-XML-BUG-0004";
    public override string Name => "A message container should not drop messages while restarting";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Elements(context))
        {
            if (!DeclaresBean(element, "DefaultMessageListenerContainer"))
                continue;

            var acknowledge = element.Children
                .FirstOrDefault(c => c.Attribute("name") == "sessionAcknowledgeMode"
                                     || c.Attribute("name") == "acknowledgeMode")
                ?.Attribute("value");
            var transacted = element.Children
                .FirstOrDefault(c => c.Attribute("name") == "sessionTransacted")
                ?.Attribute("value");
            if (transacted is "true"
                || acknowledge is not null && !acknowledge.Contains("AUTO", StringComparison.OrdinalIgnoreCase))
                continue;

            context.Report("This container acknowledges a message when it takes it, so a message picked "
                           + "up while the container is shutting down is neither processed nor returned "
                           + "to the broker. Set 'sessionTransacted' to true, or acknowledge only after "
                           + "the listener has done the work.", element.Line);
        }
    }
}

/// <summary>
/// Letting the mapping tool change the schema means the shape of the database follows whatever version
/// of the code started last — including a version that drops a column nobody meant to lose.
/// </summary>
public sealed class SchemaUpdateRuleXml : XmlDescriptorRuleBase
{
    private static readonly string[] Changing = ["update", "create", "create-drop"];

    public override string Key => "QG-XML-BUG-0005";
    public override Severity Severity => Severity.Critical;
    public override string Name => "The mapping tool should not change the database schema";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Elements(context))
        {
            var named = element.Attribute("name") ?? string.Empty;
            var isSetting = named.Contains("hbm2ddl.auto", StringComparison.OrdinalIgnoreCase)
                            || named.Contains("ddl-auto", StringComparison.OrdinalIgnoreCase);
            if (!isSetting)
                continue;

            var value = (element.Attribute("value") ?? element.Text).Trim();
            if (!Changing.Contains(value, StringComparer.OrdinalIgnoreCase))
                continue;

            context.Report($"'{value}' lets the mapping tool change the schema of the database when the "
                           + "application starts, so the shape of the data follows whichever version "
                           + "started last — and 'create' drops what was there. Use 'validate' and put "
                           + "the changes in a migration.", element.Line);
        }
    }
}
