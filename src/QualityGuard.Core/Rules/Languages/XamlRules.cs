using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Desktop markup — WPF, WinUI and Avalonia all describe a window the same way, and all three bind it
/// to a class written next to it. What breaks here breaks at run time and only on the screen that
/// uses it: a name that resolves to the wrong control, a handler the designer wrote and nobody
/// implemented, a resource key that exists in no dictionary. The compiler has nothing to say about
/// any of them.
/// </summary>
public static class XamlRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new XamlDuplicateNameRule(),
        new XamlUndefinedStaticResourceRule(),
        new XamlMissingEventHandlerRule(),
        new XamlBindingWithoutPathRule(),
        new XamlHardcodedConnectionRule()
    ];
}

public abstract class XamlRuleBase : RuleBase
{
    public override string[] Languages => ["xaml"];
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static IEnumerable<HtmlElement> Elements(IRuleContext context)
        => HtmlDocument.Parse(context.File.Content).Descendants();

    /// <summary>The value of an attribute whatever namespace prefix it was written with.</summary>
    protected static string? Attribute(HtmlElement element, string name)
    {
        foreach (var (key, value) in element.Attributes)
        {
            var local = key.Contains(':') ? key[(key.IndexOf(':') + 1)..] : key;
            if (string.Equals(local, name, StringComparison.OrdinalIgnoreCase))
                return value;
        }
        return null;
    }

    /// <summary>Whether the value is a markup extension of the given kind, as in '{StaticResource x}'.</summary>
    protected static string? Extension(string value, string kind)
    {
        var trimmed = value.Trim();
        if (!trimmed.StartsWith('{') || !trimmed.EndsWith('}'))
            return null;
        var body = trimmed[1..^1].Trim();
        if (!body.StartsWith(kind, StringComparison.OrdinalIgnoreCase))
            return null;
        return body[kind.Length..].Trim();
    }
}

public sealed class XamlDuplicateNameRule : XamlRuleBase
{
    public override string Key => "QG-XAML-BUG-0001";
    public override string Name => "A name should identify one element";

    public override void Execute(IRuleContext context)
    {
        var seen = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var element in Elements(context))
        {
            var name = Attribute(element, "Name");
            if (string.IsNullOrWhiteSpace(name))
                continue;
            if (seen.TryGetValue(name, out var first))
            {
                context.Report($"'{name}' already names the element on line {first}. The generated "
                               + "field can only point at one of them, so the code-behind reaches a "
                               + "control the markup does not show it reaching.", element.Line);
                continue;
            }
            seen[name] = element.Line;
        }
    }
}

public sealed class XamlUndefinedStaticResourceRule : XamlRuleBase
{
    public override string Key => "QG-XAML-BUG-0002";
    public override string Name => "A static resource should be defined before it is used";

    public override void Execute(IRuleContext context)
    {
        var defined = new HashSet<string>(StringComparer.Ordinal);
        var used = new List<(string Key, int Line)>();

        foreach (var element in Elements(context))
        {
            if (Attribute(element, "Key") is { Length: > 0 } key)
                defined.Add(key);
            foreach (var (_, value) in element.Attributes)
            {
                if (Extension(value, "StaticResource") is { Length: > 0 } resource)
                    used.Add((resource.Split(',')[0].Trim(), element.Line));
            }
        }

        // A dictionary merged from another file defines keys this one cannot see, and a theme brings
        // in hundreds. The rule speaks only where the file declares resources of its own, which is
        // where a missing key is a typo rather than a reference to somewhere else.
        if (defined.Count == 0)
            return;

        foreach (var (key, line) in used)
        {
            if (defined.Contains(key) || key.Length == 0 || key.Contains('.'))
                continue;

            context.Report($"'{key}' is used as a static resource and this file defines resources but "
                           + "not that one. A key that resolves nowhere throws when the element is "
                           + "created, so the screen fails to open rather than looking wrong.", line);
        }
    }
}

public sealed class XamlMissingEventHandlerRule : XamlRuleBase
{
    /// <summary>Attributes that name a method in the class behind the markup.</summary>
    private static readonly string[] EventAttributes =
    [
        "Click", "Checked", "Unchecked", "SelectionChanged", "TextChanged", "Loaded", "Unloaded",
        "MouseDown", "MouseUp", "MouseEnter", "MouseLeave", "KeyDown", "KeyUp", "GotFocus",
        "LostFocus", "Closing", "Closed", "Tapped", "DoubleTapped", "PointerPressed", "Initialized"
    ];

    public override string Key => "QG-XAML-BUG-0003";
    public override string Name => "An event named in the markup needs a handler in the class behind it";

    public override void Execute(IRuleContext context)
    {
        // The handler lives in the code-behind, which the project index has read as C#. Without that
        // index there is nothing to compare against, and a rule that guesses here would report every
        // handler in the file.
        if (!context.Project.SawCode)
            return;

        foreach (var element in Elements(context))
        {
            foreach (var (attribute, value) in element.Attributes)
            {
                var name = attribute.Contains(':') ? attribute[(attribute.IndexOf(':') + 1)..] : attribute;
                if (!EventAttributes.Contains(name, StringComparer.OrdinalIgnoreCase))
                    continue;
                var handler = value.Trim();
                if (handler.Length == 0 || handler.StartsWith('{'))
                    continue; // a binding or a command, resolved at run time rather than by name
                if (context.Project.IsDeclared(handler))
                    continue;

                context.Report($"'{handler}' is named as the handler for {name} and no method with "
                               + "that name exists in the scanned code. The screen throws while it is "
                               + "being built, which reads as a layout problem and is not one.",
                    element.Line);
            }
        }
    }
}

public sealed class XamlBindingWithoutPathRule : XamlRuleBase
{
    public override string Key => "QG-XAML-SML-0002";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string Name => "A two-way binding should say which property it writes to";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Elements(context))
        {
            foreach (var (attribute, value) in element.Attributes)
            {
                var binding = Extension(value, "Binding");
                if (binding == null || !binding.Contains("TwoWay", StringComparison.OrdinalIgnoreCase))
                    continue;
                var body = binding.Replace(" ", string.Empty, StringComparison.Ordinal);
                if (body.Contains("Path=", StringComparison.OrdinalIgnoreCase)
                    || !body.StartsWith("Mode=", StringComparison.OrdinalIgnoreCase))
                    continue;

                context.Report($"The two-way binding on '{attribute}' has no path, so it writes back "
                               + "to the bound object itself rather than to one of its properties. "
                               + "Name the property the value belongs to.", element.Line);
            }
        }
    }
}

public sealed class XamlHardcodedConnectionRule : XamlRuleBase
{
    public override string Key => "QG-XAML-SEC-0003";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";
    public override string Name => "Markup should not carry a credential";

    public override void Execute(IRuleContext context)
    {
        foreach (var element in Elements(context))
        {
            foreach (var (attribute, value) in element.Attributes)
            {
                var lowered = value.ToLowerInvariant();
                if (!lowered.Contains("password=") && !lowered.Contains("pwd=")
                    && !lowered.Contains("accountkey=") && !lowered.Contains("apikey="))
                    continue;
                if (value.Contains('{'))
                    continue; // a binding: the value comes from somewhere else at run time

                context.Report($"'{attribute}' carries a credential written into the markup, which "
                               + "ships inside the application and is readable by anyone who has a "
                               + "copy of it. Read it from configuration the deployment supplies.",
                    element.Line);
            }
        }
    }
}
