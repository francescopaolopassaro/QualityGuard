using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Configuration files that decide what an application exposes before a single line of its code
/// runs: the manifest of a mobile package, the descriptor of a web application, the settings of a
/// hosted site. Nothing here is executed, nothing fails when it is wrong, and the file is usually
/// inherited from the project it was copied from.
/// </summary>
public static class XmlPlatformRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new AndroidDebuggableRule(),
        new AndroidClearTextTrafficRule(),
        new AndroidUnprotectedReceiverRule(),
        new AndroidBackupRule(),
        new AndroidProviderPermissionRule(),
        new AndroidUnexportedComponentRule(),
        new WebDescriptorFilterMappingRule(),
        new StrutsDuplicateFormRule(),
        new DefaultInterceptorLocationRule(),
        new MimeSniffingHeaderRule()
    ];
}

public abstract class XmlPlatformRule : RuleBase
{
    public override string[] Languages => ["xml"];
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static HtmlElement Document(IRuleContext context) => HtmlDocument.Parse(context.File.Content);

    protected static string FileName(IRuleContext context) => System.IO.Path.GetFileName(context.File.Path);

    protected static bool Is(IRuleContext context, string name)
        => FileName(context).Equals(name, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// An attribute by its local name. The manifest writes every one of these behind a namespace
    /// prefix, and the prefix is chosen by whoever wrote the file — matching the qualified name
    /// works on the examples and fails on the projects that spell it differently.
    /// </summary>
    protected static string? Attribute(HtmlElement element, string localName)
    {
        foreach (var (name, value) in element.Attributes)
        {
            var colon = name.IndexOf(':');
            var local = colon < 0 ? name : name[(colon + 1)..];
            if (local.Equals(localName, StringComparison.OrdinalIgnoreCase))
                return value;
        }
        return null;
    }

    protected static bool IsTrue(string? value)
        => value != null && value.Equals("true", StringComparison.OrdinalIgnoreCase);

    protected static bool IsFalse(string? value)
        => value != null && value.Equals("false", StringComparison.OrdinalIgnoreCase);

    /// <summary>The elements of the application section of a manifest, by tag name.</summary>
    protected static IEnumerable<HtmlElement> ApplicationComponents(IRuleContext context, params string[] tags)
        => Document(context).Descendants()
            .Where(e => e.Name.Equals("application", StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Children)
            .Where(c => tags.Length == 0
                        || tags.Any(t => c.Name.Equals(t, StringComparison.OrdinalIgnoreCase)));

    protected static IEnumerable<HtmlElement> Elements(IRuleContext context, string name)
        => Document(context).Descendants()
            .Where(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
}

/// <summary>A rule that reads a mobile application manifest and nothing else.</summary>
public abstract class AndroidManifestRule : XmlPlatformRule
{
    public override void Execute(IRuleContext context)
    {
        if (!Is(context, "AndroidManifest.xml"))
            return;
        Inspect(context);
    }

    protected abstract void Inspect(IRuleContext context);
}

public sealed class AndroidDebuggableRule : XmlPlatformRule
{
    public override string Key => "QG-XML-SEC-0009";
    public override string Name => "A shipped application should not enable its debugging features";
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (Is(context, "AndroidManifest.xml"))
        {
            foreach (var application in Elements(context, "application"))
            {
                if (IsTrue(Attribute(application, "debuggable")))
                    context.Report("The package is marked debuggable, so anyone with the device can "
                                   + "attach a debugger to it: they read its memory, step through its "
                                   + "logic and take out whatever it holds — keys and session tokens "
                                   + "included. Remove the attribute; the build tools set it for you "
                                   + "in a debug build.", application.Line);
            }
            return;
        }

        // the hosted-site equivalent: turning custom errors off publishes the stack trace, the query
        // and the physical path of whatever failed, to whoever caused the failure
        if (!FileName(context).Equals("web.config", StringComparison.OrdinalIgnoreCase))
            return;

        foreach (var errors in Elements(context, "customErrors"))
        {
            var mode = errors.Attribute("mode");
            if (mode != null && mode.Equals("off", StringComparison.OrdinalIgnoreCase))
                context.Report("With custom errors off, an unhandled exception returns its stack "
                               + "trace, the failing statement and the path of the file it came from "
                               + "to the browser that caused it. That is a map of the application, "
                               + "handed to whoever was probing it. Set mode to RemoteOnly or On.",
                    errors.Line);
        }
    }
}

public sealed class AndroidClearTextTrafficRule : AndroidManifestRule
{
    public override string Key => "QG-XML-SEC-0011";
    public override string Name => "An application should not allow traffic in clear text";
    public override Severity Severity => Severity.Critical;

    protected override void Inspect(IRuleContext context)
    {
        // only the explicit opt-in is reported. The attribute is also absent on every manifest that
        // targets a recent platform, where the default is already to refuse clear text, so reporting
        // its absence means reporting every manifest that exists
        foreach (var application in Elements(context, "application"))
        {
            if (!IsTrue(Attribute(application, "usesCleartextTraffic")))
                continue;

            context.Report("This allows the application to fall back to unencrypted HTTP, so anyone "
                           + "on the same network — a shared access point, a mobile operator, a "
                           + "captive portal — reads and rewrites what it exchanges. Remove the "
                           + "attribute and declare the few hosts that still need it in the network "
                           + "security configuration.", application.Line);
        }
    }
}

public sealed class AndroidUnprotectedReceiverRule : AndroidManifestRule
{
    public override string Key => "QG-XML-SEC-0010";
    public override string Name => "A broadcast receiver should require a permission";
    public override Severity Severity => Severity.Critical;

    protected override void Inspect(IRuleContext context)
    {
        foreach (var receiver in ApplicationComponents(context, "receiver"))
        {
            if (Attribute(receiver, "permission") != null)
                continue;
            var exported = Attribute(receiver, "exported");
            if (IsFalse(exported))
                continue;
            // a receiver is reachable from other applications when it says so, and also when it
            // declares an intent filter, which is what makes it reachable in the first place
            if (!IsTrue(exported) && !receiver.Children.Any(c =>
                    c.Name.Equals("intent-filter", StringComparison.OrdinalIgnoreCase)))
                continue;

            context.Report("Any application on the device can send this receiver a broadcast, so the "
                           + "data it acts on comes from somewhere the code does not control and the "
                           + "action it performs can be triggered at will. Require a permission, or "
                           + "mark the receiver as not exported if it is only for internal use.",
                receiver.Line);
        }
    }
}

public sealed class AndroidBackupRule : AndroidManifestRule
{
    public override string Key => "QG-XML-SEC-0015";
    public override string Name => "Application backup should be disabled or restricted";
    public override Severity Severity => Severity.Major;

    protected override void Inspect(IRuleContext context)
    {
        foreach (var application in Elements(context, "application"))
        {
            if (IsFalse(Attribute(application, "allowBackup")))
                continue;
            // an agent or a declared backup content set means somebody chose what leaves the device;
            // the finding is about the default, which copies everything the application stores
            if (Attribute(application, "backupAgent") != null)
                continue;
            var content = Attribute(application, "fullBackupContent");
            if (content != null && (content.StartsWith('@') || content.StartsWith('$')))
                continue;

            context.Report("Everything the application stores is copied out of the device by the "
                           + "platform's backup, including the files it keeps private — tokens, "
                           + "cached personal data, a local database. The copy then lives wherever "
                           + "the backup goes. Disable the backup, or declare which files it may "
                           + "take.", application.Line);
        }
    }
}

public sealed class AndroidProviderPermissionRule : AndroidManifestRule
{
    public override string Key => "QG-XML-SEC-0017";
    public override string Name => "A content provider should separate its read and write permissions";

    protected override void Inspect(IRuleContext context)
    {
        foreach (var provider in ApplicationComponents(context, "provider"))
        {
            var single = Attribute(provider, "permission");
            var read = Attribute(provider, "readPermission");
            var write = Attribute(provider, "writePermission");

            var shared = (single != null && read == null && write == null)
                         || (single != null && write == null && single == read)
                         || (single != null && read == null && single == write)
                         || (read != null && read == write);
            if (!shared)
                continue;

            context.Report("Reading and writing this provider are behind the same permission, so "
                           + "every application granted the right to read the data is also granted "
                           + "the right to change it. The two are almost never wanted together — one "
                           + "is sharing, the other is trust. Declare readPermission and "
                           + "writePermission separately.", provider.Line);
        }
    }
}

public sealed class AndroidUnexportedComponentRule : AndroidManifestRule
{
    public override string Key => "QG-XML-SEC-0018";
    public override string Name => "A component with an intent filter should say whether it is exported";
    public override Severity Severity => Severity.Major;

    protected override void Inspect(IRuleContext context)
    {
        foreach (var component in ApplicationComponents(context, "activity", "activity-alias", "provider",
                     "receiver", "service"))
        {
            if (Attribute(component, "exported") != null)
                continue;
            if (!component.Children.Any(c => c.Name.Equals("intent-filter", StringComparison.OrdinalIgnoreCase)))
                continue;

            context.Report($"This {component.Name} declares an intent filter but does not say whether "
                           + "it is exported, and the default depends on the platform version the "
                           + "package is installed on: on older ones it becomes reachable from every "
                           + "other application on the device. Say it explicitly, either way.",
                component.Line);
        }
    }
}

public sealed class WebDescriptorFilterMappingRule : XmlPlatformRule
{
    public override string Key => "QG-XML-SEC-0007";
    public override string Name => "A declared filter should have a mapping";
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!Is(context, "web.xml"))
            return;

        var mapped = Elements(context, "filter-mapping")
            .SelectMany(m => m.Children)
            .Where(c => c.Name.Equals("filter-name", StringComparison.OrdinalIgnoreCase))
            .Select(c => c.Text.Trim())
            .ToHashSet(StringComparer.Ordinal);

        foreach (var filter in Elements(context, "filter"))
        {
            foreach (var name in filter.Children
                         .Where(c => c.Name.Equals("filter-name", StringComparison.OrdinalIgnoreCase)))
            {
                var declared = name.Text.Trim();
                if (declared.Length == 0 || mapped.Contains(declared))
                    continue;

                context.Report($"'{declared}' is declared but never mapped to a path, so it runs on "
                               + "no request at all. When the filter is the one that authenticates, "
                               + "or escapes, or checks a token, the protection it was written for is "
                               + "simply absent — and nothing anywhere reports its absence. Add a "
                               + "filter-mapping for it, or remove the declaration.", name.Line);
            }
        }
    }
}

public sealed class StrutsDuplicateFormRule : XmlPlatformRule
{
    public override string Key => "QG-XML-SEC-0008";
    public override string Name => "Two validation forms should not share a name";
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        foreach (var formset in Elements(context, "formset"))
        {
            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var form in formset.Children
                         .Where(c => c.Name.Equals("form", StringComparison.OrdinalIgnoreCase)))
            {
                var name = form.Attribute("name");
                if (name == null)
                    continue;
                if (seen.TryGetValue(name, out var first))
                {
                    context.Report($"A form called '{name}' is already declared on line {first}. Only "
                                   + "one of the two is used and the other is ignored without a "
                                   + "word, so the validation somebody wrote here may never run. "
                                   + "Rename it, or merge the two declarations.", form.Line);
                    continue;
                }
                seen[name] = form.Line;
            }
        }
    }
}

public sealed class DefaultInterceptorLocationRule : XmlPlatformRule
{
    public override string Key => "QG-XML-SEC-0005";
    public override string Name => "A default interceptor should be declared where it applies";
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        // in the standard descriptor the declaration is correct; anywhere else it silently applies to
        // nothing, which is the whole point of the rule
        if (Is(context, "ejb-jar.xml"))
            return;

        foreach (var binding in Elements(context, "interceptor-binding"))
        {
            var appliesToEverything = binding.Children.Any(c =>
                c.Name.Equals("ejb-name", StringComparison.OrdinalIgnoreCase) && c.Text.Trim() == "*");
            if (!appliesToEverything)
                continue;

            foreach (var interceptor in binding.Children
                         .Where(c => c.Name.Equals("interceptor-class", StringComparison.OrdinalIgnoreCase)))
            {
                context.Report("A default interceptor — one bound to every component — is only "
                               + "applied when it is declared in the standard descriptor. Declared "
                               + "here it is read, accepted and never invoked, so whatever it does "
                               + "for every call, including the checks, does not happen. Move it to "
                               + "ejb-jar.xml.", interceptor.Line);
            }
        }
    }
}

public sealed class MimeSniffingHeaderRule : XmlPlatformRule
{
    public override string Key => "QG-XML-SEC-0014";
    public override string Name => "A site should tell browsers not to guess content types";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!FileName(context).Equals("web.config", StringComparison.OrdinalIgnoreCase))
            return;

        // the rule is about a site that configures its response headers and forgets this one; a file
        // that sets no headers at all is not making that mistake, it is doing it somewhere else
        var headers = Elements(context, "customHeaders").ToList();
        if (headers.Count == 0)
            return;

        var declared = headers.SelectMany(h => h.Children)
            .Any(add => add.Name.Equals("add", StringComparison.OrdinalIgnoreCase)
                        && string.Equals(add.Attribute("name"), "X-Content-Type-Options",
                            StringComparison.OrdinalIgnoreCase)
                        && string.Equals(add.Attribute("value"), "nosniff",
                            StringComparison.OrdinalIgnoreCase));
        if (declared)
            return;

        context.Report("The response headers are configured here but nothing tells the browser to "
                       + "trust the declared content type. Without it a browser may decide for "
                       + "itself what a file is, and a document a user uploaded can end up executed "
                       + "as script in the site's own origin. Add X-Content-Type-Options: nosniff.",
            headers[0].Line);
    }
}
