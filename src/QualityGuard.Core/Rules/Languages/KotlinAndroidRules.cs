using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Mobile platform APIs whose default is the permissive one: a broadcast anyone can read, a receiver
/// anyone can trigger, a web view allowed to reach the file system, a key that unlocks without the
/// user being there. The calls read as ordinary setup code, which is why the missing argument is
/// never noticed — nothing fails, and the application works exactly as intended.
/// </summary>
public static class KotlinAndroidRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new KotlinBroadcastWithoutPermissionRule(),
        new KotlinReceiverWithoutPermissionRule(),
        new KotlinKeyWithoutUserAuthenticationRule(),
        new KotlinBiometricWithoutCryptoRule(),
        new KotlinDatabaseKeyInSourceRule(),
        new KotlinWebViewLocalFileRule(),
        new KotlinReusedInitializationVectorRule(),
        new KotlinDependencyVerificationRule(),
        new KotlinReleaseObfuscationRule(),
        new KotlinJavascriptInterfaceRule(),
        new KotlinDebuggableReleaseRule()
    ];
}

public abstract class KotlinAndroidRule : RuleBase
{
    public override string[] Languages => ["kt"];
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>The simple name of a call, which is what these platform APIs are identified by.</summary>
    protected static string Called(SyntaxNode call) => SyntaxQuery.InvokedName(call);

    protected static string CalledDotted(SyntaxNode call)
    {
        var dotted = SyntaxQuery.InvokedDottedName(call);
        return dotted.Length > 0 ? dotted : Called(call);
    }

    protected static IReadOnlyList<SyntaxNode> Args(SyntaxNode call) => SyntaxQuery.Arguments(call);

    protected static SyntaxNode? Arg(SyntaxNode call, int index)
    {
        var arguments = Args(call);
        return index < arguments.Count ? arguments[index] : null;
    }

    protected static bool IsNull(SyntaxNode? node) => node is { Kind: NodeKind.NullLiteral };

    protected static bool IsTrue(SyntaxNode? node)
        => node != null && node.Kind == NodeKind.BooleanLiteral
                        && node.Text.Equals("true", StringComparison.Ordinal);

    protected static bool IsFalse(SyntaxNode? node)
        => node != null && node.Kind == NodeKind.BooleanLiteral
                        && node.Text.Equals("false", StringComparison.Ordinal);

    /// <summary>
    /// The calls of a fluent chain, from the outermost inwards. A builder is written as one
    /// expression, and what a rule has to know — whether the chain ever asked for a guard — is only
    /// visible by walking it.
    /// </summary>
    protected static IEnumerable<SyntaxNode> Chain(SyntaxNode call)
    {
        var node = call;
        while (node != null)
        {
            if (node.Kind == NodeKind.Invocation)
                yield return node;
            var head = node.ChildAt(0);
            node = head?.Kind switch
            {
                NodeKind.Invocation => head,
                NodeKind.MemberSelect => head.ChildAt(0),
                _ => null
            };
        }
    }

    protected static bool IsGradleScript(IRuleContext context)
        => System.IO.Path.GetFileName(context.File.Path)
            .EndsWith(".gradle.kts", StringComparison.OrdinalIgnoreCase);

    /// <summary>The block a configuration call opens, as in <c>buildTypes { ... }</c>.</summary>
    protected static SyntaxNode? Section(SyntaxNode scope, string name)
    {
        foreach (var call in scope.OfKind(NodeKind.Invocation))
        {
            if (!Called(call).Equals(name, StringComparison.Ordinal))
                continue;
            var body = call.FirstChild(NodeKind.ArgumentList)?.FirstChild(NodeKind.Lambda);
            if (body != null)
                return body;
        }
        return null;
    }

    /// <summary>An assignment to a named property inside a configuration block.</summary>
    protected static SyntaxNode? Setting(SyntaxNode scope, string name)
        => scope.OfKind(NodeKind.Assignment)
            .FirstOrDefault(a => a.ChildAt(0) is { Kind: NodeKind.Identifier } target
                                 && target.Text.Equals(name, StringComparison.Ordinal));
}

public sealed class KotlinBroadcastWithoutPermissionRule : KotlinAndroidRule
{
    /// <summary>
    /// A sticky broadcast stays available to whoever asks for it afterwards, and the platform gives
    /// no way to attach a permission to it. The API is deprecated for exactly this reason.
    /// </summary>
    private static readonly string[] StickyBroadcasts =
    [
        "sendStickyBroadcast", "sendStickyBroadcastAsUser", "sendStickyOrderedBroadcast",
        "sendStickyOrderedBroadcastAsUser"
    ];

    public override string Key => "QG-KT-SEC-0041";
    public override string Name => "A broadcast should name the permission its receivers need";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = Called(call);
            if (StickyBroadcasts.Contains(name, StringComparer.Ordinal))
            {
                Report(context, call.Range.StartLine, sticky: true);
                continue;
            }

            // the permission is the argument next to the intent, and passing null there is the same
            // as not passing it at all — which is the shape this appears in most of the time
            var unprotected = name switch
            {
                "sendBroadcast" or "sendBroadcastAsUser" => Args(call).Count < 2 || IsNull(Arg(call, 1)),
                "sendOrderedBroadcast" => Args(call).Count >= 2 && IsNull(Arg(call, 1)),
                "sendOrderedBroadcastAsUser" => Args(call).Count >= 3 && IsNull(Arg(call, 2)),
                _ => false
            };
            if (unprotected)
                Report(context, call.Range.StartLine, sticky: false);
        }
    }

    private static void Report(IRuleContext context, int line, bool sticky)
        => context.Report(sticky
                ? "A sticky broadcast is kept by the system and handed to whoever asks for it later, "
                  + "and no permission can be attached to it. Everything the intent carries is "
                  + "readable by every application on the device, for as long as it stays. Send an "
                  + "ordinary broadcast with a permission, and keep the data out of the intent."
                : "This broadcast names no permission, so every application on the device receives it "
                  + "and reads what the intent carries. It is also a way in: a receiver that answers "
                  + "it may act on the response. Pass the permission that receivers must hold, or "
                  + "send the intent to a specific component.", line);
}

public sealed class KotlinReceiverWithoutPermissionRule : KotlinAndroidRule
{
    public override string Key => "QG-KT-SEC-0042";
    public override string Name => "A registered receiver should require a permission";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Called(call).Equals("registerReceiver", StringComparison.Ordinal))
                continue;
            // the permission is the third argument of the long form; the short form has none
            if (Args(call).Count >= 4 && !IsNull(Arg(call, 2)))
                continue;

            context.Report("This receiver is registered without a permission, so any application on "
                           + "the device can send it the broadcast it listens for — with whatever "
                           + "data it likes, whenever it likes. The code that handles the intent "
                           + "then treats input from an unknown source as its own. Register it with "
                           + "the permission a sender must hold.", call.Range.StartLine);
        }
    }
}

public sealed class KotlinKeyWithoutUserAuthenticationRule : KotlinAndroidRule
{
    public override string Key => "QG-KT-SEC-0044";
    public override string Name => "A stored key should require the user to authenticate";
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Called(call).Equals("build", StringComparison.Ordinal))
                continue;

            var chain = Chain(call).ToList();
            var builder = chain.FirstOrDefault(c =>
                CalledDotted(c).EndsWith("KeyGenParameterSpec.Builder", StringComparison.Ordinal));
            if (builder == null)
                continue;

            var required = chain.Any(c =>
                Called(c).Equals("setUserAuthenticationRequired", StringComparison.Ordinal)
                && !IsFalse(Arg(c, 0)));
            if (required)
                continue;

            context.Report("This key is created without asking for the user to be authenticated, so "
                           + "it can be used by anything running on the device, including while the "
                           + "screen is locked. The hardware store then protects the key material "
                           + "but not the operation it performs. Require user authentication when "
                           + "the key protects something personal.", call.Range.StartLine);
        }
    }
}

public sealed class KotlinBiometricWithoutCryptoRule : KotlinAndroidRule
{
    public override string Key => "QG-KT-SEC-0045";
    public override string Name => "Biometric authentication should be bound to a key operation";
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Called(call).Equals("authenticate", StringComparison.Ordinal))
                continue;
            // "authenticate" is a name many things have, and without the receiver's type the only
            // honest filter is the receiver itself: the prompt is what this rule is about
            var receiver = SyntaxQuery.Receiver(call);
            if (receiver.IndexOf("prompt", StringComparison.OrdinalIgnoreCase) < 0
                && receiver.IndexOf("biometric", StringComparison.OrdinalIgnoreCase) < 0)
                continue;

            var arguments = Args(call);
            var unbound = arguments.Count < 2 || arguments.Any(IsNull);
            if (!unbound)
                continue;

            context.Report("The prompt is shown without a cryptographic object, so the result is a "
                           + "boolean the application decides to trust. Nothing the user's finger "
                           + "unlocks is actually needed afterwards, and an attacker who can change "
                           + "what runs on the device only has to make that boolean true. Pass the "
                           + "crypto object whose key the authentication is meant to unlock.",
                call.Range.StartLine);
        }
    }
}

public sealed class KotlinDatabaseKeyInSourceRule : KotlinAndroidRule
{
    private static readonly string[] DatabaseOpeners =
        ["openOrCreateDatabase", "openDatabase", "create", "changePassword", "encryptionKey"];

    public override string Key => "QG-KT-SEC-0046";
    public override string Name => "A database encryption key should not be written in the source";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = Called(call);
            if (!DatabaseOpeners.Contains(name, StringComparer.Ordinal))
                continue;

            // the key is the first argument where the call is about the key itself, and the second
            // where the call opens a database with it
            var key = name is "changePassword" or "encryptionKey" ? Arg(call, 0) : Arg(call, 1);
            if (key == null || !IsLiteralKey(key))
                continue;

            context.Report("The key that encrypts the local database is written here, so it ships "
                           + "inside the package: anyone who takes the application apart — a "
                           + "five-minute job with public tools — reads it and then reads every copy "
                           + "of that database, on every device. Derive the key from something the "
                           + "user supplies, or keep it in the platform's key store.",
                call.Range.StartLine);
        }
    }

    /// <summary>Whether the value is written out here rather than obtained at run time.</summary>
    private static bool IsLiteralKey(SyntaxNode value)
    {
        if (value.Kind == NodeKind.StringLiteral)
            return true;
        if (value.Kind != NodeKind.Invocation)
            return false;
        var built = Called(value);
        if (built is not ("byteArrayOf" or "charArrayOf"))
            return false;
        var items = Args(value);
        return items.Count > 0 && items.All(i => i.Kind is NodeKind.NumberLiteral or NodeKind.StringLiteral);
    }
}

public sealed class KotlinWebViewLocalFileRule : KotlinAndroidRule
{
    private static readonly string[] Setters =
    [
        "setAllowFileAccess", "setAllowFileAccessFromFileURLs", "setAllowContentAccess",
        "setAllowUniversalAccessFromFileURLs"
    ];

    private static readonly string[] Properties =
    [
        "allowFileAccess", "allowFileAccessFromFileURLs", "allowContentAccess",
        "allowUniversalAccessFromFileURLs"
    ];

    public override string Key => "QG-KT-SEC-0048";
    public override string Name => "A web view should not be allowed to reach local files";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (Setters.Contains(Called(call), StringComparer.Ordinal) && IsTrue(Arg(call, 0)))
                Report(context, call.Range.StartLine);
        }

        // the same settings are usually written as properties in Kotlin, and a rule that reads only
        // the setter form covers the way nobody writes it
        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            var target = assignment.ChildAt(0);
            if (target == null)
                continue;
            var name = target.Kind == NodeKind.MemberSelect
                ? SyntaxQuery.SimpleName(target)
                : target.Text;
            if (Properties.Contains(name, StringComparer.Ordinal) && IsTrue(assignment.ChildAt(1)))
                Report(context, assignment.Range.StartLine);
        }
    }

    private static void Report(IRuleContext context, int line)
        => context.Report("The web view is allowed to read the device's own files, so a page loaded "
                          + "into it — including one reached through a redirect nobody planned — can "
                          + "read the application's private storage and send it out. Leave the file "
                          + "access off and serve what the page needs from the application itself.",
            line);
}

public sealed class KotlinReusedInitializationVectorRule : KotlinAndroidRule
{
    public override string Key => "QG-KT-SEC-0049";
    public override string Name => "An authenticated cipher should not reuse its initialisation vector";
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Called(call).Equals("init", StringComparison.Ordinal) || Args(call).Count < 3)
                continue;
            // the encryption direction is what makes a repeated vector fatal; decrypting with a
            // fixed one is ordinary
            var mode = Arg(call, 0);
            if (mode == null || !(mode.Text.EndsWith("ENCRYPT_MODE", StringComparison.Ordinal) || mode.Text == "1"))
                continue;

            var parameters = Arg(call, 2);
            if (parameters is not { Kind: NodeKind.Invocation }
                || !CalledDotted(parameters).EndsWith("GCMParameterSpec", StringComparison.Ordinal))
                continue;

            var vector = Arg(parameters, 1);
            if (!IsWrittenHere(vector))
                continue;

            context.Report("The initialisation vector comes from a value written in the source, so "
                           + "every message is encrypted with the same one. In this mode that is not "
                           + "a weakness of degree: two messages under one key and one vector let "
                           + "anyone who sees both recover the plaintext, and forge new messages. "
                           + "Generate a random vector per message and send it alongside.",
                call.Range.StartLine);
        }
    }

    /// <summary>
    /// Whether the bytes come from a literal written here. The receiver of the conversion is the
    /// string itself, so it is a literal node rather than a name — asking for its dotted name gives
    /// nothing back, and the rule stays silent on the only shape it is about.
    /// </summary>
    private static bool IsWrittenHere(SyntaxNode? vector)
        => vector is { Kind: NodeKind.Invocation }
           && Called(vector).Equals("toByteArray", StringComparison.Ordinal)
           && vector.ChildAt(0)?.ChildAt(0) is { Kind: NodeKind.StringLiteral };
}

public sealed class KotlinDependencyVerificationRule : KotlinAndroidRule
{
    public override string Key => "QG-KT-SEC-0050";
    public override string Name => "Dependency verification should not be switched off";
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Called(call).Equals("disableDependencyVerification", StringComparison.Ordinal))
                continue;

            context.Report("This turns off the check that the downloaded dependencies are the ones "
                           + "the project recorded. Without it a compromised mirror, or a package "
                           + "republished under the same version, is built into the artefact and "
                           + "nothing anywhere notices. Keep verification on and update the metadata "
                           + "when a dependency legitimately changes.", call.Range.StartLine);
        }
    }
}

/// <summary>A rule about the build script of a mobile application.</summary>
public abstract class GradleReleaseRule : KotlinAndroidRule
{
    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context) || !IsGradleScript(context))
            return;

        var android = Section(context.Root, "android");
        if (android == null)
            return;
        // a library module has no application identifier, and the release settings this is about
        // only apply to the package that gets installed
        var configuration = Section(android, "defaultConfig");
        if (configuration == null || Setting(configuration, "applicationId") == null)
            return;

        Inspect(context, android);
    }

    protected abstract void Inspect(IRuleContext context, SyntaxNode android);

    protected static SyntaxNode? ReleaseBlock(SyntaxNode android)
    {
        var buildTypes = Section(android, "buildTypes");
        return buildTypes == null ? null : Section(buildTypes, "release");
    }
}

public sealed class KotlinReleaseObfuscationRule : GradleReleaseRule
{
    public override string Key => "QG-KT-SEC-0051";
    public override string Name => "A release build should be obfuscated";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "30min";

    protected override void Inspect(IRuleContext context, SyntaxNode android)
    {
        var release = ReleaseBlock(android);
        if (release == null)
        {
            context.Report("No release build type is configured, so the shipped package keeps the "
                           + "defaults: every class, method and field name as written, and every "
                           + "unused piece of code still in it. Taking the application apart to find "
                           + "how it authenticates is then a matter of reading. Configure a release "
                           + "build with minification enabled.", android.Range.StartLine);
            return;
        }

        var minify = Setting(release, "isMinifyEnabled");
        if (minify == null)
        {
            context.Report("The release build does not enable minification, and the default is off. "
                           + "The package then ships with the original names and the code that is "
                           + "never called, which is what somebody reverse-engineering it reads "
                           + "first. Set isMinifyEnabled to true.", release.Range.StartLine);
            return;
        }

        if (IsFalse(minify.ChildAt(1)))
            context.Report("Minification is switched off for the release build, so the shipped "
                           + "package carries the original class and method names. Set "
                           + "isMinifyEnabled to true and keep the rules for what must survive in "
                           + "the configuration file.", minify.Range.StartLine);
    }
}

public sealed class KotlinDebuggableReleaseRule : GradleReleaseRule
{
    public override string Key => "QG-KT-SEC-0054";
    public override string Name => "A release build should not be debuggable";

    protected override void Inspect(IRuleContext context, SyntaxNode android)
    {
        var release = ReleaseBlock(android);
        var debuggable = release == null ? null : Setting(release, "isDebuggable");
        if (debuggable == null || !IsTrue(debuggable.ChildAt(1)))
            return;

        context.Report("The build that goes to users is marked debuggable, so anyone holding the "
                       + "device can attach to the running process, read its memory and step through "
                       + "it — and the platform also drops the obfuscation for such a build. Remove "
                       + "the setting from the release type.", debuggable.Range.StartLine);
    }
}

public sealed class KotlinJavascriptInterfaceRule : KotlinAndroidRule
{
    public override string Key => "QG-KT-SEC-0052";
    public override string Name => "Application code should not be exposed to a web view's page";
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!Called(call).Equals("addJavascriptInterface", StringComparison.Ordinal)
                || Args(call).Count < 2)
                continue;

            context.Report("This hands an object of the application to whatever page the web view "
                           + "loads, and the page decides when to call it. One redirect, one injected "
                           + "script in a page you do not control, and code inside the application "
                           + "runs on request. Expose nothing, or expose one narrow method and check "
                           + "the page's origin before answering.", call.Range.StartLine);
        }
    }
}
