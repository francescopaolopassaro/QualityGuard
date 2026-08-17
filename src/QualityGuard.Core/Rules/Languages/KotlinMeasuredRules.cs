using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Kotlin rules chosen by measurement against an annotated corpus, from the checks whose expected
/// lines were covered least. Two of them are about the phone the code runs on: an identifier that
/// follows the device rather than the account, and a password field the keyboard remembers.
/// </summary>
public static class KotlinMeasuredRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new KotlinHardwareIdentifierRule(),
        new KotlinIndexedAccessRule(),
        new KotlinKeyboardCacheRule()
    ];
}

public abstract class KotlinMeasuredRuleBase : RuleBase
{
    public override string[] Languages => ["kt"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "15min";

    /// <summary>
    /// Kotlin is read by the generic structural parser, which places declarations and calls but does
    /// not resolve them. These rules ask only for the shape of a call, so they run on that tree; a
    /// rule that needed a resolved type would have to wait for a dialect of its own.
    /// </summary>
    protected static bool HasTree(IRuleContext context) => context.Root.Children.Count > 0;
}

public sealed class KotlinHardwareIdentifierRule : KotlinMeasuredRuleBase
{
    /// <summary>
    /// Calls that hand back something burned into the device. None of them exists for any other
    /// purpose, so the name alone is enough to know what is being read.
    /// </summary>
    private static readonly string[] IdentifierCalls =
    [
        "getDeviceId", "getImei", "getMeid", "getSimSerialNumber", "getSubscriberId", "getSerial",
        "getLine1Number", "getAndroidId", "getHardwareAddress", "getMacAddress", "getBluetoothAddress"
    ];

    /// <summary>Receivers whose 'address' property is the hardware one.</summary>
    private static readonly string[] AddressOwners = ["bluetooth", "wifi", "adapter", "networkinterface"];

    public override string Key => "QG-KT-SEC-0056";
    public override string Name => "A device identifier should not be used to recognise a user";
    public override IssueKind Kind => IssueKind.SecurityHotspot;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!IdentifierCalls.Contains(name, StringComparer.Ordinal)
                && !(name == "getAddress" && MentionsHardware(SyntaxQuery.Receiver(call))))
                continue;

            Report(context, name, call.Range.StartLine);
        }

        foreach (var member in context.Root.OfKind(NodeKind.MemberSelect))
        {
            var dotted = SyntaxQuery.DottedName(member);
            var last = dotted.Split('.').LastOrDefault() ?? string.Empty;
            if (last is not ("address" or "ANDROID_ID"))
                continue;
            if (last == "address" && !MentionsHardware(dotted))
                continue;

            Report(context, last, member.Range.StartLine);
        }
    }

    private static void Report(IRuleContext context, string what, int line)
        => context.Report($"'{what}' identifies the device, not the account: it survives an uninstall, "
                          + "it is shared by everyone who uses the phone, and it cannot be reset by "
                          + "the person it describes. Use an identifier your own code generates and "
                          + "can throw away.", line);

    private static bool MentionsHardware(string text)
        => AddressOwners.Any(owner => text.Contains(owner, StringComparison.OrdinalIgnoreCase));
}

public sealed class KotlinIndexedAccessRule : KotlinMeasuredRuleBase
{
    public override string Key => "QG-KT-SML-0085";
    public override string Name => "An indexed accessor should be used instead of get and set";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "get", "set"))
        {
            var name = SyntaxQuery.InvokedName(call);
            var arguments = SyntaxQuery.Arguments(call);
            // 'get()' with no argument is a plain accessor — an AtomicInteger, a Provider, a Future —
            // and has no indexed form at all
            var indexed = name == "get" ? arguments.Count >= 1 : arguments.Count >= 2;
            if (!indexed)
                continue;
            var receiver = SyntaxQuery.Receiver(call);
            if (receiver.Length == 0)
                continue;

            context.Report($"Kotlin reads and writes this through brackets, so '{receiver}[…]' says "
                           + $"what '{receiver}.{name}(…)' says and is the form every reader of the "
                           + "language expects.", call.Range.StartLine);
        }
    }
}

public sealed class KotlinKeyboardCacheRule : KotlinMeasuredRuleBase
{
    /// <summary>Input types that tell the keyboard this field is a password and must not be learned.</summary>
    private static readonly string[] PasswordTypes =
    [
        "textPassword", "textVisiblePassword", "textWebPassword", "numberPassword",
        "TYPE_TEXT_VARIATION_PASSWORD", "TYPE_TEXT_VARIATION_VISIBLE_PASSWORD",
        "TYPE_TEXT_VARIATION_WEB_PASSWORD", "TYPE_NUMBER_VARIATION_PASSWORD",
        "PasswordVisualTransformation", "KeyboardType.Password", "KeyboardType.NumberPassword"
    ];

    public override string Key => "QG-KT-SEC-0057";
    public override string Name => "A password field should tell the keyboard not to remember it";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!line.Contains("inputType", StringComparison.Ordinal))
                continue;
            if (PasswordTypes.Any(type => line.Contains(type, StringComparison.Ordinal)))
                continue;
            if (!MentionsPassword(line) && !MentionsPassword(i > 0 ? lines[i - 1] : string.Empty))
                continue;

            context.Report("The field holds a password and its input type does not say so, so the "
                           + "keyboard stores what is typed in the dictionary it shares with every "
                           + "other application. Use one of the password input types.", i + 1);
        }
    }

    private static bool MentionsPassword(string line)
        => line.Contains("password", StringComparison.OrdinalIgnoreCase)
           || line.Contains("passwd", StringComparison.OrdinalIgnoreCase)
           || line.Contains("pinCode", StringComparison.OrdinalIgnoreCase);
}
