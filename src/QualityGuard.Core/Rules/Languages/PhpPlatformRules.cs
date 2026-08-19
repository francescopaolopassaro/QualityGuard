using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Constants that decide what a widely deployed content platform allows at runtime: editing code
/// from the browser, updating itself, calling out to the internet, repairing its database without a
/// login. They are all set in one file, they all default to the permissive value, and the file is
/// usually copied from an old installation — which is why the setting nobody wrote is the one that
/// matters.
/// </summary>
public static class PhpPlatformRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new WordPressFileEditingRule(),
        new WordPressAutomaticUpdateRule(),
        new WordPressExternalRequestRule(),
        new WordPressDatabaseRepairRule(),
        new WordPressUnfilteredHtmlRule()
    ];
}

/// <summary>
/// A rule about the platform's own configuration file. Reading the constants anywhere else would be
/// wrong twice over: the same names are set in tests and in deployment scripts where they mean
/// nothing, and a rule that reports a missing constant would fire on every PHP file in the world.
/// </summary>
public abstract class WordPressConfigRule : RuleBase
{
    public override string[] Languages => ["php"];
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!System.IO.Path.GetFileName(context.File.Path)
                .Equals("wp-config.php", StringComparison.OrdinalIgnoreCase))
            return;
        if (!context.Tree.HasDedicatedParser)
            return;

        Inspect(context, Constants(context));
    }

    protected abstract void Inspect(IRuleContext context, IReadOnlyDictionary<string, Setting> settings);

    /// <summary>What the file defines, by constant name.</summary>
    private static Dictionary<string, Setting> Constants(IRuleContext context)
    {
        var settings = new Dictionary<string, Setting>(StringComparer.Ordinal);
        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!string.Equals(name, "define", StringComparison.OrdinalIgnoreCase))
                continue;

            var arguments = SyntaxQuery.Arguments(call);
            if (arguments.Count < 2)
                continue;

            var key = Unquote(arguments[0].Text);
            if (key.Length == 0)
                continue;
            settings[key] = new Setting(Unquote(arguments[1].Text), call.Range.StartLine);
        }
        return settings;
    }

    private static string Unquote(string text)
    {
        var trimmed = text.Trim();
        return trimmed.Length >= 2 && (trimmed[0] == '\'' || trimmed[0] == '"') && trimmed[^1] == trimmed[0]
            ? trimmed[1..^1]
            : trimmed;
    }

    protected readonly record struct Setting(string Value, int Line)
    {
        public bool IsTrue => Value.Equals("true", StringComparison.OrdinalIgnoreCase) || Value == "1";
        public bool IsFalse => Value.Equals("false", StringComparison.OrdinalIgnoreCase) || Value == "0";
    }
}

public sealed class WordPressFileEditingRule : WordPressConfigRule
{
    public override string Key => "QG-PP-SEC-0061";
    public override string Name => "Editing code from the administration interface should be disabled";
    public override Severity Severity => Severity.Critical;

    protected override void Inspect(IRuleContext context, IReadOnlyDictionary<string, Setting> settings)
    {
        // the wider switch turns off every kind of change to the files, editing included, so a site
        // that sets it has already made this decision and asking again would be noise
        if (settings.TryGetValue("DISALLOW_FILE_MODS", out var mods) && mods.IsTrue)
            return;

        const string message =
            "The built-in editor can write to the site's own PHP files, so an administrator account "
            + "— or anything that obtains one — turns a content permission into running code on the "
            + "server. Set DISALLOW_FILE_EDIT to true and deploy code the way the rest of it is "
            + "deployed.";

        if (!settings.TryGetValue("DISALLOW_FILE_EDIT", out var editing))
            context.Report(message, 1);
        else if (editing.IsFalse)
            context.Report(message, editing.Line);
    }
}

public sealed class WordPressAutomaticUpdateRule : WordPressConfigRule
{
    public override string Key => "QG-PP-SEC-0062";
    public override string Name => "Automatic updates should not be switched off";

    protected override void Inspect(IRuleContext context, IReadOnlyDictionary<string, Setting> settings)
    {
        foreach (var name in new[] { "AUTOMATIC_UPDATER_DISABLED", "DISALLOW_FILE_MODS" })
        {
            if (settings.TryGetValue(name, out var setting) && setting.IsTrue)
                Report(context, name, setting.Line);
        }

        // this one names the behaviour rather than its absence, so it is the false value that
        // switches the updates off
        if (settings.TryGetValue("WP_AUTO_UPDATE_CORE", out var core) && core.IsFalse)
            Report(context, "WP_AUTO_UPDATE_CORE", core.Line);
    }

    private static void Report(IRuleContext context, string name, int line)
        => context.Report($"'{name}' stops the platform from updating itself. Its security fixes are "
                          + "published together with the description of what they fix, so an "
                          + "installation that does not take them is attackable from the day the fix "
                          + "appears, by anyone who reads the release notes. Leave the updates on, or "
                          + "commit to applying them by hand within days.", line);
}

public sealed class WordPressExternalRequestRule : WordPressConfigRule
{
    public override string Key => "QG-PP-SEC-0063";
    public override string Name => "Outgoing requests should be restricted to the hosts that are needed";
    public override Severity Severity => Severity.Minor;

    protected override void Inspect(IRuleContext context, IReadOnlyDictionary<string, Setting> settings)
    {
        const string message =
            "Any plugin installed here can call any address on the internet, so one that is "
            + "compromised — or simply careless — sends the site's data out without anything to "
            + "notice it, and can be used to reach hosts only this server can see. Set "
            + "WP_HTTP_BLOCK_EXTERNAL to true and list the hosts that are genuinely needed in "
            + "WP_ACCESSIBLE_HOSTS.";

        if (!settings.TryGetValue("WP_HTTP_BLOCK_EXTERNAL", out var blocking))
            context.Report(message, 1);
        else if (blocking.IsFalse)
            context.Report(message, blocking.Line);
    }
}

public sealed class WordPressDatabaseRepairRule : WordPressConfigRule
{
    public override string Key => "QG-PP-SEC-0064";
    public override string Name => "Database repair should not be reachable without logging in";
    public override Severity Severity => Severity.Critical;

    protected override void Inspect(IRuleContext context, IReadOnlyDictionary<string, Setting> settings)
    {
        if (!settings.TryGetValue("WP_ALLOW_REPAIR", out var repair) || !repair.IsTrue)
            return;

        context.Report("This exposes a page that repairs and optimises the database to anyone who "
                       + "knows its address — no login is asked for. It is meant to be switched on "
                       + "for the minutes a repair takes and switched off again, and it is almost "
                       + "always left on. Remove the constant once the repair is done.",
            repair.Line);
    }
}

public sealed class WordPressUnfilteredHtmlRule : WordPressConfigRule
{
    public override string Key => "QG-PP-SEC-0065";
    public override string Name => "Unfiltered HTML in content should be disallowed";

    protected override void Inspect(IRuleContext context, IReadOnlyDictionary<string, Setting> settings)
    {
        const string message =
            "Users who can publish content can also publish script tags, so a single editor account "
            + "— or a stolen session belonging to one — runs code in the browser of every visitor "
            + "and of every administrator who opens the page. Set DISALLOW_UNFILTERED_HTML to true "
            + "and let the platform sanitise what is posted.";

        if (!settings.TryGetValue("DISALLOW_UNFILTERED_HTML", out var unfiltered))
            context.Report(message, 1);
        else if (unfiltered.IsFalse)
            context.Report(message, unfiltered.Line);
    }
}
