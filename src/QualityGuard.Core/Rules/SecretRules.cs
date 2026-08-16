using System.Text.RegularExpressions;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Credentials committed with the source.
///
/// A leaked key is not found by reading code: it is found by its shape. Every provider issues tokens
/// with a fixed prefix and length, which is what makes them recognisable — and what makes scanners
/// find them within minutes of a repository becoming reachable. The rules below look for those shapes
/// in any language, and each one is deliberately anchored on a prefix that nothing else uses, because
/// a secret scanner that reports ordinary strings is turned off within a day.
/// </summary>
public static class SecretRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CloudProviderKeyRule(),
        new VersionControlTokenRule(),
        new PrivateKeyMaterialRule(),
        new ConnectionStringWithPasswordRule(),
        new WebhookAndChatTokenRule()
    ];
}

/// <summary>One recognisable credential shape.</summary>
public sealed record SecretShape(string Name, Regex Pattern, string Advice);

public abstract class SecretRuleBase : RuleBase
{
    public override string[] Languages => [];
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Blocker;
    public override string RemediationEffort => "30min";

    protected static Regex Shape(string pattern)
        => new(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Reports the first match of each shape. Test fixtures and documentation are skipped: a sample
    /// key in a README is what the documentation is for, and reporting it teaches people to ignore
    /// the rule.
    /// </summary>
    protected void Scan(IRuleContext context, IEnumerable<SecretShape> shapes)
    {
        var path = context.File.Path.Replace('\\', '/');
        if (path.Contains("/test", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/fixture", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/example", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/docs/", StringComparison.OrdinalIgnoreCase))
            return;

        var lines = context.File.Content.Split((char)10);
        foreach (var shape in shapes)
        {
            for (var i = 0; i < lines.Length; i++)
            {
                if (!shape.Pattern.IsMatch(lines[i]))
                    continue;

                context.Report($"This looks like {shape.Name} committed with the source. Anything in the "
                               + "repository is readable by everyone who can clone it and stays in the "
                               + $"history after deletion. {shape.Advice} Treat this credential as "
                               + "compromised and rotate it before removing it.", i + 1);
                break;
            }
        }
    }
}

public sealed class CloudProviderKeyRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("an AWS access key id", Shape(@"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
            "Use an instance role, or read the key from the platform secret store."),
        new("a Google API key", Shape(@"\bAIza[0-9A-Za-z_\-]{35}\b"),
            "Restrict the key to the APIs and referrers it needs, and keep it out of the repository."),
        new("a Google service account key", Shape(@"""type""\s*:\s*""service_account"""),
            "Mount the key file at run time, or use workload identity instead of a key at all."),
        new("an Azure storage account key", Shape(@"AccountKey\s*=\s*[A-Za-z0-9+/]{60,}={0,2}"),
            "Use a managed identity, or a shared access signature with a short lifetime."),
        new("a Stripe secret key", Shape(@"\b(sk|rk)_(live|test)_[0-9A-Za-z]{20,}\b"),
            "Read it from the environment; the publishable key is the only one a client may hold.")
    ];

    public override string Key => "QG-SEC-SEC-0001";
    public override string Name => "A cloud provider key should not be committed";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}

public sealed class VersionControlTokenRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("a GitHub token", Shape(@"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b"),
            "Use a short-lived token from the CI provider, scoped to the repository."),
        new("a GitLab token", Shape(@"\bglpat-[0-9A-Za-z_\-]{20,}\b"),
            "Use a CI job token, which expires with the job."),
        new("an npm token", Shape(@"\bnpm_[0-9A-Za-z]{36}\b"),
            "Put it in the CI secret store and reference it from .npmrc at run time.")
    ];

    public override string Key => "QG-SEC-SEC-0002";
    public override string Name => "A version control or registry token should not be committed";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}

public sealed class PrivateKeyMaterialRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("a private key", Shape(@"-----BEGIN\s+((RSA|DSA|EC|OPENSSH|PGP)\s+)?PRIVATE KEY-----"),
            "Keep private keys outside the repository and distribute them through the secret store."),
        new("a certificate with its private key", Shape(@"-----BEGIN\s+ENCRYPTED PRIVATE KEY-----"),
            "Ship only the public certificate; the private half belongs in the key store.")
    ];

    public override string Key => "QG-SEC-SEC-0003";
    public override string Name => "Private key material should not be committed";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}

public sealed class ConnectionStringWithPasswordRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("a database connection string with its password",
            Shape(@"(mongodb(\+srv)?|postgres(ql)?|mysql|amqp|redis|mssql)://[^:\s/]+:[^@\s]{4,}@"),
            "Compose the connection string at run time from a user and a secret read separately."),
        new("a connection string with an inline password",
            Shape(@"(?i)(password|pwd)\s*=\s*[^;\s""']{6,}\s*;.*(server|data source|host)\s*="),
            "Read the password from the environment or the platform secret store.")
    ];

    public override string Key => "QG-SEC-SEC-0004";
    public override string Name => "A connection string should not carry its password";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}

public sealed class WebhookAndChatTokenRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("a Slack token", Shape(@"\bxox[abposr]-[0-9A-Za-z\-]{10,}\b"),
            "Store it in the secret manager of the workspace that owns the app."),
        new("a Slack webhook", Shape(@"https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+"),
            "A webhook URL is a credential: anyone holding it can post as the app."),
        new("a Discord webhook", Shape(@"https://discord(app)?\.com/api/webhooks/[0-9]+/[0-9A-Za-z_\-]+"),
            "Keep the URL in configuration read at run time."),
        new("a Telegram bot token", Shape(@"\b[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}\b"),
            "Read the token from the environment; it grants full control of the bot.")
    ];

    public override string Key => "QG-SEC-SEC-0005";
    public override string Name => "A webhook or chat token should not be committed";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}
