using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Cloud resources declared with a protection switched off or never switched on. Infrastructure
/// written as code is applied without anyone reading it again, so a field left at its permissive
/// default outlives every review — and the resource it creates is reachable long before anybody
/// notices which setting made it so.
/// </summary>
public static class CloudRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CloudStorageEncryptionRule(),
        new CloudDatabaseTlsRule(),
        new CloudKeyRotationRule(),
        new CloudDnsSecurityRule(),
        new CloudProjectWideKeysRule(),
        new CloudSubscriptionScopeRule()
    ];
}

public abstract class CloudRuleBase : ConfigRuleBase
{
    public override string[] Languages => ["tf"];
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "20min";

    /// <summary>Whether a declared value says no, in any of the spellings the formats accept.</summary>
    protected static bool IsOff(string? value)
        => value is not null
           && (value.Equals("false", StringComparison.OrdinalIgnoreCase)
               || value.Equals("no", StringComparison.OrdinalIgnoreCase)
               || value == "0");
}

public sealed class CloudStorageEncryptionRule : CloudRuleBase
{
    public override string Key => "QG-TF-SEC-0071";
    public override string Name => "Stored data should be encrypted";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context, "storage", "disk", "volume", "bucket", "filestore"))
        {
            // the resources that carry the setting inline are already read by QG-TF-SEC-0063:
            // reporting them here would name the same line twice with two different ids
            if (resource.Labels.Count > 0
                && TerraformUnencryptedStorageRule.StorageTypes.Any(t =>
                    resource.Labels[0].Contains(t, StringComparison.OrdinalIgnoreCase)))
                continue;

            foreach (var node in resource.Descendants())
            {
                var key = node.Key;
                if (!key.Contains("encrypt", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!IsOff(node.Value))
                    continue;

                context.Report($"'{key}' is turned off, so what this stores is written to disk as it "
                               + "arrived. Anyone who obtains the underlying media — a snapshot, a "
                               + "decommissioned drive, a copy taken by the provider's own tooling — "
                               + "reads it. Leave the encryption on.", node.Line);
            }
        }
    }
}

public sealed class CloudDatabaseTlsRule : CloudRuleBase
{
    public override string Key => "QG-TF-SEC-0072";
    public override string Name => "A managed database should require an encrypted connection";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context, "sql", "database", "db_instance", "rds"))
        {
            foreach (var node in resource.Descendants())
            {
                var key = node.Key;
                var wantsTls = key.Contains("require_ssl", StringComparison.OrdinalIgnoreCase)
                               || key.Contains("ssl_enforcement", StringComparison.OrdinalIgnoreCase)
                               || key.Contains("require_secure_transport", StringComparison.OrdinalIgnoreCase);
                if (!wantsTls)
                    continue;
                var refused = IsOff(node.Value)
                              || string.Equals(node.Value, "Disabled", StringComparison.OrdinalIgnoreCase);
                if (!refused)
                    continue;

                context.Report($"'{key}' allows a client to connect without encryption, so the "
                               + "credentials and every row that follows them cross the network "
                               + "readable. One client configured the old way is enough; the server "
                               + "has to be the one that refuses.", node.Line);
            }
        }
    }
}

public sealed class CloudKeyRotationRule : CloudRuleBase
{
    /// <summary>
    /// The exact resource types that own a rotation setting. Matching the type by substring is what a
    /// first attempt does, and it reports the grants around a key — an iam_member, a key ring — none of
    /// which can be rotated because none of them holds key material.
    /// </summary>
    private static readonly string[] KeyTypes = ["google_kms_crypto_key", "aws_kms_key"];

    /// <summary>
    /// Purposes the provider cannot rotate on its own: the public half is already published, so a new
    /// version has to be distributed rather than swapped in. Reporting them asks for something the
    /// field cannot express.
    /// </summary>
    private static readonly string[] UnrotatablePurposes = ["ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT"];

    public override string Key => "QG-TF-SEC-0073";
    public override string Name => "An encryption key should be rotated";
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in context.Config.Children)
        {
            if (!string.Equals(resource.Key, "resource", StringComparison.OrdinalIgnoreCase)
                || resource.Labels.Count == 0
                || !KeyTypes.Contains(resource.Labels[0], StringComparer.OrdinalIgnoreCase))
                continue;

            var purpose = resource.Descendants()
                .FirstOrDefault(n => n.Key.Equals("purpose", StringComparison.OrdinalIgnoreCase));
            if (purpose?.Value is { } declared
                && UnrotatablePurposes.Any(p => declared.Contains(p, StringComparison.OrdinalIgnoreCase)))
                continue;

            var rotation = resource.Descendants()
                .FirstOrDefault(n => n.Key.Contains("rotation", StringComparison.OrdinalIgnoreCase));
            if (rotation != null && !IsOff(rotation.Value))
                continue;

            context.Report("This key has no rotation period, so the same key protects everything it "
                           + "ever encrypted. A key that leaks then exposes the whole history rather "
                           + "than one window of it, and there is no point at which old copies stop "
                           + "being useful to whoever holds them.", (rotation ?? resource).Line);
        }
    }
}

public sealed class CloudDnsSecurityRule : CloudRuleBase
{
    public override string Key => "QG-TF-SEC-0074";
    public override string Name => "A DNS zone should sign its answers";
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context, "dns_managed_zone", "dns_zone", "route53_zone"))
        {
            var state = resource.Descendants()
                .FirstOrDefault(n => n.Key.Contains("dnssec", StringComparison.OrdinalIgnoreCase)
                                     || n.Key.Equals("state", StringComparison.OrdinalIgnoreCase));
            var signed = state != null && !IsOff(state.Value)
                         && !string.Equals(state.Value, "off", StringComparison.OrdinalIgnoreCase);
            if (signed)
                continue;

            context.Report("This zone does not sign its answers, so a resolver cannot tell a real "
                           + "reply from one injected on the way. An attacker who can answer first "
                           + "sends traffic for this domain wherever they like, and every client "
                           + "believes it.", resource.Line);
        }
    }
}

public sealed class CloudProjectWideKeysRule : CloudRuleBase
{
    public override string Key => "QG-TF-SEC-0075";
    public override string Name => "A machine should not accept project-wide keys";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context, "compute_instance", "instance"))
        {
            foreach (var node in resource.Descendants())
            {
                if (!node.Key.Contains("block-project-ssh-keys", StringComparison.OrdinalIgnoreCase)
                    && !node.Key.Contains("block_project_ssh_keys", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!IsOff(node.Value))
                    continue;

                context.Report("This machine accepts every key registered for the whole project, so "
                               + "anyone granted access to any machine in it can log into this one. "
                               + "The list grows with the team and nobody prunes it. Block the "
                               + "project keys and grant access to this instance explicitly.",
                    node.Line);
            }
        }
    }
}

public sealed class CloudSubscriptionScopeRule : CloudRuleBase
{
    public override string Key => "QG-TF-SEC-0076";
    public override string Name => "A role should not be granted over an entire subscription";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context, "role_assignment", "iam_member", "iam_binding"))
        {
            var scope = resource.Descendants()
                .FirstOrDefault(n => n.Key is "scope" or "project" or "resource_group_name");
            var value = scope?.Value ?? string.Empty;
            var wholeSubscription = value.Contains("/subscriptions/", StringComparison.OrdinalIgnoreCase)
                                    && !value.Contains("/resourceGroups/", StringComparison.OrdinalIgnoreCase);
            if (!wholeSubscription)
                continue;

            context.Report("This grant covers the whole subscription, so it reaches every resource "
                           + "group in it — including ones created later by people who never saw this "
                           + "file. Scope the assignment to the group the identity actually works in.",
                scope!.Line);
        }
    }
}
