using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Infrastructure written as code, read as a tree of blocks instead of a list of lines.
///
/// What makes these findings worth reporting is the relationship, not the keyword: a port opened to
/// the whole internet matters because of the source range next to it, a container is privileged
/// because of a flag inside its security context, a bucket is public because of a setting three
/// blocks up. Line matching cannot see any of that, which is why these rules work on
/// <see cref="ConfigNode"/>.
/// </summary>
public static class InfrastructureRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new TerraformUnencryptedStorageRule(),
        new TerraformPublicAccessRule(),
        new TerraformWeakTlsPolicyRule(),
        new TerraformLoggingDisabledRule(),
        new TerraformOverPermissivePolicyRule(),
        new KubernetesPrivilegedContainerRule(),
        new KubernetesPrivilegeEscalationRule(),
        new KubernetesRunAsRootRule(),
        new KubernetesMissingResourceLimitsRule(),
        new KubernetesWritableRootFilesystemRule(),
        new KubernetesMutableImageTagRule(),
        new KubernetesWildcardPermissionRule()
    ];
}

public abstract class ConfigRuleBase : RuleBase
{
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "20min";

    /// <summary>Blocks of a Terraform file that declare a resource of the given types.</summary>
    protected static IEnumerable<ConfigNode> Resources(IRuleContext context, params string[] types)
    {
        foreach (var block in context.Config.Children)
        {
            if (!string.Equals(block.Key, "resource", StringComparison.OrdinalIgnoreCase)
                || block.Labels.Count == 0)
                continue;
            if (types.Length == 0 || types.Any(t => block.Labels[0].Contains(t, StringComparison.OrdinalIgnoreCase)))
                yield return block;
        }
    }

    /// <summary>Every container declared in a Kubernetes manifest, whatever wraps it.</summary>
    protected static IEnumerable<ConfigNode> Containers(IRuleContext context)
        => context.Config.Descendants()
            .Where(n => n.Key is "containers" or "initContainers" or "ephemeralContainers")
            .SelectMany(n => n.Children);

    /// <summary>The pod specification of a manifest, where the shared settings live.</summary>
    protected static IEnumerable<ConfigNode> PodSpecs(IRuleContext context)
        => context.Config.Descendants()
            .Where(n => n.Key == "spec" && n.Descendants().Any(c => c.Key == "containers"));

    protected static bool IsKubernetes(IRuleContext context)
        => context.Config.Descendants().Any(n => n.Key is "apiVersion" or "kind");

    /// <summary>
    /// The values of a list attribute. A list is written on one line, or one item per line, and the
    /// two shapes reach the tree differently — so a rule that reads only one of them is silently
    /// blind on half the files it is given.
    /// </summary>
    protected static IEnumerable<(string Text, int Line)> Items(ConfigNode? list)
    {
        if (list == null)
            yield break;

        var inline = list.Value.Trim();
        if (inline.StartsWith('['))
        {
            foreach (var part in inline.Trim('[', ']').Split(','))
            {
                var text = Clean(part);
                if (text.Length > 0)
                    yield return (text, list.Line);
            }
            yield break;
        }

        foreach (var child in list.Children)
        {
            // an indented list gives each item a node of its own and hangs the value under it; a
            // brace list writes the value on the item's own line
            var carrier = child.IsListItem && child.Key.Length == 0 && child.Value.Length == 0
                          && child.Children is [{ Value.Length: 0, Children.Count: 0 }]
                ? child.Children[0]
                : child;
            var text = Clean(carrier.Value.Length > 0 ? carrier.Value : carrier.Key);
            if (text.Length > 0)
                yield return (text, carrier.Line);
        }
    }

    private static string Clean(string text) => text.Trim().Trim(',').Trim('"').Trim();
}

// --------------------------------------------------------------------------- Terraform

public sealed class TerraformUnencryptedStorageRule : ConfigRuleBase
{
    /// <summary>
    /// Resources that carry the encryption setting inline. S3 buckets are deliberately absent: since
    /// the provider split the setting into its own resource, a bucket without an encryption block is
    /// the normal shape, and reporting it would flag every bucket in every project.
    /// </summary>
    internal static readonly string[] StorageTypes =
    [
        "_ebs_volume", "_efs_file_system", "_rds_cluster", "_db_instance", "_dynamodb_table",
        "_elasticsearch_domain", "_opensearch_domain", "_sagemaker_notebook_instance",
        "_redshift_cluster", "_kinesis_stream", "_docdb_cluster", "_neptune_cluster"
    ];

    public override string Key => "QG-TF-SEC-0063";
    public override string Name => "Stored data should be encrypted at rest";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        // a separate encryption resource in the same file covers the ones declared next to it
        var encryptionElsewhere = Resources(context)
            .Any(r => r.Labels.Count > 0
                      && (r.Labels[0].Contains("encryption", StringComparison.OrdinalIgnoreCase)
                          || r.Labels[0].Contains("kms_key", StringComparison.OrdinalIgnoreCase)));
        if (encryptionElsewhere)
            return;

        foreach (var resource in Resources(context, StorageTypes))
        {
            if (Encrypted(resource))
                continue;
            context.Report($"'{string.Join(' ', resource.Labels)}' stores data without encryption at "
                           + "rest, so anyone who reaches the underlying storage — a stolen snapshot, a "
                           + "misdirected backup, a decommissioned disk — reads it directly. Enable "
                           + "encryption and name the key the organisation controls.", resource.Line);
        }
    }

    private static bool Encrypted(ConfigNode resource)
    {
        foreach (var node in resource.Descendants())
        {
            var key = node.Key.ToLowerInvariant();
            if (key is "encrypted" or "storage_encrypted" or "encrypt_at_rest" or "at_rest_encryption_enabled")
                return !node.IsFalse;
            if (key.Contains("kms_key") || key.Contains("kms_master_key") || key.Contains("sse_algorithm")
                || key is "server_side_encryption_configuration" or "server_side_encryption"
                || key == "encryption_configuration")
                return true;
        }
        return false;
    }
}

public sealed class TerraformPublicAccessRule : ConfigRuleBase
{
    private static readonly string[] OpenRanges = ["0.0.0.0/0", "::/0", "*"];

    public override string Key => "QG-TF-SEC-0064";
    public override string Name => "A resource should not be reachable from the whole internet";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        foreach (var block in context.Config.Descendants())
        {
            var key = block.Key.ToLowerInvariant();
            if (key is not ("ingress" or "cidr_blocks" or "ipv6_cidr_blocks" or "source_ranges"
                or "publicly_accessible" or "authorized_networks"))
                continue;

            if (key == "publicly_accessible")
            {
                if (block.IsTrue)
                    context.Report("This resource is published on the internet. Put it behind a private "
                                   + "network and reach it through a gateway that authenticates the caller.",
                        block.Line);
                continue;
            }

            var open = block.Key == "ingress"
                ? block.Descendants().Any(IsOpen)
                : IsOpen(block);
            if (!open)
                continue;

            context.Report("This range lets every address on the internet reach the resource. Narrow it to "
                           + "the networks that actually need it — the exception you make here applies to "
                           + "everyone, including whoever scans the address space next.", block.Line);
        }
    }

    /// <summary>
    /// A range can be written inline (<c>["0.0.0.0/0"]</c>), as a list of items underneath, or as a
    /// bare value, so the check looks at the entries rather than at the whole text.
    /// </summary>
    private static bool IsOpen(ConfigNode node)
        => Entries(node.Value).Any(e => OpenRanges.Contains(e, StringComparer.Ordinal))
           || node.Children.Any(c => OpenRanges.Contains(c.Key, StringComparer.Ordinal)
                                     || Entries(c.Value).Any(e => OpenRanges.Contains(e, StringComparer.Ordinal)));

    private static IEnumerable<string> Entries(string value)
        => value.Trim('[', ']', ' ')
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(part => part.Trim('"', '\'', ' '));
}

public sealed class TerraformWeakTlsPolicyRule : ConfigRuleBase
{
    // every provider spells the version differently: TLSv1.1, TLS_1_1, Protocol-TLSv1, tls1.0
    private static readonly string[] WeakVersions =
    [
        "TLSv1", "TLS_1_0", "TLS_1_1", "TLS1_0", "TLS1_1", "TLS1.0", "TLS1.1",
        "SSLv3", "SSLv2", "SSL_3", "SSL3", "1.0", "1.1"
    ];

    public override string Key => "QG-TF-SEC-0065";
    public override string Name => "Transport security should require a current TLS version";
    public override Severity Severity => Severity.Major;
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        foreach (var node in context.Config.Descendants())
        {
            var key = node.Key.ToLowerInvariant();
            var mentionsTls = key.Contains("tls") || key.Contains("ssl") || key.Contains("security_policy")
                              || key.Contains("minimum_protocol") || key.Contains("min_protocol");
            if (!mentionsTls)
                continue;
            if (!WeakVersions.Any(v => node.Value.Contains(v, StringComparison.OrdinalIgnoreCase)))
                continue;
            // TLSv1.2 contains "TLSv1", so a version that is current must not be reported
            if (node.Value.Contains("1.2", StringComparison.Ordinal) || node.Value.Contains("1.3", StringComparison.Ordinal))
                continue;

            context.Report($"'{node.Value}' is a protocol version with known weaknesses, and a client that "
                           + "offers it will be served over it. Require TLS 1.2 as a minimum.", node.Line);
        }
    }
}

public sealed class TerraformLoggingDisabledRule : ConfigRuleBase
{
    public override string Key => "QG-TF-SEC-0066";
    public override string Name => "Audit logging should stay enabled";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.SecurityHotspot;
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        foreach (var node in context.Config.Descendants())
        {
            var key = node.Key.ToLowerInvariant();
            var isLogging = key is "logging" or "enable_logging" or "logging_enabled" or "access_logs"
                or "cloudwatch_logs_enabled" or "audit_logs" or "log_config";
            if (!isLogging)
                continue;

            var disabled = node.IsFalse || node.ChildrenNamed("enabled").Any(c => c.IsFalse);
            if (!disabled)
                continue;

            context.Report("Logging is switched off here, so an incident on this resource leaves no trace "
                           + "at all: nobody can tell what was reached, by whom, or when. Keep it on and "
                           + "send the records somewhere the resource itself cannot rewrite.", node.Line);
        }
    }
}

public sealed class TerraformOverPermissivePolicyRule : ConfigRuleBase
{
    public override string Key => "QG-TF-SEC-0067";
    public override string Name => "A policy should not grant every action to everyone";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        foreach (var node in context.Config.Descendants())
        {
            var key = node.Key.ToLowerInvariant();
            if (key is not ("actions" or "action" or "resources" or "resource" or "principals" or "principal"))
                continue;
            var wildcard = node.Value == "*"
                           || node.Children.Any(c => c.Key == "*" || c.Value == "*"
                                                     || c.Key == "\"*\"" || c.Value == "\"*\"");
            if (!wildcard)
                continue;

            context.Report($"'{node.Key}' is set to '*', which grants everything to everyone the policy "
                           + "applies to. One compromised credential then reaches the whole account; list "
                           + "the actions and the resources the role really needs.", node.Line);
        }
    }
}

// --------------------------------------------------------------------------- Kubernetes

public sealed class KubernetesPrivilegedContainerRule : ConfigRuleBase
{
    public override string Key => "QG-K8-SEC-0001";
    public override string Name => "A container should not run privileged";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            var security = container.Child("securityContext");
            var privileged = security?.Child("privileged");
            if (privileged is { IsTrue: true })
            {
                context.Report("A privileged container holds every capability of the host and can reach "
                               + "its devices, so escaping it is the same as owning the node. Drop the "
                               + "flag and add only the capabilities the process needs.", privileged.Line);
            }
        }
    }
}

public sealed class KubernetesHostNamespaceRule : ConfigRuleBase
{
    private static readonly string[] HostNamespaces = ["hostNetwork", "hostPID", "hostIPC"];

    public override string Key => "QG-K8-SEC-0006";
    public override string Name => "A pod should not share a namespace with the host";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var spec in PodSpecs(context))
        {
            foreach (var name in HostNamespaces)
            {
                var shared = spec.Child(name);
                if (shared is not { IsTrue: true })
                    continue;
                context.Report($"'{name}' puts the pod in the namespace of the node itself, so the "
                               + "isolation the cluster is built on no longer applies: the pod sees the "
                               + "node's traffic, processes or memory. Remove the setting, or run this "
                               + "workload on a node dedicated to it.", shared.Line);
            }
        }
    }
}

public sealed class KubernetesRunAsRootRule : ConfigRuleBase
{
    public override string Key => "QG-K8-SEC-0003";
    public override string Name => "A container should not run as root";
    public override Severity Severity => Severity.Major;
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            var security = container.Child("securityContext");
            var nonRoot = security?.Child("runAsNonRoot");
            var user = security?.Child("runAsUser");

            if (nonRoot is { IsFalse: true })
            {
                context.Report("runAsNonRoot is disabled, so the container starts as root: every file it "
                               + "writes and every mount it touches belongs to the most privileged user on "
                               + "the node. Run as an unprivileged user id.", nonRoot.Line);
                continue;
            }
            if (user is { Value: "0" })
            {
                context.Report("runAsUser is 0, which is root. Give the container a user id of its own so a "
                               + "flaw inside it cannot write anywhere on the mounted volumes.", user.Line);
            }
        }
    }
}

public sealed class KubernetesMissingResourceLimitsRule : ConfigRuleBase
{
    public override string Key => "QG-K8-SML-0004";
    public override string Name => "A container should declare its resource limits";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            if (container.Child("image") == null)
                continue; // not a container definition, whatever the surrounding key is called
            var limits = container.At("resources", "limits");
            if (limits != null && limits.Children.Count > 0)
                continue;

            var nothingDeclared = container.Child("resources") == null;
            context.Report(nothingDeclared
                    ? "This container declares no resources at all, so the scheduler places it as if "
                      + "it needed none and the runtime lets it take whatever it asks for: one "
                      + "runaway process takes the node down with every pod on it. Declare "
                      + "resources.requests and resources.limits, even generously."
                    : "This container has no memory or cpu limit, so one runaway process takes the "
                      + "whole node down with it and the scheduler cannot place the pod sensibly. "
                      + "Declare resources.limits, even generously.", container.Line);
        }
    }
}

public sealed class KubernetesWritableRootFilesystemRule : ConfigRuleBase
{
    public override string Key => "QG-K8-SML-0002";
    public override string Name => "A container filesystem should be read-only";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            var readOnly = container.At("securityContext", "readOnlyRootFilesystem");
            if (readOnly is { IsFalse: true })
            {
                context.Report("The root filesystem is writable, so anything that gets code execution can "
                               + "drop a tool in the image and survive a restart. Mount it read-only and "
                               + "give the process a volume for what it really has to write.", readOnly.Line);
            }
        }
    }
}

public sealed class KubernetesMutableImageTagRule : ConfigRuleBase
{
    public override string Key => "QG-K8-SML-0001";
    public override string Name => "A container image should be pinned";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            var image = container.Child("image");
            if (image == null || image.Value.Length == 0)
                continue;
            var reference = image.Value;
            var pinned = reference.Contains('@', StringComparison.Ordinal);
            var tag = reference.Contains(':', StringComparison.Ordinal)
                ? reference[(reference.LastIndexOf(':') + 1)..]
                : string.Empty;
            if (pinned || (tag.Length > 0 && tag != "latest"))
                continue;

            context.Report($"'{reference}' has no fixed version, so two deployments of the same manifest "
                           + "can run different code and a rollback restores nothing. Pin the tag, or "
                           + "better the digest.", image.Line);
        }
    }
}

public sealed class KubernetesWildcardPermissionRule : ConfigRuleBase
{
    public override string Key => "QG-K8-SEC-0023";
    public override string Name => "A role should not grant every permission";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;
        var kind = context.Config.Descendants().FirstOrDefault(n => n.Key == "kind")?.Value ?? string.Empty;
        if (!kind.Contains("Role", StringComparison.Ordinal))
            return;

        foreach (var node in context.Config.Descendants())
        {
            if (node.Key is not ("resources" or "verbs" or "apiGroups"))
                continue;
            // the value can be inline (["*"]) or a list of items underneath
            var wildcard = node.Value.Contains('*', StringComparison.Ordinal)
                           || node.Children.Any(c => c.Key == "*" || c.Value == "*");
            if (!wildcard)
                continue;

            context.Report($"'{node.Key}' is granted with '*', so this role can do everything the cluster "
                           + "allows. Anything that obtains the bound service account inherits it; list "
                           + "the resources and verbs the workload actually uses.", node.Line);
        }
    }
}

public sealed class KubernetesPrivilegeEscalationRule : ConfigRuleBase
{
    public override string Key => "QG-K8-SEC-0002";
    public override string Name => "A container should not be allowed to gain privileges";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            var escalation = container.At("securityContext", "allowPrivilegeEscalation");
            if (escalation is not { IsTrue: true })
                continue;

            context.Report("Allowing privilege escalation lets a process inside the container gain rights "
                           + "its parent did not have — the step an exploit takes right after it lands. "
                           + "Set allowPrivilegeEscalation to false and grant the capabilities the "
                           + "process needs explicitly.", escalation.Line);
        }
    }
}
