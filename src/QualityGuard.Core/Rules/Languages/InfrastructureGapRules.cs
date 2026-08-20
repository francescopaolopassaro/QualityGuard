using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// The checks that were still missing on infrastructure, manifests and descriptors, written in one
/// pass so the families that share a reader share their exclusions too: the storage rules read the
/// same bucket, the Kubernetes rules the same pod, the Maven rules the same descriptor.
/// </summary>
public static class InfrastructureGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new BucketHttpsOnlyRuleCloudFormation(),
        new BucketHttpsOnlyRuleTerraform(),
        new BucketVersioningRuleCloudFormation(),
        new ResourceLoggingRuleCloudFormation(),
        new ResourceLoggingRuleTerraform(),
        new BucketPublicAccessRuleCloudFormation(),
        new LambdaLogGroupRuleCloudFormation(),
        new LogGroupRetentionRuleCloudFormation(),
        new ResourceTagFormatRuleCloudFormation(),
        new ResourceTagFormatRuleTerraform(),
        new ClearTextProtocolRuleCloudFormation(),
        new ClearTextProtocolRuleKubernetes(),
        new ClearTextProtocolRuleTerraform(),
        new PrivilegedDirectoryRoleRuleTerraform(),
        new ClientCertificateRuleTerraform(),
        new HardCodedSecretRuleKubernetes(),
        new DeprecatedApiVersionRuleKubernetes(),
        new ImageVersionTagRuleKubernetes(),
        new ServiceAccountPermissionRuleKubernetes(),
        new TemplateDirectiveSpacingRuleKubernetes(),
        new ArgumentBeforeStageRuleDockerfile(),
        new LongRunInstructionRuleDockerfile(),
        new MalformedExecFormRuleDockerfile()
    ];
}

// --------------------------------------------------------------------------- CloudFormation

public abstract class CloudFormationGapRule : ConfigRuleBase
{
    public override string[] Languages => ["cf"];

    /// <summary>The resources a template declares, with the type each one names.</summary>
    protected static IEnumerable<(ConfigNode Node, string Type)> Declared(IRuleContext context,
        params string[] types)
    {
        var resources = context.Config.Descendants().FirstOrDefault(n => n.Key == "Resources");
        if (resources == null)
            yield break;

        foreach (var resource in resources.Children)
        {
            var declared = resource.Children.FirstOrDefault(c => c.Key == "Type")?.Value.Trim().Trim('\'', '"');
            if (declared is not { Length: > 0 })
                continue;
            if (types.Length == 0 || types.Contains(declared, StringComparer.OrdinalIgnoreCase))
                yield return (resource, declared);
        }
    }

    protected static ConfigNode? Properties(ConfigNode resource)
        => resource.Children.FirstOrDefault(c => c.Key == "Properties");

    protected static ConfigNode? Property(ConfigNode resource, string name)
        => Properties(resource)?.Children.FirstOrDefault(c => c.Key == name);
}

/// <summary>
/// A bucket accepts plain HTTP until a policy says otherwise, so anything read from it or written to
/// it can travel unencrypted — including the credentials of whoever is doing the reading.
/// </summary>
public sealed class BucketHttpsOnlyRuleCloudFormation : CloudFormationGapRule
{
    public override string Key => "QG-CF-SEC-0013";
    public override Severity Severity => Severity.Minor;
    public override string Name => "A bucket should refuse requests that are not encrypted";

    public override void Execute(IRuleContext context)
    {
        // one policy in the template can cover every bucket in it, and it is written as its own
        // resource: without this the rule reported buckets that are already protected
        if (Declared(context, "AWS::S3::BucketPolicy").Any(p => Denies(p.Node)))
            return;

        foreach (var (bucket, _) in Declared(context, "AWS::S3::Bucket"))
        {
            context.Report("This bucket has no policy refusing requests made over plain HTTP, so its "
                           + "content and the credentials used to reach it can travel in clear text. "
                           + "Add a bucket policy denying requests where 'aws:SecureTransport' is "
                           + "false.", bucket.Line);
        }
    }

    private static bool Denies(ConfigNode policy)
        => policy.Descendants().Any(n => n.Value.Contains("SecureTransport", StringComparison.OrdinalIgnoreCase)
                                         || n.Key.Contains("SecureTransport", StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Without versioning, an overwrite or a delete is final: there is no earlier copy to go back to, and
/// ransomware and a mistaken deployment look the same to the bucket.
/// </summary>
public sealed class BucketVersioningRuleCloudFormation : CloudFormationGapRule
{
    public override string Key => "QG-CF-SEC-0014";
    public override Severity Severity => Severity.Minor;
    public override string Name => "A bucket should keep earlier versions of its objects";

    public override void Execute(IRuleContext context)
    {
        foreach (var (bucket, _) in Declared(context, "AWS::S3::Bucket"))
        {
            var versioning = Property(bucket, "VersioningConfiguration");
            if (versioning != null && Enabled(versioning))
                continue;
            // a bucket that deletes its content on a schedule is not keeping history on purpose
            if (Property(bucket, "LifecycleConfiguration") is { } lifecycle
                && lifecycle.Descendants().Any(n => n.Value.Contains("Expiration", StringComparison.OrdinalIgnoreCase)))
                continue;

            context.Report("This bucket keeps no earlier version of its objects, so an overwrite or a "
                           + "delete cannot be undone. Set 'VersioningConfiguration' to 'Enabled', and "
                           + "add a lifecycle rule if the old versions should expire.", bucket.Line);
        }
    }

    private static bool Enabled(ConfigNode versioning)
        => versioning.Descendants().Any(n => n.Value.Contains("Enabled", StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Without access logs there is no record of who read what. The gap only becomes visible during an
/// incident, which is exactly when the record cannot be created after the fact.
/// </summary>
public sealed class ResourceLoggingRuleCloudFormation : CloudFormationGapRule
{
    private static readonly Dictionary<string, string> Settings = new(StringComparer.OrdinalIgnoreCase)
    {
        ["AWS::S3::Bucket"] = "LoggingConfiguration",
        ["AWS::ApiGateway::Stage"] = "AccessLogSetting",
        ["AWS::CloudFront::Distribution"] = "Logging",
        ["AWS::MSK::Cluster"] = "LoggingInfo",
        ["AWS::Neptune::DBCluster"] = "EnableCloudwatchLogsExports",
        ["AWS::DocDB::DBCluster"] = "EnableCloudwatchLogsExports"
    };

    public override string Key => "QG-CF-SEC-0015";
    public override Severity Severity => Severity.Major;
    public override string Name => "A cloud resource should keep its access log";

    public override void Execute(IRuleContext context)
    {
        foreach (var (resource, type) in Declared(context, [.. Settings.Keys]))
        {
            var setting = Settings[type];
            var configured = Property(resource, setting);
            if (configured != null && (configured.Children.Count > 0 || configured.Value.Trim().Length > 0))
                continue;

            context.Report($"'{resource.Key}' is declared without '{setting}', so nothing records who "
                           + "reached it. The record cannot be produced after an incident: enable the "
                           + "log now and send it to a bucket or a log group that keeps it.",
                resource.Line);
        }
    }
}

/// <summary>
/// A grant to every user, or to every authenticated user, is a grant to the internet: anyone with an
/// account on the provider is inside that group.
/// </summary>
public sealed class BucketPublicAccessRuleCloudFormation : CloudFormationGapRule
{
    private static readonly string[] OpenGrants =
        ["PublicRead", "PublicReadWrite", "AuthenticatedRead"];

    public override string Key => "QG-CF-SEC-0016";
    public override Severity Severity => Severity.Blocker;
    public override string Name => "A bucket should not grant access to everyone";

    public override void Execute(IRuleContext context)
    {
        foreach (var (bucket, _) in Declared(context, "AWS::S3::Bucket"))
        {
            var control = Property(bucket, "AccessControl")?.Value.Trim().Trim('\'', '"');
            if (control is not { Length: > 0 }
                || !OpenGrants.Contains(control, StringComparer.OrdinalIgnoreCase))
                continue;

            context.Report($"'{control}' opens this bucket to everyone — 'AuthenticatedRead' included, "
                           + "because that group is every account on the provider, not the accounts of "
                           + "this organisation. Grant access to the principals that need it.",
                bucket.Line);
        }
    }
}

/// <summary>
/// A function that creates its own log group creates it with no retention and outside the template, so
/// nothing in the infrastructure describes it and nothing removes it.
/// </summary>
public sealed class LambdaLogGroupRuleCloudFormation : CloudFormationGapRule
{
    public override string Key => "QG-CF-SML-0003";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string Name => "A function should declare the log group it writes to";

    public override void Execute(IRuleContext context)
    {
        var groups = Declared(context, "AWS::Logs::LogGroup").ToList();

        foreach (var (function, _) in Declared(context, "AWS::Lambda::Function"))
        {
            // the group is tied to the function by name, and the template writes that name with a
            // reference: any group naming this function is the one it will write to
            if (groups.Any(g => g.Node.Descendants().Any(n => n.Value.Contains(function.Key, StringComparison.Ordinal))))
                continue;

            context.Report($"'{function.Key}' writes to a log group nothing here declares, so the group "
                           + "is created on first use with no retention and outlives the stack. Declare "
                           + "an 'AWS::Logs::LogGroup' named after the function.", function.Line);
        }
    }
}

/// <summary>
/// A log group with no retention keeps everything for ever, which costs money for as long as the
/// account exists and keeps personal data far past the point anyone can justify.
/// </summary>
public sealed class LogGroupRetentionRuleCloudFormation : CloudFormationGapRule
{
    public override string Key => "QG-CF-SML-0004";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Critical;
    public override string Name => "A log group should say how long it keeps its content";

    public override void Execute(IRuleContext context)
    {
        foreach (var (group, _) in Declared(context, "AWS::Logs::LogGroup"))
        {
            if (Property(group, "RetentionInDays") is { Value.Length: > 0 })
                continue;

            context.Report($"'{group.Key}' keeps its entries for ever: the storage bill grows without a "
                           + "ceiling and personal data stays past any retention policy. Set "
                           + "'RetentionInDays' to what the audit actually needs.", group.Line);
        }
    }
}

/// <summary>
/// A tag key or value outside the accepted character set is refused when the stack is deployed, so the
/// mistake surfaces at deployment time rather than here.
/// </summary>
public abstract class ResourceTagFormatRule : ConfigRuleBase
{
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";
    public override string Name => "A resource tag should use the characters the provider accepts";

    /// <summary>
    /// Letters, digits and the handful of punctuation marks the provider documents. Anything else is
    /// refused at deployment, and the interpolation of a variable is not ours to judge.
    /// </summary>
    protected static bool IsAcceptable(string text)
        => text.Length == 0
           || text.Contains("${", StringComparison.Ordinal)
           || text.Contains('%')          // a format placeholder a macro fills in before deployment
           || text.Contains("{{", StringComparison.Ordinal)
           || text.Contains("!Ref", StringComparison.Ordinal)
           || text.All(c => char.IsLetterOrDigit(c) || c is ' ' or '_' or '.' or ':' or '/' or '=' or '+'
               or '-' or '@');

    protected static void ReportTag(IRuleContext context, string text, int line)
        => context.Report($"'{text}' holds a character the provider does not accept in a tag, so the "
                          + "deployment is refused when the stack reaches it. Keep to letters, digits "
                          + "and ' _ . : / = + - @'.", line);
}

public sealed class ResourceTagFormatRuleCloudFormation : ResourceTagFormatRule
{
    public override string Key => "QG-CF-SML-0005";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        foreach (var tags in context.Config.Descendants().Where(n => n.Key == "Tags"))
        {
            foreach (var entry in tags.Children.SelectMany(c => c.Children))
            {
                if (entry.Key is not ("Key" or "Value"))
                    continue;
                var text = entry.Value.Trim().Trim('\'', '"');
                if (IsAcceptable(text))
                    continue;
                ReportTag(context, text, entry.Line);
            }
        }
    }
}

public sealed class ResourceTagFormatRuleTerraform : ResourceTagFormatRule
{
    public override string Key => "QG-TF-SML-0004";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        foreach (var tags in context.Config.Descendants().Where(n => n.Key == "tags"))
        {
            foreach (var entry in tags.Children)
            {
                foreach (var text in new[] { entry.Key, entry.Value })
                {
                    var cleaned = text.Trim().Trim('\'', '"');
                    if (IsAcceptable(cleaned))
                        continue;
                    ReportTag(context, cleaned, entry.Line);
                    break;
                }
            }
        }
    }
}

/// <summary>
/// A bucket accepts plain HTTP until a policy refuses it, so its content and the credentials used to
/// reach it can travel where anyone on the path reads them.
/// </summary>
public sealed class BucketHttpsOnlyRuleTerraform : ConfigRuleBase
{
    public override string Key => "QG-TF-SEC-0016";
    public override Severity Severity => Severity.Minor;
    public override string[] Languages => ["tf"];
    public override string Name => "A bucket should refuse requests that are not encrypted";

    public override void Execute(IRuleContext context)
    {
        // the policy is a resource of its own, and one policy can cover several buckets: a template
        // that denies insecure transport anywhere has already answered this question
        var denied = context.Config.Descendants()
            .Any(n => n.Value.Contains("aws:SecureTransport", StringComparison.OrdinalIgnoreCase)
                      || n.Key.Contains("aws:SecureTransport", StringComparison.OrdinalIgnoreCase));
        if (denied)
            return;

        foreach (var bucket in Resources(context, "aws_s3_bucket"))
        {
            // the sub-resources of a bucket carry the same prefix and are not buckets themselves
            if (bucket.Labels.Count > 0 && !bucket.Labels[0].EndsWith("aws_s3_bucket", StringComparison.Ordinal))
                continue;

            context.Report($"'{string.Join(' ', bucket.Labels)}' has no policy refusing requests made "
                           + "over plain HTTP, so its content and the credentials used to reach it can "
                           + "travel in clear text. Add a bucket policy denying requests where "
                           + "'aws:SecureTransport' is false.", bucket.Line);
        }
    }
}

/// <summary>
/// Without access logs there is no record of who reached the resource, and the record cannot be
/// produced after the incident that makes someone ask for it.
/// </summary>
public sealed class ResourceLoggingRuleTerraform : ConfigRuleBase
{
    /// <summary>The resource types that carry their logging setting inline, with the block to look for.</summary>
    private static readonly Dictionary<string, string> Settings = new(StringComparer.OrdinalIgnoreCase)
    {
        ["aws_api_gateway_stage"] = "access_log_settings",
        ["aws_cloudfront_distribution"] = "logging_config",
        ["aws_msk_cluster"] = "logging_info",
        ["aws_neptune_cluster"] = "enable_cloudwatch_logs_exports",
        ["aws_docdb_cluster"] = "enabled_cloudwatch_logs_exports",
        ["aws_elasticsearch_domain"] = "log_publishing_options",
        ["aws_opensearch_domain"] = "log_publishing_options"
    };

    public override string Key => "QG-TF-SEC-0019";
    public override Severity Severity => Severity.Major;
    public override string[] Languages => ["tf"];
    public override string Name => "A cloud resource should keep its access log";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context))
        {
            if (resource.Labels.Count == 0)
                continue;
            var type = Settings.Keys.FirstOrDefault(
                t => resource.Labels[0].Equals(t, StringComparison.OrdinalIgnoreCase));
            if (type == null)
                continue;
            var setting = Settings[type];
            if (resource.Descendants().Any(c => c.Key.Equals(setting, StringComparison.OrdinalIgnoreCase)))
                continue;

            context.Report($"'{string.Join(' ', resource.Labels)}' is declared without '{setting}', so "
                           + "nothing records who reached it. Enable the log and send it where it is "
                           + "kept.", resource.Line);
        }
    }
}

// --------------------------------------------------------------------------- clear-text protocols

/// <summary>
/// A setting that turns encryption off, or a URL that names a protocol without it, sends the traffic
/// where anyone on the path can read and change it.
/// </summary>
public abstract class ClearTextProtocolRule : ConfigRuleBase
{
    public override Severity Severity => Severity.Minor;
    public override string Name => "Traffic should not travel over a protocol without encryption";

    /// <summary>Schemes whose encrypted form has a different name, so the plain one is a choice.</summary>
    protected static readonly string[] PlainSchemes =
        ["http://", "ftp://", "telnet://", "ldap://", "imap://", "pop3://", "smtp://"];

    /// <summary>Hosts where the plain scheme is the convention and carries nothing.</summary>
    private static readonly string[] Local =
        ["localhost", "127.0.0.1", "0.0.0.0", "::1", "example.com", "schemas.", "www.w3.org", "xmlns"];

    protected static bool CarriesTraffic(string value)
    {
        if (!PlainSchemes.Any(s => value.Contains(s, StringComparison.OrdinalIgnoreCase)))
            return false;
        // a namespace, a schema location and a loopback address name a protocol without using one
        return !Local.Any(l => value.Contains(l, StringComparison.OrdinalIgnoreCase));
    }

    protected static void ReportPlain(IRuleContext context, string value, int line)
        => context.Report($"'{Shorten(value)}' names a protocol that carries its traffic in clear text, "
                          + "so anyone on the path reads it and can change it. Use the encrypted form of "
                          + "the same protocol.", line);

    private static string Shorten(string value)
        => value.Length <= 60 ? value.Trim() : value.Trim()[..57] + "...";
}

public sealed class ClearTextProtocolRuleCloudFormation : ClearTextProtocolRule
{
    public override string Key => "QG-CF-SEC-0012";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        foreach (var node in context.Config.Descendants())
        {
            if (!CarriesTraffic(node.Value))
                continue;
            ReportPlain(context, node.Value, node.Line);
        }
    }
}

public sealed class ClearTextProtocolRuleKubernetes : ClearTextProtocolRule
{
    public override string Key => "QG-K8-SEC-0010";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var node in context.Config.Descendants())
        {
            if (!CarriesTraffic(node.Value))
                continue;
            ReportPlain(context, node.Value, node.Line);
        }
    }
}

public sealed class ClearTextProtocolRuleTerraform : ClearTextProtocolRule
{
    public override string Key => "QG-TF-SEC-0015";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        foreach (var node in context.Config.Descendants())
        {
            // the provider settings that name the plain protocol as a value of their own
            if (node.Key is "encryption_type" or "protocol" or "transit_encryption_enabled"
                && node.Value.Trim().Trim('"') is "NONE" or "HTTP" or "disabled")
            {
                context.Report($"'{node.Key}' is set to '{node.Value.Trim().Trim('"')}', so this traffic "
                               + "travels without encryption. Choose the encrypted setting.", node.Line);
                continue;
            }
            if (!CarriesTraffic(node.Value))
                continue;
            ReportPlain(context, node.Value, node.Line);
        }
    }
}

// --------------------------------------------------------------------------- Terraform

/// <summary>
/// A built-in role that can hand out roles can hand out its own: whoever holds it can reach anything in
/// the directory, and the grant is invisible in the resources it does not name.
/// </summary>
public sealed class PrivilegedDirectoryRoleRuleTerraform : ConfigRuleBase
{
    private static readonly string[] Privileged =
    [
        "Global Administrator", "Company Administrator", "Privileged Role Administrator",
        "Privileged Authentication Administrator", "Partner Tier2 Support", "Application Administrator",
        "Cloud Application Administrator", "Hybrid Identity Administrator"
    ];

    public override string Key => "QG-TF-SEC-0037";
    public override Severity Severity => Severity.Major;
    public override string[] Languages => ["tf"];
    public override string Name => "A directory role that can grant roles should not be assigned";

    public override void Execute(IRuleContext context)
    {
        foreach (var role in Resources(context, "azuread_directory_role"))
        {
            var name = role.Children.FirstOrDefault(c => c.Key == "display_name")?.Value.Trim().Trim('"');
            if (name is not { Length: > 0 }
                || !Privileged.Contains(name, StringComparer.OrdinalIgnoreCase))
                continue;

            context.Report($"'{name}' can grant roles, its own included, so whoever holds it reaches "
                           + "everything in the directory. Assign the narrowest built-in role that "
                           + "covers the task, or a custom role scoped to it.", role.Line);
        }
    }
}

/// <summary>
/// An endpoint meant for other services should require a client certificate. Left optional, a caller
/// without one is served anyway, which is the same as not requiring it at all.
/// </summary>
public sealed class ClientCertificateRuleTerraform : ConfigRuleBase
{
    private static readonly string[] Endpoints =
        ["azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_app_service",
            "azurerm_linux_function_app", "azurerm_windows_function_app"];

    public override string Key => "QG-TF-SEC-0042";
    public override Severity Severity => Severity.Major;
    public override string[] Languages => ["tf"];
    public override string Name => "A service-to-service endpoint should require a client certificate";

    public override void Execute(IRuleContext context)
    {
        foreach (var app in Resources(context, Endpoints))
        {
            // an endpoint open to the network is a public site, and a client certificate is not how
            // a browser authenticates: the rule is about the ones closed to the network
            var isPublic = app.Children.FirstOrDefault(c => c.Key == "public_network_access_enabled")
                ?.Value.Trim().Trim('"');
            if (isPublic is not ("false" or "0"))
                continue;

            var enabled = app.Children.FirstOrDefault(c => c.Key == "client_certificate_enabled")
                ?.Value.Trim().Trim('"');
            var mode = app.Children.FirstOrDefault(c => c.Key == "client_certificate_mode")
                ?.Value.Trim().Trim('"');
            if (enabled is "true" && mode is "Required")
                continue;

            context.Report($"'{string.Join(' ', app.Labels)}' is closed to the network but does not "
                           + "require a client certificate, so any caller that reaches it is served. "
                           + "Enable client certificates and set the mode to 'Required'.", app.Line);
        }
    }
}

// --------------------------------------------------------------------------- Kubernetes

/// <summary>
/// A value written into the manifest is a value in version control, in every backup of it and in the
/// output of anyone allowed to read the manifest.
/// </summary>
public sealed class HardCodedSecretRuleKubernetes : ConfigRuleBase
{
    private static readonly string[] Names =
        ["password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "credential",
            "private_key", "access_key"];

    public override string Key => "QG-K8-SEC-0012";
    public override Severity Severity => Severity.Blocker;
    public override string[] Languages => ["k8"];
    public override string Name => "A manifest should not carry a secret in clear";

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var variable in context.Config.Descendants().Where(n => n.Key == "env"))
        {
            foreach (var entry in variable.Children)
            {
                var name = entry.Children.FirstOrDefault(c => c.Key == "name")?.Value.Trim().Trim('"');
                var value = entry.Children.FirstOrDefault(c => c.Key == "value");
                if (name is not { Length: > 0 } || value is null)
                    continue;
                if (!Names.Any(n => name.Contains(n, StringComparison.OrdinalIgnoreCase)))
                    continue;
                var text = value.Value.Trim().Trim('"');
                if (text.Length == 0 || SecretFilters.LooksLikeAPlaceholder(text))
                    continue;

                context.Report($"'{name}' carries its value in the manifest, so the secret is in version "
                               + "control and in every copy of it. Reference a Secret through "
                               + "'valueFrom.secretKeyRef' and keep the value out of the file.",
                    value.Line);
            }
        }
    }
}

/// <summary>
/// A resource declared against an API version the cluster has retired stops being applied the day the
/// cluster is upgraded, and the deployment fails with an object nobody changed.
/// </summary>
public sealed class DeprecatedApiVersionRuleKubernetes : ConfigRuleBase
{
    /// <summary>Versions retired by the platform, with the one that replaced each of them.</summary>
    private static readonly Dictionary<string, string> Retired = new(StringComparer.Ordinal)
    {
        ["extensions/v1beta1"] = "apps/v1",
        ["apps/v1beta1"] = "apps/v1",
        ["apps/v1beta2"] = "apps/v1",
        ["batch/v1beta1"] = "batch/v1",
        ["policy/v1beta1"] = "policy/v1",
        ["rbac.authorization.k8s.io/v1beta1"] = "rbac.authorization.k8s.io/v1",
        ["networking.k8s.io/v1beta1"] = "networking.k8s.io/v1",
        ["storage.k8s.io/v1beta1"] = "storage.k8s.io/v1",
        ["admissionregistration.k8s.io/v1beta1"] = "admissionregistration.k8s.io/v1",
        ["apiextensions.k8s.io/v1beta1"] = "apiextensions.k8s.io/v1",
        ["autoscaling/v2beta1"] = "autoscaling/v2",
        ["autoscaling/v2beta2"] = "autoscaling/v2"
    };

    public override string Key => "QG-K8-SML-0005";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string[] Languages => ["k8"];
    public override string Name => "A manifest should not use a retired API version";

    public override void Execute(IRuleContext context)
    {
        foreach (var version in context.Config.Descendants().Where(n => n.Key == "apiVersion"))
        {
            var declared = version.Value.Trim().Trim('"', '\'');
            if (!Retired.TryGetValue(declared, out var replacement))
                continue;

            context.Report($"'{declared}' has been removed from the platform, so this object stops "
                           + $"being applied the day the cluster is upgraded. Move it to "
                           + $"'{replacement}'.", version.Line);
        }
    }
}

/// <summary>
/// An image without a version, or on the moving tag, is a different image on every pull: the cluster
/// runs one build today and another tomorrow, and nothing in the manifest records which.
/// </summary>
public sealed class ImageVersionTagRuleKubernetes : ConfigRuleBase
{
    public override string Key => "QG-K8-SML-0007";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string[] Languages => ["k8"];
    public override string Name => "A container image should name the version it runs";

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            var image = container.Children.FirstOrDefault(c => c.Key == "image");
            if (image == null)
                continue;
            var reference = image.Value.Trim().Trim('"', '\'');
            if (reference.Length == 0 || reference.Contains("${", StringComparison.Ordinal)
                || reference.Contains("{{", StringComparison.Ordinal))
                continue;
            // a digest pins the image harder than any tag does
            if (reference.Contains('@'))
                continue;

            var lastColon = reference.LastIndexOf(':');
            var lastSlash = reference.LastIndexOf('/');
            var tag = lastColon > lastSlash ? reference[(lastColon + 1)..] : string.Empty;
            if (tag.Length > 0 && !string.Equals(tag, "latest", StringComparison.OrdinalIgnoreCase))
                continue;

            context.Report($"'{reference}' does not name a version, so the cluster runs whatever the "
                           + "registry serves at pull time and a rollback has nothing to go back to. "
                           + "Name the tag, or pin the digest.", image.Line);
        }
    }
}

/// <summary>
/// A pod that says nothing about its service account gets the default one of its namespace, with the
/// token mounted: any code in the container can talk to the API server as that account.
/// </summary>
public sealed class ServiceAccountPermissionRuleKubernetes : ConfigRuleBase
{
    public override string Key => "QG-K8-SEC-0018";
    public override Severity Severity => Severity.Major;
    public override string[] Languages => ["k8"];
    public override string Name => "A pod should say which service account it runs as";

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        // a manifest that also declares accounts or bindings is one where the author is deciding
        // identities: there, a pod left on the default is an omission. Everywhere else the default
        // is the platform's choice and saying so on every pod buries the finding that matters.
        var decidesIdentity = context.Config.Descendants().Any(
            n => n.Key == "kind"
                 && n.Value.Trim().Trim('"') is "ServiceAccount" or "Role" or "ClusterRole"
                     or "RoleBinding" or "ClusterRoleBinding");
        if (!decidesIdentity)
            return;

        foreach (var spec in PodSpecs(context))
        {
            var named = spec.Children.Any(c => c.Key is "serviceAccountName" or "serviceAccount");
            var mounted = spec.Children.FirstOrDefault(c => c.Key == "automountServiceAccountToken")
                ?.Value.Trim().Trim('"');
            if (named || mounted is "false")
                continue;

            context.Report("This pod does not name a service account, so it runs as the default one of "
                           + "its namespace with the token mounted — any code in the container can call "
                           + "the API server as that account. Name an account with the permissions this "
                           + "workload needs, or set 'automountServiceAccountToken' to false.",
                spec.Line);
        }
    }
}

/// <summary>
/// A template directive written without the spaces the templating engine expects is copied into the
/// output as text, so the manifest is applied with the directive still in it.
/// </summary>
public sealed class TemplateDirectiveSpacingRuleKubernetes : ConfigRuleBase
{
    public override string Key => "QG-K8-SML-0010";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["k8"];
    public override string Name => "A template directive should keep the spaces around its braces";

    /// <summary>Whether the file is rendered by the chart engine, which is the one this rule is about.</summary>
    private static bool IsChartTemplate(IRuleContext context)
        => context.File.Content.Contains(".Values", StringComparison.Ordinal)
           || context.File.Content.Contains(".Release", StringComparison.Ordinal)
           || context.File.Content.Contains(".Chart", StringComparison.Ordinal)
           || context.File.Path.Replace('\\', '/').Contains("/templates/", StringComparison.OrdinalIgnoreCase);

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            for (var at = line.IndexOf("{{", StringComparison.Ordinal); at >= 0;
                 at = line.IndexOf("{{", at + 2, StringComparison.Ordinal))
            {
                var close = line.IndexOf("}}", at + 2, StringComparison.Ordinal);
                if (close < 0)
                    break;
                var body = line[(at + 2)..close];
                if (body.Length == 0 || (body.StartsWith(' ') && body.EndsWith(' ')))
                    continue;
                // the convention belongs to the chart templating engine. Another tool templating the
                // same braces expects them written tight, and every one of those files was reported.
                if (!IsChartTemplate(context))
                    return;
                // the trim markers carry their own space and are written tight on purpose
                if (body.StartsWith('-') || body.EndsWith('-'))
                    continue;

                context.Report($"'{{{{{body}}}}}' has no space inside its braces, which is not the form "
                               + "the templating engine renders. Write it as '{{ " + body.Trim() + " }}' "
                               + "so the value is substituted instead of copied.", i + 1);
                break;
            }
        }
    }
}

// --------------------------------------------------------------------------- Dockerfile

/// <summary>
/// An argument declared before the first stage belongs to the file, not to the stage: inside the stage
/// it expands to nothing, and the command runs with an empty value nobody notices.
/// </summary>
public sealed class ArgumentBeforeStageRuleDockerfile : ConfigRuleBase
{
    public override string Key => "QG-DK-BUG-0002";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string[] Languages => ["dk"];
    public override string Name => "A build argument should be declared inside the stage that reads it";

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var beforeFirstStage = new List<string>();
        var declaredInStage = new HashSet<string>(StringComparer.Ordinal);
        var started = false;

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            if (line.StartsWith("FROM ", StringComparison.OrdinalIgnoreCase))
            {
                started = true;
                declaredInStage.Clear();
                continue;
            }
            if (line.StartsWith("ARG ", StringComparison.OrdinalIgnoreCase))
            {
                var name = line[4..].Split('=')[0].Trim();
                if (name.Length == 0)
                    continue;
                if (started)
                    declaredInStage.Add(name);
                else
                    beforeFirstStage.Add(name);
                continue;
            }
            if (!started || beforeFirstStage.Count == 0)
                continue;

            foreach (var name in beforeFirstStage)
            {
                if (declaredInStage.Contains(name))
                    continue;
                if (!line.Contains("$" + name, StringComparison.Ordinal)
                    && !line.Contains("${" + name, StringComparison.Ordinal))
                    continue;

                context.Report($"'{name}' is declared before the first stage, so inside this stage it "
                               + "expands to nothing and the command runs with an empty value. Repeat "
                               + "the declaration after the stage begins.", i + 1);
                break;
            }
        }
    }
}

/// <summary>
/// One long command is one line in the diff: the review sees a wall of text, and a package added or
/// removed in the middle of it is invisible.
/// </summary>
public sealed class LongRunInstructionRuleDockerfile : ConfigRuleBase
{
    private const int Limit = 120;

    public override string Key => "QG-DK-SML-0010";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["dk"];
    public override string Name => "A long build command should be split across lines";

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd();
            if (!line.TrimStart().StartsWith("RUN ", StringComparison.OrdinalIgnoreCase))
                continue;
            // a command already continued on the next line is written the way this rule asks for
            if (line.EndsWith('\\') || line.Length <= Limit)
                continue;

            context.ReportCosting($"This command is {line.Length} characters on one line, so a package "
                                  + "added or removed in the middle of it does not show in a review. "
                                  + "Break it with a backslash, one argument per line.", 5, i + 1);
        }
    }
}

/// <summary>
/// The bracket form of an instruction is read as JSON. Anything written after the closing bracket is
/// not part of it, and the runtime either ignores the argument or refuses to start the image.
/// </summary>
public sealed class MalformedExecFormRuleDockerfile : ConfigRuleBase
{
    private static readonly string[] Instructions = ["CMD", "ENTRYPOINT", "RUN", "SHELL", "VOLUME"];

    public override string Key => "QG-DK-BUG-0004";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string[] Languages => ["dk"];
    public override string Name => "The bracket form of an instruction should be valid JSON";

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            var keyword = Instructions.FirstOrDefault(
                k => line.StartsWith(k + " ", StringComparison.OrdinalIgnoreCase));
            if (keyword == null)
                continue;

            var rest = line[keyword.Length..].Trim();
            if (!rest.StartsWith('['))
                continue;
            var close = rest.LastIndexOf(']');
            if (close < 0)
            {
                context.Report($"The bracket form of '{keyword}' is read as JSON and this one never "
                               + "closes, so the image fails to build. Close the bracket, or write the "
                               + "instruction in shell form.", i + 1);
                continue;
            }

            var trailing = rest[(close + 1)..].Trim();
            if (trailing.Length == 0 || trailing.StartsWith('#'))
                continue;

            context.Report($"'{trailing}' sits after the closing bracket of '{keyword}', which is read "
                           + "as JSON and ends there. The argument is dropped: put it inside the "
                           + "brackets as its own element.", i + 1);
        }
    }
}
