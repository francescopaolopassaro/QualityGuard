using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Storage and endpoints declared open. Every one of these is a single line in a template, and the
/// consequence is a bucket the internet can list, a database whose backups expire before anybody
/// notices the loss, an endpoint that answers without asking who is calling. None of them fails at
/// apply time: the infrastructure comes up healthy and wrong.
/// </summary>
public static class CloudStorageRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PublicBucketAclRule(),
        new BucketWithoutPublicAccessBlockRule(),
        new BucketWithoutVersioningRule(),
        new ShortBackupRetentionRule(),
        new AnonymousAccessRule(),
        new UnauthenticatedApiEndpointRule()
    ];
}

public abstract class CloudStorageRuleBase : ConfigRuleBase
{
    public override string[] Languages => ["tf"];
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "20min";

    /// <summary>The value of the first setting with this name anywhere inside the block.</summary>
    protected static ConfigNode? Setting(ConfigNode resource, params string[] names)
        => resource.Descendants().FirstOrDefault(n =>
            names.Any(name => n.Key.Equals(name, StringComparison.OrdinalIgnoreCase)));

    protected static bool IsOff(string? value)
        => value is not null && (value.Equals("false", StringComparison.OrdinalIgnoreCase)
                                 || value.Equals("no", StringComparison.OrdinalIgnoreCase)
                                 || value == "0");

    protected static bool IsOn(string? value)
        => value is not null && (value.Equals("true", StringComparison.OrdinalIgnoreCase)
                                 || value.Equals("yes", StringComparison.OrdinalIgnoreCase)
                                 || value == "1");
}

public sealed class PublicBucketAclRule : CloudStorageRuleBase
{
    /// <summary>Canned permissions that hand the object list to somebody who has not signed in.</summary>
    private static readonly string[] Public =
        ["public-read", "public-read-write", "authenticated-read", "allUsers", "allAuthenticatedUsers"];

    public override string Key => "QG-TF-SEC-0077";
    public override string Name => "Storage should not be readable by everyone";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context, "bucket", "storage", "container"))
        {
            foreach (var node in resource.Descendants())
            {
                if (!Public.Contains(node.Value.Trim('"'), StringComparer.OrdinalIgnoreCase))
                    continue;

                context.Report($"'{node.Value}' grants access to anyone who asks, which on a bucket "
                               + "means the object list and everything in it. Nothing about the "
                               + "deployment says so afterwards: the failure looks exactly like a "
                               + "working bucket. Grant the access to the identities that need it.",
                    node.Line);
                break;
            }
        }
    }
}

public sealed class BucketWithoutPublicAccessBlockRule : CloudStorageRuleBase
{
    public override string Key => "QG-TF-SEC-0078";
    public override string Name => "A bucket should keep the block on public access";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context, "public_access_block"))
        {
            var switchedOff = resource.Descendants()
                .Where(n => n.Key.StartsWith("block_", StringComparison.OrdinalIgnoreCase)
                            || n.Key.StartsWith("ignore_", StringComparison.OrdinalIgnoreCase)
                            || n.Key.StartsWith("restrict_", StringComparison.OrdinalIgnoreCase))
                .Where(n => IsOff(n.Value))
                .ToList();
            if (switchedOff.Count == 0)
                continue;

            context.Report("The block on public access is turned off here, so an access policy "
                           + "written anywhere else — by a person, by another template, by a tool — "
                           + "can open the bucket and nothing stops it. The block exists to make that "
                           + "impossible; leave it on.", switchedOff[0].Line);
        }
    }
}

public sealed class BucketWithoutVersioningRule : CloudStorageRuleBase
{
    public override string Key => "QG-TF-SEC-0079";
    public override Severity Severity => Severity.Major;
    public override string Name => "Object storage should keep previous versions";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context, "_bucket_versioning", "bucket_versioning"))
        {
            var status = Setting(resource, "status", "enabled");
            if (status == null)
                continue;
            var disabled = IsOff(status.Value)
                           || status.Value.Equals("Suspended", StringComparison.OrdinalIgnoreCase)
                           || status.Value.Equals("Disabled", StringComparison.OrdinalIgnoreCase);
            if (!disabled)
                continue;

            context.Report("Versioning is turned off, so an overwrite and a delete are both final. "
                           + "That covers the ordinary accident and the deliberate one alike: "
                           + "ransomware encrypts in place, and without versions there is nothing to "
                           + "roll back to.", status.Line);
        }
    }
}

public sealed class ShortBackupRetentionRule : CloudStorageRuleBase
{
    private const int MinimumDays = 7;

    public override string Key => "QG-TF-SEC-0080";
    public override Severity Severity => Severity.Major;
    public override string Name => "Backups should be kept long enough to be useful";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context))
        {
            var retention = Setting(resource, "backup_retention_period", "backup_retention_days",
                "retention_in_days", "retention_days");
            if (retention == null || !int.TryParse(retention.Value, out var days))
                continue;
            if (days >= MinimumDays)
                continue;

            context.Report($"Backups are kept for {days} day{(days == 1 ? string.Empty : "s")}. Damage "
                           + "is usually noticed later than that — a bad migration on Friday, a "
                           + "corruption nobody reads until the weekly report — and by then the last "
                           + $"good copy is gone. Keep at least {MinimumDays} days.", retention.Line);
        }
    }
}

public sealed class AnonymousAccessRule : CloudStorageRuleBase
{
    public override string Key => "QG-TF-SEC-0081";
    public override string Name => "A managed service should not answer anonymous callers";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context))
        {
            foreach (var node in resource.Descendants())
            {
                var key = node.Key;
                var anonymous =
                    (key.Contains("public_network_access", StringComparison.OrdinalIgnoreCase) && IsOn(node.Value))
                    || (key.Contains("allow_blob_public_access", StringComparison.OrdinalIgnoreCase) && IsOn(node.Value))
                    || (key.Contains("anonymous_access", StringComparison.OrdinalIgnoreCase) && IsOn(node.Value))
                    || (key.Contains("public_access_enabled", StringComparison.OrdinalIgnoreCase) && IsOn(node.Value));
                if (!anonymous)
                    continue;

                context.Report($"'{key}' lets the service answer a caller who has not identified "
                               + "themselves. Whatever authentication sits inside the application is "
                               + "then the only control left, reachable from the whole internet and "
                               + "scanned continuously. Reach it through a private endpoint, or list "
                               + "the networks that need it.", node.Line);
                break;
            }
        }
    }
}

public sealed class UnauthenticatedApiEndpointRule : CloudStorageRuleBase
{
    public override string Key => "QG-TF-SEC-0082";
    public override string Name => "An API endpoint should say who may call it";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Resources(context, "api_gateway_method", "apigatewayv2_route",
                     "api_management_api", "http_route"))
        {
            var authorization = Setting(resource, "authorization", "authorization_type",
                "authorizer_id", "authorization_scopes");
            var open = authorization == null
                       || authorization.Value.Equals("NONE", StringComparison.OrdinalIgnoreCase);
            if (!open)
                continue;
            // an endpoint that only answers OPTIONS is the preflight browsers send before the real
            // call, and it carries no data of its own
            var method = Setting(resource, "http_method", "route_key");
            if (method != null && method.Value.Contains("OPTIONS", StringComparison.OrdinalIgnoreCase))
                continue;

            context.Report("This endpoint accepts calls without asking who is making them. Every "
                           + "check that matters then lives in the handler, and one handler that "
                           + "forgets is a public API. Attach an authorizer, or require the key the "
                           + "gateway can verify before the request reaches your code.",
                (authorization ?? resource).Line);
        }
    }
}
