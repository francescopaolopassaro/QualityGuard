using System.Text.RegularExpressions;
using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Template properties that decide who reaches a resource and how much of its history survives.
/// These read the template as a tree of resources rather than as lines, so a property is judged
/// inside the resource that owns it — the same word means different things under two resource types.
/// </summary>
public static class CloudFormationSecurityRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CfPublicAccessBlockRule(),
        new CfUnauthenticatedApiRule(),
        new CfBackupRetentionRule()
    ];
}

public abstract class CloudFormationSecurityRule : ConfigRuleBase
{
    public override string[] Languages => ["cf"];
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    /// <summary>The declared resources of a template, with their type and their properties.</summary>
    protected static IEnumerable<(string Name, string Type, ConfigNode Properties, ConfigNode Node)> Resources(
        IRuleContext context)
    {
        var resources = context.Config.Descendants().FirstOrDefault(n => n.Key == "Resources");
        if (resources == null)
            yield break;

        foreach (var resource in resources.Children)
        {
            var type = resource.Child("Type")?.Value;
            var properties = resource.Child("Properties");
            if (type == null || properties == null)
                continue;
            yield return (resource.Key, type, properties, resource);
        }
    }
}

public sealed class CfPublicAccessBlockRule : CloudFormationSecurityRule
{
    private static readonly string[] Guards =
        ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"];

    public override string Key => "QG-CF-SEC-0019";
    public override string Name => "An object store should block public access on every path";
    public override Severity Severity => Severity.Blocker;

    public override void Execute(IRuleContext context)
    {
        foreach (var (_, type, properties, _) in Resources(context))
        {
            if (type != "AWS::S3::Bucket")
                continue;

            // the block is only judged when the template writes it: a bucket that says nothing is
            // covered by whatever the account enforces above it, and that is not readable from here
            var configuration = properties.Child("PublicAccessBlockConfiguration");
            if (configuration == null)
                continue;

            var switchedOff = Guards.Where(g => configuration.Child(g) is { IsFalse: true }).ToList();
            if (switchedOff.Count > 0)
            {
                context.Report($"{string.Join(", ", switchedOff)} allow a public access list or "
                               + "policy to be attached to this bucket later, from anywhere the "
                               + "account is reachable. The template reads as though access were "
                               + "settled here; it is not. Set every guard to true.",
                    configuration.Line);
                continue;
            }

            var missing = Guards.Where(g => configuration.Child(g) == null).ToList();
            if (missing.Count > 0)
                context.Report($"{string.Join(", ", missing)} are not declared, and each one defaults "
                               + "to false: the guard that is missing is the one that lets a public "
                               + "policy through. Declare all four and set them to true.",
                    configuration.Line);
        }
    }
}

public sealed class CfUnauthenticatedApiRule : CloudFormationSecurityRule
{
    /// <summary>
    /// Endpoints that exist precisely to be reached before anyone is authenticated. Reporting them
    /// asks for a check that would make the endpoint useless, so the name is what excludes them.
    /// </summary>
    private static readonly Regex OpenByDesign = new(
        "login|signup|register|authenticate|token|forgot-password|healthcheck|health-check|status"
        + "|callback|public-keys|jwks|well-known",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly HashSet<string> PrivilegedNames =
        new(StringComparer.OrdinalIgnoreCase) { "admin", "management", "internal" };

    private static readonly HashSet<string> ChangingMethods =
        new(StringComparer.OrdinalIgnoreCase) { "POST", "PUT", "DELETE", "PATCH", "ANY" };

    public override string Key => "QG-CF-SEC-0031";
    public override string Name => "An endpoint that changes data should require authentication";
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var (name, type, properties, _) in Resources(context))
        {
            if (type != "AWS::ApiGateway::Method")
                continue;

            var authorization = properties.Child("AuthorizationType");
            if (authorization == null || authorization.Value != "NONE")
                continue;

            var privileged = IsPrivileged(name);
            if (OpenByDesign.IsMatch(name) && !privileged)
                continue;

            var method = properties.Child("HttpMethod")?.Value;
            var changesData = method != null && ChangingMethods.Contains(method);
            if (!changesData && !privileged)
                continue;

            context.Report($"'{name}' accepts calls without identifying the caller, and it is an "
                           + "endpoint that acts rather than one that only informs. Whoever finds the "
                           + "address can invoke it as often as they like, and the log has nobody to "
                           + "attribute the call to. Require an authorizer or the platform's own "
                           + "signature.", authorization.Line);
        }
    }

    private static bool IsPrivileged(string name)
        => Regex.Split(name, "[-/_]|(?<=[a-z])(?=[A-Z])").Any(PrivilegedNames.Contains);
}

public sealed class CfBackupRetentionRule : CloudFormationSecurityRule
{
    private const int MinimumDays = 7;

    /// <summary>
    /// Engines that keep a continuous backup of their own, so the retention period here does not
    /// decide what can be recovered. Reporting them asks for a setting that changes nothing.
    /// </summary>
    private static readonly HashSet<string> ContinuouslyBackedUp =
        new(StringComparer.OrdinalIgnoreCase) { "aurora", "aurora-mysql", "aurora-postgresql" };

    public override string Key => "QG-CF-SEC-0032";
    public override string Name => "A database should keep backups long enough to recover from";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var (_, type, properties, resource) in Resources(context))
        {
            if (!Applies(type, properties))
                continue;

            var retention = properties.Child("BackupRetentionPeriod");
            if (retention == null)
            {
                context.Report("No backup retention is declared, and the default keeps a single day. "
                               + "A corruption noticed on a Monday morning happened on Friday, and by "
                               + $"then there is nothing left to restore. Set at least {MinimumDays} "
                               + "days.", resource.Line);
                continue;
            }

            if (int.TryParse(retention.Value, out var days) && days < MinimumDays)
                context.Report($"Backups are kept for {days} days. Data loss is usually discovered "
                               + "well after it happens — a bad migration, a deletion nobody "
                               + "questioned — and a window this short means the last good copy is "
                               + $"already gone. Set at least {MinimumDays} days.", retention.Line);
        }
    }

    private static bool Applies(string type, ConfigNode properties)
    {
        if (type == "AWS::RDS::DBCluster")
            return true;
        if (type != "AWS::RDS::DBInstance")
            return false;

        // a read replica has no backup settings of its own: it inherits from the instance it copies,
        // and the retention written here would be ignored
        if (properties.Child("SourceDBInstanceIdentifier") != null)
            return false;

        var engine = properties.Child("Engine")?.Value;
        return engine == null || !ContinuouslyBackedUp.Contains(engine);
    }
}
