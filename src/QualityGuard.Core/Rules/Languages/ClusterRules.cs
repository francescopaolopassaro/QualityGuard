using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// What a cluster declaration leaves unsaid. A manifest is read by a scheduler that fills in a
/// default for everything absent, and the defaults are chosen to let anything run — not to keep it
/// contained. Each rule here names a field whose absence hands a decision to that default.
/// </summary>
public static class ClusterRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new ClusterMemoryRequestRule(),
        new ClusterCpuRequestRule(),
        new ClusterStorageLimitRule(),
        new ClusterDuplicateEnvironmentRule(),
        new ClusterDockerSocketRule()
    ];
}

public abstract class ClusterRuleBase : ConfigRuleBase
{
    public override string[] Languages => ["k8"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "15min";
}

/// <summary>What a container asks the scheduler to reserve for it before it is placed.</summary>
public abstract class ClusterRequestRule : ClusterRuleBase
{
    protected abstract string Resource { get; }

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            if (container.Child("image") == null)
                continue;
            // a container that declares nothing at all is one decision, not four: QG-K8-SML-0004
            // names it once, and this rule speaks only where the block exists and this entry is
            // the one missing from it
            if (container.Child("resources") == null)
                continue;
            var requests = container.At("resources", "requests");
            if (requests?.Child(Resource) != null)
                continue;

            context.Report($"This container asks for no {Resource}, so the scheduler places it as if "
                           + "it needed none and puts it on a node that is already full. The pod is "
                           + $"then the first thing evicted when the node runs short. Declare "
                           + $"resources.requests.{Resource}.", container.Line);
        }
    }
}

public sealed class ClusterMemoryRequestRule : ClusterRequestRule
{
    public override string Key => "QG-K8-SML-0063";
    public override string Name => "A container should ask for the memory it needs";
    protected override string Resource => "memory";
}

public sealed class ClusterCpuRequestRule : ClusterRequestRule
{
    public override string Key => "QG-K8-SML-0064";
    public override string Name => "A container should ask for the processor time it needs";
    protected override string Resource => "cpu";
}

public sealed class ClusterStorageLimitRule : ClusterRuleBase
{
    public override string Key => "QG-K8-SML-0065";
    public override string Name => "A container should have a ceiling on the storage it writes";

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            if (container.Child("image") == null)
                continue;
            var limits = container.At("resources", "limits");
            if (limits?.Child("ephemeral-storage") != null)
                continue;
            // a container with no limits at all is already reported by the rule about limits
            if (limits == null || limits.Children.Count == 0)
                continue;

            context.Report("This container has limits for memory and processor but none for the disk "
                           + "it writes. A log that never rotates then fills the node, and every pod "
                           + "on it is evicted — including ones that had nothing to do with it. "
                           + "Declare resources.limits.ephemeral-storage.", container.Line);
        }
    }
}

public sealed class ClusterDuplicateEnvironmentRule : ClusterRuleBase
{
    public override string Key => "QG-K8-SML-0066";
    public override string Name => "A container should not set the same variable twice";

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            var environment = container.Child("env");
            if (environment == null)
                continue;

            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var entry in environment.Children)
            {
                var name = entry.Child("name")?.Value ?? string.Empty;
                if (name.Length == 0)
                    continue;
                if (seen.TryGetValue(name, out var first))
                {
                    context.Report($"'{name}' is set here and again on line {first}. The runtime keeps "
                                   + "one of the two without saying which, so the value the process "
                                   + "reads is not necessarily the one written last in the file.",
                        entry.Line);
                    continue;
                }
                seen[name] = entry.Line;
            }
        }
    }
}

public sealed class ClusterDockerSocketRule : ClusterRuleBase
{
    public override string Key => "QG-K8-SEC-0024";
    public override string Name => "The container runtime socket should not be mounted into a pod";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Blocker;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var node in context.Config.Descendants())
        {
            // the volume names the mount and holds the hostPath beneath it; reading both reported
            // the same socket twice
            var path = node.Child("hostPath")?.Child("path")?.Value;
            if (path is null)
                continue;
            if (!path.Contains("docker.sock", StringComparison.OrdinalIgnoreCase)
                && !path.Contains("containerd.sock", StringComparison.OrdinalIgnoreCase)
                && !path.Contains("crio.sock", StringComparison.OrdinalIgnoreCase))
                continue;

            context.Report("This mounts the socket the container runtime listens on. Anything that can "
                           + "write to it can start a container of its own, with any image and any "
                           + "mount — which is root on the node, whatever this pod was allowed to do.",
                node.Line);
        }
    }
}
