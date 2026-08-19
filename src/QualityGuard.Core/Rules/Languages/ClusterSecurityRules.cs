using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// What a manifest hands to a container beyond the code inside it: kernel capabilities, the node's
/// own namespaces, a port that reaches a maintenance service, a role that allows running commands in
/// somebody else's pod. Each of these is a decision written once in a file that is applied
/// automatically, and none of them produces a failure when it is wrong.
/// </summary>
public static class ClusterSecurityRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new ClusterAddedCapabilitiesRule(),
        new ClusterHostNamespaceRule(),
        new ClusterAdministrationPortRule(),
        new ClusterCommandExecutionRoleRule()
    ];
}

public abstract class ClusterSecurityRule : ConfigRuleBase
{
    public override string[] Languages => ["k8"];
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    /// <summary>The value of the manifest's kind, which decides what the rest of the file means.</summary>
    protected static string KindOf(IRuleContext context)
        => context.Config.Descendants().FirstOrDefault(n => n.Key == "kind")?.Value ?? string.Empty;
}

public sealed class ClusterAddedCapabilitiesRule : ClusterSecurityRule
{
    /// <summary>
    /// The capabilities that let a process act on the node rather than inside its own boundary.
    /// Reporting every addition is the wider reading, and it costs more than it gives: a container
    /// that drops everything and adds back the one capability it needs to bind a low port has made
    /// the right decision, and calling that a finding teaches readers to skip the rule.
    /// </summary>
    private static readonly HashSet<string> HostLevel = new(StringComparer.OrdinalIgnoreCase)
    {
        "SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE", "SYS_MODULE", "SYS_BOOT", "SYS_RAWIO",
        "SYS_TIME", "DAC_READ_SEARCH", "MAC_ADMIN", "MAC_OVERRIDE", "ALL"
    };

    public override string Key => "QG-K8-SEC-0011";
    public override string Name => "A container should not be granted extra kernel capabilities";

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            var added = container.At("securityContext", "capabilities", "add");
            if (added == null)
                continue;

            var capabilities = Items(added).Select(item => item.Text)
                .Where(HostLevel.Contains).ToList();
            if (capabilities.Count == 0)
                continue;

            context.Report($"This container is granted {string.Join(", ", capabilities)}, which the "
                           + "kernel withholds from an ordinary process for a reason: each one lifts "
                           + "a restriction that separates the container from the node it runs on. "
                           + "Whatever the process is made to execute inherits them. Drop the "
                           + "capability and give the workload the narrower mechanism it needs.",
                added.Line);
        }
    }
}

public sealed class ClusterHostNamespaceRule : ClusterSecurityRule
{
    private static readonly string[] HostNamespaces = ["hostPID", "hostIPC", "hostNetwork"];

    public override string Key => "QG-K8-SEC-0015";
    public override string Name => "A container should not share the namespaces of its host";

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

                context.Report($"'{name}' puts this pod in the node's own namespace, so it sees and "
                               + "can reach what every other workload on that node is doing — its "
                               + "processes, its local sockets, its inter-process channels. The "
                               + "isolation the cluster is built on stops at this line. Remove it, "
                               + "and expose what the pod actually needs instead.", shared.Line);
            }
        }
    }
}

public sealed class ClusterAdministrationPortRule : ClusterSecurityRule
{
    /// <summary>
    /// Ports that belong to remote administration rather than to an application. They are the ones
    /// worth naming: a container that publishes them is offering a way in that bypasses whatever the
    /// application in front of it checks.
    /// </summary>
    private static readonly HashSet<string> AdministrationPorts = ["22", "23", "3389", "5800", "5900"];

    public override string Key => "QG-K8-SEC-0016";
    public override string Name => "A workload should not expose a remote administration port";
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        if (!IsKubernetes(context))
            return;

        foreach (var container in Containers(context))
        {
            foreach (var port in container.ChildrenNamed("ports").SelectMany(p => p.Children))
            {
                var declared = port.Child("containerPort");
                if (declared != null && AdministrationPorts.Contains(declared.Value))
                    Report(context, declared.Value, declared.Line);
            }
        }

        if (KindOf(context) != "Service")
            return;

        foreach (var spec in context.Config.Descendants().Where(n => n.Key == "spec"))
        {
            foreach (var port in spec.ChildrenNamed("ports").SelectMany(p => p.Children))
            {
                var declared = port.Child("port") ?? port.Child("targetPort");
                if (declared != null && AdministrationPorts.Contains(declared.Value))
                    Report(context, declared.Value, declared.Line);
            }
        }
    }

    private static void Report(IRuleContext context, string port, int line)
        => context.Report($"Port {port} is a remote administration service. Reaching a container this "
                          + "way skips everything the application in front of it verifies, and the "
                          + "credentials it accepts are usually the ones baked into the image. Remove "
                          + "the port and use the cluster's own mechanism to run a command in a pod.",
            line);
}

public sealed class ClusterCommandExecutionRoleRule : ClusterSecurityRule
{
    private static readonly string[] RoleKinds = ["Role", "ClusterRole"];

    public override string Key => "QG-K8-SEC-0020";
    public override string Name => "A role should not allow running commands inside pods";
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!RoleKinds.Contains(KindOf(context)))
            return;

        foreach (var rules in context.Config.Descendants().Where(n => n.Key == "rules"))
        {
            foreach (var rule in rules.Children)
            {
                if (!AppliesToCoreGroup(rule) || !Allows(rule, "verbs", "create")
                    || !Allows(rule, "resources", "pods/exec"))
                    continue;

                var reported = rule.Child("resources") ?? rule;
                context.Report("This role allows creating a pod exec session, which is a shell inside "
                               + "a running container: the holder reads the files, the mounted "
                               + "secrets and the service account token of a workload it does not "
                               + "own, and does so with that workload's identity. Remove the "
                               + "permission and grant it only where a person needs to debug.",
                    reported.Line);
            }
        }
    }

    /// <summary>
    /// Whether the rule covers the group pods live in. That group is written as an empty string, and
    /// an empty string is not a value the tree can carry, so an api group list that names nothing is
    /// exactly the core group being selected.
    /// </summary>
    private static bool AppliesToCoreGroup(ConfigNode rule)
    {
        var groups = rule.Child("apiGroups");
        if (groups == null)
            return false;
        var named = Items(groups).Select(item => item.Text).ToList();
        return named.Count == 0 || named.Contains("*");
    }

    private static bool Allows(ConfigNode rule, string key, string wanted)
    {
        var declared = Items(rule.Child(key)).Select(item => item.Text).ToList();
        return declared.Contains(wanted) || declared.Contains("*");
    }
}
