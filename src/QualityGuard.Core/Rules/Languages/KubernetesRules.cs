using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class KubernetesRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new KubernetesPrivilegedContainerRule(),
        new KubernetesPrivilegeEscalationRule(),
        new KubernetesRunAsNonRootRule(),
        new KubernetesRunAsUserRootRule(),
        new KubernetesMissingSecurityContextRule(),
        new KubernetesHostNamespaceRule(),
        new KubernetesAddCapabilitiesRule(),
        new KubernetesSecretsInEnvRule(),
        new KubernetesAutomountTokenRule(),
        new KubernetesUnpinnedImageRule(),
        new KubernetesReadOnlyRootFsRule(),
        new KubernetesMissingProbesRule(),
        new KubernetesMissingResourcesRule(),
        new KubernetesMissingAppLabelRule()
    ];
}

internal static class KubernetesLine
{
    public static bool Starts(string line, string key)
        => line.TrimStart().StartsWith(key, StringComparison.OrdinalIgnoreCase);
}

public sealed class KubernetesPrivilegedContainerRule : PatternRuleBase
{
    public override string Key => "QG-K8-SEC-0001";
    public override string Name => "Container runs in privileged mode";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Remove privileged mode and grant only the capabilities the container needs.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "privileged")
                && RuleMatchers.LineContains(lines[i], "true"))
                context.Report("Do not run containers in privileged mode.", i + 1);
        }
    }
}

public sealed class KubernetesPrivilegeEscalationRule : PatternRuleBase
{
    public override string Key => "QG-K8-SEC-0002";
    public override string Name => "Privilege escalation is allowed";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set allowPrivilegeEscalation to false.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "allowPrivilegeEscalation")
                && RuleMatchers.LineContains(lines[i], "true"))
                context.Report("Disable privilege escalation for the container.", i + 1);
        }
    }
}

public sealed class KubernetesRunAsNonRootRule : PatternRuleBase
{
    public override string Key => "QG-K8-SEC-0003";
    public override string Name => "Container may run as root";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set runAsNonRoot to true and define a non-zero runAsUser.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "runAsNonRoot")
                && RuleMatchers.LineContains(lines[i], "false"))
                context.Report("Enable runAsNonRoot for the container.", i + 1);
        }
    }
}

public sealed class KubernetesRunAsUserRootRule : PatternRuleBase
{
    public override string Key => "QG-K8-SEC-0004";
    public override string Name => "Container runs as the root user";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Run the container as a non-root user (runAsUser other than 0).";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "runAsUser")
                && RuleMatchers.SplitWords(lines[i]).Any(w => w == "0"))
                context.Report("Do not run the container as root.", i + 1);
        }
    }
}

public sealed class KubernetesMissingSecurityContextRule : PatternRuleBase
{
    public override string Key => "QG-K8-SEC-0005";
    public override string Name => "Container has no securityContext";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Define a securityContext that runs the container as an unprivileged non-root user.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var containersLine = 0;
        var hasSecurityContext = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (KubernetesLine.Starts(lines[i], "containers:"))
                containersLine = i + 1;
            if (RuleMatchers.LineContains(lines[i], "securityContext"))
                hasSecurityContext = true;
        }
        if (containersLine > 0 && !hasSecurityContext)
            context.Report("Define a securityContext for containers.", containersLine);
    }
}

public sealed class KubernetesHostNamespaceRule : PatternRuleBase
{
    public override string Key => "QG-K8-SEC-0006";
    public override string Name => "Container shares the host namespace";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not enable hostNetwork, hostPID or hostIPC.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var sharesHost = RuleMatchers.LineContains(line, "hostNetwork")
                || RuleMatchers.LineContains(line, "hostPID")
                || RuleMatchers.LineContains(line, "hostIPC");
            if (sharesHost && RuleMatchers.LineContains(line, "true"))
                context.Report("Do not share the host network, PID or IPC namespace.", i + 1);
        }
    }
}

public sealed class KubernetesAddCapabilitiesRule : PatternRuleBase
{
    public override string Key => "QG-K8-SEC-0007";
    public override string Name => "Container is granted powerful capabilities";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Drop all capabilities and add only the minimal required set.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "SYS_ADMIN")
                || RuleMatchers.LineContains(line, "NET_ADMIN")
                || (RuleMatchers.LineContains(line, "ALL") && RuleMatchers.LineContains(line, "capabilities")))
                context.Report("Grant only the capabilities the container needs.", i + 1);
        }
    }
}

public sealed class KubernetesSecretsInEnvRule : PatternRuleBase
{
    public override string Key => "QG-K8-SEC-0008";
    public override string Name => "Secret exposed as an environment value";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Mount secrets as files or use secretKeyRef references instead of literal values.";
    public override string[] Languages => ["k8"];

    private static readonly string[] SecretNames = ["PASSWORD", "SECRET", "TOKEN", "API_KEY"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i].TrimStart();
            if (!line.StartsWith("value:", StringComparison.OrdinalIgnoreCase))
                continue;
            var prev = lines[i - 1].TrimStart();
            if (!prev.StartsWith("name:", StringComparison.OrdinalIgnoreCase))
                continue;
            if (SecretNames.Any(n => prev.Contains(n, StringComparison.OrdinalIgnoreCase)))
                context.Report("Do not place secrets in environment variables.", i + 1);
        }
    }
}

public sealed class KubernetesAutomountTokenRule : PatternRuleBase
{
    public override string Key => "QG-K8-SEC-0009";
    public override string Name => "Service account token is automatically mounted";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set automountServiceAccountToken to false when the pod does not need the API.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "automountServiceAccountToken")
                && RuleMatchers.LineContains(lines[i], "true"))
                context.Report("Do not automatically mount the service account token.", i + 1);
        }
    }
}

public sealed class KubernetesUnpinnedImageRule : PatternRuleBase
{
    public override string Key => "QG-K8-SML-0001";
    public override string Name => "Container image is not pinned";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Pin the image to a specific tag or digest.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].TrimStart();
            if (!trimmed.StartsWith("image:", StringComparison.OrdinalIgnoreCase))
                continue;
            var value = trimmed["image:".Length..].Trim();
            if (value.Length == 0 || value.StartsWith('$'))
                continue;
            if (value.Contains(":latest", StringComparison.OrdinalIgnoreCase)
                || !value.Contains(':'))
                context.Report("Pin the container image to a specific tag or digest.", i + 1);
        }
    }
}

public sealed class KubernetesReadOnlyRootFsRule : PatternRuleBase
{
    public override string Key => "QG-K8-SML-0002";
    public override string Name => "Container root filesystem is writable";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Set readOnlyRootFilesystem to true and write only to mounted volumes.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var containersLine = 0;
        var hasReadOnlyRoot = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (KubernetesLine.Starts(lines[i], "containers:"))
                containersLine = i + 1;
            if (RuleMatchers.LineContains(lines[i], "readOnlyRootFilesystem"))
                hasReadOnlyRoot = true;
        }
        if (containersLine > 0 && !hasReadOnlyRoot)
            context.Report("Mount the root filesystem as read-only.", containersLine);
    }
}

public sealed class KubernetesMissingProbesRule : PatternRuleBase
{
    public override string Key => "QG-K8-SML-0003";
    public override string Name => "Container has no liveness or readiness probe";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Define liveness and readiness probes for the container.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var containersLine = 0;
        var hasProbes = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (KubernetesLine.Starts(lines[i], "containers:"))
                containersLine = i + 1;
            if (RuleMatchers.LineContains(lines[i], "livenessProbe")
                || RuleMatchers.LineContains(lines[i], "readinessProbe"))
                hasProbes = true;
        }
        if (containersLine > 0 && !hasProbes)
            context.Report("Define liveness and readiness probes for the container.", containersLine);
    }
}

public sealed class KubernetesMissingResourcesRule : PatternRuleBase
{
    public override string Key => "QG-K8-SML-0004";
    public override string Name => "Container has no resource limits";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Define resource requests and limits for the container.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var containersLine = 0;
        var hasResources = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (KubernetesLine.Starts(lines[i], "containers:"))
                containersLine = i + 1;
            if (KubernetesLine.Starts(lines[i], "resources:"))
                hasResources = true;
        }
        if (containersLine > 0 && !hasResources)
            context.Report("Define resource requests and limits for the container.", containersLine);
    }
}

public sealed class KubernetesMissingAppLabelRule : PatternRuleBase
{
    public override string Key => "QG-K8-CNV-0001";
    public override string Name => "Workload has no app label";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Add an app label that identifies the workload for selectors and matching labels.";
    public override string[] Languages => ["k8"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasMetadata = false;
        var hasWorkload = false;
        var hasAppLabel = false;
        var reportLine = 0;
        for (var i = 0; i < lines.Length; i++)
        {
            if (KubernetesLine.Starts(lines[i], "metadata:"))
                hasMetadata = true;
            if (KubernetesLine.Starts(lines[i], "containers:"))
                hasWorkload = true;
            if (RuleMatchers.LineContains(lines[i], "app:"))
                hasAppLabel = true;
            if (hasMetadata && reportLine == 0)
                reportLine = i + 1;
        }
        if (hasMetadata && !hasAppLabel && (hasWorkload || hasLabels(lines)))
            context.Report("Add an app label to identify the workload.", reportLine);
    }

    private static bool hasLabels(string[] lines)
        => lines.Any(l => KubernetesLine.Starts(l, "labels:"));
}