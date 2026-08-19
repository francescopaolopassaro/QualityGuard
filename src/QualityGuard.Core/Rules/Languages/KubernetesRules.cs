using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class KubernetesRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new KubernetesAddCapabilitiesRule(),
        new KubernetesSecretsInEnvRule(),
        new KubernetesAutomountTokenRule()
    ];
}

internal static class KubernetesLine
{
    public static bool Starts(string line, string key)
        => line.TrimStart().StartsWith(key, StringComparison.OrdinalIgnoreCase);
}

public sealed class KubernetesMissingSecurityContextRule : PatternRuleBase
{
    public override string Key => "QG-K8-SEC-0005";
    public override string Name => "Container has no securityContext";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Define a securityContext that runs the container as an unprivileged non-root user.";
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

public sealed class KubernetesAddCapabilitiesRule : ConfigRuleBase
{
    public override string Key => "QG-K8-SEC-0007";
    public override string Name => "Container is granted powerful capabilities";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Drop all capabilities and add only the minimal required set.";
    public override string[] Languages => ["k8"];

    /// <summary>Capabilities that hand the container the host: the kernel treats them as root.</summary>
    private static readonly string[] Dangerous =
        ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_BOOT", "DAC_READ_SEARCH", "ALL"];

    public override void Execute(IRuleContext context)
    {
        foreach (var container in Containers(context))
        {
            var added = container.At("securityContext", "capabilities", "add");
            if (added == null)
                continue;

            foreach (var (name, line) in Granted(added))
            {
                if (!Dangerous.Contains(name, StringComparer.OrdinalIgnoreCase))
                    continue;

                context.Report($"This container is granted '{name}', which lets it act on the node "
                               + "rather than inside its own boundary — mounting host paths, reading "
                               + "other processes, changing the kernel. Drop everything and add back "
                               + "only what the process actually calls.", line);
            }
        }
    }

    /// <summary>
    /// The capabilities listed under 'add', however the manifest spells the list: inline between
    /// brackets, or one item per line — where the reader files the name as the key of the item.
    /// Matching the name anywhere in the file instead reported the policies written to forbid them.
    /// </summary>
    private static IEnumerable<(string Name, int Line)> Granted(ConfigNode added)
    {
        if (added.Value.Length > 0)
        {
            foreach (var name in added.Value.Split('[', ']', ',', '"', '\''))
                if (name.Trim().Length > 0)
                    yield return (name.Trim(), added.Line);
            yield break;
        }

        foreach (var item in added.Descendants())
        {
            var name = item.Value.Length > 0 ? item.Value : item.Key;
            if (name.Trim().Length > 0)
                yield return (name.Trim(), item.Line);
        }
    }
}

public sealed class KubernetesSecretsInEnvRule : PatternRuleBase
{
    public override string Key => "QG-K8-SEC-0008";
    public override string Name => "Secret exposed as an environment value";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Mount secrets as files or use secretKeyRef references instead of literal values.";
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
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Set automountServiceAccountToken to false when the pod does not need the API.";
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

public sealed class KubernetesMissingProbesRule : PatternRuleBase
{
    public override string Key => "QG-K8-SML-0003";
    public override string Name => "Container has no liveness or readiness probe";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Define liveness and readiness probes for the container.";
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

public sealed class KubernetesMissingAppLabelRule : PatternRuleBase
{
    public override string Key => "QG-K8-CNV-0001";
    public override string Name => "Workload has no app label";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Add an app label that identifies the workload for selectors and matching labels.";
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