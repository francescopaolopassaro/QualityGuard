using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class DockerRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new DockerUserRootRule(),
        new DockerCurlPipeShellRule(),
        new DockerCleartextDownloadRule(),
        new DockerRemoteAddRule(),
        new DockerEnvSecretRule(),
        new DockerExposedSshPortRule(),
        new DockerWorldWritableRule(),
        new DockerSkipCertValidationRule(),
        new DockerInstallMissingFlagsRule(),
        new DockerUnpinnedFromRule(),
        new DockerMissingHealthcheckRule(),
        new DockerDeprecatedMaintainerRule(),
        new DockerMissingWorkdirRule(),
        new DockerShellFormCommandRule()
    ];
}

internal static class DockerLine
{
    public static bool Is(string line, string instruction)
    {
        var trimmed = line.TrimStart();
        if (!trimmed.StartsWith(instruction, StringComparison.OrdinalIgnoreCase))
            return false;
        return trimmed.Length == instruction.Length || char.IsWhiteSpace(trimmed[instruction.Length]);
    }

    public static string Rest(string line, string instruction)
    {
        var trimmed = line.TrimStart();
        return trimmed.Length > instruction.Length ? trimmed[instruction.Length..].Trim() : string.Empty;
    }
}

public sealed class DockerUserRootRule : PatternRuleBase
{
    public override string Key => "QG-DK-SEC-0001";
    public override string Name => "Container runs as root";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Run the container as a non-root user (USER 1000 or a dedicated user).";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (!DockerLine.Is(lines[i], "USER"))
                continue;
            var rest = DockerLine.Rest(lines[i], "USER");
            if (rest.Length == 0)
                continue;
            var words = RuleMatchers.SplitWords(rest);
            if (words.Any(w => w.Equals("root", StringComparison.OrdinalIgnoreCase)
                || w == "0"
                || w.StartsWith("root:", StringComparison.OrdinalIgnoreCase)
                || w.StartsWith("0:")))
                context.Report("Do not run the container as the root user.", i + 1);
        }
    }
}

public sealed class DockerCurlPipeShellRule : PatternRuleBase
{
    public override string Key => "QG-DK-SEC-0002";
    public override string Name => "Remote script piped directly into a shell";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Download the script, verify its checksum and signature, then execute it.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if ((RuleMatchers.LineContains(line, "curl") || RuleMatchers.LineContains(line, "wget"))
                && line.Contains('|')
                && (RuleMatchers.LineContains(line, "sh") || RuleMatchers.LineContains(line, "bash")))
                context.Report("Do not pipe remote scripts directly into a shell.", i + 1);
        }
    }
}

public sealed class DockerCleartextDownloadRule : PatternRuleBase
{
    public override string Key => "QG-DK-SEC-0003";
    public override string Name => "Download over cleartext HTTP";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use HTTPS to prevent man-in-the-middle tampering of downloads.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "curl http://")
                || RuleMatchers.LineContains(lines[i], "wget http://"))
                context.Report("Download over HTTPS instead of cleartext HTTP.", i + 1);
        }
    }
}

public sealed class DockerRemoteAddRule : PatternRuleBase
{
    public override string Key => "QG-DK-SEC-0004";
    public override string Name => "ADD copies a remote URL into the image";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use COPY or a RUN download (with checksum verification) instead of ADD for remote URLs.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (DockerLine.Is(lines[i], "ADD")
                && (RuleMatchers.LineContains(lines[i], "http://")
                    || RuleMatchers.LineContains(lines[i], "https://")))
                context.Report("Do not use ADD to fetch remote content.", i + 1);
        }
    }
}

public sealed class DockerEnvSecretRule : PatternRuleBase
{
    public override string Key => "QG-DK-SEC-0005";
    public override string Name => "Secret stored in an ENV instruction";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Inject secrets at runtime instead of baking them into the image.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (DockerLine.Is(lines[i], "ENV")
                && (RuleMatchers.LineContains(lines[i], "PASSWORD")
                    || RuleMatchers.LineContains(lines[i], "SECRET")
                    || RuleMatchers.LineContains(lines[i], "TOKEN")
                    || RuleMatchers.LineContains(lines[i], "API_KEY")))
                context.Report("Do not bake secrets into environment variables.", i + 1);
        }
    }
}

public sealed class DockerExposedSshPortRule : PatternRuleBase
{
    public override string Key => "QG-DK-SEC-0006";
    public override string Name => "Container exposes an SSH or management port";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Do not expose SSH (22) or RDP (3389) ports from the container.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (!DockerLine.Is(lines[i], "EXPOSE"))
                continue;
            var ports = RuleMatchers.SplitWords(lines[i]);
            if (ports.Any(w => w == "22" || w.StartsWith("22/") || w == "3389" || w.StartsWith("3389/")))
                context.Report("Do not expose SSH or RDP management ports.", i + 1);
        }
    }
}

public sealed class DockerWorldWritableRule : PatternRuleBase
{
    public override string Key => "QG-DK-SEC-0007";
    public override string Name => "Files are made world-writable";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use restrictive permissions and chown files to a non-root user.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "chmod")
                && RuleMatchers.LineContains(lines[i], "777"))
                context.Report("Avoid world-writable permissions (chmod 777).", i + 1);
        }
    }
}

public sealed class DockerSkipCertValidationRule : PatternRuleBase
{
    public override string Key => "QG-DK-SEC-0008";
    public override string Name => "TLS certificate validation is disabled";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Keep certificate validation enabled for all downloads.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "--no-check-certificate")
                || RuleMatchers.LineContains(line, "--insecure")
                || RuleMatchers.LineContains(line, "-k ")
                || RuleMatchers.LineEndsWith(line, "-k"))
                context.Report("Do not disable certificate validation.", i + 1);
        }
    }
}

public sealed class DockerInstallMissingFlagsRule : PatternRuleBase
{
    public override string Key => "QG-DK-SML-0001";
    public override string Name => "Package installation may run interactively";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use -y and --no-install-recommends for deterministic, minimal package installation.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var installs = RuleMatchers.LineContains(line, "apt-get install")
                || RuleMatchers.LineContains(line, "apt install")
                || RuleMatchers.LineContains(line, "apk add")
                || RuleMatchers.LineContains(line, "yum install");
            if (installs && !RuleMatchers.LineContains(line, "-y"))
                context.Report("Add -y to avoid interactive prompts during package installation.", i + 1);
        }
    }
}

public sealed class DockerUnpinnedFromRule : PatternRuleBase
{
    public override string Key => "QG-DK-SML-0002";
    public override string Name => "Base image is not pinned";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Pin the base image to a fixed tag or digest.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (!DockerLine.Is(lines[i], "FROM"))
                continue;
            var rest = DockerLine.Rest(lines[i], "FROM");
            var words = RuleMatchers.SplitWords(rest).Where(w => !w.StartsWith("--")).ToArray();
            if (words.Length == 0)
                continue;
            var image = words[0];
            if (image.Equals("scratch", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!image.Contains(':'))
                context.Report("Pin the base image to a specific tag or digest.", i + 1);
            else if (image.EndsWith(":latest", StringComparison.OrdinalIgnoreCase))
                context.Report("Avoid using the :latest tag for the base image.", i + 1);
        }
    }
}

public sealed class DockerMissingHealthcheckRule : PatternRuleBase
{
    public override string Key => "QG-DK-SML-0003";
    public override string Name => "Container image has no HEALTHCHECK";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Define a HEALTHCHECK so the runtime can detect a failing process.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasFrom = false;
        var hasHealthcheck = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (DockerLine.Is(lines[i], "FROM"))
                hasFrom = true;
            if (DockerLine.Is(lines[i], "HEALTHCHECK"))
                hasHealthcheck = true;
        }
        if (hasFrom && !hasHealthcheck)
            context.Report("Define a HEALTHCHECK for the container.", 1);
    }
}

public sealed class DockerDeprecatedMaintainerRule : PatternRuleBase
{
    public override string Key => "QG-DK-SML-0004";
    public override string Name => "MAINTAINER is deprecated";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use the LABEL maintainer instruction instead of MAINTAINER.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (DockerLine.Is(lines[i], "MAINTAINER"))
                context.Report("MAINTAINER is deprecated; use LABEL instead.", i + 1);
        }
    }
}

public sealed class DockerMissingWorkdirRule : PatternRuleBase
{
    public override string Key => "QG-DK-SML-0005";
    public override string Name => "Container image has no WORKDIR";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Set a WORKDIR for the container.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasFrom = false;
        var hasWorkdir = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (DockerLine.Is(lines[i], "FROM"))
                hasFrom = true;
            if (DockerLine.Is(lines[i], "WORKDIR"))
                hasWorkdir = true;
        }
        if (hasFrom && !hasWorkdir)
            context.Report("Set a WORKDIR for the container.", 1);
    }
}

public sealed class DockerShellFormCommandRule : PatternRuleBase
{
    public override string Key => "QG-DK-CNV-0001";
    public override string Name => "CMD or ENTRYPOINT uses shell form";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use the exec form (JSON array) for CMD and ENTRYPOINT.";
    public override string[] Languages => ["dk"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var isCommand = DockerLine.Is(lines[i], "CMD") || DockerLine.Is(lines[i], "ENTRYPOINT");
            if (!isCommand)
                continue;
            var rest = DockerLine.Is(lines[i], "CMD")
                ? DockerLine.Rest(lines[i], "CMD")
                : DockerLine.Rest(lines[i], "ENTRYPOINT");
            if (!rest.TrimStart().StartsWith("["))
                context.Report("Prefer the exec form (JSON array) for CMD and ENTRYPOINT.", i + 1);
        }
    }
}