using System.Text.RegularExpressions;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Instructions that widen what the built image can do or what it exposes. An image is built once
/// and then runs everywhere unchanged, so a flag added to get a build working locally ships with it
/// and keeps working — which is exactly why nobody goes back to remove it.
/// </summary>
public static class DockerSecurityRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new DockerDebugEnvironmentRule(),
        new DockerHostNetworkRule(),
        new DockerMountPermissionRule(),
        new DockerInsecureBuilderRule(),
        new DockerCopiedOwnershipRule()
    ];
}

public abstract class DockerSecurityRule : DockerfileRuleBase
{
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    /// <summary>
    /// The instructions that end up in the image being built, which is the last stage of the file.
    /// Everything a builder stage does is thrown away when the build finishes, so judging those
    /// instructions reports settings that never reach anything that runs.
    /// </summary>
    protected static IEnumerable<(int Line, string Instruction, string Arguments)> FinalImage(IRuleContext context)
    {
        var steps = Steps(context).ToList();
        var lastStage = steps.FindLastIndex(step =>
            string.Equals(step.Instruction, "FROM", StringComparison.OrdinalIgnoreCase));
        return lastStage < 0 ? steps : steps.Skip(lastStage);
    }

    /// <summary>The flags written before an instruction's arguments, as in <c>RUN --mount=... cmd</c>.</summary>
    protected static IEnumerable<string> Flags(string arguments)
    {
        foreach (var word in arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!word.StartsWith("--", StringComparison.Ordinal))
                yield break;
            yield return word;
        }
    }
}

public sealed class DockerDebugEnvironmentRule : DockerSecurityRule
{
    private static readonly Regex EnvironmentName = new(@"^([_A-Z]+)?ENV(IRONMENT)?$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex DevelopmentValue = new(@"^dev(el(op(ment)?)?)?$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex DebugName = new(@"^([_A-Z]+)?DEBUG$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex DebugValue = new(@"^(true|yes|on|1)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public override string Key => "QG-DK-SEC-0009";
    public override string Name => "A shipped image should not switch on debugging features";
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        foreach (var (line, instruction, arguments) in FinalImage(context))
        {
            if (!string.Equals(instruction, "ENV", StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var (name, value) in Assignments(arguments))
            {
                if (!IsDebugging(name, value))
                    continue;

                context.Report($"'{name}={value}' leaves a development setting switched on in the "
                               + "image that ships. What it turns on is usually a page that prints "
                               + "the stack trace, the configuration and the query that failed — to "
                               + "whoever caused the error. Set it in the local environment only.",
                    line);
            }
        }
    }

    private static bool IsDebugging(string name, string value)
        => (EnvironmentName.IsMatch(name) && DevelopmentValue.IsMatch(value))
           || (DebugName.IsMatch(name) && DebugValue.IsMatch(value))
           || (name.EndsWith("XDEBUG_MODE", StringComparison.OrdinalIgnoreCase)
               && !string.Equals(value, "off", StringComparison.OrdinalIgnoreCase));

    /// <summary>The variables an ENV instruction sets, in either of the forms it accepts.</summary>
    private static IEnumerable<(string Name, string Value)> Assignments(string arguments)
    {
        var text = arguments.Trim();
        if (!text.Contains('='))
        {
            var space = text.IndexOf(' ');
            if (space > 0)
                yield return (text[..space], Unquote(text[(space + 1)..]));
            yield break;
        }

        foreach (var pair in SplitOutsideQuotes(text))
        {
            var equals = pair.IndexOf('=');
            if (equals > 0)
                yield return (pair[..equals].Trim(), Unquote(pair[(equals + 1)..]));
        }
    }

    private static IEnumerable<string> SplitOutsideQuotes(string text)
    {
        var quoted = false;
        var start = 0;
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '"')
                quoted = !quoted;
            else if (text[i] == ' ' && !quoted)
            {
                if (i > start)
                    yield return text[start..i];
                start = i + 1;
            }
        }
        if (start < text.Length)
            yield return text[start..];
    }

    private static string Unquote(string text) => text.Trim().Trim('"').Trim('\'').Trim();
}

public sealed class DockerHostNetworkRule : DockerSecurityRule
{
    public override string Key => "QG-DK-SEC-0011";
    public override string Name => "A build step should not run in the network of its host";

    public override void Execute(IRuleContext context)
    {
        foreach (var (line, instruction, arguments) in Steps(context))
        {
            if (!string.Equals(instruction, "RUN", StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var flag in Flags(arguments))
            {
                if (!flag.Equals("--network=host", StringComparison.OrdinalIgnoreCase))
                    continue;

                context.Report("This step runs in the network namespace of the machine that builds "
                               + "the image, so whatever it downloads and executes reaches services "
                               + "that are only meant to be reachable from inside that machine — "
                               + "including the ones a build agent keeps unauthenticated. Let the "
                               + "step use the default isolated network.", line);
            }
        }
    }
}

public sealed class DockerMountPermissionRule : DockerSecurityRule
{
    private static readonly Regex MountType = new(@"type=(secret|ssh)", RegexOptions.Compiled);
    private static readonly Regex MountMode = new(@"mode=(\d+)", RegexOptions.Compiled);

    public override string Key => "QG-DK-SEC-0012";
    public override string Name => "A mounted secret should not be readable by every user";
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        foreach (var (line, instruction, arguments) in Steps(context))
        {
            if (!string.Equals(instruction, "RUN", StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var flag in Flags(arguments))
            {
                if (!flag.StartsWith("--mount=", StringComparison.OrdinalIgnoreCase))
                    continue;

                var type = MountType.Match(flag);
                var mode = MountMode.Match(flag);
                if (!type.Success || !mode.Success)
                    continue;

                var permissions = mode.Groups[1].Value;
                // the last digit is what everyone else on the system is granted; the rest describe
                // the owner and the group, which are the ones meant to read it
                if (permissions[^1] == '0')
                    continue;

                var what = type.Groups[1].Value == "secret" ? "secret file" : "agent socket";
                context.Report($"This {what} is mounted with mode {permissions}, so every account "
                               + "inside the build step can read it — including anything a dependency "
                               + "runs during installation. Give the mode a trailing 0 so only the "
                               + "owner has access.", line);
            }
        }
    }
}

public sealed class DockerInsecureBuilderRule : DockerSecurityRule
{
    public override string Key => "QG-DK-SEC-0017";
    public override string Name => "A build step should not disable the builder sandbox";
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        foreach (var (line, instruction, arguments) in Steps(context))
        {
            if (!string.Equals(instruction, "RUN", StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var flag in Flags(arguments))
            {
                if (!flag.Equals("--security=insecure", StringComparison.OrdinalIgnoreCase))
                    continue;

                context.Report("This step runs without the sandbox, which means the command has the "
                               + "privileges of the build machine rather than those of a container. "
                               + "Every dependency the step fetches inherits them, and a build agent "
                               + "usually holds credentials for far more than this image. Remove the "
                               + "flag and give the step the specific capability it needs.", line);
            }
        }
    }
}

public sealed class DockerCopiedOwnershipRule : DockerSecurityRule
{
    private static readonly Regex SystemPath =
        new(@"^/(bin|boot|dev|etc|lib|lib32|lib64|proc|root|usr|sbin)(/.*)?$", RegexOptions.Compiled);

    private static readonly Regex ExecutableFile =
        new(@"\.(sh|bash|zsh|fish|py|rb|pl|php|bin|elf|so|service|timer|socket)$", RegexOptions.Compiled);

    private static readonly HashSet<string> RootOwners =
        new(StringComparer.OrdinalIgnoreCase) { "root", "0", "root:root", "0:0" };

    public override string Key => "QG-DK-SEC-0018";
    public override string Name => "An executable copied into an image should stay owned by root";
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        foreach (var (line, instruction, arguments) in Steps(context))
        {
            if (!string.Equals(instruction, "COPY", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(instruction, "ADD", StringComparison.OrdinalIgnoreCase))
                continue;

            var owner = Flags(arguments)
                .FirstOrDefault(f => f.StartsWith("--chown=", StringComparison.OrdinalIgnoreCase));
            if (owner == null || RootOwners.Contains(owner["--chown=".Length..]))
                continue;

            var paths = arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Where(word => !word.StartsWith("--", StringComparison.Ordinal))
                .ToList();
            if (paths.Count == 0)
                continue;

            var destination = paths[^1].Trim('"');
            var sources = paths[..^1];
            var sensitive = SystemPath.IsMatch(destination)
                            || sources.Any(source => ExecutableFile.IsMatch(source.Trim('"')));
            if (!sensitive)
                continue;

            context.Report($"What is copied here belongs to '{owner["--chown=".Length..]}' rather "
                           + "than to root, and it is either a program or a file in a system "
                           + "directory. Anything running as that account can rewrite it, so a "
                           + "process that is compromised once keeps its foothold across every "
                           + "restart. Copy it as root and give the runtime user read access only.",
                line);
        }
    }
}
