using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// A Dockerfile is a short program with a long shadow: every instruction becomes a layer, and the
/// mistakes in it are silent — an image that rebuilds differently, a context copied whole, a command
/// that is never the one that runs. These rules read the instruction list, which is all a Dockerfile
/// is, and report the shapes that behave differently from how they read.
/// </summary>
public static class DockerfileRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new DockerInstructionCaseRule(),
        new DockerRelativeWorkdirRule(),
        new DockerRepeatedEntrypointRule(),
        new DockerAddForLocalFilesRule(),
        new DockerWholeContextCopiedRule(),
        new DockerSpaceBeforeEqualsRule(),
        new DockerConsecutiveRunRule()
    ];
}

public abstract class DockerfileRuleBase : RuleBase
{
    protected static readonly string[] Instructions =
    [
        "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT",
        "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL"
    ];

    public override string[] Languages => ["dk"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    /// <summary>Instruction lines, with continuations already joined and comments removed.</summary>
    protected static IEnumerable<(int Line, string Instruction, string Arguments)> Steps(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var text = lines[i].TrimEnd('\r').Trim();
            if (text.Length == 0 || text.StartsWith('#'))
                continue;

            var start = i;
            while (text.EndsWith('\\') && i + 1 < lines.Length)
            {
                text = text[..^1].TrimEnd() + " " + lines[++i].TrimEnd('\r').Trim();
            }

            var space = text.IndexOf(' ');
            if (space <= 0)
                continue;
            var instruction = text[..space];
            if (!Instructions.Contains(instruction, StringComparer.OrdinalIgnoreCase))
                continue;

            yield return (start + 1, instruction, text[(space + 1)..].Trim());
        }
    }
}

public sealed class DockerInstructionCaseRule : DockerfileRuleBase
{
    public override string Key => "QG-DK-CNV-0002";
    public override string Name => "Instructions should be written in upper case";

    public override void Execute(IRuleContext context)
    {
        foreach (var (line, instruction, _) in Steps(context))
        {
            if (instruction == instruction.ToUpperInvariant())
                continue;

            context.Report($"'{instruction}' is an instruction, and instructions are written in upper "
                           + "case by convention. Mixed case makes the arguments harder to pick out and "
                           + "breaks the tooling that reads Dockerfiles line by line.", line);
        }
    }
}

public sealed class DockerRelativeWorkdirRule : DockerfileRuleBase
{
    public override string Key => "QG-DK-BUG-0005";
    public override string Name => "WORKDIR should take an absolute path";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var (line, instruction, arguments) in Steps(context))
        {
            if (!instruction.Equals("WORKDIR", StringComparison.OrdinalIgnoreCase))
                continue;
            var path = arguments.Trim('"');
            if (path.Length == 0 || path.StartsWith('/') || path.StartsWith('$')
                || (path.Length > 1 && path[1] == ':'))
                continue;

            context.Report($"'{path}' is relative, so the directory this instruction lands in depends on "
                           + "whatever WORKDIR ran before it — including the ones in the base image. "
                           + "Write the absolute path so the layer is the same wherever it is built.", line);
        }
    }
}

public sealed class DockerRepeatedEntrypointRule : DockerfileRuleBase
{
    public override string Key => "QG-DK-BUG-0006";
    public override string Name => "Only the last CMD or ENTRYPOINT of a stage takes effect";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        var seen = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var (line, instruction, _) in Steps(context))
        {
            // each FROM starts a new stage, and every stage may declare its own entry point
            if (instruction.Equals("FROM", StringComparison.OrdinalIgnoreCase))
            {
                seen.Clear();
                continue;
            }
            if (!instruction.Equals("CMD", StringComparison.OrdinalIgnoreCase)
                && !instruction.Equals("ENTRYPOINT", StringComparison.OrdinalIgnoreCase))
                continue;

            if (seen.TryGetValue(instruction, out var first))
            {
                context.Report($"This stage already declares {instruction.ToUpperInvariant()} on line "
                               + $"{first}. Only the last one runs, so the earlier instruction is dead "
                               + "and whoever reads the file will believe it is the one in effect.", line);
            }
            else
            {
                seen[instruction] = line;
            }
        }
    }
}

public sealed class DockerAddForLocalFilesRule : DockerfileRuleBase
{
    public override string Key => "QG-DK-SML-0017";
    public override string Name => "Local files should be copied with COPY";

    public override void Execute(IRuleContext context)
    {
        foreach (var (line, instruction, arguments) in Steps(context))
        {
            if (!instruction.Equals("ADD", StringComparison.OrdinalIgnoreCase))
                continue;
            // a remote source or an archive is what ADD is for; anything else is a plain copy
            if (arguments.Contains("://", StringComparison.Ordinal)
                || arguments.Contains(".tar", StringComparison.OrdinalIgnoreCase)
                || arguments.Contains(".tgz", StringComparison.OrdinalIgnoreCase)
                || arguments.Contains(".gz", StringComparison.OrdinalIgnoreCase))
                continue;

            context.Report("ADD also fetches URLs and unpacks archives, so a file whose name changes can "
                           + "silently do something else. Use COPY for local files and keep ADD for the "
                           + "two cases only it handles.", line);
        }
    }
}

public sealed class DockerWholeContextCopiedRule : DockerfileRuleBase
{
    public override string Key => "QG-DK-SEC-0019";
    public override string Name => "The whole build context should not be copied into the image";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.SecurityHotspot;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        foreach (var (line, instruction, arguments) in Steps(context))
        {
            if (!instruction.Equals("COPY", StringComparison.OrdinalIgnoreCase)
                && !instruction.Equals("ADD", StringComparison.OrdinalIgnoreCase))
                continue;
            var parts = arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                continue;
            var source = parts[0].Trim('"');
            if (source is not ("." or "./" or "*" or "./*"))
                continue;

            context.Report("This copies the whole build context into the image, so whatever happens to be "
                           + "in the directory travels with it: local configuration, credentials, the .git "
                           + "history. Copy the paths the image needs, or keep a .dockerignore that is "
                           + "reviewed as carefully as this file.", line);
        }
    }
}

public sealed class DockerSpaceBeforeEqualsRule : DockerfileRuleBase
{
    public override string Key => "QG-DK-BUG-0007";
    public override string Name => "A key and its value should not be separated from the equal sign";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var (line, instruction, arguments) in Steps(context))
        {
            if (!instruction.Equals("ENV", StringComparison.OrdinalIgnoreCase)
                && !instruction.Equals("ARG", StringComparison.OrdinalIgnoreCase)
                && !instruction.Equals("LABEL", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!arguments.Contains(" =", StringComparison.Ordinal)
                && !arguments.Contains("= ", StringComparison.Ordinal))
                continue;
            if (arguments.Contains('"') || arguments.Contains('\''))
                continue; // a quoted value may legitimately contain spaces around an equal sign

            context.Report($"The space around '=' changes what this {instruction.ToUpperInvariant()} "
                           + "declares: the parts become separate arguments, so the variable ends up with "
                           + "a different name or an empty value. Write key=value with no spaces.", line);
        }
    }
}

public sealed class DockerConsecutiveRunRule : DockerfileRuleBase
{
    /// <summary>Three commands in a row are already three layers that could have been one.</summary>
    private const int MaxConsecutive = 2;

    public override string Key => "QG-DK-SML-0018";
    public override string Name => "Consecutive RUN instructions should be merged";

    public override void Execute(IRuleContext context)
    {
        var run = 0;
        var firstLine = 0;

        foreach (var (line, instruction, _) in Steps(context))
        {
            if (instruction.Equals("RUN", StringComparison.OrdinalIgnoreCase))
            {
                if (run == 0)
                    firstLine = line;
                run++;
                continue;
            }
            Flush(line);
        }
        Flush(0);

        void Flush(int _)
        {
            if (run > MaxConsecutive)
            {
                context.Report($"{run} RUN instructions in a row create {run} layers, and each one keeps "
                               + "whatever the previous left behind — caches, build tools, temporary files. "
                               + "Merge them into a single RUN that also cleans up.", firstLine);
            }
            run = 0;
        }
    }
}
