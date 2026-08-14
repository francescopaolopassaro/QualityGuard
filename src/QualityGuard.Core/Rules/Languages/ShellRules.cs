using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class ShellRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new ShEvalRule(),
        new ShCommandSubstitutionRule(),
        new ShRemoteScriptRule(),
        new ShWorldWritableRule(),
        new ShHardcodedCredentialsRule(),
        new ShSourceVariableRule(),
        new ShPathRelativeRule(),
        new ShRmRecursiveRule(),
        new ShMissingSetERule(),
        new ShUselessCatRule(),
        new ShDeprecatedGrepRule(),
        new ShMktempRule(),
        new ShWeakIntegrityRule()
    ];

    internal static string[] LinesOf(IRuleContext context) => context.File.Content.Split('\n');

    internal static bool HasAny(string text, string[] fragments)
        => fragments.Any(f => text.Contains(f, StringComparison.OrdinalIgnoreCase));
}

public sealed class ShEvalRule : PatternRuleBase
{
    public override string Key => "QG-SH-SEC-0001";
    public override string Name => "Eval of dynamic shell code";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not eval dynamic code; run the intended command directly.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["eval"]))
            context.Report("Do not evaluate dynamic shell code.", token.Line);
    }
}

public sealed class ShCommandSubstitutionRule : PatternRuleBase
{
    public override string Key => "QG-SH-SEC-0002";
    public override string Name => "Command substitution with variable";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Validate the variable before using it inside command substitution.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var idx = lines[i].IndexOf("$(", StringComparison.Ordinal);
            if (idx >= 0 && lines[i].IndexOf('$', idx + 2) >= 0)
                context.Report("Command substitution built from a variable may allow injection.", i + 1);
        }
    }
}

public sealed class ShRemoteScriptRule : PatternRuleBase
{
    public override string Key => "QG-SH-SEC-0003";
    public override string Name => "Remote script piped to a shell";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not pipe downloaded scripts directly into a shell; verify the source first.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!(RuleMatchers.LineContains(line, "curl") || RuleMatchers.LineContains(line, "wget"))) continue;
            if (!line.Contains('|')) continue;
            if (!(RuleMatchers.LineContains(line, "sh") || RuleMatchers.LineContains(line, "bash"))) continue;
            context.Report("Do not pipe downloaded scripts directly into a shell.", i + 1);
        }
    }
}

public sealed class ShWorldWritableRule : PatternRuleBase
{
    public override string Key => "QG-SH-SEC-0004";
    public override string Name => "World-writable permissions";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Restrict permissions; avoid chmod 777 and umask 000.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "chmod")
                && (RuleMatchers.LineContains(line, "0777") || RuleMatchers.LineContains(line, "777")))
            {
                context.Report("Avoid world-writable permissions.", i + 1);
                continue;
            }
            var words = RuleMatchers.SplitWords(line);
            for (var w = 0; w < words.Length - 1; w++)
            {
                if (words[w] == "umask" && (words[w + 1] == "0" || words[w + 1] == "000"))
                    context.Report("Set a restrictive umask instead of 0.", i + 1);
            }
        }
    }
}

public sealed class ShHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-SH-SEC-0005";
    public override string Name => "Hardcoded credentials";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Read secrets from the environment or a secret store instead of source code.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.TrimStart().StartsWith("#")) continue;
            var words = RuleMatchers.SplitWords(line);
            if (!words.Any(w => w.Length >= 3 && RuleMatchers.Contains(
                    w, ["password", "pass", "secret", "token", "api_key", "apikey", "credential"], true)))
                continue;
            var eq = line.IndexOf('=');
            if (eq < 0) continue;
            var value = line.Substring(eq + 1).Trim();
            if (value.Length == 0 || value.StartsWith('$') || value.StartsWith('`')) continue;
            context.Report("Hardcoded credentials must not be committed.", i + 1);
        }
    }
}

public sealed class ShSourceVariableRule : PatternRuleBase
{
    public override string Key => "QG-SH-SEC-0006";
    public override string Name => "Sourcing a file from a variable path";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Do not source files whose path comes from an unvalidated variable.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("#")) continue;
            if (RuleMatchers.LineContains(line, "source") && line.Contains('$'))
                context.Report("Do not source a file whose path comes from a variable.", i + 1);
            if (trimmed.StartsWith(". ") && line.Contains('$'))
                context.Report("Do not source a file whose path comes from a variable.", i + 1);
        }
    }
}

public sealed class ShPathRelativeRule : PatternRuleBase
{
    public override string Key => "QG-SH-SEC-0007";
    public override string Name => "Relative path in PATH";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Remove the current directory or relative components from PATH.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!RuleMatchers.LineContains(line, "PATH=")) continue;
            if (line.Contains(":.", StringComparison.Ordinal) || line.Contains(".:", StringComparison.Ordinal))
                context.Report("PATH contains a relative component.", i + 1);
        }
    }
}

public sealed class ShRmRecursiveRule : PatternRuleBase
{
    public override string Key => "QG-SH-BUG-0001";
    public override string Name => "Recursive force removal";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "Verify the target before a recursive force removal; guard against empty variables.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "rm -rf") || RuleMatchers.LineContains(lines[i], "rm -fr"))
                context.Report("Recursive force removal can destroy data; verify the target.", i + 1);
        }
    }
}

public sealed class ShMissingSetERule : PatternRuleBase
{
    public override string Key => "QG-SH-SML-0001";
    public override string Name => "Script without set -euo pipefail";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Add 'set -euo pipefail' to fail fast on errors and undefined variables.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        var limit = Math.Min(lines.Length, 15);
        for (var i = 0; i < limit; i++)
        {
            var line = lines[i].TrimStart();
            if (line.Length == 0 || line.StartsWith("#")) continue;
            if (line.StartsWith("set -", StringComparison.Ordinal) && line.Contains("-e") && line.Contains("-u"))
                return;
        }
        context.Report("Add 'set -euo pipefail' to exit early on errors.", 1);
    }
}

public sealed class ShUselessCatRule : PatternRuleBase
{
    public override string Key => "QG-SH-SML-0002";
    public override string Name => "Useless use of cat";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Redirect the file into the command instead of piping cat output.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "cat ") && lines[i].Contains('|'))
                context.Report("Do not pipe cat output into other commands; use redirection.", i + 1);
        }
    }
}

public sealed class ShDeprecatedGrepRule : PatternRuleBase
{
    public override string Key => "QG-SH-SML-0003";
    public override string Name => "Use of deprecated egrep/fgrep";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Use grep -E and grep -F instead of egrep and fgrep.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (ShellRuleSet.HasAny(lines[i], ["egrep", "fgrep"]))
                context.Report("egrep/fgrep are deprecated; use grep -E and grep -F.", i + 1);
        }
    }
}

public sealed class ShMktempRule : PatternRuleBase
{
    public override string Key => "QG-SH-SML-0004";
    public override string Name => "mktemp output not bound to a variable";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Assign mktemp output to a variable or use -t for safe temporary files.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "mktemp")
                && !lines[i].Contains("-t")
                && !lines[i].Contains('='))
                context.Report("Assign mktemp output to a variable or use -t.", i + 1);
        }
    }
}

public sealed class ShWeakIntegrityRule : PatternRuleBase
{
    public override string Key => "QG-SH-SML-0005";
    public override string Name => "Weak hash for integrity check";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Use sha256sum for integrity checks instead of MD5 or SHA-1.";
    public override string[] Languages => ["sh"];

    public override void Execute(IRuleContext context)
    {
        var lines = ShellRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (ShellRuleSet.HasAny(lines[i], ["md5sum", "sha1sum"]))
                context.Report("MD5 and SHA-1 are weak for integrity checks; use sha256sum.", i + 1);
        }
    }
}
