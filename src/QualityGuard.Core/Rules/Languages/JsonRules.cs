using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Configuration written as JSON. Nothing validates these files until the program reads them, and by
/// then the failure is a missing setting rather than a syntax error — so the rules here look for the
/// mistakes that survive parsing: a key written twice, a secret committed with the file, a dependency
/// left open to any future version.
/// </summary>
public static class JsonRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JsonDuplicateKeyRule(),
        new JsonCommittedSecretRule(),
        new JsonOpenDependencyRangeRule()
    ];
}

public abstract class JsonRuleBase : RuleBase
{
    public override string[] Languages => ["json"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";
}

public sealed class JsonDuplicateKeyRule : JsonRuleBase
{
    public override string Key => "QG-JSON-BUG-0001";
    public override string Name => "An object should not repeat a key";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        Walk(context.Config, context);
    }

    private static void Walk(ConfigNode node, IRuleContext context)
    {
        // The members of an array carry no name, so two equal ones are a list with a repeat in it,
        // not a name defined twice. Reading them as keys reported every command list in a settings
        // file, and the reported name was the value cut at its first escaped quote.
        var seen = new Dictionary<string, int>(StringComparer.Ordinal);
        var isList = node.Children.Count(c => c.Key.Length == 0) > node.Children.Count / 2;
        foreach (var child in node.Children)
        {
            if (!isList && child.Key.Length > 0)
            {
                if (seen.TryGetValue(child.Key, out var first))
                {
                    context.Report($"'{child.Key}' is already defined on line {first}. Parsers keep one "
                                   + "of the two — usually the last — without warning, so the value the "
                                   + "program reads is not the one a reader would expect.", child.Line);
                }
                else
                {
                    seen[child.Key] = child.Line;
                }
            }
            Walk(child, context);
        }
    }
}

public sealed class JsonCommittedSecretRule : JsonRuleBase
{
    private static readonly string[] SecretKeys =
    [
        "password", "passwd", "secret", "apikey", "api_key", "token", "access_token", "refresh_token",
        "private_key", "client_secret", "connectionstring", "connection_string", "credential"
    ];

    private static readonly string[] Placeholders =
    [
        "", "null", "changeme", "todo", "xxx", "***", "<value>", "your-", "example", "placeholder",
        "dummy", "sample"
    ];

    public override string Key => "QG-JSON-SEC-0001";
    public override string Name => "A credential should not be written into a configuration file";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var node in context.Config.Descendants())
        {
            var key = node.Key.Replace("-", string.Empty).Replace("_", string.Empty).ToLowerInvariant();
            if (!SecretKeys.Any(s => key.Contains(s.Replace("_", string.Empty), StringComparison.Ordinal)))
                continue;
            var value = node.Value.Trim();
            if (value.Length < 6)
                continue;
            if (Placeholders.Any(p => p.Length > 0 && value.Contains(p, StringComparison.OrdinalIgnoreCase)))
                continue;
            // a reference to a variable or a vault entry is exactly the fix this rule asks for
            if (value.Contains("${", StringComparison.Ordinal) || value.StartsWith('$')
                || value.Contains("{{", StringComparison.Ordinal) || value.StartsWith("env:", StringComparison.OrdinalIgnoreCase))
                continue;

            context.Report($"'{node.Key}' holds what looks like a real credential. Committed with the "
                           + "file it is readable by everyone who can clone the repository and it stays "
                           + "in the history after deletion. Read it from the environment or a secret "
                           + "store, and treat this one as compromised.", node.Line);
        }
    }
}

public sealed class JsonOpenDependencyRangeRule : JsonRuleBase
{
    public override string Key => "QG-JSON-SEC-0002";
    public override string Name => "A dependency should not accept any future version";
    public override IssueKind Kind => IssueKind.SecurityHotspot;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!context.File.FileName.Equals("package.json", StringComparison.OrdinalIgnoreCase))
            return;

        foreach (var section in context.Config.Descendants())
        {
            if (section.Key is not ("dependencies" or "devDependencies" or "peerDependencies"))
                continue;

            foreach (var dependency in section.Children)
            {
                var range = dependency.Value.Trim();
                if (range is not ("*" or "latest" or "x" or ">=0.0.0"))
                    continue;

                context.Report($"'{dependency.Key}' accepts any version that is ever published, so an "
                               + "install tomorrow can pull code nobody has reviewed — which is how a "
                               + "compromised package reaches a build. Pin the range you have tested.",
                    dependency.Line);
            }
        }
    }
}
