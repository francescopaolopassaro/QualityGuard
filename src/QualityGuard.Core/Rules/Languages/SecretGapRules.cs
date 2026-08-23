using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Second wave of credential patterns: providers whose token shape is distinctive enough to
/// anchor on the prefix alone. Same contract as the first wave — test fixtures and docs are
/// skipped, and each rule reports once per line per shape.
/// </summary>
public static class SecretGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new DiscordWebhookSecretRule(),
        new RedisUrlSecretRule(),
        new InfuraApiKeySecretRule(),
        new DockerSwarmTokenSecretRule(),
        new SplunkTokenSecretRule(),
        new OpenAiApiKeySecretRule(),
        new CodeQualityServiceTokenSecretRule(),
    ];
}

public sealed class DiscordWebhookSecretRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("a Discord webhook URL", Shape(@"https://discord\.com/api/webhooks/\d{10,}/[\w\-]{30,}"),
            "Revoke it from the channel integrations page."),
    ];

    public override string Key => "QG-SEC-SEC-0018";
    public override string Name => "Discord webhook URLs should not be disclosed";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}

public sealed class RedisUrlSecretRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("a Redis URL with embedded credentials", Shape(@"redis://[\w\-]+:[\w\-]{4,}@[\w\-]+\.\w+"),
            "Move credentials to configuration and rotate the exposed password."),
    ];

    public override string Key => "QG-SEC-SEC-0019";
    public override string Name => "Redis credentials should not be disclosed";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}

public sealed class InfuraApiKeySecretRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("an Infura project secret", Shape(@"https://\w+\.infura\.io/v3/[0-9a-f]{32}"),
            "Rotate it from the Infura dashboard."),
    ];

    public override string Key => "QG-SEC-SEC-0026";
    public override string Name => "Infura API keys should not be disclosed";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}

public sealed class DockerSwarmTokenSecretRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("a Docker Swarm join token", Shape(@"SWMTKN-1-[0-9a-z]{25}-[0-9a-z]{25}"),
            "Rotate it with 'docker swarm join-token --rotate'."),
    ];

    public override string Key => "QG-SEC-SEC-0027";
    public override string Name => "Docker Swarm tokens should not be disclosed";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}

public sealed class SplunkTokenSecretRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("a Splunk HEC token", Shape(@"(?i)\bSplunk [0-9a-f]{8}[-][0-9a-f]{4}[-][0-9a-f]{4}[-][0-9a-f]{4}[-][0-9a-f]{12}\b"),
            "Rotate it from the Splunk console."),
    ];

    public override string Key => "QG-SEC-SEC-0028";
    public override string Name => "Splunk tokens should not be disclosed";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}

public sealed class OpenAiApiKeySecretRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("an OpenAI API key", Shape(@"sk-[A-Za-z0-9_-]{40,}"),
            "Revoke it at platform.openai.com and use an environment variable."),
    ];

    public override string Key => "QG-SEC-SEC-0029";
    public override string Name => "OpenAI API keys should not be disclosed";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}

public sealed class CodeQualityServiceTokenSecretRule : SecretRuleBase
{
    private static readonly SecretShape[] Shapes =
    [
        new("a SonarQube project token", Shape(@"\bsq[a-z]{1,3}_[0-9a-f]{40}"),
            "Revoke it from the SonarQube security page."),
        new("a Codacy project API token", Shape(@"\b[0-9a-f]{32}\b(?=.*codacy)"),
            "Revoke it from the Codacy project settings."),
    ];

    public override string Key => "QG-SEC-SEC-0030";
    public override string Name => "Code-quality service tokens should not be disclosed";

    public override void Execute(IRuleContext context) => Scan(context, Shapes);
}
