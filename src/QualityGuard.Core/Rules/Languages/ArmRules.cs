using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class ArmRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new ArmHardcodedSecretRule(),
        new ArmHttpsDisabledRule(),
        new ArmWeakTlsVersionRule(),
        new ArmSqlAdminPasswordRule(),
        new ArmOpenSecurityRulesRule(),
        new ArmAppServiceHttpOnlyRule(),
        new ArmFlexibleServerPublicNetworkRule(),
        new ArmMissingContentVersionRule(),
        new ArmMissingSchemaRule()
    ];
}

internal static class ArmLine
{
    public static bool HasQuotedLiteral(string line) => line.Contains('"');

    public static bool HasKey(string line, string key)
        => line.Contains("\"" + key + "\"", StringComparison.OrdinalIgnoreCase)
           || line.Contains(key + ":", StringComparison.OrdinalIgnoreCase)
           || line.TrimStart().StartsWith(key, StringComparison.OrdinalIgnoreCase);
}

public sealed class ArmHardcodedSecretRule : PatternRuleBase
{
    public override string Key => "QG-AR-SEC-0001";
    public override string Name => "Credential hardcoded in the template";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use parameters(), variables(), or listKeys() instead of literal credentials.";
    public override string[] Languages => ["ar"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!(RuleMatchers.LineContains(line, "password")
                  || RuleMatchers.LineContains(line, "secret")
                  || RuleMatchers.LineContains(line, "key")
                  || RuleMatchers.LineContains(line, "connectionString")))
                continue;
            if (!ArmLine.HasQuotedLiteral(line))
                continue;
            if (RuleMatchers.LineContains(line, "parameters(")
                || RuleMatchers.LineContains(line, "variables(")
                || RuleMatchers.LineContains(line, "listKeys("))
                continue;
            context.Report("Do not hardcode credentials in the template.", i + 1);
        }
    }
}

public sealed class ArmHttpsDisabledRule : PatternRuleBase
{
    public override string Key => "QG-AR-SEC-0002";
    public override string Name => "Storage account allows plain HTTP traffic";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Set supportsHttpsTrafficOnly to true.";
    public override string[] Languages => ["ar"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "supportsHttpsTrafficOnly")
                && RuleMatchers.LineContains(lines[i], "false"))
                context.Report("Require HTTPS for the storage account.", i + 1);
        }
    }
}

public sealed class ArmWeakTlsVersionRule : PatternRuleBase
{
    public override string Key => "QG-AR-SEC-0003";
    public override string Name => "Storage account allows a weak minimum TLS version";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Set minimumTlsVersion to TLS1_2 or higher.";
    public override string[] Languages => ["ar"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "minimumTlsVersion")
                && (RuleMatchers.LineContains(line, "TLS1_0") || RuleMatchers.LineContains(line, "TLS1_1")))
                context.Report("Enforce at least TLS 1.2 for the storage account.", i + 1);
        }
    }
}

public sealed class ArmSqlAdminPasswordRule : PatternRuleBase
{
    public override string Key => "QG-AR-SEC-0004";
    public override string Name => "SQL administrator password is hardcoded";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Reference administratorLoginPassword through parameters() or key vault instead of a literal.";
    public override string[] Languages => ["ar"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "administratorLoginPassword")
                && ArmLine.HasQuotedLiteral(line)
                && !RuleMatchers.LineContains(line, "parameters(")
                && !RuleMatchers.LineContains(line, "variables("))
                context.Report("Do not hardcode the SQL administrator password.", i + 1);
        }
    }
}

public sealed class ArmOpenSecurityRulesRule : PatternRuleBase
{
    public override string Key => "QG-AR-SEC-0005";
    public override string Name => "Network security rule allows any source address";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Restrict sourceAddressPrefix to specific trusted ranges instead of * or 0.0.0.0/0.";
    public override string[] Languages => ["ar"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if ((RuleMatchers.LineContains(line, "sourceAddressPrefix")
                 || RuleMatchers.LineContains(line, "sourceAddressPrefixes"))
                && (RuleMatchers.LineContains(line, "\"*\"") || RuleMatchers.LineContains(line, "0.0.0.0/0")))
                context.Report("Do not allow traffic from any source address.", i + 1);
        }
    }
}

public sealed class ArmAppServiceHttpOnlyRule : PatternRuleBase
{
    public override string Key => "QG-AR-SEC-0006";
    public override string Name => "App Service allows plain HTTP traffic";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Set httpsOnly to true.";
    public override string[] Languages => ["ar"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "httpsOnly")
                && RuleMatchers.LineContains(lines[i], "false"))
                context.Report("Require HTTPS for the App Service.", i + 1);
        }
    }
}

public sealed class ArmFlexibleServerPublicNetworkRule : PatternRuleBase
{
    public override string Key => "QG-AR-SEC-0007";
    public override string Name => "Flexible server is publicly reachable";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Set publicNetworkAccess to Disabled and keep the server in a private network.";
    public override string[] Languages => ["ar"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "publicNetworkAccess")
                && RuleMatchers.LineContains(lines[i], "Enabled"))
                context.Report("Do not expose the flexible server to the public network.", i + 1);
        }
    }
}

public sealed class ArmMissingContentVersionRule : PatternRuleBase
{
    public override string Key => "QG-AR-SML-0001";
    public override string Name => "Template is missing contentVersion";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Declare a contentVersion for the template.";
    public override string[] Languages => ["ar"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        if (lines.All(l => !RuleMatchers.LineContains(l, "contentVersion")))
            context.Report("Declare contentVersion for the template.", 1);
    }
}

public sealed class ArmMissingSchemaRule : PatternRuleBase
{
    public override string Key => "QG-AR-SML-0002";
    public override string Name => "Template is missing $schema";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Declare the $schema of the template.";
    public override string[] Languages => ["ar"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        if (lines.All(l => !RuleMatchers.LineContains(l, "$schema")))
            context.Report("Declare the $schema of the template.", 1);
    }
}
