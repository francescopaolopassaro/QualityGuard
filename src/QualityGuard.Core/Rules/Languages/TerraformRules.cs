using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class TerraformRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new TerraformWideOpenIngressRule(),
        new TerraformPublicDatabaseRule(),
        new TerraformPublicS3AclRule(),
        new TerraformS3WithoutVersioningRule(),
        new TerraformOpenManagementPortRule(),
        new TerraformUnencryptedDatabaseRule(),
        new TerraformUnencryptedS3Rule(),
        new TerraformIamWildcardRule(),
        new TerraformHardcodedSecretRule(),
        new TerraformRdsMasterPasswordRule(),
        new TerraformSqlNoSslRule(),
        new TerraformPublicEksEndpointRule(),
        new TerraformBackendCredentialRule(),
        new TerraformUserDataPipeRule(),
        new TerraformMissingRequiredVersionRule(),
        new TerraformVariableWithoutTypeRule()
    ];
}

internal static class TerraformLine
{
    public static bool HasLiteralAssignment(string line)
        => line.Contains('=') && line.Contains('"');
}

public sealed class TerraformWideOpenIngressRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0001";
    public override string Name => "Security group opens port to the whole internet";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Restrict the source IP range instead of 0.0.0.0/0 or ::/0.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "0.0.0.0/0") || RuleMatchers.LineContains(lines[i], "::/0"))
                context.Report("Do not open the resource to the whole internet.", i + 1);
        }
    }
}

public sealed class TerraformPublicDatabaseRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0002";
    public override string Name => "Database is publicly accessible";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set publicly_accessible to false and keep the database in a private network.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "publicly_accessible")
                && RuleMatchers.LineContains(lines[i], "true"))
                context.Report("Do not make the database publicly accessible.", i + 1);
        }
    }
}

public sealed class TerraformPublicS3AclRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0003";
    public override string Name => "S3 bucket uses a public ACL";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use private ACLs or bucket policies restricted to trusted principals.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "acl")
                && RuleMatchers.LineContains(lines[i], "public-read"))
                context.Report("Do not expose the bucket through a public ACL.", i + 1);
        }
    }
}

public sealed class TerraformS3WithoutVersioningRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0004";
    public override string Name => "Storage bucket has versioning disabled";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Enable versioning on the bucket to keep history and recover from data loss.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var resourceLine = 0;
        var hasVersioning = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "aws_s3_bucket")
                || RuleMatchers.LineContains(lines[i], "google_storage_bucket"))
                resourceLine = i + 1;
            if (lines[i].TrimStart().StartsWith("versioning", StringComparison.OrdinalIgnoreCase))
                hasVersioning = true;
        }
        if (resourceLine > 0 && !hasVersioning)
            context.Report("Enable versioning on the storage bucket.", resourceLine);
    }
}

public sealed class TerraformOpenManagementPortRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0005";
    public override string Name => "SSH or management port is open to the whole internet";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Restrict SSH (22) and RDP (3389) access to trusted networks.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (!RuleMatchers.LineContains(lines[i], "0.0.0.0/0"))
                continue;
            var ports = RuleMatchers.SplitWords(lines[i]).Select(w => w.Trim('"'));
            if (ports.Any(w => w is "22" or "3389"))
                context.Report("SSH or management ports are open to the whole internet.", i + 1);
        }
    }
}

public sealed class TerraformUnencryptedDatabaseRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0006";
    public override string Name => "Database storage is not encrypted at rest";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set storage_encrypted to true for the database instance.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var resourceLine = 0;
        var hasEncryption = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "aws_db_instance")
                || RuleMatchers.LineContains(lines[i], "aws_rds_cluster"))
                resourceLine = i + 1;
            if (RuleMatchers.LineContains(lines[i], "storage_encrypted")
                && RuleMatchers.LineContains(lines[i], "true"))
                hasEncryption = true;
        }
        if (resourceLine > 0 && !hasEncryption)
            context.Report("Encrypt the database storage at rest.", resourceLine);
    }
}

public sealed class TerraformUnencryptedS3Rule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0007";
    public override string Name => "S3 bucket has server-side encryption disabled";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Configure server_side_encryption_configuration with a managed or KMS key.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var resourceLine = 0;
        var hasEncryption = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "aws_s3_bucket")
                || RuleMatchers.LineContains(lines[i], "google_storage_bucket"))
                resourceLine = i + 1;
            if (RuleMatchers.LineContains(lines[i], "server_side_encryption_configuration"))
                hasEncryption = true;
        }
        if (resourceLine > 0 && !hasEncryption)
            context.Report("Enable server-side encryption on the storage bucket.", resourceLine);
    }
}

public sealed class TerraformIamWildcardRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0008";
    public override string Name => "IAM policy grants wildcard action or resource";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Scope actions and resources to the minimal set required.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasIamPolicy = lines.Any(l => RuleMatchers.LineContains(l, "aws_iam_policy")
            || RuleMatchers.LineContains(l, "aws_iam_policy_document"));
        if (!hasIamPolicy)
            return;
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "\"*\"")
                && (RuleMatchers.LineContains(lines[i], "action")
                    || RuleMatchers.LineContains(lines[i], "resource")))
                context.Report("Avoid wildcard statements in IAM policies.", i + 1);
        }
    }
}

public sealed class TerraformHardcodedSecretRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0009";
    public override string Name => "Secret is hardcoded as a literal value";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Reference secrets from a secure store or variable instead of a literal.";
    public override string[] Languages => ["tf"];

    private static readonly string[] SecretKeys = ["password", "secret", "token", "api_key"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (!TerraformLine.HasLiteralAssignment(lines[i]))
                continue;
            if (SecretKeys.Any(k => RuleMatchers.LineContains(lines[i], k)))
                context.Report("Do not hardcode secrets in configuration.", i + 1);
        }
    }
}

public sealed class TerraformRdsMasterPasswordRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0010";
    public override string Name => "Database admin password is a literal value";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set master_password from a secret reference, not a literal.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "master_password")
                && TerraformLine.HasLiteralAssignment(lines[i]))
                context.Report("Do not set the database admin password as a literal.", i + 1);
        }
    }
}

public sealed class TerraformSqlNoSslRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0011";
    public override string Name => "Cloud SQL accepts connections without TLS";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Enforce require_ssl to true on the database instance.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "require_ssl")
                && RuleMatchers.LineContains(lines[i], "false"))
                context.Report("Enforce SSL connections for the database.", i + 1);
        }
    }
}

public sealed class TerraformPublicEksEndpointRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0012";
    public override string Name => "Kubernetes cluster endpoint is publicly accessible";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Disable endpoint_public_access or restrict it to trusted networks.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "endpoint_public_access")
                && RuleMatchers.LineContains(lines[i], "true"))
                context.Report("Do not expose the cluster endpoint publicly.", i + 1);
        }
    }
}

public sealed class TerraformBackendCredentialRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0013";
    public override string Name => "Backend credentials are hardcoded";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use environment variables or non-interactive credential providers for the backend.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasBackend = lines.Any(l => l.TrimStart().StartsWith("backend", StringComparison.OrdinalIgnoreCase));
        if (!hasBackend)
            return;
        for (var i = 0; i < lines.Length; i++)
        {
            if (TerraformLine.HasLiteralAssignment(lines[i])
                && (RuleMatchers.LineContains(lines[i], "access_key")
                    || RuleMatchers.LineContains(lines[i], "secret_key")))
                context.Report("Do not hardcode backend credentials.", i + 1);
        }
    }
}

public sealed class TerraformUserDataPipeRule : PatternRuleBase
{
    public override string Key => "QG-TF-SEC-0014";
    public override string Name => "User data pipes remote script into a shell";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Bootstrap instances from a pinned, signed artifact instead of piping remote scripts to sh.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "user_data")
                && RuleMatchers.LineContains(line, "curl")
                && line.Contains('|')
                && RuleMatchers.LineContains(line, "sh"))
                context.Report("Avoid executing scripts retrieved over the wire via pipe to a shell.", i + 1);
        }
    }
}

public sealed class TerraformMissingRequiredVersionRule : PatternRuleBase
{
    public override string Key => "QG-TF-SML-0001";
    public override string Name => "Terraform block does not pin provider versions";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Declare required_version and required_providers in the terraform block.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasTerraform = false;
        var hasVersionConstraint = false;
        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].TrimStart();
            if (trimmed.StartsWith("terraform", StringComparison.OrdinalIgnoreCase))
                hasTerraform = true;
            if (trimmed.StartsWith("required_version", StringComparison.OrdinalIgnoreCase)
                || trimmed.StartsWith("required_providers", StringComparison.OrdinalIgnoreCase))
                hasVersionConstraint = true;
        }
        if (hasTerraform && !hasVersionConstraint)
            context.Report("Pin the Terraform and provider versions.", 1);
    }
}

public sealed class TerraformVariableWithoutTypeRule : PatternRuleBase
{
    public override string Key => "QG-TF-SML-0002";
    public override string Name => "Variable has no explicit type";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Declare the type of every variable.";
    public override string[] Languages => ["tf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var variableLine = 0;
        var hasType = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (lines[i].TrimStart().StartsWith("variable", StringComparison.OrdinalIgnoreCase)
                && variableLine == 0)
                variableLine = i + 1;
            if (lines[i].TrimStart().StartsWith("type", StringComparison.OrdinalIgnoreCase)
                && lines[i].Contains('='))
                hasType = true;
        }
        if (variableLine > 0 && !hasType)
            context.Report("Declare an explicit type for this variable.", variableLine);
    }
}