using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class CloudFormationRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CfWideOpenIngressRule(),
        new CfOpenSshRdpRule(),
        new CfPublicS3AclRule(),
        new CfS3WithoutEncryptionRule(),
        new CfPublicDatabaseRule(),
        new CfUnencryptedDatabaseRule(),
        new CfIamWildcardRule(),
        new CfHardcodedSecretRule(),
        new CfUserDataPipeRule(),
        new CfUnencryptedEbsRule(),
        new CfAllowAllViewerRule(),
        new CfS3WithoutVersioningRule()
    ];
}

internal static class CloudFormationLine
{
    public static bool HasQuotedLiteral(string line) => line.Contains('"');

    public static bool HasPort(string line, string port)
        => line.Contains(": " + port, StringComparison.Ordinal)
           || line.Contains(": \"" + port + "\"", StringComparison.Ordinal);
}

public sealed class CfWideOpenIngressRule : PatternRuleBase
{
    public override string Key => "QG-CF-SEC-0001";
    public override string Name => "Security group ingress open to the world";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Restrict CidrIp to specific trusted ranges.";
    public override string[] Languages => ["cf"];

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

public sealed class CfOpenSshRdpRule : PatternRuleBase
{
    public override string Key => "QG-CF-SEC-0002";
    public override string Name => "SSH or RDP port open to the whole internet";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Restrict the source IP range instead of opening management ports to 0.0.0.0/0.";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasWideOpen = lines.Any(l => RuleMatchers.LineContains(l, "0.0.0.0/0"));
        if (!hasWideOpen)
            return;
        for (var i = 0; i < lines.Length; i++)
        {
            if (CloudFormationLine.HasPort(lines[i], "22") || CloudFormationLine.HasPort(lines[i], "3389"))
                context.Report("Management port is exposed to the whole internet.", i + 1);
        }
    }
}

public sealed class CfPublicS3AclRule : PatternRuleBase
{
    public override string Key => "QG-CF-SEC-0003";
    public override string Name => "S3 bucket uses a public ACL";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use private ACLs or restrict access through bucket policies.";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "AccessControl")
                && RuleMatchers.LineContains(lines[i], "PublicRead"))
                context.Report("Do not expose the bucket through a public ACL.", i + 1);
        }
    }
}

public sealed class CfS3WithoutEncryptionRule : PatternRuleBase
{
    public override string Key => "QG-CF-SEC-0004";
    public override string Name => "S3 bucket does not enforce encryption";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Configure BucketEncryption with a server-side encryption algorithm.";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var resourceLine = 0;
        var hasEncryption = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "AWS::S3::Bucket"))
                resourceLine = i + 1;
            if (RuleMatchers.LineContains(lines[i], "BucketEncryption")
                || RuleMatchers.LineContains(lines[i], "ServerSideEncryptionConfiguration"))
                hasEncryption = true;
        }
        if (resourceLine > 0 && !hasEncryption)
            context.Report("Enable server-side encryption on the bucket.", resourceLine);
    }
}

public sealed class CfPublicDatabaseRule : PatternRuleBase
{
    public override string Key => "QG-CF-SEC-0005";
    public override string Name => "Database is publicly accessible";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set PubliclyAccessible to false and keep the database in a private network.";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "PubliclyAccessible")
                && RuleMatchers.LineContains(lines[i], "true"))
                context.Report("Do not make the database publicly accessible.", i + 1);
        }
    }
}

public sealed class CfUnencryptedDatabaseRule : PatternRuleBase
{
    public override string Key => "QG-CF-SEC-0006";
    public override string Name => "RDS database does not enforce encryption";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set StorageEncrypted to true for the database instance.";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var resourceLine = 0;
        var hasEncryption = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "AWS::RDS::DBInstance"))
                resourceLine = i + 1;
            if (RuleMatchers.LineContains(lines[i], "StorageEncrypted")
                && RuleMatchers.LineContains(lines[i], "true"))
                hasEncryption = true;
        }
        if (resourceLine > 0 && !hasEncryption)
            context.Report("Enable storage encryption on the database.", resourceLine);
    }
}

public sealed class CfIamWildcardRule : PatternRuleBase
{
    public override string Key => "QG-CF-SEC-0007";
    public override string Name => "IAM policy allows wildcard actions or resources";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Scope IAM actions and resources to the minimum required set.";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if ((RuleMatchers.LineContains(line, "Action") || RuleMatchers.LineContains(line, "Resource"))
                && RuleMatchers.LineContains(line, "\"*\""))
                context.Report("Avoid wildcards in IAM policies.", i + 1);
        }
    }
}

public sealed class CfHardcodedSecretRule : PatternRuleBase
{
    public override string Key => "QG-CF-SEC-0008";
    public override string Name => "Credential hardcoded in the template";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use a parameter, a secret reference such as {{resolve:secretsmanager:...}}, or !Ref/!GetAtt instead of a literal.";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!(RuleMatchers.LineContains(line, "Password")
                  || RuleMatchers.LineContains(line, "Secret")
                  || RuleMatchers.LineContains(line, "Token")
                  || RuleMatchers.LineContains(line, "AccessKey")
                  || RuleMatchers.LineContains(line, "SecretKey")))
                continue;
            if (!CloudFormationLine.HasQuotedLiteral(line))
                continue;
            if (RuleMatchers.LineContains(line, "!Ref")
                || RuleMatchers.LineContains(line, "!GetAtt")
                || RuleMatchers.LineContains(line, "{{resolve"))
                continue;
            context.Report("Do not hardcode credentials in the template.", i + 1);
        }
    }
}

public sealed class CfUserDataPipeRule : PatternRuleBase
{
    public override string Key => "QG-CF-SEC-0009";
    public override string Name => "UserData pipes remote script to the shell";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Fetch and verify the script before execution, and avoid chmod 777 on it.";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var downloads = RuleMatchers.LineContains(line, "curl") || RuleMatchers.LineContains(line, "wget");
            var pipesToShell = downloads && RuleMatchers.LineContains(line, "|")
                && (RuleMatchers.LineContains(line, "sh") || RuleMatchers.LineContains(line, "bash"));
            if (pipesToShell || RuleMatchers.LineContains(line, "chmod 777"))
                context.Report("Avoid executing remote scripts piped to the shell.", i + 1);
        }
    }
}

public sealed class CfUnencryptedEbsRule : PatternRuleBase
{
    public override string Key => "QG-CF-SEC-0010";
    public override string Name => "EBS volume does not enforce encryption";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set Encrypted to true on the volume.";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var resourceLine = 0;
        var hasEncryption = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "AWS::EC2::Volume"))
                resourceLine = i + 1;
            if (RuleMatchers.LineContains(lines[i], "Encrypted")
                && RuleMatchers.LineContains(lines[i], "true"))
                hasEncryption = true;
        }
        if (resourceLine > 0 && !hasEncryption)
            context.Report("Enable encryption on the EBS volume.", resourceLine);
    }
}

public sealed class CfAllowAllViewerRule : PatternRuleBase
{
    public override string Key => "QG-CF-SEC-0011";
    public override string Name => "CloudFront distribution allows insecure HTTP";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Set ViewerProtocolPolicy to redirect-to-https or https-only.";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "ViewerProtocolPolicy")
                && RuleMatchers.LineContains(lines[i], "allow-all"))
                context.Report("Force HTTPS on the CloudFront distribution.", i + 1);
        }
    }
}

public sealed class CfS3WithoutVersioningRule : PatternRuleBase
{
    public override string Key => "QG-CF-SML-0001";
    public override string Name => "S3 bucket has versioning disabled";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Enable VersioningConfiguration to keep object history.";
    public override string[] Languages => ["cf"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var resourceLine = 0;
        var hasVersioning = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (RuleMatchers.LineContains(lines[i], "AWS::S3::Bucket"))
                resourceLine = i + 1;
            if (RuleMatchers.LineContains(lines[i], "VersioningConfiguration"))
                hasVersioning = true;
        }
        if (resourceLine > 0 && !hasVersioning)
            context.Report("Enable versioning on the bucket.", resourceLine);
    }
}
