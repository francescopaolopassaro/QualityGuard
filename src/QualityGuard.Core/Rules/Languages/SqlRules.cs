using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class SqlRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new SqlGrantToPublicRule(),
        new SqlGrantAllPrivilegesRule(),
        new SqlHardcodedCredentialRule(),
        new SqlIdentifiedByPasswordRule(),
        new SqlSetPasswordPlaintextRule(),
        new SqlSelectStarRule(),
        new SqlMissingSemicolonRule(),
        new SqlDeleteUpdateWithoutWhereRule(),
        new SqlLiteralEqualsTrueRule()
    ];
}

public sealed class SqlGrantToPublicRule : PatternRuleBase
{
    public override string Key => "QG-SQL-SEC-0001";
    public override string Name => "Privileges granted to PUBLIC";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Grant privileges to specific roles or users instead of PUBLIC.";
    public override string[] Languages => ["sql"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if ((RuleMatchers.LineContains(line, "GRANT") || RuleMatchers.LineContains(line, "REVOKE"))
                && RuleMatchers.LineContains(line, "PUBLIC"))
                context.Report("Do not grant or revoke privileges on PUBLIC.", i + 1);
        }
    }
}

public sealed class SqlGrantAllPrivilegesRule : PatternRuleBase
{
    public override string Key => "QG-SQL-SEC-0002";
    public override string Name => "Excessive privileges granted";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Grant only the specific privileges each role or user needs.";
    public override string[] Languages => ["sql"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!RuleMatchers.LineContains(line, "GRANT"))
                continue;
            if (RuleMatchers.LineContains(line, "ALL PRIVILEGES")
                || RuleMatchers.LineContains(line, "GRANT ALL"))
                context.Report("Avoid granting ALL privileges.", i + 1);
        }
    }
}

public sealed class SqlHardcodedCredentialRule : PatternRuleBase
{
    public override string Key => "QG-SQL-SEC-0003";
    public override string Name => "Hardcoded database credential";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use a secret manager or environment variable instead of embedding the credential.";
    public override string[] Languages => ["sql"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "IDENTIFIED BY PASSWORD"))
                continue;
            if ((RuleMatchers.LineContains(line, "IDENTIFIED BY") || RuleMatchers.LineContains(line, "PASSWORD"))
                && line.Contains('\''))
                context.Report("Do not hardcode credentials in the script.", i + 1);
        }
    }
}

public sealed class SqlIdentifiedByPasswordRule : PatternRuleBase
{
    public override string Key => "QG-SQL-SEC-0004";
    public override string Name => "Weak password hash algorithm";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Use a strong hash algorithm instead of the PASSWORD() function.";
    public override string[] Languages => ["sql"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
            if (RuleMatchers.LineContains(lines[i], "IDENTIFIED BY PASSWORD"))
                context.Report("Avoid the weak PASSWORD() hash; use a strong algorithm.", i + 1);
    }
}

public sealed class SqlSetPasswordPlaintextRule : PatternRuleBase
{
    public override string Key => "QG-SQL-SEC-0005";
    public override string Name => "Plaintext password in SET PASSWORD";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "Assign the password via a variable or secret instead of a literal.";
    public override string[] Languages => ["sql"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "SET PASSWORD") && line.Contains('\''))
                context.Report("Do not set a plaintext password literal.", i + 1);
        }
    }
}

public sealed class SqlSelectStarRule : PatternRuleBase
{
    public override string Key => "QG-SQL-SML-0001";
    public override string Name => "Avoid SELECT *";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "List only the columns the query actually needs.";
    public override string[] Languages => ["sql"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
            if (RuleMatchers.LineContains(lines[i], "SELECT *"))
                context.Report("Select only the columns you need instead of SELECT *.", i + 1);
    }
}

public sealed class SqlMissingSemicolonRule : PatternRuleBase
{
    public override string Key => "QG-SQL-CNV-0001";
    public override string Name => "Statements should end with a semicolon";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "Terminate the statement with a semicolon.";
    public override string[] Languages => ["sql"];

    private static readonly string[] StatementKeywords =
    [
        "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP",
        "ALTER", "GRANT", "REVOKE", "TRUNCATE"
    ];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith("--") || trimmed.StartsWith("/*"))
                continue;
            var isStatement = false;
            foreach (var keyword in StatementKeywords)
            {
                if (RuleMatchers.LineContains(lines[i], keyword))
                {
                    isStatement = true;
                    break;
                }
            }
            if (isStatement && !trimmed.EndsWith(";"))
                context.Report("Terminate the statement with a semicolon.", i + 1);
        }
    }
}

public sealed class SqlDeleteUpdateWithoutWhereRule : PatternRuleBase
{
    public override string Key => "QG-SQL-BUG-0001";
    public override string Name => "DELETE or UPDATE without WHERE";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "Add a WHERE clause to limit the affected rows.";
    public override string[] Languages => ["sql"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        var hasWhere = lines.Any(l => RuleMatchers.LineContains(l, "WHERE"));
        if (hasWhere)
            return;
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "DELETE FROM") || RuleMatchers.LineContains(line, "UPDATE"))
                context.Report("This statement modifies rows without a WHERE clause.", i + 1);
        }
    }
}

public sealed class SqlLiteralEqualsTrueRule : PatternRuleBase
{
    public override string Key => "QG-SQL-BUG-0002";
    public override string Name => "Condition that is always true";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "Remove the tautological condition or rewrite the predicate.";
    public override string[] Languages => ["sql"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RuleMatchers.LineContains(line, "1=1") || RuleMatchers.LineContains(line, "1 = 1"))
                context.Report("Avoid conditions that always evaluate to true (1=1).", i + 1);
        }
    }
}
