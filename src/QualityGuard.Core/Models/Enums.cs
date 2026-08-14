namespace QualityGuard.Core.Models;

public enum Severity
{
    Info,
    Minor,
    Major,
    Critical,
    Blocker
}

public enum IssueKind
{
    Bug,
    Vulnerability,
    CodeSmell,
    SecurityHotspot
}

public enum MetricOperator
{
    LessThan,
    GreaterThan
}

public enum QualityGateStatus
{
    Passed,
    Failed
}

public enum ConditionStatus
{
    Ok,
    Error
}

public enum Rating
{
    A = 1,
    B = 2,
    C = 3,
    D = 4,
    E = 5
}