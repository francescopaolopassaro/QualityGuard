using QualityGuard.Core.Models;

namespace QualityGuard.Core.Analysis;

/// <summary>
/// Turns findings into the numbers a gate can be argued about.
///
/// Two things make a rating trustworthy: it has to move for a reason a reader can name, and it has to
/// come from the severity of what was found rather than from how many findings there happen to be.
/// One blocker is worse than forty minor smells, and a rating that says otherwise is a rating nobody
/// acts on. Maintainability is the exception: it is a ratio, because "twelve smells" means something
/// different in a hundred lines and in a hundred thousand.
/// </summary>
public static class QualityRatings
{
    /// <summary>Minutes a developer is assumed to need to write one line of code.</summary>
    private const double DevelopmentCostPerLine = 30.0;

    /// <summary>Kept for callers that only have a count; prefer the severity-driven overload.</summary>
    public static int RatingFromCount(int count) => count switch
    {
        0 => 1,
        1 => 2,
        2 => 3,
        3 => 4,
        _ => 5
    };

    /// <summary>
    /// A = nothing found, B = at least one minor, C = major, D = critical, E = blocker. The worst
    /// finding decides, which is what makes the letter mean something on its own.
    /// </summary>
    public static int RatingFromSeverity(IEnumerable<Issue> issues)
    {
        var rating = 1;
        foreach (var issue in issues)
        {
            var candidate = issue.Severity switch
            {
                Severity.Blocker => 5,
                Severity.Critical => 4,
                Severity.Major => 3,
                Severity.Minor => 2,
                _ => 1
            };
            if (candidate > rating)
                rating = candidate;
        }
        return rating;
    }

    /// <summary>
    /// Remediation effort in minutes. Rules state it as "5min", "1h30min" or "2d". Anything that is
    /// not a duration reads as zero instead of being guessed at, and the reading is deliberately
    /// strict: a rule that describes its fix in a sentence used to contribute whatever number and
    /// letter happened to appear in it, which put minutes into the debt that nobody had estimated.
    /// </summary>
    public static int EffortMinutes(string? effort)
    {
        if (string.IsNullOrWhiteSpace(effort) || !IsDuration(effort))
            return 0;

        var total = 0;
        var number = 0;
        var seenDigit = false;
        for (var i = 0; i < effort.Length; i++)
        {
            var c = effort[i];
            if (char.IsAsciiDigit(c))
            {
                number = number * 10 + (c - '0');
                seenDigit = true;
                continue;
            }
            if (!seenDigit)
                continue;

            if (c is 'd' or 'D')
                total += number * 8 * 60; // a working day, not a calendar one
            else if (c is 'h' or 'H')
                total += number * 60;
            else if (c is 'm' or 'M')
                total += number;
            else
                continue;

            number = 0;
            seenDigit = false;
            while (i + 1 < effort.Length && char.IsLetter(effort[i + 1]))
                i++;
        }
        return total;
    }

    /// <summary>A duration and nothing else: digits, then d, h or min, repeated.</summary>
    private static bool IsDuration(string effort)
    {
        var i = 0;
        var parts = 0;
        while (i < effort.Length)
        {
            var start = i;
            while (i < effort.Length && char.IsAsciiDigit(effort[i]))
                i++;
            if (i == start)
                return false;

            var unit = i;
            while (i < effort.Length && char.IsAsciiLetter(effort[i]))
                i++;
            var suffix = effort[unit..i];
            if (suffix is not ("d" or "h" or "min" or "m"))
                return false;
            parts++;
        }
        return parts > 0;
    }

    /// <summary>
    /// What a finding is worth in debt when its rule never stated a duration. Guessing from the
    /// severity is not precise, but it is the same guess for every rule, so the ratio stays
    /// comparable between scans instead of depending on which rules happen to fire.
    /// </summary>
    public static int DefaultEffortMinutes(Severity severity) => severity switch
    {
        Severity.Blocker => 60,
        Severity.Critical => 30,
        Severity.Major => 15,
        Severity.Minor => 10,
        _ => 5
    };

    public static int TotalDebtMinutes(IEnumerable<Issue> issues)
        => issues.Sum(issue => EffortMinutes(issue.RemediationEffort) is var minutes && minutes > 0
            ? minutes
            : DefaultEffortMinutes(issue.Severity));

    /// <summary>
    /// Debt as a share of what the code cost to write. The thresholds are the usual ones: up to 5 %
    /// is an A, then 10 %, 20 % and 50 %.
    /// </summary>
    public static double DebtRatio(int debtMinutes, double ncloc)
        => ncloc <= 0 ? 0 : debtMinutes / (ncloc * DevelopmentCostPerLine) * 100.0;

    public static int MaintainabilityRating(double debtRatio) => debtRatio switch
    {
        <= 5 => 1,
        <= 10 => 2,
        <= 20 => 3,
        <= 50 => 4,
        _ => 5
    };

    public static string Letter(double rating) => rating switch
    {
        <= 1 => "A",
        <= 2 => "B",
        <= 3 => "C",
        <= 4 => "D",
        _ => "E"
    };

    /// <summary>Every quality number of a scan, computed from the findings themselves.</summary>
    public static IReadOnlyDictionary<string, double> ComputeMetrics(IReadOnlyList<Issue> issues, double ncloc)
    {
        var bugs = issues.Where(i => i.Kind == IssueKind.Bug).ToList();
        var vulnerabilities = issues.Where(i => i.Kind == IssueKind.Vulnerability).ToList();
        var smells = issues.Where(i => i.Kind == IssueKind.CodeSmell).ToList();
        var hotspots = issues.Count(i => i.Kind == IssueKind.SecurityHotspot);
        var debt = TotalDebtMinutes(smells);
        var ratio = DebtRatio(debt, ncloc);

        return new Dictionary<string, double>
        {
            [CoreMetrics.Bugs] = bugs.Count,
            [CoreMetrics.Vulnerabilities] = vulnerabilities.Count,
            [CoreMetrics.CodeSmells] = smells.Count,
            [CoreMetrics.SecurityHotspots] = hotspots,
            [CoreMetrics.TechnicalDebt] = debt,
            [CoreMetrics.DebtRatio] = ratio,
            [CoreMetrics.ReliabilityRating] = RatingFromSeverity(bugs),
            [CoreMetrics.SecurityRating] = RatingFromSeverity(vulnerabilities),
            [CoreMetrics.MaintainabilityRating] = MaintainabilityRating(ratio)
        };
    }

    /// <summary>The same numbers, reported against the new-code metric keys the gate evaluates.</summary>
    public static IReadOnlyDictionary<string, double> ComputeNewCodeMetrics(
        IReadOnlyList<Issue> issues, double newLines)
    {
        var overall = ComputeMetrics(issues, newLines);
        var hotspots = issues.Count(i => i.Kind == IssueKind.SecurityHotspot);
        return new Dictionary<string, double>
        {
            [CoreMetrics.NewReliabilityRating] = overall[CoreMetrics.ReliabilityRating],
            [CoreMetrics.NewSecurityRating] = overall[CoreMetrics.SecurityRating],
            [CoreMetrics.NewMaintainabilityRating] = overall[CoreMetrics.MaintainabilityRating],
            [CoreMetrics.NewSecurityHotspotsReviewed] = hotspots == 0 ? 100.0 : 0.0,
            [CoreMetrics.NewLines] = newLines
        };
    }

    /// <summary>Count-based variant kept for callers that do not hold the findings themselves.</summary>
    public static IReadOnlyDictionary<string, double> ComputeNewCodeMetrics(
        int bugs, int vulnerabilities, int codeSmells, int securityHotspots, double newLines)
    {
        return new Dictionary<string, double>
        {
            [CoreMetrics.NewReliabilityRating] = RatingFromCount(bugs),
            [CoreMetrics.NewSecurityRating] = RatingFromCount(vulnerabilities),
            [CoreMetrics.NewMaintainabilityRating] = RatingFromCount(codeSmells),
            [CoreMetrics.NewSecurityHotspotsReviewed] = securityHotspots == 0 ? 100.0 : 0.0,
            [CoreMetrics.NewLines] = newLines
        };
    }
}
