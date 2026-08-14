using QualityGuard.Core.Models;

namespace QualityGuard.Core.Analysis;

public static class QualityRatings
{
    public static int RatingFromCount(int count) => count switch
    {
        0 => 1,
        1 => 2,
        2 => 3,
        3 => 4,
        _ => 5
    };

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