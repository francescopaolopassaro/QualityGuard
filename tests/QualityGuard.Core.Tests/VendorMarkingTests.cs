using QualityGuard.Core.Analysis;
using QualityGuard.Core.Tokenization;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Third-party marking keeps files inside metrics and the project index while rules stay silent:
/// findings on code nobody here can change are noise by definition.
/// </summary>
public class VendorMarkingTests
{
    private static AnalysisContext Context(params string[] vendorGlobs) =>
        new(
        [
            new SourceFile("src/ours/Mine.cs", "public class Mine { }", BuiltInLanguages.CSharp),
            new SourceFile("libs/Ajax/Toolkit.cs", "public class Toolkit { }", BuiltInLanguages.CSharp)
        ],
        new AnalysisOptions { VendorPaths = vendorGlobs });

    [Fact]
    public void Files_matching_a_vendor_pattern_are_marked()
    {
        var context = Context("**/Ajax/**");
        var results = new AnalysisEngine().Run(context);
        Assert.False(results.Single(r => r.File.Path == "src/ours/Mine.cs").File.IsVendor);
        Assert.True(results.Single(r => r.File.Path == "libs/Ajax/Toolkit.cs").File.IsVendor);
    }

    [Fact]
    public void Without_patterns_nothing_is_marked()
    {
        var results = new AnalysisEngine().Run(Context());
        Assert.All(results, r => Assert.False(r.File.IsVendor));
    }
}
