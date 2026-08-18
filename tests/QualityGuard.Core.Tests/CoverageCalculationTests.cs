using System.Diagnostics;
using QualityGuard.Core.Analysis;
using Xunit;

// The reference engine counts lines and conditions separately and combines them into one coverage
// percentage. These tests keep QualityGuard's numbers on the same definitions, because a gate a
// team cannot reconcile with the engine it already trusts will not be believed.

namespace QualityGuard.Core.Tests;

public class CoverageCalculationTests
{
    [Fact]
    public void Lcov_lines_and_branches_compute_the_three_reference_percentages()
    {
        const string lcov = """
            SF:src/A.cs
            DA:1,5
            DA:2,0
            DA:3,2
            BRDA:2,0,0,1
            BRDA:2,0,1,0
            end_of_record
            SF:src/B.cs
            DA:1,1
            end_of_record
            """;

        var report = CoverageReport.Parse(lcov)!;

        Assert.Equal(4, report.LinesToCover);
        Assert.Equal(3, report.CoveredLines);
        Assert.Equal(2, report.ConditionsToCover);
        Assert.Equal(1, report.CoveredConditions);
        Assert.Equal(66.67, report.Coverage, 2);
        Assert.Equal(75.0, report.LineCoverage, 2);
        Assert.Equal(50.0, report.BranchCoverage, 2);
    }

    [Fact]
    public void Lcov_a_branch_never_taken_is_uncovered()
    {
        const string lcov = """
            SF:src/A.cs
            DA:1,1
            BRDA:1,0,0,-
            BRDA:1,0,1,3
            end_of_record
            """;

        var report = CoverageReport.Parse(lcov)!;

        Assert.Equal(2, report.ConditionsToCover);
        Assert.Equal(1, report.CoveredConditions);
        Assert.Equal(50.0, report.BranchCoverage, 2);
    }

    [Fact]
    public void Jacoco_lines_keep_hits_and_branch_counts()
    {
        const string jacoco = """
            <report name="sample">
              <package name="com.example">
                <sourcefile name="Foo.java">
                  <line nr="5" mi="0" ci="3" mb="0" cb="0"/>
                  <line nr="6" mi="2" ci="0" mb="2" cb="1"/>
                </sourcefile>
              </package>
            </report>
            """;

        var report = CoverageReport.Parse(jacoco)!;

        var file = Assert.Single(report.Files);
        Assert.Equal("com/example/Foo.java", file.Path);
        Assert.Equal(1, file.Lines[5].Hits);
        Assert.Equal(0, file.Lines[6].Hits);
        Assert.Equal(3, file.Lines[6].Conditions);
        Assert.Equal(1, file.Lines[6].CoveredConditions);
        Assert.Equal(2, report.LinesToCover);
        Assert.Equal(1, report.CoveredLines);
        Assert.Equal(40.0, report.Coverage, 2);
        Assert.Equal(50.0, report.LineCoverage, 2);
        Assert.Equal(33.33, report.BranchCoverage, 2);
    }

    [Fact]
    public void Cobertura_condition_coverage_is_split_into_conditions()
    {
        const string cobertura = """
            <coverage>
              <packages>
                <package name="x">
                  <classes>
                    <class name="X" filename="src/X.cs">
                      <lines>
                        <line number="10" hits="3" branch="True" condition-coverage="50% (1/2)"/>
                        <line number="11" hits="0"/>
                      </lines>
                    </class>
                  </classes>
                </package>
              </packages>
            </coverage>
            """;

        var report = CoverageReport.Parse(cobertura)!;

        Assert.Equal(2, report.LinesToCover);
        Assert.Equal(1, report.CoveredLines);
        Assert.Equal(2, report.ConditionsToCover);
        Assert.Equal(1, report.CoveredConditions);
        Assert.Equal(50.0, report.Coverage, 2);
    }

    [Fact]
    public void Merging_two_reports_cumulates_hits_and_keeps_the_max_conditions()
    {
        var first = CoverageReport.Parse("""
            SF:src/A.cs
            DA:1,2
            DA:2,0
            BRDA:2,0,0,1
            BRDA:2,0,1,0
            end_of_record
            """)!;
        var second = CoverageReport.Parse("""
            SF:src/A.cs
            DA:1,3
            DA:2,5
            BRDA:2,0,0,1
            BRDA:2,0,1,1
            end_of_record
            """)!;

        var merged = CoverageReport.Merge([first, second]);

        var file = Assert.Single(merged.Files);
        Assert.Equal(5, file.Lines[1].Hits);
        Assert.Equal(5, file.Lines[2].Hits);
        Assert.Equal(2, file.Lines[2].Conditions);
        Assert.Equal(2, file.Lines[2].CoveredConditions);
        Assert.Equal(2, merged.CoveredLines);
        Assert.Equal(100.0, merged.Coverage, 2);
    }

    [Fact]
    public void New_code_measures_only_the_lines_that_are_new()
    {
        var report = CoverageReport.Parse("""
            SF:src/A.cs
            DA:1,1
            DA:2,5
            end_of_record
            SF:src/B.cs
            DA:1,0
            DA:2,0
            BRDA:1,0,0,-
            BRDA:1,0,1,-
            end_of_record
            """)!;
        var newLines = new Dictionary<string, IReadOnlySet<int>>(StringComparer.OrdinalIgnoreCase)
        {
            ["src/A.cs"] = new HashSet<int> { 1 },
            ["src/B.cs"] = new HashSet<int> { 1 }
        };

        var newCode = report.NewCode(newLines);

        Assert.True(newCode.HasData);
        Assert.Equal(2, newCode.LinesToCover);
        Assert.Equal(1, newCode.CoveredLines);
        Assert.Equal(2, newCode.ConditionsToCover);
        Assert.Equal(0, newCode.CoveredConditions);
        Assert.Equal(25.0, newCode.Coverage, 2);
        Assert.Equal(1, newCode.UncoveredLines);
    }

    [Fact]
    public void New_code_with_no_new_lines_reports_nothing()
    {
        var report = CoverageReport.Parse("""
            SF:src/A.cs
            DA:1,1
            end_of_record
            """)!;

        var newCode = report.NewCode(new Dictionary<string, IReadOnlySet<int>>());

        Assert.False(newCode.HasData);
        Assert.Equal(0.0, newCode.Coverage);
    }

    [Fact]
    public void Excluded_test_files_leave_production_coverage_alone()
    {
        var report = CoverageReport.Parse("""
            SF:src/Production.cs
            DA:1,1
            DA:2,0
            end_of_record
            SF:tests/ProductionTests.cs
            DA:1,5
            DA:2,5
            end_of_record
            """)!;

        var production = report.ExcludingTests();

        Assert.Single(production.Files);
        Assert.Equal("src/Production.cs", production.Files[0].Path);
        Assert.Equal(2, production.LinesToCover);
        Assert.Equal(1, production.CoveredLines);
    }

    [Theory]
    [InlineData("t/ProdTest.cs", true)]
    [InlineData("src/helper/Tools.cs", false)]
    [InlineData("src/production/X.cs", false)]
    [InlineData("tests/ProductionTests.cs", true)]
    [InlineData("src/__tests__/x.ts", true)]
    [InlineData("src/production/foo_test.py", true)]
    [InlineData("src/test_foo.py", true)]
    [InlineData("src/production/FooTest.java", true)]
    [InlineData("src/KotlinFooTest.kt", true)]
    [InlineData("src/production/FooSpec.java", true)]
    [InlineData("src/foo.test.js", true)]
    [InlineData("src/foo.spec.ts", true)]
    public void Test_files_are_recognised_by_path_and_name(string path, bool expected)
        => Assert.Equal(expected, TestFileDetector.IsTestFile(path));

    [Fact]
    public void Git_diff_marks_added_and_modified_lines_as_new()
    {
        const string diff = """
            diff --git a/src/A.cs b/src/A.cs
            index 1111111..2222222 100644
            --- a/src/A.cs
            +++ b/src/A.cs
            @@ -1,3 +1,4 @@
             line1
            -old2
            -old3
            +new2
            +new3
            +new4
            diff --git a/test/T.cs b/test/T.cs
            new file mode 100644
            index 0000000..abc1234
            --- /dev/null
            +++ b/test/T.cs
            @@ -0,0 +1,1 @@
            +namespace T { }
            """;

        var root = "C:/repo";
        var lines = GitChangedLines.Parse(diff, root);

        Assert.Equal(new HashSet<int> { 2, 3, 4 },
            lines[CoveragePathResolver.Normalize("C:/repo/src/A.cs")]);
        Assert.Equal(new HashSet<int> { 1 },
            lines[CoveragePathResolver.Normalize("C:/repo/test/T.cs")]);
    }

    [Fact]
    public void A_deleted_file_contributes_no_new_lines()
    {
        const string diff = """
            diff --git a/src/Gone.cs b/src/Gone.cs
            deleted file mode 100644
            index 1111111..0000000
            --- a/src/Gone.cs
            +++ /dev/null
            @@ -1,2 +0,0 @@
            -bye
            -bye
            """;

        var lines = GitChangedLines.Parse(diff, "C:/repo");

        Assert.Empty(lines);
    }

    [Fact]
    public void Git_Resolve_keeps_named_refs_unchanged_and_recognizes_dates()
    {
        Assert.Equal("origin/main", GitChangedLines.Resolve("origin/main"));
        Assert.Equal("feature/x", GitChangedLines.Resolve("feature/x"));
        Assert.Equal("abc1234", GitChangedLines.Resolve("abc1234"));
        Assert.False(GitChangedLines.IsDate("origin/main"));
        Assert.False(GitChangedLines.IsDate("abc1234"));
        Assert.True(GitChangedLines.IsDate("2024-01-01"));
    }

    [Fact]
    public void Git_Resolve_a_date_to_the_last_commit_before_it()
    {
        var dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "qg-git-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            if (!Git(dir, "init -q", out _))
                return; // no git on this machine: the pure parse contract is covered by the tests above
            _ = Git(dir, "config user.email qg@test", out _);
            _ = Git(dir, "config user.name qg", out _);
            _ = Git(dir, "commit --allow-empty -m base", out _);
            _ = Git(dir, "rev-parse HEAD", out var head);

            // a date after the only commit resolves to that commit; a date before any of them has
            // nothing to resolve to and falls back to HEAD, so the diff fails cleanly instead of
            // silently comparing against nothing
            Assert.Equal(head.Trim(), GitChangedLines.Resolve("2099-01-01", dir));
            Assert.Equal("HEAD", GitChangedLines.Resolve("2000-01-01", dir));
        }
        finally
        {
            // git writes its object files read-only; deleting them straight away fails on Windows
            if (Directory.Exists(dir))
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    File.SetAttributes(file, FileAttributes.Normal);
            }
            Directory.Delete(dir, recursive: true);
        }
    }

    private static bool Git(string cwd, string arguments, out string output)
    {
        try
        {
            var start = new ProcessStartInfo
            {
                FileName = "git",
                Arguments = arguments,
                WorkingDirectory = cwd,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var process = Process.Start(start);
            if (process is null)
            {
                output = string.Empty;
                return false;
            }
            output = process.StandardOutput.ReadToEnd();
            _ = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return process.ExitCode == 0;
        }
        catch (Exception)
        {
            output = string.Empty;
            return false;
        }
    }

    [Fact]
    public void Coverage_paths_resolve_by_exact_name_and_suffix()
    {
        var resolver = new CoveragePathResolver(
        [
            "C:/proj/src/A.cs",
            "C:/proj/lib/B.cs",
            "C:/proj/test/ta/C.cs"
        ]);

        Assert.Equal("C:/proj/src/A.cs", resolver.Resolve("C:/proj/src/A.cs"));
        Assert.Equal("C:/proj/src/A.cs", resolver.Resolve("src/A.cs"));
        Assert.Equal("C:/proj/src/A.cs", resolver.Resolve("A.cs"));
        Assert.Equal("C:/proj/lib/B.cs", resolver.Resolve("B.cs"));
        Assert.Equal("C:/proj/test/ta/C.cs", resolver.Resolve("C.cs"));
        Assert.Null(resolver.Resolve("phantom/D.cs"));
        Assert.Null(resolver.Resolve(""));
    }

    [Fact]
    public void Path_normalization_uses_forward_slashes()
    {
        Assert.Equal("C:/proj/src/A.cs", CoveragePathResolver.Normalize("C:\\proj\\src\\A.cs"));
        Assert.Equal("src/A.cs", CoveragePathResolver.Normalize("./src/A.cs"));
    }
}