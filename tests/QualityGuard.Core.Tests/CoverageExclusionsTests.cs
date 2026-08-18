using QualityGuard.Core.Analysis;
using Xunit;

// Every instrumented platform has a way to tell the coverage tooling "this is not code to measure":
// an attribute on the member or a marker comment in the source. QualityGuard reads the same markers,
// because a line the team explicitly asked its runner to skip must not then count against the gate —
// the percentage the engine reports would argue with every other tool reading the same files.

namespace QualityGuard.Core.Tests;

public class CoverageExclusionsTests
{
    [Fact]
    public void CSharp_ExcludeFromCodeCoverage_on_a_class_removes_its_lines()
    {
        var analysis = Analyze.File("Foo.cs", """
            [ExcludeFromCodeCoverage]
            public class Generated
            {
                public void Run()
                {
                    Console.WriteLine("x");
                }
            }

            public class Real
            {
                public void Run()
                {
                    Console.WriteLine("y");
                }
            }
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.cs
            DA:6,0
            DA:14,1
            end_of_record
            """)!;
        var expected = new HashSet<int>(Enumerable.Range(1, 8));

        var excluded = CoverageExclusions.Compute([analysis]);
        var fileExclusions = Assert.Single(excluded.Values);

        Assert.Equal(expected, fileExclusions.Lines);
        var result = report.ExcludingFromSource([analysis]);
        Assert.Equal(1, result.LinesToCover);
        Assert.Equal(1, result.CoveredLines);
        Assert.Equal(100.0, result.Coverage, 2);
    }

    [Fact]
    public void CSharp_ExcludeFromCodeCoverage_on_a_method_removes_only_that_method()
    {
        var analysis = Analyze.File("Foo.cs", """
            public class Real
            {
                [ExcludeFromCodeCoverage]
                public void Skipped()
                {
                    Console.WriteLine("x");
                }

                public void Kept()
                {
                    Console.WriteLine("y");
                }
            }
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.cs
            DA:6,0
            DA:11,1
            end_of_record
            """)!;

        var result = report.ExcludingFromSource([analysis]);

        Assert.Equal(1, result.LinesToCover);
        Assert.Equal(1, result.CoveredLines);
        Assert.Equal(100.0, result.Coverage, 2);
    }

    [Fact]
    public void CSharp_GeneratedCode_attribute_marks_generated_members()
    {
        var analysis = Analyze.File("Foo.cs", """
            [GeneratedCode("tooling", "1.0")]
            public class Tooled
            {
                public void Run()
                {
                    Console.WriteLine("x");
                }
            }
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.cs
            DA:6,0
            end_of_record
            """)!;

        var result = report.ExcludingFromSource([analysis]);

        Assert.Equal(0, result.LinesToCover);
        Assert.True(result.Coverage == 0);
    }

    [Fact]
    public void Java_Generated_annotation_on_a_class_removes_its_lines()
    {
        var analysis = Analyze.File("Foo.java", """
            @Generated
            class GeneratedThing {
                void run() {
                    System.out.println("x");
                }
            }

            class Real {
                void run() {
                    System.out.println("y");
                }
            }
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.java
            DA:4,0
            DA:10,1
            end_of_record
            """)!;

        var result = report.ExcludingFromSource([analysis]);

        Assert.Equal(1, result.LinesToCover);
        Assert.Equal(1, result.CoveredLines);
        Assert.Equal(100.0, result.Coverage, 2);
    }

    [Fact]
    public void Java_Generated_annotation_on_a_method_removes_only_that_method()
    {
        var analysis = Analyze.File("Foo.java", """
            class Real {
                @Generated
                void gen() {
                    System.out.println("x");
                }
                void kept() {
                    System.out.println("y");
                }
            }
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.java
            DA:4,0
            DA:7,1
            end_of_record
            """)!;

        var result = report.ExcludingFromSource([analysis]);

        Assert.Equal(1, result.LinesToCover);
        Assert.Equal(1, result.CoveredLines);
    }

    [Fact]
    public void Java_Generated_spelled_out_in_a_comment_excludes_nothing()
    {
        var analysis = Analyze.File("Foo.java", """
            // this class is not @Generated, whatever the comment says
            class Real {
                void kept() {
                    System.out.println("y");
                }
            }
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.java
            DA:4,1
            end_of_record
            """)!;

        var result = report.ExcludingFromSource([analysis]);

        Assert.Equal(1, result.LinesToCover);
        Assert.Equal(1, result.CoveredLines);
    }

    [Fact]
    public void Python_pragma_no_cover_removes_the_line_and_wont_match_inside_a_string()
    {
        var analysis = Analyze.File("Foo.py", """
            def f():
                x = 1
                return x  # pragma: no cover


            def g():
                s = "# pragma: no cover"
                return s
            """);
        var excluded = CoverageExclusions.Compute([analysis]);
        var fileExclusions = Assert.Single(excluded.Values);

        Assert.Contains(3, fileExclusions.Lines);
        Assert.DoesNotContain(7, fileExclusions.Lines);
    }

    [Fact]
    public void JavaScript_istanbul_ignore_next_removes_the_following_line()
    {
        var analysis = Analyze.File("Foo.js", """
            /* istanbul ignore next */
            function a() { return 1; }
            function b() { return 2; }
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.js
            DA:2,0
            DA:3,1
            end_of_record
            """)!;

        var result = report.ExcludingFromSource([analysis]);

        Assert.Equal(1, result.LinesToCover);
        Assert.Equal(1, result.CoveredLines);
    }

    [Fact]
    public void JavaScript_v8_ignore_file_drops_the_whole_file()
    {
        var analysis = Analyze.File("Foo.js", """
            /* v8 ignore file */
            function a() { return 1; }
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.js
            DA:2,0
            end_of_record
            """)!;

        var result = report.ExcludingFromSource([analysis]);

        Assert.Empty(result.Files);
        Assert.Equal(0, result.LinesToCover);
    }

    [Fact]
    public void Ruby_nocov_pair_removes_the_region_between_the_markers()
    {
        var analysis = Analyze.File("Foo.rb", """
            def ok
              puts "a"
            end

            # :nocov:
            def hidden
              puts "b"
            end
            # :nocov:

            def shown
              puts "c"
            end
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.rb
            DA:2,1
            DA:7,0
            DA:12,1
            end_of_record
            """)!;

        var result = report.ExcludingFromSource([analysis]);

        Assert.Equal(2, result.LinesToCover);
        Assert.Equal(2, result.CoveredLines);
        Assert.Equal(100.0, result.Coverage, 2);
    }

    [Fact]
    public void CSharp_LCOV_excl_start_and_stop_remove_the_region()
    {
        var analysis = Analyze.File("Foo.cs", """
            public class Real
            {
                // LCOV_EXCL_START
                public void Hidden()
                {
                    Console.WriteLine("x");
                }
                // LCOV_EXCL_STOP
                public void Shown()
                {
                    Console.WriteLine("y");
                }
            }
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.cs
            DA:6,0
            DA:11,1
            end_of_record
            """)!;

        var result = report.ExcludingFromSource([analysis]);

        Assert.Equal(1, result.LinesToCover);
        Assert.Equal(1, result.CoveredLines);
    }

    [Fact]
    public void Php_codeCoverageIgnore_in_a_doc_block_removes_the_next_line()
    {
        var analysis = Analyze.File("Foo.php", """
            <?php
            /** @codeCoverageIgnore */
            function hidden() { return 1; }
            function shown() { return 2; }
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.php
            DA:3,0
            DA:4,1
            end_of_record
            """)!;

        var result = report.ExcludingFromSource([analysis]);

        Assert.Equal(1, result.LinesToCover);
        Assert.Equal(1, result.CoveredLines);
    }

    [Fact]
    public void CSharp_a_marker_inside_a_string_literal_excludes_nothing()
    {
        var analysis = Analyze.File("Foo.cs", """
            public class Real
            {
                public const string Text = "[ExcludeFromCodeCoverage]";
                public void Kept()
                {
                    Console.WriteLine(Text);
                }
            }
            """);
        var report = CoverageReport.Parse("""
            SF:Foo.cs
            DA:6,1
            end_of_record
            """)!;

        var excluded = CoverageExclusions.Compute([analysis]);
        Assert.Empty(excluded);

        var result = report.ExcludingFromSource([analysis]);
        Assert.Same(report, result);
        Assert.Equal(1, result.LinesToCover);
    }

    [Fact]
    public void ExcludingLines_drops_a_file_whose_whole_range_is_excluded()
    {
        var report = CoverageReport.Parse("""
            SF:src/Lead.cs
            DA:1,1
            DA:2,1
            end_of_record
            SF:src/Other.cs
            DA:1,0
            end_of_record
            SF:src/Keep.cs
            DA:1,0
            DA:2,1
            end_of_record
            """)!;
        var byPath = new Dictionary<string, FileExclusions>(StringComparer.OrdinalIgnoreCase)
        {
            ["src/Lead.cs"] = new FileExclusions { Lines = new HashSet<int> { 1, 2 } },
            ["src/Other.cs"] = new FileExclusions { ExcludeFile = true }
        };

        var result = report.ExcludingLines(byPath);

        // Lead became empty once its lines were dropped, Other declared gone entirely: only Keep stays
        var file = Assert.Single(result.Files);
        Assert.Equal("src/Keep.cs", file.Path);
        Assert.Equal(2, result.LinesToCover);
        Assert.Equal(1, result.CoveredLines);
    }
}