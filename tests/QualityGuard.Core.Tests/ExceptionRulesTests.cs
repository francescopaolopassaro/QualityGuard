using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>Failure-handling rules, each pinned on the defect and on the correct code next to it.</summary>
public class ExceptionRulesTests
{
    private static IReadOnlyList<int> Lines(string file, string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_catch_that_only_rethrows_is_reported()
    {
        var code = """
            public class Loader
            {
                public void Run()
                {
                    try { Work(); }
                    catch (System.Exception) { throw; }
                }

                private void Work() { }
            }
            """;
        Assert.NotEmpty(Lines("Loader.cs", code, "QG-ALL-SML-0048"));
    }

    [Fact]
    public void A_catch_that_wraps_the_exception_is_left_alone()
    {
        var code = """
            public class Loader
            {
                public void Run()
                {
                    try { Work(); }
                    catch (System.Exception e) { throw new LoadFailed("loading the profile", e); }
                }

                private void Work() { }
            }
            """;
        Assert.Empty(Lines("Loader.cs", code, "QG-ALL-SML-0048"));
    }

    [Fact]
    public void A_throw_inside_finally_is_reported()
    {
        var code = """
            public class Loader
            {
                public void Run()
                {
                    try { Work(); }
                    finally { throw new System.InvalidOperationException("cleanup"); }
                }

                private void Work() { }
            }
            """;
        Assert.NotEmpty(Lines("Loader.cs", code, "QG-ALL-BUG-0037"));
    }

    [Fact]
    public void A_finally_that_only_cleans_up_is_left_alone()
    {
        var code = """
            public class Loader
            {
                public void Run()
                {
                    try { Work(); }
                    finally { Close(); }
                }

                private void Work() { }
                private void Close() { }
            }
            """;
        Assert.Empty(Lines("Loader.cs", code, "QG-ALL-BUG-0037"));
    }

    [Fact]
    public void A_local_returned_on_the_next_line_is_reported()
    {
        var code = """
            public class Loader
            {
                public int Count()
                {
                    var total = Compute();
                    return total;
                }

                private int Compute() => 1;
            }
            """;
        Assert.Equal([5], Lines("Loader.cs", code, "QG-ALL-SML-0050"));
    }

    [Fact]
    public void A_local_that_is_used_before_being_returned_is_left_alone()
    {
        var code = """
            public class Loader
            {
                public int Count()
                {
                    var total = Compute();
                    Log(total);
                    return total;
                }

                private int Compute() => 1;
                private void Log(int value) { }
            }
            """;
        Assert.Empty(Lines("Loader.cs", code, "QG-ALL-SML-0050"));
    }

    [Fact]
    public void Catching_a_failure_the_process_cannot_survive_is_reported()
    {
        var code = """
            public class Loader
            {
                public void Run()
                {
                    try { Work(); }
                    catch (System.NullReferenceException) { }
                }

                private void Work() { }
            }
            """;
        Assert.NotEmpty(Lines("Loader.cs", code, "QG-ALL-BUG-0038"));
    }

    [Fact]
    public void Catching_a_specific_exception_is_left_alone()
    {
        var code = """
            public class Loader
            {
                public void Run()
                {
                    try { Work(); }
                    catch (System.IO.FileNotFoundException) { Report(); }
                }

                private void Work() { }
                private void Report() { }
            }
            """;
        Assert.Empty(Lines("Loader.cs", code, "QG-ALL-BUG-0038"));
    }

    [Fact]
    public void An_empty_comment_is_reported_but_a_blank_line_of_a_doc_block_is_not()
    {
        var withEmpty = """
            public class Loader
            {
                //
                public void Run() { }
            }
            """;
        Assert.NotEmpty(Lines("Loader.cs", withEmpty, "QG-ALL-SML-0051"));

        var docBlock = """
            public class Loader
            {
                /// <summary>
                ///
                /// Loads the profile.
                /// </summary>
                public void Run() { }
            }
            """;
        Assert.Empty(Lines("Loader.cs", docBlock, "QG-ALL-SML-0051"));
    }
}
