using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Go precision. Each case was a false positive found on real Go code, and each covers something Go
/// does on purpose: panic where nobody can recover, an octal permission mask, a defer at function
/// level in a file that also has a loop.
/// </summary>
public class GoPrecisionTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "main.go")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_panic_is_reported_only_where_an_error_was_promised()
    {
        var promised = """
            package main

            func load(path string) ([]byte, error) {
                if path == "" {
                    panic("empty path")
                }
                return nil, nil
            }
            """;
        Assert.NotEmpty(Lines(promised, "QG-GO-BUG-0001"));

        // main has nobody to return an error to, and a panic there is how Go stops
        var entryPoint = """
            package main

            func main() {
                panic("cannot start")
            }
            """;
        Assert.Empty(Lines(entryPoint, "QG-GO-BUG-0001"));
    }

    [Fact]
    public void A_permission_mask_is_not_an_accidental_octal()
    {
        Assert.Empty(Lines("package main\n\nfunc go1() {\n    mkdir(\"/tmp/x\", 0755)\n}\n",
            "QG-ALL-BUG-0033"));
        Assert.Empty(Lines("package main\n\nfunc go1() {\n    chmod(\"/tmp/x\", 0644)\n}\n",
            "QG-ALL-BUG-0033"));
        // a number that simply starts with a zero is still the accident the rule is about
        Assert.NotEmpty(Lines("package main\n\nfunc go1() int {\n    return 012345\n}\n",
            "QG-ALL-BUG-0033"));
    }

    [Fact]
    public void A_defer_is_reported_only_inside_the_loop_that_holds_it()
    {
        var inLoop = """
            package main

            func a(paths []string) {
                for _, p := range paths {
                    f, _ := open(p)
                    defer f.Close()
                }
            }
            """;
        Assert.NotEmpty(Lines(inLoop, "QG-GO-BUG-0004"));

        // the file has a loop, but the defer is at function level and runs once
        var outside = """
            package main

            func b(p string) {
                f, _ := open(p)
                defer f.Close()
                for i := 0; i < 3; i++ {
                    println(i)
                }
            }
            """;
        Assert.Empty(Lines(outside, "QG-GO-BUG-0004"));
    }
}
