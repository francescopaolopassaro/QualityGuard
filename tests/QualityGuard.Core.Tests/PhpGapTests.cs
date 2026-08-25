using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The PHP security-shape rules read the dedicated tree; each test keeps the reported form beside
/// the ordinary code next to it that must stay silent.
/// </summary>
public class PhpGapTests
{
    private static IReadOnlyList<int> Lines(string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules("Sample.php", code, rule), rule);

    [Fact]
    public void A_duplicated_catch_type_is_reported()
    {
        var code = """
            <?php
            try {
                work();
            } catch (RuntimeException $e) {
            } catch (RuntimeException $other) {
            }
            """;
        Assert.Equal([5], Lines(code, "QG-PP-BUG-0134"));
    }

    [Fact]
    public void Distinct_catch_types_are_left_alone()
    {
        var code = """
            <?php
            try {
                work();
            } catch (RuntimeException $e) {
            } catch (LogicException $e2) {
            }
            """;
        Assert.Empty(Lines(code, "QG-PP-BUG-0134"));
    }

    [Fact]
    public void Throwing_a_bare_exception_is_reported()
    {
        var code = """
            <?php
            function fail($why) {
                throw new Exception($why);
            }
            """;
        Assert.Equal([3], Lines(code, "QG-PP-SML-0301"));
    }

    [Fact]
    public void A_named_exception_is_left_alone()
    {
        var code = """
            <?php
            function fail($why) {
                throw new PaymentRejected($why);
            }
            """;
        Assert.Empty(Lines(code, "QG-PP-SML-0301"));
    }

    [Fact]
    public void Set_accessible_true_is_reported()
    {
        var code = """
            <?php
            class Peeper {
                public function peek($target) {
                    $m = new ReflectionMethod($target, 'secret');
                    $m->setAccessible(true);
                }
            }
            """;
        Assert.Equal([5], Lines(code, "QG-PP-SML-0303"));
    }

    [Fact]
    public void An_invariant_for_condition_is_reported()
    {
        // nothing in init, body or update ever changes $limit
        var code = """
            <?php
            function drain($limit) {
                for ($i = 0; $limit > 0; $i++) {
                    echo $i;
                }
            }
            """;
        Assert.Equal([3], Lines(code, "QG-PP-SML-0304"));
    }

    [Fact]
    public void An_advanced_counter_keeps_the_loop_silent()
    {
        var code = """
            <?php
            function walk($width) {
                for ($shift = $width - 1; $shift >= 0; --$shift) {
                    echo $shift;
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-PP-SML-0304"));
    }
}
