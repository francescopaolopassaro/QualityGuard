using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Regression tests for rules that used to fire on correct code. Each one pins the pattern that was
/// wrongly reported, so the precision that was won back cannot be lost again silently.
/// </summary>
public class RulePrecisionTests
{
    private static IReadOnlyList<int> Lines(string file, string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void An_assert_on_an_argument_is_reported_as_validation_that_disappears()
    {
        var code = """
            def handler(size):
                assert size > 0
                return size
            """;
        Assert.Equal([2], Lines("handler.py", code, "QG-PY-SEC-0010"));
    }

    [Fact]
    public void An_assert_on_an_internal_invariant_is_left_alone()
    {
        var code = """
            def handler(size):
                total = size * 2
                assert total is not None
                return total
            """;
        Assert.Empty(Lines("handler.py", code, "QG-PY-SEC-0010"));
    }

    [Fact]
    public void Asserts_in_a_test_file_are_left_alone()
    {
        var code = """
            def test_handler(value):
                assert value == 3
            """;
        Assert.Empty(Lines("test_handler.py", code, "QG-PY-SEC-0010"));
    }

    [Fact]
    public void A_string_replace_is_not_treated_as_a_regular_expression()
    {
        var code = """
            public class Paths
            {
                public string Normalize(string path) => path.Replace("\\", "/");
            }
            """;
        Assert.Empty(Lines("Paths.cs", code, "QG-ALL-BUG-0007"));
    }

    [Fact]
    public void A_broken_pattern_passed_to_the_regex_engine_is_still_reported()
    {
        var code = """
            public class Check
            {
                public bool Run(string text) => System.Text.RegularExpressions.Regex.IsMatch(text, "([a-z]");
            }
            """;
        Assert.Equal([3], Lines("Check.cs", code, "QG-ALL-BUG-0007"));
    }

    [Fact]
    public void Only_the_optional_is_unwrapped_not_every_get_in_the_file()
    {
        var code = """
            import java.util.*;

            public class Store {
                private Map<String, String> cache = new HashMap<>();

                public String find(Optional<String> maybe, String key) {
                    String cached = cache.get(key);
                    return maybe.get() + cached;
                }
            }
            """;
        Assert.Equal([8], Lines("Store.java", code, "QG-JV-SML-0011"));
    }

    [Fact]
    public void A_print_in_a_script_is_left_alone_and_one_inside_a_class_is_reported()
    {
        var script = """
            def main():
                print("done")

            if __name__ == "__main__":
                main()
            """;
        Assert.Empty(Lines("run.py", script, "QG-PY-SML-0001"));

        var library = """
            class Loader:
                def load(self, path):
                    print("loading", path)
                    return path
            """;
        Assert.Equal([3], Lines("loader.py", library, "QG-PY-SML-0001"));
    }

    [Fact]
    public void A_private_method_is_reported_once_not_by_two_rules_at_the_same_time()
    {
        var code = """
            public class Service
            {
                public void Run() { }

                private void Unused() { }
            }
            """;
        var analysis = Analyze.WithRules("Service.cs", code);
        var reported = analysis.Issues
            .Where(i => i.RuleKey is "QG-ALL-SML-0028" or "QG-ALL-SML-0032")
            .Select(i => i.RuleKey)
            .ToList();
        Assert.Single(reported);
    }
}
