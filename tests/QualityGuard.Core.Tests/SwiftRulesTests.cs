using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Swift. There is no Swift corpus on this machine to measure against, so the negative cases carry
/// the weight: every rule is pinned against the shape that resembles it and must stay silent.
/// </summary>
public class SwiftRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "Service.swift")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_forced_try_is_reported_and_an_optional_try_is_not()
    {
        Assert.NotEmpty(Lines("func load() {\n  let d = try! read()\n}\n", "QG-SW-BUG-0001"));
        Assert.Empty(Lines("func load() {\n  let d = try? read()\n}\n", "QG-SW-BUG-0001"));
    }

    [Fact]
    public void A_forced_cast_is_reported_but_a_dequeued_cell_is_not()
    {
        Assert.NotEmpty(Lines("func go(_ v: Any) {\n  let s = v as! String\n}\n", "QG-SW-BUG-0002"));
        Assert.Empty(Lines("func go(_ v: Any) {\n  let s = v as? String\n}\n", "QG-SW-BUG-0002"));
        Assert.Empty(Lines("func go() {\n  let c = table.dequeueReusableCell(withIdentifier: \"a\") as! Cell\n}\n",
            "QG-SW-BUG-0002"));
    }

    [Fact]
    public void A_decimal_equality_is_reported_and_an_integer_one_is_not()
    {
        Assert.NotEmpty(Lines("func go(_ x: Double) -> Bool {\n  return x == 0.1\n}\n", "QG-SW-BUG-0003"));
        Assert.Empty(Lines("func go(_ x: Int) -> Bool {\n  return x == 1\n}\n", "QG-SW-BUG-0003"));
    }

    [Fact]
    public void An_empty_catch_is_reported()
    {
        Assert.NotEmpty(Lines("func go() {\n  do {\n    try save()\n  } catch {\n  }\n}\n",
            "QG-SW-BUG-0004"));
        Assert.Empty(Lines("func go() {\n  do {\n    try save()\n  } catch {\n    report(error)\n  }\n}\n",
            "QG-SW-BUG-0004"));
    }

    [Fact]
    public void Waiting_on_the_main_queue_is_reported_and_dispatching_to_it_is_not()
    {
        Assert.NotEmpty(Lines("func go() {\n  DispatchQueue.main.sync { render() }\n}\n", "QG-SW-BUG-0005"));
        Assert.Empty(Lines("func go() {\n  DispatchQueue.main.async { render() }\n}\n", "QG-SW-BUG-0005"));
    }

    [Fact]
    public void A_comparison_against_a_boolean_literal_is_reported()
        => Assert.NotEmpty(Lines("func go(_ f: Bool) -> Bool {\n  return f == true\n}\n", "QG-SW-SML-0004"));

    [Fact]
    public void Returning_true_and_false_from_the_two_branches_is_reported()
    {
        var code = """
            func check(_ a: Int, _ b: Int) -> Bool {
              if a > b {
                return true
              } else {
                return false
              }
            }
            """;
        Assert.NotEmpty(Lines(code, "QG-SW-SML-0001"));

        var different = """
            func pick(_ a: Int, _ b: Int) -> Int {
              if a > b {
                return a
              } else {
                return b
              }
            }
            """;
        Assert.Empty(Lines(different, "QG-SW-SML-0001"));
    }

    [Fact]
    public void A_print_is_reported_outside_tests()
    {
        Assert.NotEmpty(Lines("func go() {\n  print(\"hi\")\n}\n", "QG-SW-SML-0002"));
        Assert.Empty(Lines("func go() {\n  print(\"hi\")\n}\n", "QG-SW-SML-0002", "ServiceTests.swift"));
    }

    [Fact]
    public void A_cleartext_address_is_reported_but_the_loopback_is_not()
    {
        Assert.NotEmpty(Lines("let a = \"http://api.acme.io/login\"\n", "QG-SW-SEC-0001"));
        Assert.Empty(Lines("let a = \"http://localhost:8080/health\"\n", "QG-SW-SEC-0001"));
        Assert.Empty(Lines("let a = \"https://api.acme.io/login\"\n", "QG-SW-SEC-0001"));
    }

    [Fact]
    public void A_broken_hash_is_reported()
    {
        Assert.NotEmpty(Lines("func go() {\n  let d = Insecure.MD5.hash(data: input)\n}\n",
            "QG-SW-SEC-0002"));
        Assert.Empty(Lines("func go() {\n  let d = SHA256.hash(data: input)\n}\n", "QG-SW-SEC-0002"));
    }

    [Fact]
    public void A_secret_written_to_user_defaults_is_reported()
    {
        Assert.NotEmpty(Lines("func go(_ token: String) {\n  UserDefaults.standard.set(token, forKey: \"token\")\n}\n",
            "QG-SW-SEC-0003"));
        Assert.Empty(Lines("func go(_ theme: String) {\n  UserDefaults.standard.set(theme, forKey: \"theme\")\n}\n",
            "QG-SW-SEC-0003"));
    }

    [Fact]
    public void An_interpolated_query_is_reported_and_a_bound_one_is_not()
    {
        Assert.NotEmpty(Lines("func go(_ name: String) {\n  let q = \"SELECT * FROM users WHERE n = '\\(name)'\"\n}\n",
            "QG-SW-SEC-0004"));
        Assert.Empty(Lines("func go() {\n  let q = \"SELECT * FROM users WHERE n = ?\"\n}\n",
            "QG-SW-SEC-0004"));
    }

    [Fact]
    public void A_lower_case_type_name_is_reported()
    {
        Assert.NotEmpty(Lines("class userSession {\n  var a = 1\n}\n", "QG-SW-CNV-0001"));
        Assert.Empty(Lines("class UserSession {\n  var a = 1\n}\n", "QG-SW-CNV-0001"));
    }
}
