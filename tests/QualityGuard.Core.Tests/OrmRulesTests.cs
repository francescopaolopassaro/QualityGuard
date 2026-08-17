using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The rules about talking to a database through a mapper. Each case here was taken from production
/// C#: the negative ones are shapes that look like the defect and are not it.
/// </summary>
public class OrmRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "Sample.cs")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_query_inside_a_loop_is_reported()
    {
        var perItem = """
            class A
            {
                async Task F(List<int> ids)
                {
                    foreach (var id in ids)
                    {
                        var order = await _db.Orders.FirstOrDefaultAsync(o => o.Id == id);
                    }
                }
            }
            """;
        Assert.NotEmpty(Lines(perItem, "QG-CS-PRF-0003"));

        var once = """
            class A
            {
                async Task F(List<int> ids)
                {
                    var orders = await _db.Orders.Where(o => ids.Contains(o.Id)).ToListAsync();
                    foreach (var order in orders)
                    {
                        Use(order);
                    }
                }
            }
            """;
        Assert.Empty(Lines(once, "QG-CS-PRF-0003"));
    }

    [Fact]
    public void Reading_a_list_in_a_loop_is_not_a_query()
    {
        // the same call names exist on collections, and a list in memory costs nothing to read
        var code = """
            class A
            {
                void F(List<Order> orders)
                {
                    foreach (var o in orders)
                    {
                        var first = orders.FirstOrDefault(x => x.Id == o.Id);
                    }
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-CS-PRF-0003"));
    }

    [Fact]
    public void Saving_inside_a_loop_is_reported()
    {
        var perItem = """
            class A
            {
                async Task F(List<Order> orders)
                {
                    foreach (var order in orders)
                    {
                        _db.Orders.Add(order);
                        await _db.SaveChangesAsync();
                    }
                }
            }
            """;
        Assert.NotEmpty(Lines(perItem, "QG-CS-PRF-0004"));

        var once = """
            class A
            {
                async Task F(List<Order> orders)
                {
                    foreach (var order in orders)
                    {
                        _db.Orders.Add(order);
                    }
                    await _db.SaveChangesAsync();
                }
            }
            """;
        Assert.Empty(Lines(once, "QG-CS-PRF-0004"));
    }

    [Fact]
    public void Filtering_after_reading_the_whole_set_is_reported()
    {
        var late = """
            class A
            {
                void F()
                {
                    var active = _db.Orders.ToList().Where(o => o.IsActive);
                }
            }
            """;
        Assert.NotEmpty(Lines(late, "QG-CS-PRF-0005"));

        var early = """
            class A
            {
                void F()
                {
                    var active = _db.Orders.Where(o => o.IsActive).ToList();
                }
            }
            """;
        Assert.Empty(Lines(early, "QG-CS-PRF-0005"));
    }

    [Fact]
    public void A_query_used_twice_is_reported()
    {
        var twice = """
            class A
            {
                void F()
                {
                    var pending = _db.Orders.Where(o => o.IsPending);
                    var count = pending.Count();
                    var first = pending.FirstOrDefault();
                }
            }
            """;
        Assert.NotEmpty(Lines(twice, "QG-CS-PRF-0006"));

        var materialised = """
            class A
            {
                void F()
                {
                    var pending = _db.Orders.Where(o => o.IsPending).ToList();
                    var count = pending.Count();
                    var first = pending.FirstOrDefault();
                }
            }
            """;
        Assert.Empty(Lines(materialised, "QG-CS-PRF-0006"));
    }

    [Fact]
    public void Loading_related_data_after_a_projection_is_reported()
    {
        var ignored = """
            class A
            {
                void F()
                {
                    var names = _db.Orders.Select(o => o.Name).Include(o => o.Customer);
                }
            }
            """;
        Assert.NotEmpty(Lines(ignored, "QG-CS-BUG-0147"));

        var ordered = """
            class A
            {
                void F()
                {
                    var names = _db.Orders.Include(o => o.Customer).Select(o => o.Customer.Name);
                }
            }
            """;
        Assert.Empty(Lines(ordered, "QG-CS-BUG-0147"));
    }
    [Fact]
    public void A_command_joined_from_values_is_reported()
    {
        var joined = """
            class A
            {
                void F(IDbConnection con, string query, string param)
                {
                    con.Query(query + param);
                }
            }
            """;
        Assert.NotEmpty(Lines(joined, "QG-CS-SEC-0093"));

        var parameterised = """
            class A
            {
                void F(IDbConnection con, int id)
                {
                    con.Query("select * from Orders where Id = @id", new { id });
                }
            }
            """;
        Assert.Empty(Lines(parameterised, "QG-CS-SEC-0093"));
    }

    [Fact]
    public void A_short_key_is_reported()
    {
        var weak = """
            class A
            {
                object F() => new RSACryptoServiceProvider(1024);
            }
            """;
        Assert.NotEmpty(Lines(weak, "QG-CS-SEC-0094"));

        var strong = """
            class A
            {
                object F() => new RSACryptoServiceProvider(2048);
            }
            """;
        Assert.Empty(Lines(strong, "QG-CS-SEC-0094"));
    }

    [Fact]
    public void A_blocking_query_in_an_async_method_is_reported()
    {
        var blocking = """
            class A
            {
                async Task F()
                {
                    var n = _db.Orders.AsNoTracking().Count();
                }
            }
            """;
        Assert.NotEmpty(Lines(blocking, "QG-CS-PRF-0007"));

        var inMemory = """
            class A
            {
                async Task F(List<Order> orders)
                {
                    var n = orders.Count();
                }
            }
            """;
        Assert.Empty(Lines(inMemory, "QG-CS-PRF-0007"));
    }

}
