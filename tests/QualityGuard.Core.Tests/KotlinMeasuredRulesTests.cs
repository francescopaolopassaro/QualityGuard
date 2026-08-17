using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The Kotlin rules chosen by measuring against an annotated corpus. Kotlin is read by the generic
/// structural parser, so each of these asks only for the shape of a call.
/// </summary>
public class KotlinMeasuredRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "Sample.kt")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void Reading_a_device_identifier_is_reported()
    {
        var hardware = """
            class A {
                fun id(manager: TelephonyManager): String {
                    return manager.getDeviceId()
                }
            }
            """;
        Assert.NotEmpty(Lines(hardware, "QG-KT-SEC-0056"));

        var own = """
            class A {
                fun id(store: Store): String {
                    return store.installationId()
                }
            }
            """;
        Assert.Empty(Lines(own, "QG-KT-SEC-0056"));
    }

    [Fact]
    public void A_bluetooth_address_is_reported_and_another_address_is_not()
    {
        var bluetooth = """
            class A {
                fun read(bluetoothAdapter: BluetoothAdapter): String {
                    return bluetoothAdapter.address
                }
            }
            """;
        Assert.NotEmpty(Lines(bluetooth, "QG-KT-SEC-0056"));

        var postal = """
            class A {
                fun read(customer: Customer): String {
                    return customer.address
                }
            }
            """;
        Assert.Empty(Lines(postal, "QG-KT-SEC-0056"));
    }

    [Fact]
    public void An_indexed_read_written_as_a_call_is_reported()
    {
        var call = """
            class A {
                fun read(list: List<Int>): Int {
                    return list.get(1)
                }
            }
            """;
        Assert.NotEmpty(Lines(call, "QG-KT-SML-0085"));

        var brackets = """
            class A {
                fun read(list: List<Int>): Int {
                    return list[1]
                }
            }
            """;
        Assert.Empty(Lines(brackets, "QG-KT-SML-0085"));
    }

    [Fact]
    public void A_plain_accessor_is_not_an_indexed_read()
    {
        // 'get()' with no argument is an AtomicInteger, a Provider, a Future: there is no index
        var code = """
            class A {
                fun read(counter: AtomicInteger): Int {
                    return counter.get()
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0085"));
    }

    [Fact]
    public void A_short_key_is_reported_in_kotlin_too()
    {
        var weak = """
            class A {
                fun make(generator: KeyPairGenerator) {
                    generator.initialize(1024)
                }
            }
            """;
        Assert.NotEmpty(Lines(weak, "QG-JV-SEC-0069"));

        var strong = """
            class A {
                fun make(generator: KeyPairGenerator) {
                    generator.initialize(2048)
                }
            }
            """;
        Assert.Empty(Lines(strong, "QG-JV-SEC-0069"));
    }
}
