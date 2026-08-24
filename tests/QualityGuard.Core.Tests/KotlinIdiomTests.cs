using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The Kotlin idiom rules read the dedicated tree, so every test pins both sides: the shape that is
/// reported and the near-miss next to it that must stay silent.
/// </summary>
public class KotlinIdiomTests
{
    private static IReadOnlyList<int> Lines(string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules("Sample.kt", code, rule), rule);

    [Fact]
    public void An_equals_call_is_reported()
    {
        var code = """
            fun check(a: String, b: String) = a.equals(b)
            """;
        Assert.Equal([1], Lines(code, "QG-KT-SML-0066"));
    }

    [Fact]
    public void The_equality_operator_is_left_alone()
    {
        var code = """
            fun check(a: String, b: String) = a == b
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0066"));
    }

    [Fact]
    public void A_find_compared_to_null_is_reported()
    {
        var code = """
            fun hasBig(list: List<Int>) = list.find { it > 5 } != null
            """;
        Assert.Equal([1], Lines(code, "QG-KT-SML-0070"));
    }

    [Fact]
    public void Any_says_the_same_thing_without_a_null_comparison()
    {
        var code = """
            fun hasBig(list: List<Int>) = list.any { it > 5 }
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0070"));
    }

    [Fact]
    public void A_size_compared_to_zero_is_reported()
    {
        var code = """
            fun empty(list: List<Int>) = list.size == 0
            """;
        Assert.Equal([1], Lines(code, "QG-KT-SML-0071"));
    }

    [Fact]
    public void An_array_size_stays_silent()
    {
        // arrays have no isEmpty(); suggesting it would not compile
        var code = """
            fun empty(bytes: ByteArray) = bytes.size == 0
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0071"));
    }

    [Fact]
    public void An_explicit_it_parameter_is_reported()
    {
        var code = """
            val inc = listOf(1).map { it -> it + 1 }
            """;
        Assert.Equal([1], Lines(code, "QG-KT-SML-0075"));
    }

    [Fact]
    public void The_implicit_it_is_left_alone()
    {
        var code = """
            val inc = listOf(1).map { it + 1 }
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0075"));
    }

    [Fact]
    public void Branches_that_all_return_are_reported()
    {
        var code = """
            fun label(value: Int): String {
                if (value >= 0) {
                    return "positive"
                } else {
                    return "negative"
                }
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-SML-0058"));
    }

    [Fact]
    public void A_guard_clause_with_no_else_is_left_alone()
    {
        // only one path returns here: the else-less if used to be misread as two returning arms
        var code = """
            fun work(list: List<Int>): Int {
                if (list.isEmpty()) return 0
                return list.size
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0058"));
    }

    [Fact]
    public void A_type_dispatch_chain_is_reported()
    {
        var code = """
            fun run(value: Any) {
                if (value is Foo) {
                    value.go()
                } else if (value is Bar) {
                    value.stop()
                }
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-SML-0059"));
    }

    [Fact]
    public void A_getter_method_is_reported_when_the_field_exists()
    {
        var code = """
            class Store {
                private var index: Int = 0

                fun getIndex(): Int {
                    return index
                }
            }
            """;
        Assert.Equal([4], Lines(code, "QG-KT-SML-0060"));
    }

    [Fact]
    public void A_single_function_interface_without_fun_is_reported()
    {
        var code = """
            interface Single {
                fun only()
            }
            """;
        Assert.Equal([1], Lines(code, "QG-KT-SML-0064"));
    }

    [Fact]
    public void A_declared_fun_interface_is_left_alone()
    {
        var code = """
            fun interface Single {
                fun only()
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0064"));
    }

    [Fact]
    public void An_interface_object_without_parentheses_is_reported_for_sam()
    {
        var code = """
            val task = object : Runnable {
                override fun run() {
                }
            }
            """;
        Assert.Equal([1], Lines(code, "QG-KT-SML-0063"));
    }

    [Fact]
    public void A_class_instance_with_a_constructor_call_is_left_alone()
    {
        // Socket() calls a constructor: no SAM conversion applies to a class
        var code = """
            val socket = object : Socket() {
                override fun getOutputStream() = output
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0063"));
    }

    [Fact]
    public void Require_not_null_replaces_the_null_throw()
    {
        var code = """
            fun handle(argument: Int?) {
                if (argument == null) throw IllegalArgumentException()
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-SML-0074"));
    }

    [Fact]
    public void Require_with_a_non_null_check_is_reported()
    {
        var code = """
            fun handle(argument: Int?) {
                require(argument != null)
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-SML-0074"));
    }

    [Fact]
    public void A_data_class_with_an_array_field_and_no_override_is_reported()
    {
        var code = """
            data class Holder(var data: ByteArray)
            """;
        Assert.Equal([1], Lines(code, "QG-KT-BUG-0027"));
    }

    [Fact]
    public void A_data_class_that_overrides_equals_is_left_alone()
    {
        var code = """
            data class Holder(var data: ByteArray) {
                override fun equals(other: Any?): Boolean = data.contentEquals(other as ByteArray)
                override fun hashCode(): Int = data.contentHashCode()
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-BUG-0027"));
    }

    [Fact]
    public void A_suspend_function_returning_flow_is_reported()
    {
        var code = """
            suspend fun load(): Flow<Int> {
                return flowOf(1)
            }
            """;
        Assert.Equal([1], Lines(code, "QG-KT-SML-0049"));
    }

    [Fact]
    public void A_plain_suspending_function_is_left_alone()
    {
        var code = """
            suspend fun load(): List<Int> {
                return listOf(1)
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0049"));
    }

    [Fact]
    public void A_suspending_coroutine_scope_extension_is_reported()
    {
        var code = """
            suspend fun CoroutineScope.badExt() {
            }
            """;
        Assert.Equal([1], Lines(code, "QG-KT-SML-0052"));
    }

    [Fact]
    public void A_public_mutable_state_flow_is_reported()
    {
        var code = """
            class Machine {
                val state = MutableStateFlow(0)
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-SML-0046"));
    }

    [Fact]
    public void A_private_mutable_flow_is_left_alone()
    {
        var code = """
            class Machine {
                private val state = MutableStateFlow(0)
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0046"));
    }

    [Fact]
    public void An_uncollected_sequence_chain_is_reported()
    {
        var code = """
            fun work(items: List<Int>) {
                items.map { it + 1 }.filter { it > 0 }
                return items.size
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-BUG-0022"));
    }

    [Fact]
    public void A_collected_sequence_chain_is_left_alone()
    {
        var code = """
            fun work(items: List<Int>): Int {
                return items.map { it + 1 }.filter { it > 0 }.size
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-BUG-0022"));
    }

    [Fact]
    public void The_last_expression_of_a_lambda_is_its_return_value()
    {
        var code = """
            val result = items.let { list -> list.map { it + 1 } }
            """;
        Assert.Empty(Lines(code, "QG-KT-BUG-0022"));
    }

    [Fact]
    public void A_flow_pipeline_without_a_collector_is_reported()
    {
        var code = """
            fun work(flow: Flow<Int>) {
                flow.filter { it > 0 }.onEach { log(it) }
                return
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-BUG-0028"));
    }

    [Fact]
    public void An_ignored_delete_result_is_reported()
    {
        var code = """
            fun clean(file: File) {
                file.delete()
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-BUG-0030"));
    }

    [Fact]
    public void A_checked_delete_result_is_left_alone()
    {
        var code = """
            fun clean(file: File): Boolean {
                return file.delete()
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-BUG-0030"));
    }

    [Fact]
    public void Multiline_with_anchor_only_pattern_is_reported()
    {
        var code = """
            val p = Pattern.compile("^$", Pattern.MULTILINE)
            """;
        Assert.Equal([1], Lines(code, "QG-KT-SML-0040"));
    }

    [Fact]
    public void Multiline_with_a_real_pattern_is_left_alone()
    {
        var code = """
            val p = Pattern.compile("^\\\\w+$", Pattern.MULTILINE)
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0040"));
    }

    [Fact]
    public void Index_zero_on_a_prepared_statement_is_reported()
    {
        var code = """
            fun bind(statement: PreparedStatement) {
                statement.setString(0, "x")
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-BUG-0021"));
    }

    [Fact]
    public void Index_one_on_a_prepared_statement_is_left_alone()
    {
        var code = """
            fun bind(statement: PreparedStatement) {
                statement.setString(1, "x")
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-BUG-0021"));
    }

    [Fact]
    public void Index_zero_outside_jdbc_is_left_alone()
    {
        var code = """
            fun bind(list: MutableList<String>) {
                list.set(0, "x")
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-BUG-0021"));
    }

    [Fact]
    public void A_hard_coded_dependency_version_in_gradle_is_reported()
    {
        var code = """
            dependencies {
                implementation("com.google.guava:guava:33.0.0-jre")
            }
            """;
        Assert.Equal([2], Analyze.LinesOf(
            Analyze.WithRules("build.gradle.kts", code, "QG-KT-SML-0079"), "QG-KT-SML-0079"));
    }

    [Fact]
    public void A_version_from_a_variable_is_left_alone()
    {
        var code = """
            dependencies {
                implementation("com.google.guava:guava:$guavaVersion")
            }
            """;
        Assert.Empty(Analyze.LinesOf(
            Analyze.WithRules("build.gradle.kts", code, "QG-KT-SML-0079"), "QG-KT-SML-0079"));
    }

    [Fact]
    public void A_long_kotlin_plugin_id_is_reported_in_gradle()
    {
        var code = """
            plugins {
                id("org.jetbrains.kotlin.jvm") version "2.0.0"
            }
            """;
        Assert.Equal([2], Analyze.LinesOf(
            Analyze.WithRules("build.gradle.kts", code, "QG-KT-SML-0084"), "QG-KT-SML-0084"));
    }

    [Fact]
    public void A_useless_null_check_on_a_parameter_is_reported()
    {
        var code = """
            fun check(name: String) {
                if (name != null) {
                    print(name)
                }
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-SML-0077"));
    }

    [Fact]
    public void A_null_check_on_a_nullable_parameter_is_left_alone()
    {
        var code = """
            fun check(name: String?) {
                if (name != null) {
                    print(name)
                }
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0077"));
    }

    [Fact]
    public void A_double_bang_on_a_map_lookup_is_reported()
    {
        var code = """
            fun read(map: Map<String, Int>, key: String): Int {
                return map[key]!!
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-BUG-0029"));
    }

    [Fact]
    public void A_deprecated_function_called_in_its_own_file_is_reported()
    {
        var code = """
            @Deprecated("use newThing")
            fun oldThing() {
            }

            fun caller() {
                oldThing()
            }
            """;
        Assert.Equal([6], Lines(code, "QG-KT-SML-0033"));
    }

    [Fact]
    public void A_guava_import_with_a_native_equivalent_is_reported()
    {
        var code = """
            import com.google.common.collect.Lists

            val x = Lists.newArrayList(1)
            """;
        Assert.Equal([1], Lines(code, "QG-KT-SML-0037"));
    }

    [Fact]
    public void A_stateless_abstract_class_is_reported_as_interface_candidate()
    {
        var code = """
            abstract class Visitor {
                abstract fun visit(node: Node)
            }
            """;
        Assert.Equal([1], Lines(code, "QG-KT-SML-0068"));
    }

    [Fact]
    public void An_expect_declaration_is_left_alone()
    {
        // multiplatform expect/actual reads as an empty shell here; the real body lives elsewhere
        var code = """
            expect abstract class FileSystem() : Closeable {
                fun resolve(path: String): Path
            }
            """;
        Assert.Empty(Lines(code, "QG-KT-SML-0068"));
    }

    [Fact]
    public void A_singleton_by_private_constructor_is_reported()
    {
        var code = """
            class Registry private constructor() {
                companion object {
                    val INSTANCE = Registry()
                }
            }
            """;
        Assert.Equal([3], Lines(code, "QG-KT-SML-0062"));
    }

    [Fact]
    public void A_secondary_constructor_mirroring_the_primary_is_reported()
    {
        var code = """
            data class Point(val x: Int, val y: Int) {
                constructor(x: Int, y: Int) : this(x, y)
            }
            """;
        Assert.Equal([2], Lines(code, "QG-KT-SML-0045"));
    }
}
