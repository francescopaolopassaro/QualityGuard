using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Components. A '.razor' file is markup with its code in an '@code' block, and the engine reads that
/// block as C# — before it did, the prose in the markup parsed as expressions and the fields of every
/// component read as unused.
/// </summary>
public class BlazorRulesTests
{
    private static IReadOnlyList<int> Lines(string fileName, string content, string rule)
        => Analyze.LinesOf(Analyze.WithRules(fileName, content, rule), rule);

    [Fact]
    public void The_markup_of_a_component_is_not_read_as_code()
    {
        var component = """
            <div class="my-component">
                This component is defined in the library.
            </div>

            @code {
                private string _title = "";
            }
            """;

        var analysis = Analyze.File("Component.razor", component);
        var declaration = analysis.Tree.Root.OfKind(QualityGuard.Core.Syntax.NodeKind.FieldDeclaration)
            .Select(f => f.Text)
            .ToList();

        Assert.Contains("_title", declaration);
        // the sentence in the markup used to become a chain of comparisons
        Assert.DoesNotContain(analysis.Tree.Root.DescendantsAndSelf(),
            n => n.Kind == QualityGuard.Core.Syntax.NodeKind.Binary && n.Text is "in" or "is");
    }

    [Fact]
    public void A_query_parameter_the_framework_cannot_bind_is_reported()
    {
        var component = """
            @page "/orders"

            @code {
                [Parameter, SupplyParameterFromQuery]
                public OrderFilter? Filter { get; set; }

                [Parameter, SupplyParameterFromQuery]
                public int Page { get; set; }
            }
            """;
        Assert.Single(Lines("Orders.razor", component, "QG-CS-BUG-0190"));
    }

    [Fact]
    public void A_method_javascript_calls_has_to_be_public()
    {
        var component = """
            @code {
                [JSInvokable]
                private void OnScrolled() { }

                [JSInvokable]
                public void OnResized() { }
            }
            """;
        Assert.Single(Lines("Scroll.razor", component, "QG-CS-BUG-0191"));
    }

    [Fact]
    public void A_lambda_handler_inside_a_markup_loop_is_reported()
    {
        var component = """
            @foreach (var item in Items)
            {
                <li><button @onclick="() => Remove(item)">@item.Name</button></li>
            }

            @code {
                private void Remove(Order item) { }
            }
            """;
        Assert.NotEmpty(Lines("List.razor", component, "QG-CS-SML-0556"));
    }

    [Fact]
    public void A_handler_that_names_a_method_is_left_alone()
    {
        var component = """
            @foreach (var item in Items)
            {
                <li><button @onclick="Remove">@item.Name</button></li>
            }

            @code {
                private void Remove() { }
            }
            """;
        Assert.Empty(Lines("List.razor", component, "QG-CS-SML-0556"));
    }
}
