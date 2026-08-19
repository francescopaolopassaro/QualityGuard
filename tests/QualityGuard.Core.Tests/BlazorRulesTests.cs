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
        Assert.Single(Lines("Orders.razor", component, "QG-CS-BUG-0096"));
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
        Assert.Single(Lines("Scroll.razor", component, "QG-CS-BUG-0097"));
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
        Assert.NotEmpty(Lines("List.razor", component, "QG-CS-SML-0339"));
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
        Assert.Empty(Lines("List.razor", component, "QG-CS-SML-0339"));
    }
    [Fact]
    public void An_api_controller_that_never_renders_a_view_is_reported()
    {
        var code = """
            namespace Demo
            {
                [ApiController]
                public class OrdersController : Controller
                {
                    [HttpGet("orders")]
                    public IActionResult List() => Ok();
                }
            }
            """;
        Assert.NotEmpty(Lines("OrdersController.cs", code, "QG-CS-SML-0345"));
    }

    [Fact]
    public void An_api_controller_that_does_render_views_is_left_alone()
    {
        // deriving from the lighter base would stop compiling, so asking for it asks for nothing
        var code = """
            namespace Demo
            {
                [ApiController]
                public class ViewsController : Controller
                {
                    [HttpGet("all")]
                    public IActionResult All() => View("list");
                }
            }
            """;
        Assert.Empty(Lines("ViewsController.cs", code, "QG-CS-SML-0345"));
    }

    [Fact]
    public void A_route_written_with_a_backslash_is_reported()
    {
        var code = """
            namespace Demo
            {
                public class OrdersController : ControllerBase
                {
                    [HttpPost(@"orders\create")]
                    public IActionResult Create() => Ok();
                }
            }
            """;
        Assert.NotEmpty(Lines("OrdersController.cs", code, "QG-CS-BUG-0099"));
    }

    [Fact]
    public void A_parameter_that_contradicts_its_route_constraint_is_reported()
    {
        var component = """
            @page "/orders/{Id:int}"

            @code {
                [Parameter]
                public string Id { get; set; } = "";
            }
            """;
        Assert.NotEmpty(Lines("Detail.razor", component, "QG-CS-BUG-0098"));
    }

    [Fact]
    public void A_parameter_that_matches_its_route_constraint_is_left_alone()
    {
        var component = """
            @page "/orders/{Id:int}"

            @code {
                [Parameter]
                public int Id { get; set; }
            }
            """;
        Assert.Empty(Lines("Detail.razor", component, "QG-CS-BUG-0098"));
    }
    [Fact]
    public void A_component_parameter_that_is_not_public_is_reported()
    {
        var component = """
            @code {
                [Parameter]
                private string Title { get; set; } = "";

                [Parameter]
                public string Subtitle { get; set; } = "";
            }
            """;
        Assert.Single(Lines("Widget.razor", component, "QG-CS-BUG-0193"));
    }

    [Fact]
    public void A_parameter_attribute_on_a_field_is_reported()
    {
        var component = """
            @code {
                [Parameter]
                public string Subtitle = "";
            }
            """;
        Assert.NotEmpty(Lines("Widget.razor", component, "QG-CS-BUG-0194"));
    }

    [Fact]
    public void An_async_void_method_in_a_component_is_reported()
    {
        var component = """
            @code {
                private async void OnMoved(object sender, EventArgs e)
                {
                    await Load();
                }

                private async Task Reload()
                {
                    await Load();
                }
            }
            """;
        Assert.Single(Lines("Widget.razor", component, "QG-CS-BUG-0195"));
    }

    [Fact]
    public void A_subscription_the_component_releases_is_left_alone()
    {
        var component = """
            @code {
                protected override void OnInitialized()
                {
                    Navigation.LocationChanged += OnMoved;
                }

                public void Dispose()
                {
                    Navigation.LocationChanged -= OnMoved;
                }

                private void OnMoved(object sender, EventArgs e) { }
            }
            """;
        Assert.Empty(Lines("Widget.razor", component, "QG-CS-BUG-0196"));
    }

    [Fact]
    public void A_subscription_nothing_releases_is_reported()
    {
        var component = """
            @code {
                protected override void OnInitialized()
                {
                    Navigation.LocationChanged += OnMoved;
                }

                private void OnMoved(object sender, EventArgs e) { }
            }
            """;
        Assert.NotEmpty(Lines("Widget.razor", component, "QG-CS-BUG-0196"));
    }
}
