using QualityGuard.Core.Analysis;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Stylesheets, markup and Flutter. Each rule is pinned on the defect and on the correct code beside
/// it, because these three languages are where a noisy checker is abandoned fastest: the files are
/// many, small, and full of shapes that only look wrong.
/// </summary>
public class WebAndMobileRulesTests
{
    private static IReadOnlyList<int> Lines(string file, string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    // ------------------------------------------------------------------ stylesheets

    [Fact]
    public void A_stylesheet_is_read_as_blocks_and_declarations()
    {
        var sheet = StyleSheet.Parse("""
            .card {
              color: red;
              .title { font-size: 12px !important; }
            }
            """);

        var card = Assert.Single(sheet.Children);
        Assert.Equal(".card", card.Selector);
        Assert.Equal("color", card.Declarations[0].Property);
        var title = Assert.Single(card.Children);
        Assert.True(title.Declarations[0].Important);
        Assert.Equal(1, title.Depth);
    }

    [Fact]
    public void A_property_set_twice_in_one_block_is_reported()
    {
        var sheet = """
            .card {
              color: red;
              color: blue;
            }
            """;
        Assert.Equal([3], Lines("site.css", sheet, "QG-CSS-BUG-0027"));
    }

    [Fact]
    public void The_same_property_in_two_blocks_is_left_alone()
    {
        var sheet = """
            .card { color: red; }
            .note { color: blue; }
            """;
        Assert.Empty(Lines("site.css", sheet, "QG-CSS-BUG-0027"));
    }

    [Fact]
    public void A_shorthand_after_a_longhand_is_reported()
    {
        var sheet = """
            .card {
              margin-top: 8px;
              margin: 0;
            }
            """;
        Assert.Equal([3], Lines("site.css", sheet, "QG-CSS-BUG-0028"));
    }

    [Fact]
    public void A_longhand_after_its_shorthand_is_the_correct_order()
    {
        var sheet = """
            .card {
              margin: 0;
              margin-top: 8px;
            }
            """;
        Assert.Empty(Lines("site.css", sheet, "QG-CSS-BUG-0028"));
    }

    [Fact]
    public void A_font_list_without_a_generic_family_is_reported()
    {
        Assert.NotEmpty(Lines("site.css", ".a { font-family: Helvetica, Arial; }", "QG-CSS-BUG-0029"));
        Assert.Empty(Lines("site.css", ".a { font-family: Helvetica, sans-serif; }", "QG-CSS-BUG-0029"));
    }

    [Fact]
    public void An_import_after_the_first_rule_is_reported()
    {
        var sheet = """
            @import "base";
            .card { color: red; }
            @import "late";
            """;
        Assert.Equal([3], Lines("site.css", sheet, "QG-CSS-BUG-0030"));
    }

    [Fact]
    public void Deep_preprocessor_nesting_is_reported()
    {
        var sheet = """
            .a { .b { .c { .d { .e { color: red; } } } } }
            """;
        Assert.NotEmpty(Lines("site.scss", sheet, "QG-CSS-SML-0024"));
    }

    // ------------------------------------------------------------------ markup

    [Fact]
    public void A_document_is_read_as_a_tree_of_elements()
    {
        var document = HtmlDocument.Parse("""
            <div class="row" data-id="7">
              <img src="a.png" alt="A">
              <span>text</span>
            </div>
            """);

        var div = Assert.Single(document.Children);
        Assert.Equal("row", div.Attribute("class"));
        Assert.Equal(2, div.Children.Count);
        Assert.Equal("A", div.Children[0].Attribute("alt"));
    }

    [Fact]
    public void An_image_without_alternative_text_is_reported()
    {
        var page = """
            <html lang="en"><body>
            <img src="a.png">
            <img src="b.png" alt="">
            </body></html>
            """;
        Assert.Equal([2], Lines("page.html", page, "QG-HTML-CNV-0001"));
    }

    [Fact]
    public void A_duplicate_id_is_reported()
    {
        var page = """
            <html lang="en"><body>
            <div id="main"></div>
            <div id="main"></div>
            </body></html>
            """;
        Assert.Equal([3], Lines("page.html", page, "QG-HTML-BUG-0001"));
    }

    [Fact]
    public void Only_an_external_blank_target_needs_the_relation()
    {
        var page = """
            <html lang="en"><body>
            <a href="https://example.com" target="_blank">out</a>
            <a href="/inside" target="_blank">in</a>
            <a href="https://example.com" target="_blank" rel="noopener">safe</a>
            </body></html>
            """;
        Assert.Equal([2], Lines("page.html", page, "QG-HTML-SEC-0004"));
    }

    [Fact]
    public void A_control_named_by_a_label_is_left_alone()
    {
        var page = """
            <html lang="en"><body>
            <input type="text" name="q">
            <label for="named">Named</label><input id="named" type="text">
            <input type="submit" value="Go">
            </body></html>
            """;
        Assert.Equal([2], Lines("page.html", page, "QG-HTML-SML-0005"));
    }

    [Fact]
    public void A_deprecated_element_is_reported()
        => Assert.NotEmpty(Lines("page.html", "<html lang=\"en\"><center>x</center></html>", "QG-HTML-SML-0007"));

    // ------------------------------------------------------------------ Flutter

    [Fact]
    public void Rebuilding_from_inside_build_is_reported()
    {
        var code = """
            class Counter extends StatefulWidget {
            }

            class _CounterState extends State<Counter> {
              @override
              Widget build(BuildContext context) {
                setState(() {});
                return Container();
              }
            }
            """;
        Assert.Equal([7], Lines("counter.dart", code, "QG-DART-BUG-0001"));
    }

    [Fact]
    public void A_controller_released_in_dispose_is_left_alone()
    {
        var code = """
            class _EditorState extends State<Editor> {
              final TextEditingController kept = TextEditingController();
              final AnimationController leaked = AnimationController();

              @override
              void dispose() {
                kept.dispose();
                super.dispose();
              }
            }
            """;
        Assert.Equal([3], Lines("editor.dart", code, "QG-DART-BUG-0003"));
    }

    [Fact]
    public void A_context_used_after_an_await_is_reported()
    {
        var code = """
            class _PageState extends State<Page> {
              Future<void> save() async {
                await store();
                Navigator.of(context).pop();
              }
            }
            """;
        Assert.NotEmpty(Lines("page.dart", code, "QG-DART-BUG-0004"));
    }

    [Fact]
    public void A_context_guarded_by_mounted_is_left_alone()
    {
        var code = """
            class _PageState extends State<Page> {
              Future<void> save() async {
                await store();
                if (!mounted) return;
                Navigator.of(context).pop();
              }
            }
            """;
        Assert.Empty(Lines("page.dart", code, "QG-DART-BUG-0004"));
    }

    [Fact]
    public void A_mutable_field_on_a_stateless_widget_is_reported()
    {
        var code = """
            class Banner extends StatelessWidget {
              String title = 'hello';
              final String subtitle = 'world';
            }
            """;
        Assert.Equal([2], Lines("banner.dart", code, "QG-DART-BUG-0002"));
    }

    [Fact]
    public void An_async_function_that_never_waits_is_reported()
    {
        var code = """
            class Store {
              Future<void> load() async {
                var x = 1;
              }

              Future<void> save() async {
                await write();
              }
            }
            """;
        Assert.Equal([2], Lines("store.dart", code, "QG-DART-SML-0002"));
    }
}
