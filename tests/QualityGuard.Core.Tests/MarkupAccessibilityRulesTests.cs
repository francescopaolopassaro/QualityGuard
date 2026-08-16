using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The second wave of markup rules. Each defect is paired with the shape that looks like it and must
/// stay silent — a component-driven anchor, an image the stylesheet sizes, a case where the missing
/// element is really there.
/// </summary>
public class MarkupAccessibilityRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules("page.html", code, rule), rule);

    [Fact]
    public void A_page_without_a_doctype_is_reported()
    {
        Assert.NotEmpty(Lines("<html lang=\"en\">\n<body>hi</body>\n</html>\n", "QG-HTML-SML-0076"));
        Assert.Empty(Lines("<!DOCTYPE html>\n<html lang=\"en\">\n<body>hi</body>\n</html>\n",
            "QG-HTML-SML-0076"));
    }

    [Fact]
    public void A_head_without_a_title_is_reported()
    {
        Assert.NotEmpty(Lines("<html><head><meta charset=\"utf-8\"></head></html>\n", "QG-HTML-SML-0077"));
        Assert.Empty(Lines("<html><head><title>Orders</title></head></html>\n", "QG-HTML-SML-0077"));
    }

    [Fact]
    public void A_link_that_leads_nowhere_is_reported_but_a_component_hook_is_not()
    {
        Assert.NotEmpty(Lines("<a href=\"#\">More</a>\n", "QG-HTML-SML-0080"));
        Assert.NotEmpty(Lines("<a href=\"javascript:void(0)\">More</a>\n", "QG-HTML-SML-0080"));
        Assert.Empty(Lines("<a href=\"#\" role=\"button\">Menu</a>\n", "QG-HTML-SML-0080"));
        Assert.Empty(Lines("<a href=\"#\" data-bs-toggle=\"dropdown\">Menu</a>\n", "QG-HTML-SML-0080"));
        Assert.Empty(Lines("<a href=\"/orders\">Orders</a>\n", "QG-HTML-SML-0080"));
    }

    [Fact]
    public void A_fieldset_without_a_legend_is_reported()
    {
        Assert.NotEmpty(Lines("<fieldset><input id=\"a\"></fieldset>\n", "QG-HTML-SML-0081"));
        Assert.Empty(Lines("<fieldset><legend>Size</legend><input id=\"a\"></fieldset>\n",
            "QG-HTML-SML-0081"));
    }

    [Fact]
    public void A_list_item_outside_a_list_is_reported()
    {
        Assert.NotEmpty(Lines("<div><li>One</li></div>\n", "QG-HTML-SML-0083"));
        Assert.Empty(Lines("<ul><li>One</li></ul>\n", "QG-HTML-SML-0083"));
    }

    [Fact]
    public void A_skipped_heading_level_is_reported()
    {
        Assert.NotEmpty(Lines("<h1>Title</h1>\n<h3>Sub</h3>\n", "QG-HTML-SML-0084"));
        Assert.Empty(Lines("<h1>Title</h1>\n<h2>Sub</h2>\n<h2>Other</h2>\n<h3>Deep</h3>\n",
            "QG-HTML-SML-0084"));
    }

    [Fact]
    public void An_empty_link_is_reported_unless_it_is_named()
    {
        Assert.NotEmpty(Lines("<a href=\"/x\"><i class=\"icon\"></i></a>\n", "QG-HTML-SML-0086"));
        Assert.Empty(Lines("<a href=\"/x\" aria-label=\"Close\"><i class=\"icon\"></i></a>\n",
            "QG-HTML-SML-0086"));
        Assert.Empty(Lines("<a href=\"/x\">Open</a>\n", "QG-HTML-SML-0086"));
    }

    [Fact]
    public void A_positive_tab_index_is_reported()
    {
        Assert.NotEmpty(Lines("<button tabindex=\"3\">Go</button>\n", "QG-HTML-SML-0087"));
        Assert.Empty(Lines("<button tabindex=\"0\">Go</button>\n<div tabindex=\"-1\"></div>\n",
            "QG-HTML-SML-0087"));
    }

    [Fact]
    public void A_focusable_element_hidden_from_assistive_technology_is_reported()
    {
        Assert.NotEmpty(Lines("<button aria-hidden=\"true\">Go</button>\n", "QG-HTML-BUG-0027"));
        Assert.Empty(Lines("<button aria-hidden=\"true\" tabindex=\"-1\">Go</button>\n",
            "QG-HTML-BUG-0027"));
        Assert.Empty(Lines("<span aria-hidden=\"true\">*</span>\n", "QG-HTML-BUG-0027"));
    }

    [Fact]
    public void The_misspelled_role_attribute_is_reported()
        => Assert.NotEmpty(Lines("<div aria-role=\"button\">Go</div>\n", "QG-HTML-BUG-0028"));

    [Fact]
    public void A_mixed_srcset_is_reported()
    {
        Assert.NotEmpty(Lines("<img src=\"a.png\" alt=\"a\" srcset=\"a.png, b.png 2x\">\n",
            "QG-HTML-BUG-0029"));
        Assert.Empty(Lines("<img src=\"a.png\" alt=\"a\" srcset=\"a.png 1x, b.png 2x\">\n",
            "QG-HTML-BUG-0029"));
    }

    [Fact]
    public void A_viewport_that_blocks_zooming_is_reported()
    {
        Assert.NotEmpty(Lines("<meta name=\"viewport\" content=\"width=device-width, user-scalable=no\">\n",
            "QG-HTML-SML-0090"));
        Assert.Empty(Lines("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
            "QG-HTML-SML-0090"));
    }

    [Fact]
    public void Media_that_plays_by_itself_is_reported_unless_it_is_muted()
    {
        Assert.NotEmpty(Lines("<audio autoplay src=\"a.mp3\"></audio>\n", "QG-HTML-SML-0091"));
        Assert.Empty(Lines("<video autoplay muted src=\"a.mp4\"></video>\n", "QG-HTML-SML-0091"));
    }

    [Fact]
    public void A_mouse_handler_without_its_keyboard_pair_is_reported()
    {
        Assert.NotEmpty(Lines("<div onmouseover=\"show()\">x</div>\n", "QG-HTML-SML-0093"));
        Assert.Empty(Lines("<div onmouseover=\"show()\" onfocus=\"show()\">x</div>\n", "QG-HTML-SML-0093"));
    }

    [Fact]
    public void An_image_is_asked_for_its_size_only_when_nothing_else_sets_it()
    {
        Assert.NotEmpty(Lines("<img src=\"a.png\" alt=\"a\">\n", "QG-HTML-SML-0095"));
        Assert.Empty(Lines("<img src=\"a.png\" alt=\"a\" class=\"avatar\">\n", "QG-HTML-SML-0095"));
        Assert.Empty(Lines("<img src=\"a.png\" alt=\"a\" width=\"20\">\n", "QG-HTML-SML-0095"));
    }

    [Fact]
    public void A_remote_script_without_an_integrity_hash_is_reported()
    {
        Assert.NotEmpty(Lines("<script src=\"https://cdn.example.com/a.js\"></script>\n",
            "QG-HTML-SEC-0010"));
        Assert.Empty(Lines("<script src=\"https://cdn.example.com/a.js\" integrity=\"sha384-x\"></script>\n",
            "QG-HTML-SEC-0010"));
        Assert.Empty(Lines("<script src=\"/assets/a.js\"></script>\n", "QG-HTML-SEC-0010"));
    }

    [Fact]
    public void A_url_that_runs_code_is_reported_but_the_placeholder_is_not()
    {
        Assert.NotEmpty(Lines("<a href=\"javascript:steal(document.cookie)\">x</a>\n", "QG-HTML-SEC-0002"));
        Assert.Empty(Lines("<a href=\"javascript:void(0)\">x</a>\n", "QG-HTML-SEC-0002"));
        Assert.Empty(Lines("<script>var s = 'javascript:';</script>\n", "QG-HTML-SEC-0002"));
    }
}
