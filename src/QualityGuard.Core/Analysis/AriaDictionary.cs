using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;

namespace QualityGuard.Core.Analysis;

/// <summary>
/// WAI-ARIA 1.2 role and property matrices, read from the markup tree. The dictionaries answer
/// three questions: is this role real, what does it require, and does this element already carry
/// an implicit version of it.
/// </summary>
public static class AriaDictionary
{
    /// <summary>Every non-abstract ARIA role.</summary>
    public static readonly HashSet<string> ConcreteRoles = new(StringComparer.Ordinal)
    {
        // widget roles
        "alert", "alertdialog", "button", "checkbox", "combobox", "dialog", "grid",
        "gridcell", "link", "listbox", "menu", "menubar", "menuitem", "menuitemcheckbox",
        "menuitemradio", "option", "progressbar", "radio", "radiogroup", "scrollbar",
        "searchbox", "slider", "spinbutton", "switch", "tab", "tablist", "tabpanel",
        "textbox", "timer", "tooltip", "tree", "treegrid", "treeitem",
        // composite roles
        "combobox", "grid", "listbox", "menu", "menubar", "radiogroup", "tablist",
        "tree", "treegrid",
        // document structure roles
        "article", "associationlist", "blockquote", "caption", "cell", "code",
        "columnheader", "comment", "definition", "deletion", "directory", "document",
        "emphasis", "feed", "figure", "footnote", "group", "heading", "img", "insertion",
        "link", "list", "listitem", "mark", "math", "meter", "note", "paragraph",
        "presentation", "row", "rowgroup", "rowheader", "separator", "strong",
        "subscript", "superscript", "table", "term", "time", "toolbar", "tooltip",
        // landmark roles
        "banner", "complementary", "contentinfo", "form", "main", "navigation",
        "region", "search"
    };

    /// <summary>Abstract roles cannot be used directly in markup.</summary>
    public static readonly HashSet<string> AbstractRoles = new(StringComparer.Ordinal)
    {
        "command", "composite", "input", "landmark", "range", "roledescription",
        "section", "sectionhead", "select", "structure", "widget", "window"
    };

    /// <summary>Required owned elements or properties per composite role.</summary>
    public static readonly Dictionary<string, string[]> RequiredOwned = new(StringComparer.Ordinal)
    {
        ["grid"] = ["row", "rowgroup"],
        ["list"] = ["listitem"],
        ["listbox"] = ["option"],
        ["menu"] = ["menuitem", "menuitemcheckbox", "menuitemradio"],
        ["menubar"] = ["menuitem", "menuitemcheckbox", "menuitemradio"],
        ["radiogroup"] = ["radio"],
        ["tablist"] = ["tab"],
        ["table"] = ["row", "rowgroup"],
        ["tree"] = ["treeitem", "group"],
        ["treegrid"] = ["row", "rowgroup"],
        ["row"] = ["cell", "columnheader", "rowheader", "gridcell"],
        ["rowgroup"] = ["row"]
    };

    /// <summary>Properties every instance of the role must carry.</summary>
    public static readonly Dictionary<string, string[]> RequiredProperties = new(StringComparer.Ordinal)
    {
        ["checkbox"] = ["aria-checked"],
        ["menuitemcheckbox"] = ["aria-checked"],
        ["menuitemradio"] = ["aria-checked"],
        ["radio"] = ["aria-checked"],
        ["switch"] = ["aria-checked"],
        ["option"] = ["aria-selected"],
        ["tab"] = ["aria-selected"],
        ["combobox"] = ["aria-expanded"],
        ["slider"] = ["aria-valuenow"],
        ["spinbutton"] = ["aria-valuenow"],
        ["separator"] = ["aria-valuenow"]
    };

    /// <summary>HTML element → its implicit ARIA role (when one exists).</summary>
    public static readonly Dictionary<string, string> ImplicitRole = new(StringComparer.Ordinal)
    {
        ["a"] = "link",
        ["article"] = "article",
        ["aside"] = "complementary",
        ["button"] = "button",
        ["footer"] = "contentinfo",
        ["form"] = "form",
        ["h1"] = "heading",
        ["h2"] = "heading",
        ["h3"] = "heading",
        ["h4"] = "heading",
        ["h5"] = "heading",
        ["h6"] = "heading",
        ["header"] = "banner",
        ["hr"] = "separator",
        ["img"] = "img",
        ["input[type=checkbox]"] = "checkbox",
        ["input[type=number]"] = "spinbutton",
        ["input[type=radio]"] = "radio",
        ["input[type=range]"] = "slider",
        ["input[type=search]"] = "searchbox",
        ["input[type=text]"] = "textbox",
        ["li"] = "listitem",
        ["main"] = "main",
        ["nav"] = "navigation",
        ["ol"] = "list",
        ["option"] = "option",
        ["output"] = "status",
        ["progress"] = "progressbar",
        ["section"] = "region",
        ["select"] = "listbox",
        ["table"] = "table",
        ["textarea"] = "textbox",
        ["ul"] = "list"
    };

    /// <summary>Elements that are interactive by default without any ARIA annotation.</summary>
    public static readonly HashSet<string> InteractiveElements = new(StringComparer.Ordinal)
    {
        "a", "button", "details", "embed", "iframe", "input", "label", "select",
        "summary", "textarea", "audio", "video"
    };

    /// <summary>All valid global ARIA properties (usable on any element).</summary>
    public static readonly HashSet<string> GlobalProperties = new(StringComparer.Ordinal)
    {
        "aria-atomic", "aria-braillelabel", "aria-brailleroledescription", "aria-busy",
        "aria-controls", "aria-current", "aria-describedby", "aria-description",
        "aria-details", "aria-disabled", "aria-dropeffect", "aria-errormessage",
        "aria-flowto", "aria-grabbed", "aria-haspopup", "aria-hidden", "aria-invalid",
        "aria-keyshortcuts", "aria-label", "aria-labelledby", "aria-live",
        "aria-owns", "aria-relevant", "aria-roledescription"
    };

    /// <summary>All valid aria-* attribute names (global + role-specific).</summary>
    public static readonly HashSet<string> AllProperties = new(StringComparer.Ordinal)
    {
        // global
        "aria-atomic", "aria-braillelabel", "aria-brailleroledescription", "aria-busy",
        "aria-controls", "aria-current", "aria-describedby", "aria-description",
        "aria-details", "aria-disabled", "aria-dropeffect", "aria-errormessage",
        "aria-flowto", "aria-grabbed", "aria-haspopup", "aria-hidden", "aria-invalid",
        "aria-keyshortcuts", "aria-label", "aria-labelledby", "aria-live",
        "aria-owns", "aria-relevant", "aria-roledescription",
        // widget
        "aria-autocomplete", "aria-checked", "aria-expanded", "aria-level",
        "aria-modal", "aria-multiline", "aria-multiselectable", "aria-orientation",
        "aria-placeholder", "aria-pressed", "aria-readonly", "aria-required",
        "aria-selected", "aria-sort", "aria-valuemax", "aria-valuemin", "aria-valuenow",
        "aria-valuetext",
        // landmark
        "aria-activedescendant", "aria-colcount", "aria-colindex", "aria-colindextext",
        "aria-posinset", "aria-rowcount", "aria-rowindex", "aria-rowindextext",
        "aria-setsize"
    };
}
