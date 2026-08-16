using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Stylesheet rules that work on the parsed sheet: blocks, selectors and declarations. They cover
/// plain CSS and the preprocessor dialects (SCSS, Sass, Less) because the defects are the same in all
/// four — a property set twice, a shorthand cancelled by the longhand after it, a block that styles
/// nothing.
/// </summary>
public static class StyleSheetRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new DuplicatePropertyRule(),
        new ShorthandOverriddenRule(),
        new EmptyStyleBlockRule(),
        new ImportantOverusedRule(),
        new DuplicateSelectorRule(),
        new FontWithoutFallbackRule(),
        new ImportAfterRulesRule(),
        new DeepStyleNestingRule(),
        new SuspiciousZIndexRule()
    ];
}

public abstract class StyleRuleBase : RuleBase
{
    public override string[] Languages => ["css"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    protected static StyleRule Sheet(IRuleContext context) => StyleSheet.Parse(context.File.Content);

    /// <summary>Blocks that hold declarations, at every level of nesting.</summary>
    protected static IEnumerable<StyleRule> Blocks(StyleRule root)
        => root.Descendants().Where(r => !r.IsAtRule);
}

public sealed class DuplicatePropertyRule : StyleRuleBase
{
    public override string Key => "QG-CSS-BUG-0027";
    public override string Name => "A block should not set the same property twice";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var block in Blocks(Sheet(context)))
        {
            var seen = new Dictionary<string, StyleDeclaration>(StringComparer.OrdinalIgnoreCase);
            foreach (var declaration in block.Declarations)
            {
                if (!seen.TryGetValue(declaration.Property, out var first))
                {
                    seen[declaration.Property] = declaration;
                    continue;
                }
                // the same property with the same value twice is redundant; with a different value
                // the first one is dead, which is the case that surprises people
                if (string.Equals(first.Value, declaration.Value, StringComparison.OrdinalIgnoreCase)
                    && first.Important == declaration.Important)
                {
                    context.Report($"'{declaration.Property}' is repeated with the same value; the second "
                                   + "declaration changes nothing.", declaration.Line);
                }
                else
                {
                    context.Report($"'{declaration.Property}' is set again here, so the value on line "
                                   + $"{first.Line} never applies. Keep the one you mean, or move the "
                                   + "other into the rule that should override it.", declaration.Line);
                }
                seen[declaration.Property] = declaration;
            }
        }
    }
}

public sealed class ShorthandOverriddenRule : StyleRuleBase
{
    /// <summary>Shorthand properties and the longhands they cover.</summary>
    private static readonly Dictionary<string, string[]> Shorthands = new(StringComparer.OrdinalIgnoreCase)
    {
        ["margin"] = ["margin-top", "margin-right", "margin-bottom", "margin-left"],
        ["padding"] = ["padding-top", "padding-right", "padding-bottom", "padding-left"],
        ["border"] = ["border-top", "border-right", "border-bottom", "border-left", "border-width",
                      "border-style", "border-color"],
        ["background"] = ["background-color", "background-image", "background-position",
                          "background-repeat", "background-size", "background-attachment"],
        ["font"] = ["font-family", "font-size", "font-style", "font-weight", "line-height", "font-variant"],
        ["flex"] = ["flex-grow", "flex-shrink", "flex-basis"],
        ["grid"] = ["grid-template-rows", "grid-template-columns", "grid-template-areas"],
        ["transition"] = ["transition-property", "transition-duration", "transition-timing-function",
                          "transition-delay"],
        ["animation"] = ["animation-name", "animation-duration", "animation-timing-function",
                         "animation-delay", "animation-iteration-count"],
        ["overflow"] = ["overflow-x", "overflow-y"]
    };

    public override string Key => "QG-CSS-BUG-0028";
    public override string Name => "A shorthand should not cancel the longhand written before it";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var block in Blocks(Sheet(context)))
        {
            var longhands = new Dictionary<string, StyleDeclaration>(StringComparer.OrdinalIgnoreCase);
            foreach (var declaration in block.Declarations)
            {
                if (Shorthands.TryGetValue(declaration.Property, out var covered))
                {
                    var overridden = covered.FirstOrDefault(longhands.ContainsKey);
                    if (overridden != null)
                    {
                        context.Report($"'{declaration.Property}' resets everything it covers, so "
                                       + $"'{overridden}' on line {longhands[overridden].Line} is lost. "
                                       + "Put the shorthand first and the exception after it.",
                            declaration.Line);
                    }
                    continue;
                }
                longhands[declaration.Property] = declaration;
            }
        }
    }
}

public sealed class EmptyStyleBlockRule : StyleRuleBase
{
    public override string Key => "QG-CSS-SML-0021";
    public override string Name => "A style block should declare something";

    public override void Execute(IRuleContext context)
    {
        foreach (var block in Sheet(context).Descendants())
        {
            if (block.Declarations.Count > 0 || block.Children.Count > 0)
                continue;
            // an @import or @charset is a statement, not a block that forgot its declarations
            if (block.Selector.Length == 0 || block.IsAtRule)
                continue;

            context.Report($"'{block.Selector}' styles nothing. It was either emptied during a cleanup "
                           + "and forgotten, or it is waiting for declarations that never arrived; either "
                           + "way the selector still has to be maintained.", block.Line);
        }
    }
}

public sealed class ImportantOverusedRule : StyleRuleBase
{
    private const int Limit = 5;

    public override string Key => "QG-CSS-SML-0022";
    public override string Name => "A stylesheet should not rely on !important";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        var root = Sheet(context);
        var forced = Blocks(root).SelectMany(b => b.Declarations).Where(d => d.Important).ToList();
        if (forced.Count <= Limit)
            return;

        context.Report($"This sheet forces {forced.Count} declarations with !important. Each one wins "
                       + "against every future rule, so the next change has to escalate too, and the "
                       + "cascade stops describing what the page looks like. Give the rules that must "
                       + "win a more specific selector instead.", forced[0].Line);
    }
}

public sealed class DuplicateSelectorRule : StyleRuleBase
{
    public override string Key => "QG-CSS-SML-0023";
    public override string Name => "A selector should be defined once";

    public override void Execute(IRuleContext context)
    {
        var seen = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var block in Blocks(Sheet(context)))
        {
            var selector = Normalize(block.Selector);
            if (selector.Length == 0 || block.Declarations.Count == 0)
                continue;
            if (seen.TryGetValue(selector, out var first))
            {
                context.Report($"'{block.Selector}' is already defined on line {first}. Two blocks for "
                               + "one selector means the reader has to find both to know what applies, "
                               + "and the order between them decides the result.", block.Line);
                continue;
            }
            seen[selector] = block.Line;
        }
    }

    private static string Normalize(string selector)
        => string.Join(", ", selector.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(part => string.Join(' ', part.Split(' ', StringSplitOptions.RemoveEmptyEntries)))
            .OrderBy(part => part, StringComparer.Ordinal));
}

public sealed class FontWithoutFallbackRule : StyleRuleBase
{
    private static readonly string[] GenericFamilies =
    [
        "serif", "sans-serif", "monospace", "cursive", "fantasy", "system-ui", "ui-serif",
        "ui-sans-serif", "ui-monospace", "ui-rounded", "math", "emoji", "fangsong", "inherit",
        "initial", "unset", "revert"
    ];

    public override string Key => "QG-CSS-BUG-0029";
    public override string Name => "A font family should end with a generic family";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var block in Blocks(Sheet(context)))
        {
            foreach (var declaration in block.Declarations)
            {
                if (!declaration.Property.Equals("font-family", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (declaration.Value.Contains("var(", StringComparison.OrdinalIgnoreCase)
                    || declaration.Value.Contains('$') || declaration.Value.Contains('@'))
                    continue; // the list comes from a variable the sheet does not show

                var families = declaration.Value
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(f => f.Trim('"', '\'', ' '))
                    .ToList();
                if (families.Count == 0 || GenericFamilies.Contains(families[^1], StringComparer.OrdinalIgnoreCase))
                    continue;

                context.Report($"The list ends with '{families[^1]}', so a reader without that font gets "
                               + "whatever the browser picks — often a serif face in a design built for "
                               + "sans. End the list with a generic family.", declaration.Line);
            }
        }
    }
}

public sealed class ImportAfterRulesRule : StyleRuleBase
{
    public override string Key => "QG-CSS-BUG-0030";
    public override string Name => "An import should come before the rules";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        var root = Sheet(context);
        var sawRule = false;

        foreach (var child in root.Children)
        {
            if (child.Selector.StartsWith("@import", StringComparison.OrdinalIgnoreCase))
            {
                if (sawRule)
                {
                    context.Report("An @import after the first rule is ignored by the browser, so the "
                                   + "sheet it names is never loaded. Move every import to the top of "
                                   + "the file.", child.Line);
                }
                continue;
            }
            if (child.Selector.StartsWith("@charset", StringComparison.OrdinalIgnoreCase)
                || child.Selector.StartsWith("@use", StringComparison.OrdinalIgnoreCase)
                || child.Selector.StartsWith("@forward", StringComparison.OrdinalIgnoreCase))
                continue;
            sawRule = true;
        }
    }
}

public sealed class DeepStyleNestingRule : StyleRuleBase
{
    private const int MaxDepth = 3;

    public override string Key => "QG-CSS-SML-0024";
    public override string Name => "Nested style blocks should stay shallow";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        foreach (var block in Blocks(Sheet(context)))
        {
            if (block.Depth <= MaxDepth || block.Declarations.Count == 0)
                continue;

            context.Report($"This block is nested {block.Depth} levels deep, so the selector it produces "
                           + "is long, specific and hard to override — and nobody can tell what it "
                           + "matches without reading every level above it. Flatten it, or name the "
                           + "component and style it directly.", block.Line);
        }
    }
}

public sealed class SuspiciousZIndexRule : StyleRuleBase
{
    private const int Reasonable = 100;

    public override string Key => "QG-CSS-SML-0025";
    public override string Name => "A stacking order should stay in a range people can reason about";

    public override void Execute(IRuleContext context)
    {
        foreach (var block in Blocks(Sheet(context)))
        {
            foreach (var declaration in block.Declarations)
            {
                if (!declaration.Property.Equals("z-index", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!int.TryParse(declaration.Value, out var value) || Math.Abs(value) <= Reasonable)
                    continue;

                context.Report($"z-index {value} is an escalation, not a position: the next element that "
                               + "has to sit on top will pick a bigger number, and the stacking order "
                               + "stops meaning anything. Define a small scale and use it.",
                    declaration.Line);
            }
        }
    }
}
