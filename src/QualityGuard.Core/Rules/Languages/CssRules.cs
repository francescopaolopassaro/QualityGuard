using QualityGuard.Core.Models;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class CssRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CssImportantRule(),
        new CssImportRule(),
        new CssUniversalSelectorRule(),
        new CssEmptyBlockRule(),
        new CssZIndexRule(),
        new CssTransitionAllRule(),
        new CssZeroUnitRule()
    ];
}

public sealed class CssImportantRule : PatternRuleBase
{
    public override string Key => "QG-CSS-SML-0001";
    public override string Name => "Avoid the !important annotation";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Increase specificity instead of using !important.";
    public override string[] Languages => ["css"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
            if (RuleMatchers.LineContains(lines[i], "!important"))
                context.Report("Avoid using !important; it overrides specificity.", i + 1);
    }
}

public sealed class CssImportRule : PatternRuleBase
{
    public override string Key => "QG-CSS-SML-0002";
    public override string Name => "Prefer @use or <link> over @import";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use @use in Sass or a <link> element to load stylesheets.";
    public override string[] Languages => ["css"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
            if (lines[i].TrimStart().StartsWith("@import", StringComparison.Ordinal))
                context.Report("Avoid @import; it blocks parallel loading.", i + 1);
    }
}

public sealed class CssUniversalSelectorRule : PatternRuleBase
{
    public override string Key => "QG-CSS-SML-0003";
    public override string Name => "Avoid the universal selector";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Replace * with a more specific selector or a reset of the elements you target.";
    public override string[] Languages => ["css"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
            if (RuleMatchers.LineContains(lines[i], "*{"))
                context.Report("Avoid the universal selector; it applies to every element.", i + 1);
    }
}

public sealed class CssEmptyBlockRule : PatternRuleBase
{
    public override string Key => "QG-CSS-SML-0004";
    public override string Name => "Remove empty rule blocks";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Delete the empty rule or fill it with declarations.";
    public override string[] Languages => ["css"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
            if (RuleMatchers.LineContains(lines[i], "{}"))
                context.Report("Remove this empty rule block.", i + 1);
    }
}

public sealed class CssZIndexRule : PatternRuleBase
{
    /// <summary>Values of position that take an element out of the normal flow.</summary>
    private static readonly string[] Positioned = ["relative", "absolute", "fixed", "sticky"];

    public override string Key => "QG-CSS-BUG-0001";
    public override string Name => "z-index requires a positioned element";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Set a position value (relative, absolute, fixed or sticky) for z-index to apply.";
    public override string[] Languages => ["css"];

    public override void Execute(IRuleContext context)
    {
        var sheet = Analysis.StyleSheet.Parse(context.File.Content);
        foreach (var block in sheet.Descendants())
        {
            var stack = block.Declarations
                .FirstOrDefault(d => d.Property.Equals("z-index", StringComparison.OrdinalIgnoreCase));
            if (stack == null)
                continue;

            // the position can be set here, or on a block this one is nested inside
            if (IsPositioned(block))
                continue;

            context.Report($"'z-index: {stack.Value}' does nothing here: the browser only stacks an "
                           + "element that has been taken out of the normal flow. Set position to "
                           + "relative, absolute, fixed or sticky, or drop the z-index.", stack.Line);
        }
    }

    private static bool IsPositioned(Analysis.StyleRule block)
    {
        for (var node = block; node != null; node = node.Parent)
        {
            var position = node.Declarations
                .FirstOrDefault(d => d.Property.Equals("position", StringComparison.OrdinalIgnoreCase));
            if (position == null)
                continue;
            // a variable or a function is something this rule cannot read, so it stays quiet
            if (position.Value.Contains("var(", StringComparison.OrdinalIgnoreCase)
                || position.Value.Contains('$') || position.Value.Contains('#'))
                return true;
            if (Positioned.Any(v => position.Value.Contains(v, StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
    }
}

public sealed class CssTransitionAllRule : PatternRuleBase
{
    public override string Key => "QG-CSS-PRF-0001";
    public override string Name => "Avoid animating the all keyword";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Animate specific properties instead of the all keyword.";
    public override string[] Languages => ["css"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if ((RuleMatchers.LineContains(line, "transition") || RuleMatchers.LineContains(line, "animation"))
                && RuleMatchers.LineContains(line, ": all"))
                context.Report("Animating the all keyword hurts performance; target specific properties.", i + 1);
        }
    }
}

public sealed class CssZeroUnitRule : PatternRuleBase
{
    public override string Key => "QG-CSS-CNV-0001";
    public override string Name => "Omit the unit on zero values";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Write 0 instead of 0px; a unit is redundant on zero.";
    public override string[] Languages => ["css"];

    public override void Execute(IRuleContext context)
    {
        var lines = context.File.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (!HasZeroWithUnit(lines[i]))
                continue;
            context.Report("The unit says nothing on a zero: zero pixels, zero rems and zero percent "
                           + "are the same length. Write 0.", i + 1);
        }
    }

    /// <summary>
    /// Whether the line writes a zero with a unit on it. The digit before matters: searching for the
    /// text "0px" also finds it inside 40px and 1280px, which are ordinary lengths.
    /// </summary>
    private static bool HasZeroWithUnit(string line)
    {
        for (var i = 0; i < line.Length; i++)
        {
            if (line[i] != '0')
                continue;
            if (i > 0 && (char.IsAsciiDigit(line[i - 1]) || line[i - 1] == '.'))
                continue;

            foreach (var unit in Units)
            {
                if (i + 1 + unit.Length > line.Length)
                    continue;
                if (!line.AsSpan(i + 1, unit.Length).SequenceEqual(unit))
                    continue;
                var after = i + 1 + unit.Length;
                if (after < line.Length && (char.IsAsciiLetterOrDigit(line[after]) || line[after] == '%'))
                    continue;
                return true;
            }
        }
        return false;
    }

    /// <summary>Units that say nothing on a zero. Time and angle units are left out: 0s is not 0deg.</summary>
    private static readonly string[] Units =
        ["px", "em", "rem", "ex", "ch", "vw", "vh", "vmin", "vmax", "cm", "mm", "in", "pt", "pc"];
}
