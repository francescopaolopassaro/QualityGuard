using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// CSS checks from the default profile that read tokens or declarations on the stylesheet tree.
/// </summary>
public static class CssGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CssEmptyFileRule(),
        new CssSingleLineCommentRule(),
        new CssInvalidColorRule(),
        new CssInvalidPseudoClassRule(),
        new CssInvalidPseudoElementRule(),
        new CssInvalidAtRuleRule(),
        new CssStringWithNewlineRule(),
        new CssValidUnitRule(),
        new CssLinearGradientDirectionRule(),
        new CssCalcExpressionRule(),
        new CssMediaFeatureRule(),
    ];
}

public abstract class CssGapRuleBase : RuleBase
{
    public override string[] Languages => ["css"];
}

public sealed class CssEmptyFileRule : CssGapRuleBase
{
    public override string Key => "QG-CSS-SML-0076";
    public override string Name => "A stylesheet should not be empty";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";

    public override void Execute(IRuleContext context)
    {
        if (context.Tokens.Any(t => t.Kind != TokenKind.Comment && t.Text.Trim().Length > 0))
            return;
        context.Report("This file holds no style: either delete it or add the rules it was meant "
                       + "to carry.");
    }
}

public sealed class CssSingleLineCommentRule : CssGapRuleBase
{
    public override string Key => "QG-CSS-SML-0077";
    public override string Name => "Use /* */ comments in CSS";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.Comment))
        {
            if (!token.Text.StartsWith("//"))
                continue;
            context.Report("'//' is not valid CSS comment syntax: browsers treat it as an "
                                  + "unexpected token and skip every rule after it until the next "
                                  + "'}'. Use /* ... */.", token.Line);
        }
    }
}

public sealed class CssInvalidColorRule : CssGapRuleBase
{
    private static readonly System.Text.RegularExpressions.Regex HexColor =
        new(@"#[0-9a-fA-F]{3,8}\b", System.Text.RegularExpressions.RegexOptions.Compiled);

    public override string Key => "QG-CSS-SML-0078";
    public override string Name => "Hex color definitions should be valid";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t =>
                     t.Kind == TokenKind.Identifier && t.Text.StartsWith("#")))
        {
            var hex = token.Text[1..];
            if (hex.Length is 3 or 4 or 6 or 8) continue;
            if (hex.All(c => Uri.IsHexDigit(c))) continue;
            if (hex.Length == 0 || hex.Length > 8) continue;
            if (hex.All(c => char.IsLetterOrDigit(c))) continue;
            context.Report($"'{token.Text}' is not a valid hex color: use #RGB, #RGBA, "
                                  + "#RRGGBB or #RRGGBBAA.", token.Line);
        }
    }
}

public sealed class CssInvalidPseudoClassRule : CssGapRuleBase
{
    private static readonly HashSet<string> Known = new(StringComparer.Ordinal)
    {
        "active", "any-link", "autofill", "blank", "checked", "current", "default", "defined",
        "disabled", "empty", "enabled", "first", "first-child", "first-of-type", "focus",
        "focus-visible", "focus-within", "fullscreen", "has", "host", "host-context",
        "hover", "indeterminate", "in-range", "invalid", "is", "lang", "last-child",
        "last-of-type", "left", "link", "local-link", "modal", "not", "nth-child", "nth-col",
        "nth-last-child", "nth-last-col", "nth-last-of-type", "nth-of-type", "only-child",
        "only-of-type", "optional", "out-of-range", "past", "paused", "picture-in-picture",
        "placeholder-shown", "playing", "popover-open", "read-only", "read-write",
        "required", "right", "root", "scope", "state", "target", "target-text", "user-invalid",
        "user-valid", "valid", "visited", "where"
    };

    public override string Key => "QG-CSS-SML-0079";
    public override string Name => "Pseudo-class selectors should be valid";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.Identifier))
        {
            if (!token.Text.StartsWith(':') || token.Text.StartsWith("::"))
                continue;
            var name = token.Text.TrimStart(':').Split('(')[0];
            if (name.Length == 0 || Known.Contains(name))
                continue;
            context.Report($"'{token.Text}' is not a standard pseudo-class: browsers ignore "
                                  + "the rule it appears in.", token.Line);
        }
    }
}

public sealed class CssInvalidPseudoElementRule : CssGapRuleBase
{
    private static readonly HashSet<string> Known = new(StringComparer.Ordinal)
    {
        "after", "backdrop", "before", "cue", "cue-region", "file-selector-button", "first-letter",
        "first-line", "grammar-error", "highlight", "marker", "part", "placeholder", "selection",
        "slotted", "spelling-error", "target-text"
    };

    public override string Key => "QG-CSS-SML-0080";
    public override string Name => "Pseudo-element selectors should be valid";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.Identifier))
        {
            if (!token.Text.StartsWith("::"))
                continue;
            var name = token.Text[2..].Split('(')[0];
            if (name.Length == 0 || Known.Contains(name))
                continue;
            context.Report($"'::{name}' is not a standard pseudo-element: browsers ignore "
                                  + "the rule it appears in.", token.Line);
        }
    }
}

public sealed class CssInvalidAtRuleRule : CssGapRuleBase
{
    private static readonly HashSet<string> Known = new(StringComparer.Ordinal)
    {
        "@charset", "@color-profile", "@container", "@counter-style", "@document", "@font-face",
        "@font-feature-values", "@layer", "@media", "@page", "@property", "@scope", "@supports",
        "@keyframes", "@import", "@namespace", "@apply", "@tailwind", "@screen", "@variants",
        "@responsive", "@use", "@forward", "@function", "@mixin", "@include", "@extend", "@if",
        "@else", "@for", "@each", "@while", "@return", "@warn", "@error", "@debug", "@at-root",
        "@content"
    };

    public override string Key => "QG-CSS-SML-0081";
    public override string Name => "At-rules should be recognised";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.Keyword || t.Kind == TokenKind.Identifier))
        {
            if (!token.Text.StartsWith('@'))
                continue;
            var name = token.Text.ToLowerInvariant();
            if (Known.Contains(name))
                continue;
            // preprocessor extensions (@mixin etc.) and newer specs are acceptable; flag unknown bare @
            if (name.Length < 3)
                context.Report($"'{token.Text}' is not a standard at-rule: browsers ignore "
                                      + "everything up to the next block or semicolon.", token.Line);
        }
    }
}

public sealed class CssStringWithNewlineRule : CssGapRuleBase
{
    public override string Key => "QG-CSS-SML-0082";
    public override string Name => "CSS strings cannot contain literal newlines";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.String))
        {
            if (!token.Text.Contains('\n') && !token.Text.Contains('\r'))
                continue;
            context.Report("A quoted CSS value breaks when it spans lines without escaping: "
                                  + "browsers drop everything after the newline. Use \\A for a "
                                  + "literal newline inside content strings.", token.Line);
        }
    }
}

// ------------------------------------------------------------------ validity dictionaries

public sealed class CssValidUnitRule : CssGapRuleBase
{
    private static readonly HashSet<string> Units = new(StringComparer.Ordinal)
    {
        "px", "em", "rem", "%", "vh", "vw", "vmin", "vmax", "cm", "mm", "in", "pt", "pc",
        "ex", "ch", "fr", "deg", "grad", "rad", "turn", "s", "ms", "Hz", "kHz",
        "dpi", "dpcm", "dppx", "x", "lh", "rlh", "cap", "ic", "Q"
    };

    public override string Key => "QG-CSS-SML-0083";
    public override string Name => "CSS units should be recognised";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.Number))
        {
            var text = token.Text;
            var unitStart = text.Length;
            for (var i = text.Length - 1; i >= 0; i--)
            {
                if (!char.IsLetter(text[i])) break;
                unitStart = i;
            }
            if (unitStart >= text.Length) continue;
            var unit = text[unitStart..];
            if (unit.Length == 0 || Units.Contains(unit)) continue;
            // hex colors are identifiers not numbers; skip anything that looks like one
            if (text.StartsWith("#")) continue;
            context.Report($"'{unit}' is not a standard CSS unit. Check the spelling.", token.Line);
        }
    }
}

public sealed class CssLinearGradientDirectionRule : CssGapRuleBase
{
    private static readonly HashSet<string> Directions = new(StringComparer.OrdinalIgnoreCase)
    {
        "to top", "to bottom", "to left", "to right",
        "to top right", "to top left", "to bottom right", "to bottom left",
        "top", "bottom", "left", "right"
    };

    public override string Key => "QG-CSS-SML-0084";
    public override string Name => "linear-gradient directions should be valid";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t =>
                     t.Kind == TokenKind.Identifier &&
                     t.Text.Contains("linear-gradient")))
        {
            var line = token.Text;
            if (!line.Contains('(')) continue;
            // extract the first argument before a comma or closing paren
            var open = line.IndexOf('(');
            var argEnd = line.IndexOf(',', open);
            if (argEnd < 0) argEnd = line.IndexOf(')', open);
            if (argEnd < 0 || argEnd <= open + 1) continue;
            var firstArg = line[(open + 1)..argEnd].Trim();
            if (Directions.Contains(firstArg)) continue;
            // angles are valid too
            if (firstArg.EndsWith("deg") || firstArg.EndsWith("grad")
                || firstArg.EndsWith("rad") || firstArg.EndsWith("turn"))
            {
                if (double.TryParse(firstArg.TrimEnd("gradnrs ".ToCharArray()),
                        System.Globalization.CultureInfo.InvariantCulture, out _))
                    continue;
            }
            // color stops without direction are valid (defaults to to bottom)
            if (firstArg.StartsWith("#") || char.IsDigit(firstArg[0])
                || firstArg.StartsWith("rgb") || firstArg.StartsWith("hsl")
                || firstArg.StartsWith("transparent") || !firstArg.StartsWith("to"))
                continue;
            context.Report($"'{firstArg}' is not a valid linear-gradient direction: use 'to <side>', "
                                  + "an angle, or omit it entirely.", token.Line);
        }
    }
}

public sealed class CssCalcExpressionRule : CssGapRuleBase
{
    public override string Key => "QG-CSS-SML-0085";
    public override string Name => "Expressions within calc() should be valid";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t =>
                     t.Kind == TokenKind.Identifier && t.Text.Contains("calc(")))
        {
            var open = token.Text.IndexOf("calc(");
            if (open < 0) continue;
            var exprStart = open + 5;
            var depth = 1;
            var end = exprStart;
            while (end < token.Text.Length && depth > 0)
            {
                if (token.Text[end] == '(') depth++;
                else if (token.Text[end] == ')') depth--;
                end++;
            }
            var expr = token.Text[exprStart..(end - 1)].Trim();
            if (expr.Length == 0)
            {
                context.Report("calc() with no arguments is ignored by browsers.", token.Line);
                continue;
            }
            // calc requires whitespace around + and -
            for (var i = 1; i < expr.Length - 1; i++)
            {
                if ((expr[i] == '+' || expr[i] == '-') && expr[i - 1] != ' '
                    && expr[i - 1] != '(' && char.IsLetterOrDigit(expr[i - 1]))
                {
                    context.Report($"In calc(), '{expr[i]}' requires whitespace on both sides: "
                                          + "browsers reject 'width: calc(100%-20px)'. Add spaces.",
                        token.Line);
                    break;
                }
            }
        }
    }
}

public sealed class CssMediaFeatureRule : CssGapRuleBase
{
    private static readonly HashSet<string> Known = new(StringComparer.Ordinal)
    {
        "width", "min-width", "max-width", "height", "min-height", "max-height",
        "aspect-ratio", "min-aspect-ratio", "max-aspect-ratio", "orientation",
        "resolution", "min-resolution", "max-resolution", "scan", "grid", "update",
        "overflow-block", "overflow-inline", "color", "min-color", "max-color",
        "color-index", "min-color-index", "max-color-index", "color-gamut",
        "monochrome", "min-monochrome", "max-monochrome", "pointer", "any-pointer",
        "hover", "any-hover", "scripting", "prefers-color-scheme",
        "prefers-reduced-motion", "prefers-reduced-transparency", "prefers-contrast",
        "forced-colors", "inverted-colors", "display-mode", "dynamic-range",
        "video-dynamic-range"
    };

    public override string Key => "QG-CSS-SML-0086";
    public override string Name => "Media features should be recognised";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t =>
                     t.Kind == TokenKind.Comment || t.Kind == TokenKind.String))
            continue;
        // scan raw source for @media blocks and their feature names
        var content = context.File.Content;
        var mediaIdx = 0;
        while ((mediaIdx = content.IndexOf("@media", mediaIdx, StringComparison.Ordinal)) >= 0)
        {
            var braceIdx = content.IndexOf('{', mediaIdx);
            if (braceIdx < 0 || braceIdx - mediaIdx > 200) { mediaIdx += 6; continue; }
            var header = content[(mediaIdx + 6)..braceIdx];
            foreach (System.Text.RegularExpressions.Match m in
                     System.Text.RegularExpressions.Regex.Matches(header, @"\(([a-zA-Z-]+)\s*[:)]"))
            {
                var feature = m.Groups[1].Value.ToLowerInvariant();
                if (Known.Contains(feature)) continue;
                var lineNumber = content[..mediaIdx].Count(c => c == '\n') + 1;
                context.Report($"'{feature}' is not a standard media feature: the query never "
                                      + "matches. Check the spelling.", lineNumber);
            }
            mediaIdx = braceIdx;
        }
    }
}









