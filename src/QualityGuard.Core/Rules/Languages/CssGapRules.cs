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
