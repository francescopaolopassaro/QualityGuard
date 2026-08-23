using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Rust rules on the dedicated tree. The language joins the C-family parser with a dialect of its
/// own, so the shared structural families read functions, matches and blocks directly, and the
/// standard-library families read the calls they are written against.
/// </summary>
public static class RustTreeRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new RustSelfAssignmentRule(),
        new RustUnreachableCodeAfterJumpRule(),
        new RustDuplicateConditionRule(),
        new RustConstantConditionRule(),
        new RustIdenticalBranchesRule(),
        new RustMergeableIfRule(),
        new RustCognitiveComplexityRule(),
        new RustTooManyParametersRule(),
        new RustEmptyFunctionRule(),
        new RustUnusedInternalMemberRule(),
        new RustUnusedLocalVariableRule(),
        new RustUnusedParameterRule(),
        new RustIdenticalBodiesRule(),
        new RustHardcodedIpRule(),
        new RustWildcardImportRule(),
        new RustInvisibleCharacterRule(),
        new RustMathConstantRule(),
        new RustNullTransmuteRule(),
        new RustUninitializedMemoryRule(),
        new RustZeroLimitCallRule(),
        new RustRemainderByOneRule(),
        new RustDecimalPermissionRule(),
    ];
}

// ------------------------------------------------------- shared structural families

public sealed class RustSelfAssignmentRule : SelfAssignmentRule
{
    public override string Key => "QG-RS-BUG-0120";
    public override string[] Languages => ["rs"];
}

public sealed class RustUnreachableCodeAfterJumpRule : UnreachableCodeAfterJumpRule
{
    public override string Key => "QG-RS-BUG-0121";
    public override string[] Languages => ["rs"];
}

public sealed class RustDuplicateConditionRule : DuplicateConditionRule
{
    public override string Key => "QG-RS-BUG-0122";
    public override string[] Languages => ["rs"];
}

public sealed class RustConstantConditionRule : ConstantConditionRule
{
    public override string Key => "QG-RS-BUG-0123";
    public override string[] Languages => ["rs"];
}

public sealed class RustIdenticalBranchesRule : IdenticalBranchesRule
{
    public override string Key => "QG-RS-BUG-0124";
    public override string[] Languages => ["rs"];
}

public sealed class RustMergeableIfRule : MergeableIfRule
{
    public override string Key => "QG-RS-SML-0049";
    public override string[] Languages => ["rs"];
}

public sealed class RustCognitiveComplexityRule : CognitiveComplexityRule
{
    public override string Key => "QG-RS-SML-0050";
    public override string[] Languages => ["rs"];
}

public sealed class RustTooManyParametersRule : TooManyParametersRule
{
    public override string Key => "QG-RS-SML-0051";
    public override string[] Languages => ["rs"];
}

public sealed class RustEmptyFunctionRule : EmptyFunctionRule
{
    public override string Key => "QG-RS-SML-0052";
    public override string[] Languages => ["rs"];
}

public sealed class RustUnusedInternalMemberRule : UnusedInternalMemberRule
{
    public override string Key => "QG-RS-SML-0053";
    public override string[] Languages => ["rs"];
}

public sealed class RustUnusedLocalVariableRule : UnusedLocalVariableRule
{
    public override string Key => "QG-RS-SML-0054";
    public override string[] Languages => ["rs"];
}

public sealed class RustUnusedParameterRule : UnusedParameterRule
{
    public override string Key => "QG-RS-SML-0055";
    public override string[] Languages => ["rs"];
}

public sealed class RustIdenticalBodiesRule : IdenticalBodiesRule
{
    public override string Key => "QG-RS-SML-0056";
    public override string[] Languages => ["rs"];
}

public sealed class RustHardcodedIpRule : HardcodedIpRule
{
    public override string Key => "QG-RS-SML-0057";
    public override string[] Languages => ["rs"];
}

// ------------------------------------------------------------------ Rust-specific

internal static class RustCallName
{
    /// <summary>The name a call is invoked by: the last segment of a dotted receiver path.</summary>
    public static string LastSegment(SyntaxNode call)
        => call.Text.Contains('.') ? call.Text[(call.Text.LastIndexOf('.') + 1)..] : call.Text;
}

public sealed class RustWildcardImportRule : StructuralRuleBase
{
    public override string Key => "QG-RS-CNV-0005";
    public override string[] Languages => ["rs"];

    public override string Name => "Wildcard imports should not be used";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var import in context.Root.OfKind(NodeKind.ImportDeclaration))
        {
            if (!import.Text.EndsWith("::*", StringComparison.Ordinal))
                continue;
            // 'use self::Enum::*' and 'use crate::Module::*' are idiomatic for enum variants:
            // they bring names from the same crate, not from an external dependency
            if (import.Text.StartsWith("self::") || import.Text.StartsWith("crate::"))
                continue;
            context.Report(import, $"'{import.Text}' brings every name of the module into scope, so a "
                                   + "reader cannot tell where a name comes from and an added export "
                                   + "can silently change which one a call resolves to. Name the "
                                   + "items you use.");
        }
    }
}

public sealed class RustInvisibleCharacterRule : StructuralRuleBase
{
    public override string Key => "QG-RS-SML-0059";
    public override string[] Languages => ["rs"];

    private static readonly HashSet<char> Invisible =
        ['\0', (char)0x200b, (char)0x200c, (char)0x200d, (char)0x2060, (char)0xfeff];

    public override string Name => "Invisible Unicode characters should not be used";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t =>
                     t.Kind is TokenKind.Identifier or TokenKind.String or TokenKind.Comment))
        {
            var hit = token.Text.FirstOrDefault(Invisible.Contains);
            if (hit == default(char) && !token.Text.Contains('\u00a0'))
                continue;
            context.Report($"A character that renders as nothing (U+{(int)hit:X4}) hides inside this "
                           + $"{token.Kind.ToString().ToLowerInvariant()}. Two names that print alike "
                           + "can be different identifiers, and a reviewer sees one line while the "
                           + "compiler reads another. Replace it with the visible character.",
                token.Line);
        }
    }
}

public sealed class RustMathConstantRule : StructuralRuleBase
{
    public override string Key => "QG-RS-SML-0060";
    public override string[] Languages => ["rs"];

    private static readonly HashSet<string> Constants = new(StringComparer.Ordinal)
    {
        "3.14159265358979", "3.141592653589793", "3.141592653589793238",
        "2.71828182845904", "2.718281828459045",
        "1.41421356237309", "1.4142135623730951",
        "1.61803398874989", "1.618033988749895"
    };

    public override string Name => "Mathematical constants should not be hardcoded";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var literal in context.Root.OfKind(NodeKind.NumberLiteral))
        {
            if (!Constants.Contains(literal.Text.TrimEnd('f', '3', '2', '6', '4').TrimEnd('_')))
                continue;
            context.Report(literal, $"Use the constant from the standard library "
                                   + $"instead of the literal '{literal.Text}': the named one carries "
                                   + "its precision and its meaning.");
        }
    }
}

public sealed class RustNullTransmuteRule : StructuralRuleBase
{
    public override string Key => "QG-RS-BUG-0126";
    public override string[] Languages => ["rs"];

    public override string Name => "Null pointers should not be created through transmute";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var call in context.Root.OfKind(NodeKind.Invocation))
        {
            if (RustCallName.LastSegment(call) != "transmute")
                continue;
            var tokens = string.Concat(call.Tokens.Select(t => t.Text));
            if (!tokens.Contains("::transmute") && !tokens.StartsWith("transmute"))
                continue;
            var argument = call.FirstChild(NodeKind.ArgumentList);
            if (argument == null || !argument.OfKind(NodeKind.Identifier)
                    .Any(i => i.Text is "null" || i.Text.EndsWith("null", StringComparison.Ordinal)))
                continue;
            context.Report(call, "A null pointer built through transmute has no layout guarantee and "
                                 + "is undefined behaviour the moment it is read. Use "
                                 + "core::ptr::null or core::ptr::null_mut, which say exactly that.");
        }
    }
}

public sealed class RustUninitializedMemoryRule : StructuralRuleBase
{
    public override string Key => "QG-RS-BUG-0127";
    public override string[] Languages => ["rs"];

    private static readonly HashSet<string> Markers = new(StringComparer.Ordinal)
    {
        "assume_init", "set_len", "uninitialized"
    };

    public override string Name => "Uninitialized memory should not be read or exposed";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var call in context.Root.OfKind(NodeKind.Invocation))
        {
            if (!Markers.Contains(RustCallName.LastSegment(call)))
                continue;
            var tokens = string.Concat(call.Tokens.Select(t => t.Text));
            if (!tokens.Contains("MaybeUninit") && !tokens.Contains("mem::")
                && !tokens.Contains("Vec::") && !tokens.Contains(".set_len"))
                continue;
            context.Report(call, $"'{call.Text}' exposes memory that was never written: every value "
                                 + "read from it is undefined behaviour unless initialization is "
                                 + "proven. Write through the safe API, or keep the unsafe block "
                                 + "with the invariant documented next to it.");
        }
    }
}

public sealed class RustZeroLimitCallRule : StructuralRuleBase
{
    public override string Key => "QG-RS-BUG-0128";
    public override string[] Languages => ["rs"];

    private static readonly HashSet<string> Methods = new(StringComparer.Ordinal)
    {
        "splitn", "rsplitn", "skip", "step_by", "resize", "repeatn"
    };

    public override string Name => "Iterator and buffer calls should not use a limit of zero";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var call in context.Root.OfKind(NodeKind.Invocation))
        {
            if (!Methods.Contains(RustCallName.LastSegment(call)))
                continue;
            var arguments = call.FirstChild(NodeKind.ArgumentList);
            var first = arguments?.Children.FirstOrDefault();
            if (first?.Kind != NodeKind.NumberLiteral || first.Text is not ("0" or "1"))
                continue;
            // splitn(1) is meaningful: it takes the first piece and stops. skip(0), step_by(0),
            // resize(0) are the shapes that either do nothing or panic with the count in the source
            if (first.Text == "1" && call.Text is not ("skip" or "step_by" or "resize"))
                continue;
            context.Report(call, $"'{call.Text}({first.Text})' either does nothing or panics at "
                                 + "runtime: the count is fixed in the source. Pass the real limit, "
                                 + "or remove the call.");
        }
    }
}

public sealed class RustRemainderByOneRule : StructuralRuleBase
{
    public override string Key => "QG-RS-BUG-0129";
    public override string[] Languages => ["rs"];

    public override string Name => "Remainder operations by one should be avoided";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("%" or "%="))
                continue;
            var right = binary.ChildAt(binary.Children.Count > 1 ? 1 : 0);
            if (right?.Kind != NodeKind.NumberLiteral || right.Text.TrimStart('-') != "1")
                continue;
            context.Report(binary, "'value % 1' is always zero and 'value % -1' panics on signed "
                                   + "types: neither can be what the code means. Remove the "
                                   + "operation or compare the value directly.");
        }
    }
}

public sealed class RustDecimalPermissionRule : StructuralRuleBase
{
    public override string Key => "QG-RS-SML-0061";
    public override string[] Languages => ["rs"];

    public override string Name => "Unix file permissions should be set with octal values";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var call in context.Root.OfKind(NodeKind.Invocation))
        {
            if (RustCallName.LastSegment(call) is not ("mode" or "set_mode" or "set_permissions"))
                continue;
            var arguments = call.FirstChild(NodeKind.ArgumentList);
            var first = arguments?.Children.FirstOrDefault();
            if (first?.Kind != NodeKind.NumberLiteral)
                continue;
            var digits = first.Text.TrimEnd('u', 'i', '3', '2', '6', '4');
            if (digits.Length is not (3 or 4) || digits.Any(c => c is < '0' or > '7'))
                continue;
            context.Report(first, $"'{first.Text}' reads as a decimal number here; the permission "
                                  + "it names only matches by accident. Write it as 0o{digits} so "
                                  + "the reader sees the rwx bits.");
        }
    }
}




