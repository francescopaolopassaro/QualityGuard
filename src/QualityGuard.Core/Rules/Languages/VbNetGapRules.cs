using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

public static class VbNetGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new VbRecursiveInheritanceRule(),
        new VbInvalidCastRule(),
        new VbPropertyCollectionCopyRule(),
        new VbAssemblyVersionRule(),
        new VbCustomCryptoRule(),
    ];
}

public abstract class VbGapBase : RuleBase
{
    public override string[] Languages => ["cs", "vb"];
}

public sealed class VbRecursiveInheritanceRule : VbGapBase
{
    public override string Key => "QG-CS-BUG-0119";
    public override string Name => "A type should not derive from itself";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var tokens = type.Tokens.Select(t => t.Text).ToList();
            var idx = tokens.IndexOf("extends");
            if (idx < 0) idx = tokens.IndexOf(":");
            if (idx < 0 || idx + 1 >= tokens.Count) continue;
            if (!tokens[idx + 1].Equals(type.Text, StringComparison.OrdinalIgnoreCase)) continue;
            context.Report(type, "'" + type.Text + "' derives from itself: no instance can be built.");
        }
    }
}

public sealed class VbInvalidCastRule : VbGapBase
{
    public override string Key => "QG-CS-SML-0382";
    public override string Name => "Casting between unrelated types is always wrong";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var cast in context.Root.OfKind(NodeKind.Cast))
        {
            var operand = cast.ChildAt(1) ?? cast.ChildAt(0);
            if (operand?.Kind == NodeKind.StringLiteral && cast.Text != "string"
                && cast.Text != "object")
                context.Report(cast, "Casting a string literal to '" + cast.Text + "' always fails: "
                                     + "use Convert or Parse.");
        }
    }
}

public sealed class VbPropertyCollectionCopyRule : VbGapBase
{
    public override string Key => "QG-CS-SML-0399";
    public override string Name => "Properties should not return a copy of a collection field";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    private static string Simple(string? dotted) =>
        (dotted ?? "").Split('.').LastOrDefault() ?? "";

    public override void Execute(IRuleContext context)
    {
        foreach (var prop in context.Root.OfKind(NodeKind.PropertyDeclaration))
        {
            foreach (var creation in prop.OfKind(NodeKind.ObjectCreation))
            {
                if (Simple(creation.Text) is not ("List" or "Dictionary" or "HashSet")) continue;
                var arg = creation.FirstChild(NodeKind.ArgumentList)?.Children.FirstOrDefault();
                if (arg?.Kind != NodeKind.Identifier) continue;
                context.Report(creation, "This property allocates on every read: callers who cache "
                                         + "see stale data after the next call. Return a "
                                         + "ReadOnlyCollection instead.");
            }
        }
    }
}

public sealed class VbAssemblyVersionRule : VbGapBase
{
    public override string Key => "QG-CS-SML-0424";
    public override string Name => "Assemblies should declare version information";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        if (!context.File.FileName.Contains("AssemblyInfo", StringComparison.OrdinalIgnoreCase))
            return;
        if (context.File.Content.Contains("AssemblyVersion(")) return;
        context.Report("No AssemblyVersion declared: builds without one cannot be tracked.");
    }
}

public sealed class VbCustomCryptoRule : VbGapBase
{
    public override string Key => "QG-CS-SEC-0084";
    public override string Name => "Custom cryptographic algorithms should not be invented";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "60min";

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!type.Text.Contains("Crypt", StringComparison.OrdinalIgnoreCase)
                && !type.Text.Contains("Cipher", StringComparison.OrdinalIgnoreCase))
                continue;
            var usesStandard = type.OfKind(NodeKind.Invocation).Any(i =>
                Simple(i.Text).Contains("Aes") || Simple(i.Text).Contains("Rijndael")
                || Simple(i.Text).Contains("SHA") || Simple(i.Text).Contains("MD5"));
            if (usesStandard) continue;
            var hasXor = type.OfKind(NodeKind.Binary).Any(b => b.Text == "^");
            if (!hasXor) continue;
            context.Report(type, "'" + type.Text + "' implements its own cipher with XOR: custom "
                                 + "cryptography is always weaker than the platform's audited "
                                 + "primitives. Use System.Security.Cryptography.");
        }
    }

    private static string Simple(string? dotted) =>
        (dotted ?? "").Split('.').LastOrDefault() ?? "";
}
