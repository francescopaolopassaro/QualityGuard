using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Checks that read the same way in every language, written once and given an identifier per
/// language. What makes them worth having is not the shape they look for — that part is easy — but
/// the list of things they must stay quiet about, which only shows up on real code.
/// </summary>
public static class SharedCheckSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new HardcodedIpRuleCs(), new HardcodedIpRuleJava(), new HardcodedIpRuleKotlin(),
        new HardcodedIpRulePhp(), new HardcodedIpRulePython(), new HardcodedIpRuleRuby(),
        new LoopCounterNotUpdatedRuleCs(), new LoopCounterNotUpdatedRuleJava(),
        new ForWithoutCounterRuleCs(), new ForWithoutCounterRuleJava(), new ForWithoutCounterRulePhp(),
        new ArrayHashCodeRuleKotlin(),
        new EqualsWithoutTypeTestRuleKotlin(),
        new TooManyBranchesRuleKotlin(), new TooManyBranchesRulePhp(), new TooManyBranchesRuleGo(),
        new TooManyBranchesRuleRuby()
    ];
}

/// <summary>
/// An address written into the source. Deployment moves, environments differ, and the value that was
/// right when it was typed is the one thing a build cannot change.
/// </summary>
public abstract class HardcodedIpRule : RuleBase
{
    /// <summary>
    /// Addresses that are not a deployment decision: the loopback, the broadcast, the unspecified
    /// address, the ranges reserved for documentation, and the prefix that belongs to object
    /// identifiers rather than to networking. Every one of these was a false positive somewhere.
    /// </summary>
    private static readonly string[] NotADeploymentChoice =
        ["127.", "2.5.", "192.0.2.", "198.51.100.", "203.0.113.", "255.255.255.255", "0.0.0.0"];

    public override string Name => "IP addresses should not be written into the source";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice =>
        "Read the address from configuration the deployment supplies, and keep a default only where it is documentation.";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (token.Kind != Tokenization.TokenKind.String)
                continue;
            var address = AddressOf(token.Text);
            if (address == null)
                continue;

            context.Report($"'{address}' is fixed in the source, so moving the service means changing "
                           + "the code and shipping a build. Read it from configuration instead.",
                token.Line);
        }
    }

    /// <summary>
    /// The address a literal consists of, when the whole literal is one — optionally as a URL with a
    /// port and a path. A number that merely appears inside a sentence is a version, an identifier or
    /// a piece of prose, and reading those as addresses is how this rule goes wrong.
    /// </summary>
    private static string? AddressOf(string literal)
    {
        var text = literal.Trim();
        if (text.Length is < 7 or > 120)
            return null;

        // strip a scheme and a path so 'http://10.0.0.8:8080/health' is read as its address
        var scheme = text.IndexOf("//", StringComparison.Ordinal);
        if (scheme >= 0)
            text = text[(scheme + 2)..];
        var slash = text.IndexOf('/');
        if (slash >= 0)
            text = text[..slash];
        var colon = text.IndexOf(':');
        if (colon >= 0)
            text = text[..colon];

        var parts = text.Split('.');
        if (parts.Length != 4)
            return null;
        foreach (var part in parts)
        {
            if (part.Length is 0 or > 3 || !part.All(char.IsAsciiDigit))
                return null;
            // '01.02.03.04' is a version or a date, not an address: a real octet has no leading zero
            if (part.Length > 1 && part[0] == '0')
                return null;
            if (int.Parse(part) > 255)
                return null;
        }
        return NotADeploymentChoice.Any(e => text.StartsWith(e, StringComparison.Ordinal)) ? null : text;
    }
}

public sealed class HardcodedIpRuleCs : HardcodedIpRule
{
    public override string Key => "QG-CS-SML-0106";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class HardcodedIpRuleJava : HardcodedIpRule
{
    public override string Key => "QG-JV-SML-0094";
    public override string[] Languages => ["java"];
}

public sealed class HardcodedIpRuleKotlin : HardcodedIpRule
{
    public override string Key => "QG-KT-SML-0029";
    public override string[] Languages => ["kt"];
}

public sealed class HardcodedIpRulePhp : HardcodedIpRule
{
    public override string Key => "QG-PP-SML-0031";
    public override string[] Languages => ["php"];
}

public sealed class HardcodedIpRulePython : HardcodedIpRule
{
    public override string Key => "QG-PY-SML-0038";
    public override string[] Languages => ["py"];
}

public sealed class HardcodedIpRuleRuby : HardcodedIpRule
{
    public override string Key => "QG-RB-SML-0014";
    public override string[] Languages => ["rb"];
}

/// <summary>
/// A counting loop whose update touches something other than the name it tests. The loop then either
/// never ends or ends for a reason the header does not state.
/// </summary>
public abstract class LoopCounterNotUpdatedRule : StructuralRuleBase
{
    public override string Name => "The update of a loop should move the value its condition tests";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (loop.Text != "for")
                continue;
            var parts = loop.Children.Where(c => c.Kind != NodeKind.Block).ToList();
            if (parts.Count != 3)
                continue; // only the three-part form states a counter at all

            var tested = parts[1].OfKind(NodeKind.Identifier).Select(i => i.Text).ToHashSet(StringComparer.Ordinal);
            var updated = parts[2].OfKind(NodeKind.Identifier).Select(i => i.Text).ToHashSet(StringComparer.Ordinal);
            if (tested.Count == 0 || updated.Count == 0 || tested.Overlaps(updated))
                continue;
            // the body may well move the counter itself, which is a legitimate way to write the loop
            var body = loop.FirstChild(NodeKind.Block);
            if (body != null && body.OfKind(NodeKind.Identifier).Any(i => tested.Contains(i.Text)
                                                                         && IsWritten(i)))
                continue;

            context.Report(loop, $"The condition tests '{string.Join("', '", tested)}' and the update "
                                 + $"moves '{string.Join("', '", updated)}'. Nothing brings the loop "
                                 + "closer to ending, so it runs until something inside it breaks out "
                                 + "— or it does not.");
        }
    }

    private static bool IsWritten(SyntaxNode identifier)
    {
        var parent = identifier.Parent;
        if (parent is { Kind: NodeKind.Unary } && parent.Text is "++" or "--")
            return true;
        return parent is { Kind: NodeKind.Assignment } && parent.ChildAt(0) == identifier;
    }
}

public sealed class LoopCounterNotUpdatedRuleCs : LoopCounterNotUpdatedRule
{
    public override string Key => "QG-CS-SML-0122";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class LoopCounterNotUpdatedRuleJava : LoopCounterNotUpdatedRule
{
    public override string Key => "QG-JV-SML-0138";
    public override string[] Languages => ["java"];
}

/// <summary>
/// A three-part loop with neither a start nor a step: everything it does is test a condition, which
/// is what a while loop says in fewer characters and no ceremony.
/// </summary>
public abstract class ForWithoutCounterRule : StructuralRuleBase
{
    public override string Name => "A loop that only tests a condition should be written as a while";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (loop.Text != "for")
                continue;
            // An empty clause leaves no node at all, so the shape is read from the header: the three
            // part form is the one with two semicolons, and only the condition is left in the tree.
            var header = context.Tokens
                .Where(t => t.Line >= loop.Range.StartLine && t.Line <= loop.Range.StartLine)
                .SkipWhile(t => t.Text != "for")
                .TakeWhile(t => t.Text != "{")
                .ToList();
            if (header.Count(t => t.Text == ";") != 2)
                continue;
            var parts = loop.Children.Where(c => c.Kind != NodeKind.Block).ToList();
            if (parts.Count != 1)
                continue; // something is declared or stepped, so the loop counts after all

            context.Report(loop, "This loop declares nothing and steps nothing: the only part of it "
                                 + "that does anything is the condition. A while loop says the same "
                                 + "thing without the two empty clauses a reader has to check.");
        }
    }

}

public sealed class ForWithoutCounterRuleCs : ForWithoutCounterRule
{
    public override string Key => "QG-CS-SML-0101";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class ForWithoutCounterRuleJava : ForWithoutCounterRule
{
    public override string Key => "QG-JV-SML-0087";
    public override string[] Languages => ["java"];
}

public sealed class ForWithoutCounterRulePhp : ForWithoutCounterRule
{
    public override string Key => "QG-PP-SML-0027";
    public override string[] Languages => ["php"];
}

/// <summary>
/// An array answers these two from the object it is, not from what it holds: the hash is its
/// identity and the text is its type name. Both read as if they described the contents.
/// </summary>
public abstract class ArrayHashCodeRule : StructuralRuleBase
{
    public override string Name => "The identity of an array is not the value of its contents";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (name is not ("hashCode" or "toString"))
                continue;
            if (SyntaxQuery.Arguments(call).Count > 0)
                continue;
            var receiver = call.ChildAt(0)?.ChildAt(0);
            var type = receiver == null ? null : context.Types.TypeOf(receiver);
            if (type == null || !context.Types.IsKnownType(type))
                continue;
            if (!type.EndsWith("Array", StringComparison.Ordinal) && !type.EndsWith("[]", StringComparison.Ordinal))
                continue;

            context.Report(call, $"'{name}' on an array answers about the array object, not about what "
                                 + "it holds: two arrays with the same elements give different answers, "
                                 + "and the text is the type name rather than the contents. Use the "
                                 + "helper that reads the elements.");
        }
    }
}

public sealed class ArrayHashCodeRuleKotlin : ArrayHashCodeRule
{
    public override string Key => "QG-KT-BUG-0016";
    public override string[] Languages => ["kt"];
}

/// <summary>
/// Equality that never asks what it was given. The argument arrives as the most general type there
/// is, so a comparison written without a type test either throws when something else is passed or —
/// worse — answers true for an object that merely happens to have the same fields.
/// </summary>
public abstract class EqualsWithoutTypeTestRule : StructuralRuleBase
{
    /// <summary>
    /// The four ways a type test is written. The rule reports only when none of them appears: the
    /// reference engine checks exactly these, because each is a legitimate way to answer the question
    /// and a rule that knows only one of them reports correct code.
    /// </summary>
    private static readonly string[] TypeTests = ["is", "instanceof", "as?", "javaClass", "getClass", "::class"];

    public override string Name => "Equality should test the type of what it was given";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (method.Text != "equals")
                continue;
            var parameters = method.FirstChild(NodeKind.ParameterList)?.ChildrenOf(NodeKind.Parameter).ToList();
            if (parameters is not { Count: 1 })
                continue;
            var body = SyntaxQuery.Body(method);
            if (body is not { Children.Count: > 0 })
                continue; // a declaration without a body states a contract and tests nothing

            var tested = context.Tokens.Any(t => t.Line >= body.Range.StartLine
                                                 && t.Line <= body.Range.EndLine
                                                 && TypeTests.Contains(t.Text, StringComparer.Ordinal));
            if (tested)
                continue;
            // 'equals(other) = commonEquals(other)' hands the question to another function, and the
            // test lives there. A body that is one call answers nothing itself, so there is nothing
            // here to report — a multiplatform library writes every equality this way.
            if (Delegates(body))
                continue;

            context.Report(method, "This equality never asks what it was handed. The argument can be "
                                   + "anything, so the comparison either fails at run time or quietly "
                                   + "answers true for an object of another type that happens to line "
                                   + "up. Test the type first and return false when it does not match.");
        }
    }
    /// <summary>Whether the body is a single call, which passes the decision somewhere else.</summary>
    private static bool Delegates(SyntaxNode body)
    {
        var statements = body.Children;
        if (statements.Count != 1)
            return false;
        var only = statements[0];
        var expression = only.Kind == NodeKind.Jump ? only.ChildAt(0) : only.ChildAt(0) ?? only;
        return expression is { Kind: NodeKind.Invocation };
    }
}

public sealed class EqualsWithoutTypeTestRuleKotlin : EqualsWithoutTypeTestRule
{
    public override string Key => "QG-KT-BUG-0014";
    public override string[] Languages => ["kt"];
}

/// <summary>
/// A multi-way branch long enough that nobody reads it to the end. Past a certain number of clauses
/// the structure is a table written as control flow, and the reader has to hold all of it at once.
/// </summary>
public abstract class TooManyBranchesRule : StructuralRuleBase
{
    private const int Limit = 30;

    public override string Name => "A multi-way branch should not grow past what a reader can hold";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var match in context.Root.OfKind(NodeKind.Match))
        {
            var body = match.FirstChild(NodeKind.Block);
            var clauses = (body ?? match).ChildrenOf(NodeKind.SwitchSection).Count();
            if (clauses <= Limit)
                continue;

            context.Report(match, $"This branches {clauses} ways, past the {Limit} a reader can keep "
                                  + "track of. What it really holds is a table: move the mapping into "
                                  + "data, or give each group of cases a name of its own.");
        }
    }
}

public sealed class TooManyBranchesRuleKotlin : TooManyBranchesRule
{
    public override string Key => "QG-KT-SML-0031";
    public override string[] Languages => ["kt"];
}

public sealed class TooManyBranchesRulePhp : TooManyBranchesRule
{
    public override string Key => "QG-PP-SML-0035";
    public override string[] Languages => ["php"];
}

public sealed class TooManyBranchesRuleGo : TooManyBranchesRule
{
    public override string Key => "QG-GO-SML-0014";
    public override string[] Languages => ["go"];
}

public sealed class TooManyBranchesRuleRuby : TooManyBranchesRule
{
    public override string Key => "QG-RB-SML-0017";
    public override string[] Languages => ["rb"];
}
