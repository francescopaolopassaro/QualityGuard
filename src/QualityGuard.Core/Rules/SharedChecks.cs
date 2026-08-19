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
        new TooManyBranchesRuleRuby(),
        new NullInsteadOfEmptyRuleCs(),
        new ConstructorCallsOverridableRuleCs(), new ConstructorCallsOverridableRuleJava(),
        new DebugFeatureRuleKotlin(), new DebugFeatureRulePhp(),
        new DatabasePasswordRulePhp(), new HostnameVerificationRulePhp()
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

/// <summary>
/// A method that answers with nothing where the caller expects a collection. Every call site then has
/// to remember the special case, and the one that forgets fails at run time rather than at the point
/// where the decision was made.
/// </summary>
public abstract class NullInsteadOfEmptyRule : StructuralRuleBase
{
    private static readonly string[] Collections =
        ["List", "IList", "IEnumerable", "ICollection", "IReadOnlyList", "IReadOnlyCollection",
         "Array", "Dictionary", "IDictionary", "HashSet", "ISet", "Queue", "Stack", "Collection"];

    public override string Name => "A method that returns a collection should return an empty one, not nothing";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var returned = method.FirstChild(NodeKind.TypeReference)?.Text ?? string.Empty;
            if (returned.Length == 0)
                continue;
            var bare = returned.TrimEnd('?').Split('<')[0].Split('[')[0];
            if (!Collections.Contains(bare, StringComparer.Ordinal) && !returned.EndsWith("[]", StringComparison.Ordinal))
                continue;
            // a signature that says it may answer with nothing has made the decision on purpose, and
            // every caller has been told
            if (returned.EndsWith('?'))
                continue;

            var nulls = method.OfKind(NodeKind.Jump)
                .Where(j => j.Text == "return"
                            && j.ChildAt(0) is { Kind: NodeKind.NullLiteral or NodeKind.Identifier } value
                            && value.Text is "null" or "None" or "nil")
                .ToList();
            if (nulls.Count == 0)
                continue;

            context.Report(nulls[0], $"'{method.Text}' promises a collection and answers with nothing "
                                     + "on this path. Every caller now needs a check before the loop, "
                                     + "and the one that forgets fails where the collection is used "
                                     + "instead of here. Return an empty collection.");
        }
    }
}

public sealed class NullInsteadOfEmptyRuleCs : NullInsteadOfEmptyRule
{
    public override string Key => "QG-CS-SML-0095";
    public override string[] Languages => ["cs", "vb"];
}

/// <summary>
/// A constructor that calls something a subclass can replace. The replacement runs while the object
/// is half-built: its own fields are not assigned yet, and nothing in either file says so.
/// </summary>
public abstract class ConstructorCallsOverridableRule : StructuralRuleBase
{
    public override string Name => "A constructor should not call a method a subclass can replace";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var modifiers = type.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            // a type nobody can derive from cannot be surprised this way
            if (modifiers.Contains("sealed") || modifiers.Contains("final") || modifiers.Contains("static"))
                continue;

            // the members of this type that a subclass is allowed to replace
            var overridable = type.OfKind(NodeKind.FunctionDeclaration)
                .Where(m => m.Ancestor(NodeKind.ClassDeclaration) == type)
                .Where(m => m.ChildrenOf(NodeKind.Modifier).Select(x => x.Text)
                    .Any(x => x is "virtual" or "abstract" or "override" or "open"))
                .Select(m => m.Text)
                .ToHashSet(StringComparer.Ordinal);
            if (overridable.Count == 0)
                continue;

            foreach (var constructor in type.OfKind(NodeKind.ConstructorDeclaration))
            {
                foreach (var call in constructor.OfKind(NodeKind.Invocation))
                {
                    var name = SyntaxQuery.InvokedName(call);
                    if (!overridable.Contains(name))
                        continue;
                    var receiver = SyntaxQuery.Receiver(call);
                    if (receiver.Length > 0 && receiver != "this")
                        continue; // a call on another object is that object's business

                    context.Report(call, $"'{name}' can be replaced by a subclass, and this call runs "
                                         + "while the object is still being built: the replacement "
                                         + "sees fields that have not been assigned yet. The failure "
                                         + "appears in the subclass, which did nothing wrong.");
                    break;
                }
            }
        }
    }
}

public sealed class ConstructorCallsOverridableRuleCs : ConstructorCallsOverridableRule
{
    public override string Key => "QG-CS-SML-0115";
    public override string[] Languages => ["cs", "vb"];
}

public sealed class ConstructorCallsOverridableRuleJava : ConstructorCallsOverridableRule
{
    public override string Key => "QG-JV-SML-0121";
    public override string[] Languages => ["java"];
}

/// <summary>
/// Something left on that only belongs on a developer's machine: a debug flag, a stack trace shown to
/// the caller, a console that answers over the network. Each one hands an attacker the map.
/// </summary>
public abstract class DebugFeatureRule : RuleBase
{
    /// <summary>Settings whose value being on is the defect.</summary>
    private static readonly string[] SwitchedOn =
        ["debug", "isDebuggable", "debuggable", "display_errors", "WebContentsDebuggingEnabled",
         "setWebContentsDebuggingEnabled", "APP_DEBUG"];

    public override string Name => "Debugging features should not be left on";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice =>
        "Drive the setting from configuration and keep it off wherever the application is reachable by somebody else.";

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            if (!SwitchedOn.Contains(tokens[i].Text, StringComparer.OrdinalIgnoreCase))
                continue;
            // 'debug = true', 'setWebContentsDebuggingEnabled(true)', "display_errors" => "1"
            var next = tokens[i + 1].Text;
            if (next is not ("=" or "(" or ":" or "=>" or ","))
                continue;
            var value = tokens[i + 2].Text.Trim('"', '\'');
            if (value is not ("true" or "True" or "on" or "On" or "1" or "yes"))
                continue;

            context.Report($"'{tokens[i].Text}' is switched on here. In anything reachable by somebody "
                           + "else that means stack traces, internal paths and often a console: the "
                           + "map an attacker would otherwise have to guess at.", tokens[i].Line);
        }
    }
}

public sealed class DebugFeatureRuleKotlin : DebugFeatureRule
{
    public override string Key => "QG-KT-SEC-0040";
    public override string[] Languages => ["kt"];
}

public sealed class DebugFeatureRulePhp : DebugFeatureRule
{
    public override string Key => "QG-PP-SEC-0051";
    public override string[] Languages => ["php"];
}

/// <summary>A database reached with no password at all, or with one everybody already knows.</summary>
public abstract class DatabasePasswordRule : RuleBase
{
    private static readonly string[] Known = ["root", "admin", "password", "123456", "changeme", "test"];

    public override string Name => "A database connection needs a password worth having";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice =>
        "Give the account a generated password, keep it in configuration the deployment supplies, and rotate the one that has been committed.";

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            var name = tokens[i].Text.Trim('"', '\'', '$');
            if (!name.Equals("password", StringComparison.OrdinalIgnoreCase)
                && !name.Equals("passwd", StringComparison.OrdinalIgnoreCase)
                && !name.Equals("pwd", StringComparison.OrdinalIgnoreCase))
                continue;
            if (tokens[i + 1].Text is not ("=" or ":" or "=>" or ","))
                continue;

            var value = tokens[i + 2];
            if (value.Kind != Tokenization.TokenKind.String)
                continue;
            var text = value.Text.Trim();
            var weak = text.Length == 0 || Known.Contains(text, StringComparer.OrdinalIgnoreCase);
            if (!weak)
                continue;

            context.Report(text.Length == 0
                    ? "The connection is opened with an empty password, so anyone who can reach the "
                      + "database is already inside it. Network rules are then the only thing between "
                      + "the data and whoever finds the port."
                    : $"'{text}' is one of the first passwords anything scanning this port will try. "
                      + "It is not a placeholder to an attacker; it is a working credential.",
                value.Line);
        }
    }
}

public sealed class DatabasePasswordRulePhp : DatabasePasswordRule
{
    public override string Key => "QG-PP-SEC-0036";
    public override string[] Languages => ["php"];
}

/// <summary>
/// Certificate checking turned off. The connection is still encrypted, which is what makes this hard
/// to see: it is encrypted to whoever answered.
/// </summary>
public abstract class HostnameVerificationRule : RuleBase
{
    public override string Name => "The certificate of the other side has to be checked";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice =>
        "Leave verification on and install the certificate authority the environment needs, rather than turning the check off.";

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            var setting = tokens[i].Text.Trim('"', '\'');
            var verifying = setting is "CURLOPT_SSL_VERIFYPEER" or "CURLOPT_SSL_VERIFYHOST"
                or "verify_peer" or "verify_peer_name" or "verify";
            if (!verifying)
                continue;
            if (tokens[i + 1].Text is not ("," or "=>" or "=" or ":"))
                continue;
            var value = tokens[i + 2].Text.Trim('"', '\'');
            if (value is not ("false" or "False" or "0" or "off"))
                continue;

            context.Report($"'{setting}' is turned off, so the connection accepts any certificate at "
                           + "all. It is still encrypted — to whoever answered, which may be somebody "
                           + "sitting between the two ends reading everything in both directions.",
                tokens[i].Line);
        }
    }
}

public sealed class HostnameVerificationRulePhp : HostnameVerificationRule
{
    public override string Key => "QG-PP-SEC-0055";
    public override string[] Languages => ["php"];
}
