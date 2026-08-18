using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// JavaScript and TypeScript rules chosen by measurement: each closes a gap that
/// <c>tools/compare_expectations.py</c> found against an annotated reference corpus. Two families
/// dominated that list — assertions that assert nothing, and cloud resources declared in code with
/// their protection left off.
/// </summary>
public static class JsTsMeasuredRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JsIncompleteAssertionRule(),
        new JsDuplicateAssertionArgumentRule(),
        new JsClearTextProtocolRule(),
        new JsWeakTlsVersionRule(),
        new JsCloudResourceWithoutEncryptionRule(),
        new JsCloudResourcePubliclyReachableRule(),
        new JsWildcardPolicyRule(),
        new JsRelativeCommandPathRule(),
        new JsTestHookOrderRule(),
        new JsMemoizeWithoutKeyRule(),
        new JsUncertainAssertionRule(),
        new JsReplaceAllRule(),
        new JsCodeAfterDoneRule(),
        new JsFunctionScopedDeclarationRule()
    ];
}

public abstract class JsTsMeasuredRuleBase : RuleBase
{
    public override string[] Languages => ["js", "ts"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>
    /// Object creations, in both shapes JavaScript produces: a real ObjectCreation and the unary
    /// "new" the parser builds over a call.
    /// </summary>
    protected static IEnumerable<(SyntaxNode Node, string Type)> Constructions(SyntaxNode root)
    {
        foreach (var creation in root.OfKind(NodeKind.ObjectCreation))
            yield return (creation, creation.Text);

        foreach (var unary in root.OfKind(NodeKind.Unary))
        {
            if (unary.Text != "new")
                continue;
            var target = unary.ChildAt(0);
            if (target == null)
                continue;
            var name = target.Kind == NodeKind.Invocation
                ? SyntaxQuery.InvokedName(target)
                : SyntaxQuery.SimpleName(target);
            if (name.Length > 0)
                yield return (unary, name);
        }
    }

    /// <summary>The source of a construction, used to read the options object it was given.</summary>
    protected static string Text(IRuleContext context, SyntaxNode node)
    {
        var lines = LanguageRuleSupport.Lines(context);
        var from = Math.Max(0, node.Range.StartLine - 1);
        var to = Math.Min(lines.Length - 1, node.Range.EndLine - 1);
        if (from > to)
            return string.Empty;
        return string.Join('\n', lines[from..(to + 1)]);
    }
}

public sealed class JsIncompleteAssertionRule : JsTsMeasuredRuleBase
{
    private static readonly string[] AssertionRoots = ["assert", "expect", "should", "chai"];

    /// <summary>
    /// Words that only join one part of a chained assertion to the next. A statement that ends on one
    /// of them has read a property and asserted nothing.
    /// </summary>
    private static readonly HashSet<string> Connectors = new(StringComparer.Ordinal)
    {
        "to", "be", "been", "is", "that", "which", "and", "has", "have", "with", "at", "of", "same",
        "but", "does", "still", "not", "deep", "nested", "own", "ordered", "any", "all", "itself",
        "also", "another"
    };

    /// <summary>
    /// Matchers that assert only when they are called. Their siblings that assert as a plain property
    /// read — 'true', 'ok', 'empty' and the rest — are deliberately absent: reading those is correct.
    /// </summary>
    private static readonly HashSet<string> CallableMatchers = new(StringComparer.Ordinal)
    {
        "fail", "a", "an", "include", "includes", "contain", "contains", "equal", "equals", "eq",
        "eql", "eqls", "above", "gt", "greaterThan", "least", "gte", "below", "lt", "lessThan",
        "most", "lte", "within", "instanceof", "instanceOf", "property", "ownPropertyDescriptor",
        "haveOwnPropertyDescriptor", "lengthOf", "length", "match", "matches", "string", "key",
        "keys", "throw", "throws", "Throw", "respondTo", "respondsTo", "satisfy", "satisfies",
        "closeTo", "approximately", "members", "oneOf", "change", "changes", "increase", "increases",
        "decrease", "decreases", "by"
    };

    public override string Key => "QG-JS-BUG-0143";
    public override string Name => "An assertion should be called";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var statement in context.Root.OfKind(NodeKind.ExpressionStatement))
        {
            if (statement.Children.Count != 1)
                continue;
            var expression = statement.Children[0];

            // 'assert.fail;' and 'expect(x).to.throw;' — a property read that asserts nothing
            if (expression.Kind == NodeKind.MemberSelect)
            {
                var dotted = SyntaxQuery.DottedName(expression);
                var last = dotted.Split('.').LastOrDefault() ?? string.Empty;
                var connector = Connectors.Contains(last);
                if (!connector && !CallableMatchers.Contains(last))
                    continue;
                if (!AssertionRoots.Any(r => dotted.StartsWith(r + ".", StringComparison.Ordinal))
                    && !expression.DescendantsAndSelf().Any(
                        n => n.Kind == NodeKind.Invocation
                             && AssertionRoots.Contains(SyntaxQuery.InvokedName(n), StringComparer.Ordinal)))
                    continue;

                context.Report(connector
                    ? $"'{last}' only joins one part of the chain to the next, so this statement reads "
                      + "a property and asserts nothing. The test passes whatever happened. Finish the "
                      + "assertion."
                    : $"'{last}' is read and never called, so this line checks nothing and the test "
                      + "passes whatever happened. Call the assertion.",
                    statement.Range.StartLine);
                continue;
            }

            // 'expect(value);' — the subject is stated and no matcher follows
            if (expression.Kind != NodeKind.Invocation)
                continue;
            if (SyntaxQuery.InvokedName(expression) is not ("expect" or "should"))
                continue;
            // '.expect(302, done)' at the end of a chain is the matcher, not a subject left bare:
            // that is how supertest writes every assertion, and a whole test suite was reported.
            if (SyntaxQuery.InvokedDottedName(expression).Contains('.'))
                continue;
            // 'expect(value)' with nothing after it is the defect; 'expect(value).toBe(1)' is not,
            // and there the outermost call is 'toBe', so only a bare subject reaches this point.
            if (SyntaxQuery.Arguments(expression).Count > 1)
                continue;

            context.Report("The subject of the assertion is stated and nothing is asserted about it, "
                           + "so the line passes for every value. Add the matcher.",
                statement.Range.StartLine);
        }
    }
}

public sealed class JsDuplicateAssertionArgumentRule : JsTsMeasuredRuleBase
{
    public override string Key => "QG-JS-BUG-0144";
    public override string Name => "An assertion should compare two different things";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var chain = call.Text.Split('.');
            var arguments = SyntaxQuery.Arguments(call).ToList();

            // 'expect(subject).matcher(a, b)' — the subject is one of the things being compared
            if (chain.Length > 1 && chain[0] == "expect" && Subject(call) is { } subject)
                arguments.Insert(0, subject);
            else if (chain[0] != "assert")
                continue;
            if (arguments.Count < 2)
                continue;

            for (var i = 0; i < arguments.Count; i++)
            for (var j = i + 1; j < arguments.Count; j++)
            {
                var written = Normalised(arguments[i]);
                if (written.Length == 0 || written != Normalised(arguments[j]))
                    continue;

                context.Report($"Two parts of this assertion are '{written}', so it holds whatever the "
                               + "code under test did. One of the two was meant to be the expected "
                               + "value.", call.Range.StartLine);
                i = arguments.Count;
                break;
            }
        }
    }

    /// <summary>The value an 'expect(...)' chain is asserting about.</summary>
    private static SyntaxNode? Subject(SyntaxNode call)
    {
        foreach (var inner in call.OfKind(NodeKind.Invocation))
        {
            if (SyntaxQuery.InvokedName(inner) != "expect")
                continue;
            return SyntaxQuery.ArgumentAt(inner, 0);
        }
        return null;
    }

    /// <summary>
    /// The argument as written, without its spacing, so '1 + 1' and '1+1' are recognised as the same
    /// text. A plain literal returns nothing: asserting that 42 equals 42 is a deliberate constant
    /// check, and the message an assertion carries is a literal too.
    /// </summary>
    private static string Normalised(SyntaxNode argument)
    {
        if (argument.Kind is NodeKind.StringLiteral or NodeKind.NumberLiteral or NodeKind.BooleanLiteral)
            return string.Empty;
        if (argument.Tokens.Count is 0 or > 60)
            return string.Empty;
        // a string token carries its text without the quotes, so "1" and 1 would compare equal:
        // the kind has to travel with the text
        return string.Concat(argument.Tokens.Select(
            t => t.Kind == TokenKind.String ? "'" + t.Text + "'" : t.Text));
    }
}

public sealed class JsClearTextProtocolRule : JsTsMeasuredRuleBase
{
    private static readonly string[] Insecure = ["http://", "ftp://", "telnet://"];

    /// <summary>Protocols named in the options of a listener, with no TLS underneath them.</summary>
    private static readonly string[] PlainProtocols =
    [
        "LoadBalancingProtocol.TCP", "LoadBalancingProtocol.HTTP", "ApplicationProtocol.HTTP",
        "Protocol.TCP", "protocol:'TCP'", "protocol:'tcp'", "protocol:'HTTP'", "protocol:'http'",
        "protocol:\"TCP\"", "protocol:\"tcp\"", "protocol:\"HTTP\"", "protocol:\"http\""
    ];

    public override string Key => "QG-JS-SEC-0080";
    public override string Name => "Traffic should not travel in cleartext";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        // a fixture reaching a test server over plain HTTP is not shipping anything in the clear
        if (LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
            return;

        foreach (var token in context.Tokens)
        {
            if (token.Kind != TokenKind.String)
                continue;
            if (!CleartextProtocols.IsExposedAddress(token.Text, out var scheme, out var instead))
                continue;
            context.Report(CleartextProtocols.Advice(scheme, instead), token.Line);
        }

        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Replace(" ", string.Empty);
            var comment = line.IndexOf("//", StringComparison.Ordinal);
            if (comment >= 0)
                line = line[..comment];

            if (Disabled(line, "transitEncryptionEnabled") || Disabled(line, "atRestEncryptionEnabled"))
            {
                context.Report("Transit encryption is switched off here, so the traffic between the "
                               + "cluster and whatever talks to it travels readable across the "
                               + "network. Turn it on.", i + 1);
                continue;
            }

            if (line.Contains("StreamEncryption.UNENCRYPTED", StringComparison.Ordinal))
            {
                context.Report("The stream is declared unencrypted, so every record in it is written "
                               + "and read in the clear. Choose a managed or a customer key.", i + 1);
                continue;
            }

            var plain = PlainProtocols.FirstOrDefault(p => line.Contains(p, StringComparison.Ordinal));
            if (plain == null)
                continue;

            context.Report($"'{plain}' puts the listener on a protocol with nothing underneath it, so "
                           + "everything it carries — credentials included — crosses the network "
                           + "readable. Terminate TLS on the listener.", i + 1);
        }
    }

    /// <summary>A property written as switched off, or written as nothing at all.</summary>
    private static bool Disabled(string line, string property)
        => line.Contains($"{property}:false", StringComparison.Ordinal)
           || line.Contains($"{property}:undefined", StringComparison.Ordinal)
           || line.Contains($"'{property}':false", StringComparison.Ordinal)
           || line.Contains($"'{property}':undefined", StringComparison.Ordinal);
}

public sealed class JsWeakTlsVersionRule : JsTsMeasuredRuleBase
{
    private static readonly string[] Obsolete =
    [
        "TLSv1_method", "TLSv1_1_method", "SSLv2_method", "SSLv3_method", "SSLv23_method",
        "TLSv1", "TLSv1.1", "SSLv3"
    ];

    public override string Key => "QG-JS-SEC-0081";
    public override string Name => "An obsolete TLS version should not be selected";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!line.Contains("secureProtocol", StringComparison.Ordinal)
                && !line.Contains("minVersion", StringComparison.Ordinal)
                && !line.Contains("maxVersion", StringComparison.Ordinal))
                continue;
            var version = Obsolete.FirstOrDefault(v => line.Contains($"'{v}'", StringComparison.Ordinal)
                                                       || line.Contains($"\"{v}\"", StringComparison.Ordinal));
            if (version == null)
                continue;

            context.Report($"'{version}' has published attacks against it, and a connection that offers "
                           + "it can be pushed down onto it. Ask for TLS 1.2 at the lowest, and let "
                           + "the library negotiate above it.", i + 1);
        }
    }
}

public sealed class JsCloudResourceWithoutEncryptionRule : JsTsMeasuredRuleBase
{
    /// <summary>Resource types declared in code, with the property that turns their encryption on.</summary>
    private static readonly Dictionary<string, string> EncryptionProperty = new(StringComparer.Ordinal)
    {
        ["CfnDBCluster"] = "storageEncrypted",
        ["CfnDBInstance"] = "storageEncrypted",
        ["CfnVolume"] = "encrypted",
        ["CfnFileSystem"] = "encrypted",
        ["CfnQueue"] = "kmsMasterKeyId",
        ["CfnTopic"] = "kmsMasterKeyId",
        ["CfnDomain"] = "encryptionAtRestOptions",
        ["CfnBucket"] = "bucketEncryption",
        ["CfnReplicationGroup"] = "atRestEncryptionEnabled",
        ["CfnCluster"] = "encrypted",
        ["CfnStream"] = "streamEncryption"
    };

    public override string Key => "QG-JS-SEC-0082";
    public override string Name => "A stored resource should be encrypted";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        var known = BooleanConstants(context);
        foreach (var (node, type) in Constructions(context.Root))
        {
            if (!EncryptionProperty.TryGetValue(type, out var property))
                continue;
            var written = Text(context, node);
            var value = PropertyValue(written, property);

            if (value == null)
            {
                // The options may be a name, and then the property cannot be seen from here. Saying
                // "not set" would be guessing: the engine answers "cannot tell" by staying silent.
                if (OptionsAreComputed(written))
                    continue;
                context.Report($"'{property}' is not set, and the default is no encryption. The data "
                               + "is written to disk in the clear, and a snapshot or a backup carries "
                               + "it that way too.", node.Range.StartLine);
                continue;
            }

            var off = value == "false" || (known.TryGetValue(value, out var constant) && !constant);
            if (!off)
                continue;

            context.Report($"'{property}' is switched off, so the data is written to disk in the clear "
                           + "and anyone who reaches the storage — a snapshot, a backup, a "
                           + "decommissioned volume — reads it.", node.Range.StartLine);
        }
    }

    /// <summary>
    /// The value written for a property in an options literal, or null when the property is absent.
    /// The options are read as source because they are a literal written on the spot, and the
    /// interesting part of them is one word long.
    /// </summary>
    private static string? PropertyValue(string written, string property)
    {
        var at = written.IndexOf(property + ":", StringComparison.Ordinal);
        if (at < 0)
        {
            at = written.IndexOf(property + " :", StringComparison.Ordinal);
            if (at < 0)
                return null;
        }
        var rest = written[(written.IndexOf(':', at) + 1)..];
        var stop = rest.IndexOfAny([',', '}', ')']);
        return (stop < 0 ? rest : rest[..stop]).Trim();
    }

    /// <summary>
    /// The file's constants that hold a plain true or false, so a property given one of them by name
    /// can still be judged. Anything else stays unknown.
    /// </summary>
    private static Dictionary<string, bool> BooleanConstants(IRuleContext context)
    {
        var found = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var declaration in context.Root.OfKind(NodeKind.VariableDeclaration))
        {
            var initial = declaration.ChildAt(0);
            if (initial is { Kind: NodeKind.Assignment })
                initial = initial.ChildAt(1);
            if (initial == null)
                continue;
            var text = initial.Text;
            if (text is not ("true" or "false"))
                continue;
            found[declaration.Text] = text == "true";
        }
        return found;
    }

    /// <summary>
    /// Whether the construction was given its options as something other than a literal. Everything
    /// after the last comma is read: an object literal shows a brace, an omitted or empty one shows
    /// nothing to read, and a name shows a name.
    /// </summary>
    private static bool OptionsAreComputed(string written)
    {
        var open = written.IndexOf('(');
        if (open < 0)
            return false;
        var arguments = written[(open + 1)..];
        var lastComma = arguments.LastIndexOf(',');
        if (lastComma < 0)
            return false; // fewer than two arguments: the options really are missing

        var options = arguments[(lastComma + 1)..].Trim().TrimEnd(')', ';').Trim();
        if (options.Length == 0 || options is "undefined" or "null" or "{}")
            return false;
        return !options.StartsWith('{');
    }

}

public sealed class JsCloudResourcePubliclyReachableRule : JsTsMeasuredRuleBase
{
    private static readonly string[] PublicFlags =
    [
        "publiclyAccessible: true", "publicReadAccess: true", "publicWriteAccess: true",
        "publiclyAccessible:true", "publicReadAccess:true", "anonymousAccess: true"
    ];

    private static readonly string[] OpenRanges = ["0.0.0.0/0", "::/0"];

    public override string Key => "QG-JS-SEC-0083";
    public override string Name => "A resource should not be reachable from the whole internet";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var flag = PublicFlags.FirstOrDefault(f => line.Contains(f, StringComparison.Ordinal));
            if (flag != null)
            {
                context.Report($"'{flag}' opens this resource to anyone who can reach the network it "
                               + "sits on. Keep it private and reach it through a gateway that "
                               + "authenticates.", i + 1);
                continue;
            }

            var range = OpenRanges.FirstOrDefault(r => line.Contains(r, StringComparison.Ordinal));
            if (range == null)
                continue;
            if (!line.Contains("cidr", StringComparison.OrdinalIgnoreCase)
                && !line.Contains("ingress", StringComparison.OrdinalIgnoreCase)
                && !line.Contains("anyIpv", StringComparison.OrdinalIgnoreCase))
                continue;

            context.Report($"'{range}' admits every address on the internet, so whatever is behind this "
                           + "rule is exposed to the whole of it — including the ports meant for "
                           + "administration. Name the ranges that need access.", i + 1);
        }
    }
}

public sealed class JsWildcardPolicyRule : JsTsMeasuredRuleBase
{
    public override string Key => "QG-JS-SEC-0084";
    public override string Name => "A policy should name what it grants";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Replace(" ", string.Empty);
            var granting = line.Contains("actions:", StringComparison.Ordinal)
                           || line.Contains("resources:", StringComparison.Ordinal)
                           || line.Contains("Action:", StringComparison.Ordinal)
                           || line.Contains("Resource:", StringComparison.Ordinal);
            if (!granting)
                continue;
            if (!line.Contains("['*']", StringComparison.Ordinal)
                && !line.Contains("[\"*\"]", StringComparison.Ordinal)
                && !line.Contains(":'*'", StringComparison.Ordinal)
                && !line.Contains(":\"*\"", StringComparison.Ordinal))
                continue;

            context.Report("A star here grants everything the service can do, on everything it owns. "
                           + "Whoever holds this policy can do more than the code that uses it needs, "
                           + "and nothing records what that extra is. List the actions and the "
                           + "resources.", i + 1);
        }
    }
}

public sealed class JsRelativeCommandPathRule : JsTsMeasuredRuleBase
{
    public override string Key => "QG-JS-SEC-0085";
    public override string Name => "An executable should be named without a relative path";
    public override IssueKind Kind => IssueKind.SecurityHotspot;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "exec", "execSync", "spawn",
                     "spawnSync", "execFile", "execFileSync"))
        {
            var command = SyntaxQuery.ArgumentAt(call, 0);
            if (command is not { Kind: NodeKind.StringLiteral })
                continue;
            var text = command.Text;
            if (!text.StartsWith("./", StringComparison.Ordinal)
                && !text.StartsWith("../", StringComparison.Ordinal)
                && !text.StartsWith(".\\", StringComparison.Ordinal))
                continue;

            context.Report($"'{text}' is resolved against whatever the working directory happens to be "
                           + "when the process starts, so the program that runs depends on where it "
                           + "was launched from — and on what someone was able to write there. Use an "
                           + "absolute path built from a known root.", call.Range.StartLine);
        }
    }
}

public sealed class JsTestHookOrderRule : JsTsMeasuredRuleBase
{
    private static readonly string[] BeforeHooks = ["before", "beforeAll", "beforeEach"];
    private static readonly string[] AfterHooks = ["after", "afterAll", "afterEach"];
    private static readonly string[] TestCases = ["it", "test", "specify"];

    public override string Key => "QG-JS-SML-0372";
    public override string Name => "A test hook should sit outside the tests it wraps";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var block in context.Root.OfKind(NodeKind.Block, NodeKind.TopLevel))
        {
            var statements = block.Children
                .Select(child => (Statement: child, Name: CalledName(child)))
                .Where(entry => entry.Name.Length > 0)
                .ToList();
            if (statements.Count == 0)
                continue;

            var firstTest = statements.FindIndex(e => TestCases.Contains(e.Name, StringComparer.Ordinal));
            var lastTest = statements.FindLastIndex(e => TestCases.Contains(e.Name, StringComparer.Ordinal));
            if (firstTest < 0)
                continue;

            for (var i = 0; i < statements.Count; i++)
            {
                var (statement, name) = statements[i];
                if (BeforeHooks.Contains(name, StringComparer.Ordinal) && i > firstTest)
                {
                    context.Report($"'{name}' runs before every test in this scope but is written after "
                                   + "one of them, so the order on the page is not the order at run "
                                   + "time. Move it above the tests.", statement.Range.StartLine);
                }
                else if (AfterHooks.Contains(name, StringComparer.Ordinal) && i < lastTest)
                {
                    context.Report($"'{name}' runs after every test in this scope but is written in the "
                                   + "middle of them, so a reader has to know the framework to know "
                                   + "when it runs. Move it above or below the tests.",
                        statement.Range.StartLine);
                }
            }
        }
    }

    /// <summary>The name a statement calls, when the statement is nothing but one call.</summary>
    private static string CalledName(SyntaxNode statement)
    {
        if (statement.Kind != NodeKind.ExpressionStatement || statement.Children.Count != 1)
            return string.Empty;
        var call = statement.Children[0];
        return call.Kind == NodeKind.Invocation ? SyntaxQuery.InvokedName(call) : string.Empty;
    }
}

public sealed class JsMemoizeWithoutKeyRule : JsTsMeasuredRuleBase
{
    public override string Key => "QG-JS-BUG-0145";
    public override string Name => "A memoised function of several arguments needs a key";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "memoize"))
        {
            var arguments = SyntaxQuery.Arguments(call);
            if (arguments.Count != 1)
                continue; // a second argument is the key resolver, which is the fix
            var function = arguments[0];
            if (function.Kind is not (NodeKind.Lambda or NodeKind.FunctionDeclaration))
                continue;
            var parameters = function.FirstChild(NodeKind.ParameterList);
            if (parameters == null || parameters.Children.Count < 2)
                continue;

            context.Report($"The cache is keyed on the first argument alone, so calls that differ only "
                           + "in the other {parameters.Children.Count - 1} get each other's answer. "
                           + "Pass a resolver that builds the key from every argument.",
                call.Range.StartLine);
        }
    }
}

public sealed class JsUncertainAssertionRule : JsTsMeasuredRuleBase
{
    /// <summary>
    /// Matchers that hold for more than one reason once they are negated: not throwing a given error
    /// is true when nothing was thrown at all, and not including one member is true of an empty list.
    /// </summary>
    private static readonly HashSet<string> Uncertain = new(StringComparer.Ordinal)
    {
        "throw", "throws", "Throw", "include", "includes", "contain", "contains", "property",
        "ownPropertyDescriptor", "haveOwnPropertyDescriptor", "members", "increase", "increases",
        "decrease", "decreases", "change", "changes", "by", "satisfy", "satisfies", "finite"
    };

    public override string Key => "QG-JS-BUG-0146";
    public override string Name => "An assertion should have one reason to hold";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var statement in context.Root.OfKind(NodeKind.ExpressionStatement))
        {
            if (statement.Children.Count != 1)
                continue;
            var expression = statement.Children[0];
            if (expression.Kind is not (NodeKind.Invocation or NodeKind.MemberSelect))
                continue;

            var chain = expression.Text.Split('.');
            if (chain.Length < 3)
                continue;
            if (!chain[0].StartsWith("expect", StringComparison.Ordinal)
                && !chain.Contains("should", StringComparer.Ordinal))
                continue;

            var negated = Array.IndexOf(chain, "not");
            var offender = negated >= 0
                ? chain.Skip(negated + 1).FirstOrDefault(Uncertain.Contains)
                : null;

            // 'change(...).by(...)' states two things at once even without a negation
            if (offender == null)
            {
                var changed = Array.FindIndex(chain, c => c is "change" or "changes");
                if (changed >= 0 && Array.IndexOf(chain, "by", changed) > changed)
                    offender = "by";
                if (offender == null)
                    continue;
            }

            context.Report($"'{offender}' here holds for more than one reason — the state it names, and "
                           + "the state where there is nothing to name at all — so the test passes in a "
                           + "case it was not written for. Assert the one thing that must be true.",
                statement.Range.StartLine);
        }
    }
}

public sealed class JsReplaceAllRule : JsTsMeasuredRuleBase
{
    public override string Key => "QG-JS-SML-0319";
    public override string Name => "A global replacement should say so in the method";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "replace"))
        {
            var pattern = SyntaxQuery.ArgumentAt(call, 0);
            if (pattern == null)
                continue;

            // 'replace' with a plain string changes the first occurrence only, which is a decision
            // the author may well have meant. What is worth saying is the other case: a regular
            // expression written only to carry the global flag, where replaceAll says it in a word.
            var written = pattern.Tokens.Count == 1 ? pattern.Tokens[0].Text : pattern.Text;
            if (!IsSimpleGlobalPattern(written))
                continue;

            context.Report("This uses a regular expression only to say 'every occurrence'. "
                           + "'replaceAll' says the same thing with a plain string, and a string "
                           + "needs no escaping.", call.Range.StartLine);
        }
    }

    /// <summary>
    /// A pattern that is a literal run of characters with the global flag: nothing in it needs a
    /// regular expression engine.
    /// </summary>
    private static bool IsSimpleGlobalPattern(string written)
    {
        // the tokenizer hands the flags back as an inline group in front of the pattern
        if (!written.StartsWith("(?", StringComparison.Ordinal))
            return false;
        var close = written.IndexOf(')');
        if (close < 0)
            return false;
        var flags = written[2..close];
        if (!flags.Contains('g'))
            return false;

        var body = written[(close + 1)..];
        // any metacharacter means the expression is doing real work
        return body.Length > 0 && body.All(c => char.IsLetterOrDigit(c) || c is ' ' or '_' or '-' or ',');
    }
}


/// <summary>
/// An asynchronous test signals that it has finished by calling the callback it was handed. Anything
/// written after that call still runs, but the framework has already moved on: the assertion is not
/// attributed to this test, and if it throws, the failure surfaces against whichever test happens to
/// be running. Reading it as "any call named done" reported every asynchronous test there is.
/// </summary>
public sealed class JsCodeAfterDoneRule : JsTsMeasuredRuleBase
{
    private static readonly string[] TestNames = ["it", "test", "specify", "before", "after",
                                                  "beforeEach", "afterEach"];

    public override string Key => "QG-JS-SML-0158";
    public override string Name => "A test should finish where it says it finished";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!TestNames.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;

            var callback = SyntaxQuery.Arguments(call)
                .Select(a => a.Kind == NodeKind.Lambda ? a : a.FirstChild(NodeKind.Lambda))
                .FirstOrDefault(a => a is not null);
            if (callback is null)
                continue;

            var signal = SyntaxQuery.Parameters(callback).FirstOrDefault()?.Text;
            if (string.IsNullOrEmpty(signal))
                continue;

            var body = SyntaxQuery.Body(callback);
            if (body is null)
                continue;

            Inspect(context, body, signal);
        }
    }

    /// <summary>Report the statements that follow the signal inside the block that carries it.</summary>
    private static void Inspect(IRuleContext context, SyntaxNode block, string signal)
    {
        var children = block.Children;
        for (var i = 0; i < children.Count - 1; i++)
        {
            if (!Signals(children[i], signal))
                continue;
            context.Report(children[i + 1],
                $"'{signal}()' on line {children[i].Line} already told the framework this test was "
                + "over, so what follows runs outside it: an assertion here is not counted, and a "
                + "failure here is blamed on another test. Move it above the call.");
            return;
        }

        foreach (var nested in children.Where(c => c.Kind == NodeKind.Block))
            Inspect(context, nested, signal);
    }

    private static bool Signals(SyntaxNode statement, string signal)
    {
        if (statement.Kind != NodeKind.ExpressionStatement || statement.Children.Count != 1)
            return false;
        var expression = statement.Children[0];
        return expression.Kind == NodeKind.Invocation
               && SyntaxQuery.InvokedDottedName(expression) == signal;
    }
}


/// <summary>
/// A declaration that is function-scoped rather than block-scoped. Reporting every one of them said
/// nothing useful about a codebase written before block scoping existed — it was one finding per
/// declaration, a hundred per thousand lines. The finding is the odd one out, so a file where this
/// is plainly the chosen style is left alone and only the exceptions are reported.
/// </summary>
public sealed class JsFunctionScopedDeclarationRule : JsTsMeasuredRuleBase
{
    private const int Enough = 3;
    private const double Dominant = 0.5;

    public override string Key => "QG-JS-SML-0010";
    public override string Name => "Variables should be declared with let or const";
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var functionScoped = new List<Token>();
        var total = 0;

        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Kind != TokenKind.Keyword)
                continue;
            if (tokens[i].Text is not ("var" or "let" or "const"))
                continue;
            // a declaration names something straight away; 'const' in a type position does not
            if (tokens[i + 1].Kind != TokenKind.Identifier)
                continue;
            total++;
            if (tokens[i].Text == "var")
                functionScoped.Add(tokens[i]);
        }

        if (total == 0 || functionScoped.Count == 0)
            return;
        if (functionScoped.Count >= Enough && (double)functionScoped.Count / total > Dominant)
            return;

        foreach (var token in functionScoped)
        {
            context.Report("This declaration is visible in the whole function however far down it "
                           + "appears, and it can be declared a second time without complaint. The "
                           + "rest of this file already scopes its declarations to the block; use "
                           + "const, or let where the value changes.", token.Line);
        }
    }
}
