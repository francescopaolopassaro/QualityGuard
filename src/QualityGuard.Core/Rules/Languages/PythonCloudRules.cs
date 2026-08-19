using System.Text.RegularExpressions;
using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Infrastructure declared from Python: permission statements, security group rules and the address
/// a server listens on. What makes these worth reporting is that the code around them is ordinary
/// application code — it compiles, it deploys, and the grant it writes is applied by a pipeline that
/// nobody reads afterwards.
/// </summary>
public static class PythonCloudRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PythonWildcardPolicyRule(),
        new PythonPrivilegeEscalationPolicyRule(),
        new PythonUnrestrictedAdministrationRule(),
        new PythonBindAllInterfacesRule()
    ];
}

public abstract class PythonCloudRule : RuleBase
{
    public override string[] Languages => ["py"];
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>The last segment of a dotted call name, which is what identifies the API.</summary>
    protected static string LastSegment(string dotted)
    {
        var dot = dotted.LastIndexOf('.');
        return dot < 0 ? dotted : dotted[(dot + 1)..];
    }

    /// <summary>
    /// The whole dotted name of a call. The simple name is not enough here: what identifies these
    /// APIs is the type in front of the method — <c>Peer.any_ipv4</c> and <c>Port.tcp</c> say what
    /// they are only together, and <c>any_ipv4</c> alone matches anything.
    /// </summary>
    protected static string CallName(SyntaxNode call)
    {
        var dotted = SyntaxQuery.InvokedDottedName(call);
        return dotted.Length > 0 ? dotted : SyntaxQuery.InvokedName(call);
    }

    protected static bool CallsInto(string dotted, string tail)
        => dotted.Equals(tail, StringComparison.Ordinal)
           || dotted.EndsWith("." + tail, StringComparison.Ordinal);

    /// <summary>The value written for a keyword argument of a call.</summary>
    protected static SyntaxNode? Keyword(SyntaxNode call, string name)
    {
        foreach (var argument in SyntaxQuery.Arguments(call))
        {
            if (argument.Kind == NodeKind.NamedArgument
                && string.Equals(argument.Text, name, StringComparison.Ordinal)
                && argument.Children.Count > 1)
                return argument.Children[^1];
        }
        return null;
    }

    protected static SyntaxNode? Positional(SyntaxNode call, int index)
    {
        var positional = SyntaxQuery.Arguments(call)
            .Where(a => a.Kind != NodeKind.NamedArgument).ToList();
        return index < positional.Count ? positional[index] : null;
    }

    /// <summary>The strings a value holds, whether it is one literal or a list of them.</summary>
    protected static IEnumerable<string> Strings(SyntaxNode? value)
    {
        if (value == null)
            yield break;
        if (value.Kind == NodeKind.StringLiteral)
        {
            yield return value.Text;
            yield break;
        }
        foreach (var item in value.Children.Where(c => c.Kind == NodeKind.StringLiteral))
            yield return item.Text;
    }

    /// <summary>
    /// One permission statement, however it was written: as a construct of the deployment library or
    /// as the plain dictionary that ends up in the template. Reading only the first form covers the
    /// tidy half of the code and misses the policies that were pasted in from the console.
    /// </summary>
    protected readonly record struct PolicyStatement(
        string Effect, SyntaxNode? Actions, SyntaxNode? Resources, int Line)
    {
        public bool Allows => !Effect.Equals("deny", StringComparison.OrdinalIgnoreCase);
    }

    protected static IEnumerable<PolicyStatement> Statements(SyntaxNode root)
    {
        foreach (var call in SyntaxQuery.Invocations(root))
        {
            var name = CallName(call);
            if (!CallsInto(name, "PolicyStatement"))
                continue;

            var effect = Keyword(call, "effect");
            yield return new PolicyStatement(
                effect == null ? string.Empty : LastSegment(effect.Text),
                Keyword(call, "actions"), Keyword(call, "resources"), call.Range.StartLine);
        }

        foreach (var dictionary in root.OfKind(NodeKind.ObjectInitializer))
        {
            SyntaxNode? actions = null, resources = null;
            var effect = string.Empty;
            var children = dictionary.Children;
            for (var i = 0; i + 1 < children.Count; i += 2)
            {
                if (children[i].Kind != NodeKind.StringLiteral)
                    continue;
                switch (children[i].Text)
                {
                    case "Effect": effect = children[i + 1].Text; break;
                    case "Action": actions = children[i + 1]; break;
                    case "Resource": resources = children[i + 1]; break;
                }
            }

            // a dictionary without an effect is not a policy statement, it is any other dictionary
            // that happens to have a key called Action
            if (effect.Length > 0 && (actions != null || resources != null))
                yield return new PolicyStatement(effect, actions, resources, dictionary.Range.StartLine);
        }
    }
}

public sealed class PythonWildcardPolicyRule : PythonCloudRule
{
    public override string Key => "QG-PY-SEC-0063";
    public override string Name => "A permission statement should not allow every action";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var statement in Statements(context.Root))
        {
            if (!statement.Allows || !Strings(statement.Actions).Any(action => action == "*"))
                continue;

            context.Report("This statement allows every action the services offer, so whoever holds "
                           + "it can read, change and delete anything the resources it names contain "
                           + "— and can also grant the same to somebody else. A wildcard is written "
                           + "to get a deployment working and then never narrowed. List the actions "
                           + "the workload actually calls.", statement.Line);
        }
    }
}

public sealed class PythonPrivilegeEscalationPolicyRule : PythonCloudRule
{
    /// <summary>
    /// Actions that let their holder obtain rights they were not given: creating a credential for
    /// another identity, attaching a policy, passing a role to something that then runs with it.
    /// Granted on a specific resource they are ordinary; granted on every resource they are the
    /// whole account.
    /// </summary>
    private static readonly HashSet<string> EscalationActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:CreateAccessKey",
        "iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy", "iam:AttachRolePolicy", "sts:AssumeRole", "iam:PutUserPolicy",
        "iam:PutGroupPolicy", "iam:PutRolePolicy", "iam:AddUserToGroup",
        "iam:UpdateAssumeRolePolicy", "iam:PassRole", "ec2:RunInstances", "lambda:CreateFunction",
        "lambda:InvokeFunction", "lambda:AddPermission", "lambda:CreateEventSourceMapping",
        "cloudformation:CreateStack", "datapipeline:CreatePipeline",
        "datapipeline:PutPipelineDefinition", "glue:CreateDevEndpoint", "glue:UpdateDevEndpoint",
        "lambda:UpdateFunctionCode"
    };

    private static readonly Regex EveryIdentity =
        new(@"^\*$|^arn:.*:(role|user|group)/\*$", RegexOptions.Compiled);

    public override string Key => "QG-PY-SEC-0067";
    public override string Name => "A permission statement should not allow escalation over every resource";
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var statement in Statements(context.Root))
        {
            if (!statement.Allows)
                continue;
            if (!Strings(statement.Resources).Any(EveryIdentity.IsMatch))
                continue;

            var escalating = Strings(statement.Actions).FirstOrDefault(EscalationActions.Contains);
            if (escalating == null)
                continue;

            context.Report($"'{escalating}' is granted over every identity in the account. It is one "
                           + "of the actions that turn limited access into unlimited access — a new "
                           + "credential for somebody else, a policy attached, a role passed to "
                           + "something that then runs with it — so this policy is worth as much as "
                           + "the most privileged role it can reach. Name the resources it applies to.",
                statement.Line);
        }
    }
}

public sealed class PythonUnrestrictedAdministrationRule : PythonCloudRule
{
    private static readonly HashSet<string> AdministrationPorts = ["22", "3389"];

    private static readonly HashSet<string> EveryAddress = new(StringComparer.Ordinal)
    {
        "0.0.0.0/0", "::/0"
    };

    public override string Key => "QG-PY-SEC-0069";
    public override string Name => "Remote administration should not be open to every address";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = CallName(call);

            if (CallsInto(name, "add_ingress_rule") || CallsInto(name, "allow_from"))
            {
                var peer = Keyword(call, "peer") ?? Keyword(call, "other") ?? Positional(call, 0);
                var port = Keyword(call, "connection") ?? Keyword(call, "port_range") ?? Positional(call, 1);
                if (OpenToEveryone(peer) && ReachesAdministration(port))
                    Report(context, call.Range.StartLine);
                continue;
            }

            if (CallsInto(name, "allow_from_any_ipv4"))
            {
                var port = Keyword(call, "port_range") ?? Positional(call, 0);
                if (ReachesAdministration(port))
                    Report(context, call.Range.StartLine);
                continue;
            }

            if (CallsInto(name, "CfnSecurityGroupIngress") || CallsInto(name, "IngressProperty"))
                CheckIngressProperties(context, call);
        }
    }

    private void CheckIngressProperties(IRuleContext context, SyntaxNode call)
    {
        var open = Strings(Keyword(call, "cidr_ip")).Concat(Strings(Keyword(call, "cidr_ipv6")))
            .Any(EveryAddress.Contains);
        if (!open)
            return;

        var protocol = Strings(Keyword(call, "ip_protocol")).FirstOrDefault() ?? string.Empty;
        // "-1" means every protocol, which reaches the administration ports whatever range is given
        if (protocol == "-1")
        {
            Report(context, call.Range.StartLine);
            return;
        }
        if (protocol is not ("tcp" or "6"))
            return;

        var from = Number(Keyword(call, "from_port"));
        var to = Number(Keyword(call, "to_port"));
        if (from == null || to == null)
            return;
        if (AdministrationPorts.Any(p => int.Parse(p) >= from && int.Parse(p) <= to))
            Report(context, call.Range.StartLine);
    }

    private static int? Number(SyntaxNode? node)
        => node != null && node.Kind == NodeKind.NumberLiteral && int.TryParse(node.Text, out var value)
            ? value
            : null;

    /// <summary>Whether the peer of a rule is the whole internet rather than a range somebody chose.</summary>
    private static bool OpenToEveryone(SyntaxNode? peer)
    {
        if (peer == null)
            return false;
        var name = CallName(peer);
        if (CallsInto(name, "Peer.any_ipv4") || CallsInto(name, "Peer.any_ipv6"))
            return true;
        return (CallsInto(name, "Peer.ipv4") || CallsInto(name, "Peer.ipv6"))
               && Strings(Positional(peer, 0)).Concat(Strings(Keyword(peer, "cidr_ip")))
                   .Any(EveryAddress.Contains);
    }

    /// <summary>Whether the port range of a rule includes a port used to administer the machine.</summary>
    private static bool ReachesAdministration(SyntaxNode? port)
    {
        if (port == null)
            return false;
        var name = CallName(port);
        if (CallsInto(name, "Port.all_tcp") || CallsInto(name, "Port.all_traffic"))
            return true;
        if (CallsInto(name, "Port.tcp"))
        {
            var declared = Positional(port, 0) ?? Keyword(port, "port");
            return declared != null && AdministrationPorts.Contains(declared.Text);
        }
        if (!CallsInto(name, "Port.tcp_range"))
            return false;

        var from = Number(Positional(port, 0) ?? Keyword(port, "start_port"));
        var to = Number(Positional(port, 1) ?? Keyword(port, "end_port"));
        return from != null && to != null
                             && AdministrationPorts.Any(p => int.Parse(p) >= from && int.Parse(p) <= to);
    }

    private static void Report(IRuleContext context, int line)
        => context.Report("This opens a remote administration port to every address on the internet. "
                          + "Whatever authentication sits behind it is now the only thing between the "
                          + "machine and the scanners that reach it within minutes of the rule being "
                          + "applied. Restrict the range to the networks that administer this system.",
            line);
}

public sealed class PythonBindAllInterfacesRule : PythonCloudRule
{
    private static readonly HashSet<string> EveryInterface = new(StringComparer.Ordinal)
    {
        "0.0.0.0", "::"
    };

    public override string Key => "QG-PY-SEC-0084";
    public override string Name => "A server should not listen on every network interface";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = CallName(call);
            if (!CallsInto(name, "run"))
                continue;

            // the keyword is what makes the intent unambiguous; a bare first argument only counts
            // when the call is the one a web framework exposes
            var host = Keyword(call, "host")
                       ?? (LastSegment(name) == "run" && name.Contains('.') ? Positional(call, 0) : null);
            if (host == null || host.Kind != NodeKind.StringLiteral || !EveryInterface.Contains(host.Text))
                continue;

            context.Report("The server listens on every interface of the machine, so it is reachable "
                           + "from any network the machine is attached to — including the ones nobody "
                           + "meant to expose it on, and including the public one when it is deployed "
                           + "somewhere with a routable address. Bind to the address it is meant to "
                           + "serve, and let a proxy publish it.", call.Range.StartLine);
        }
    }
}
