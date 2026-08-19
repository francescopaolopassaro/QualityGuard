using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// The libraries a .NET application is actually written against: the ORM, the micro-ORM, the HTTP
/// client, the mobile toolkit. What goes wrong with them is invisible in a review of a single method
/// — a query per row of a list, a connection pool exhausted by a client nobody reused, a handler that
/// throws where no one is listening — and every one of them is a shape that can be recognised.
/// </summary>
public static class DotNetFrameworkRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new EntityFrameworkQueryInLoopRule(),
        new EntityFrameworkSaveInLoopRule(),
        new EntityFrameworkClientSideFilterRule(),
        new EntityFrameworkBlockingCallRule(),
        new DapperConcatenatedSqlRule(),
        new HttpClientPerCallRule()
    ];
}

public abstract class DotNetFrameworkRuleBase : RuleBase
{
    public override string[] Languages => ["cs", "raz"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "20min";

    /// <summary>Calls that send the query to the database and bring the rows back.</summary>
    protected static readonly string[] Materialisers =
    [
        "ToList", "ToListAsync", "ToArray", "ToArrayAsync", "First", "FirstAsync", "FirstOrDefault",
        "FirstOrDefaultAsync", "Single", "SingleAsync", "SingleOrDefault", "SingleOrDefaultAsync",
        "Count", "CountAsync", "Any", "AnyAsync", "Find", "FindAsync", "ToDictionary",
        "ToDictionaryAsync", "Sum", "SumAsync", "Max", "MaxAsync", "Min", "MinAsync"
    ];

    /// <summary>Whether the receiver of the call looks like a set of rows rather than a collection.</summary>
    protected static bool ReadsFromTheDatabase(SyntaxNode call, IRuleContext context)
    {
        var chain = SyntaxQuery.InvokedDottedName(call);
        if (chain.Length == 0)
            return false;
        var lowered = chain.ToLowerInvariant();
        if (lowered.Contains("context.") || lowered.Contains("db.") || lowered.Contains("dbcontext")
            || lowered.Contains("repository.") || lowered.Contains("_db") || lowered.Contains("_context"))
            return true;
        // 'Where(...)' straight after a queryable is the other half of the shape, and the type
        // resolver names it when the declaration is in the scan
        var receiver = SyntaxQuery.Receiver(call);
        var type = receiver.Length > 0 ? context.Types.TypeOf(call.ChildAt(0)?.ChildAt(0)) : null;
        return type != null && (type.Contains("DbSet", StringComparison.Ordinal)
                                || type.Contains("IQueryable", StringComparison.Ordinal));
    }

    protected static bool InsideLoop(SyntaxNode node) => node.Ancestor(NodeKind.Loop) != null;
}

public sealed class EntityFrameworkQueryInLoopRule : DotNetFrameworkRuleBase
{
    public override string Key => "QG-CS-PRF-0009";
    public override string Name => "A query inside a loop asks the database once per iteration";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            foreach (var call in loop.OfKind(NodeKind.Invocation))
            {
                var name = SyntaxQuery.InvokedName(call);
                if (!Materialisers.Contains(name, StringComparer.Ordinal))
                    continue;
                if (!ReadsFromTheDatabase(call, context))
                    continue;

                context.Report($"'{name}' runs inside a loop, so the database is asked once for every "
                               + "item instead of once for the set. A list that grows from ten rows to "
                               + "ten thousand turns a page that loads into a page that times out, and "
                               + "nothing in the method changed. Read what the loop needs in one query "
                               + "before it starts.", call.Range.StartLine);
                break; // one report per loop: the shape is the loop, not each call in it
            }
        }
    }
}

public sealed class EntityFrameworkSaveInLoopRule : DotNetFrameworkRuleBase
{
    public override string Key => "QG-CS-PRF-0010";
    public override string Name => "Changes should be saved once, not once per item";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            foreach (var call in loop.OfKind(NodeKind.Invocation))
            {
                if (SyntaxQuery.InvokedName(call) is not ("SaveChanges" or "SaveChangesAsync"))
                    continue;

                context.Report("Saving inside the loop opens a transaction per item: the work that "
                               + "could travel in one round trip becomes one per row, and a failure "
                               + "halfway through leaves the earlier items committed and the rest not. "
                               + "Collect the changes and save once after the loop.",
                    call.Range.StartLine);
                break;
            }
        }
    }
}

public sealed class EntityFrameworkClientSideFilterRule : DotNetFrameworkRuleBase
{
    public override string Key => "QG-CS-PRF-0011";
    public override string Name => "A query should filter in the database, not after it";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            // 'ToList().Where(...)' brings every row across and throws most of them away in memory
            if (SyntaxQuery.InvokedName(call) is not ("Where" or "First" or "FirstOrDefault"
                or "Single" or "SingleOrDefault" or "Any" or "Count"))
                continue;
            var receiver = call.ChildAt(0)?.ChildAt(0);
            if (receiver is not { Kind: NodeKind.Invocation })
                continue;
            if (SyntaxQuery.InvokedName(receiver) is not ("ToList" or "ToListAsync" or "ToArray"
                or "ToArrayAsync"))
                continue;
            if (!ReadsFromTheDatabase(receiver, context))
                continue;

            context.Report("The rows are brought into memory and filtered afterwards, so the database "
                           + "sends the whole table and the application throws most of it away. Put the "
                           + "condition before the call that runs the query.", call.Range.StartLine);
        }
    }
}

public sealed class EntityFrameworkBlockingCallRule : DotNetFrameworkRuleBase
{
    public override string Key => "QG-CS-BUG-0197";
    public override IssueKind Kind => IssueKind.Bug;
    public override string Name => "An asynchronous method should not wait for the database synchronously";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!method.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "async"))
                continue;

            foreach (var call in method.OfKind(NodeKind.Invocation))
            {
                var name = SyntaxQuery.InvokedName(call);
                if (name is not ("ToList" or "ToArray" or "First" or "FirstOrDefault" or "Single"
                    or "SingleOrDefault" or "Count" or "Any" or "SaveChanges"))
                    continue;
                if (!ReadsFromTheDatabase(call, context))
                    continue;

                context.Report($"'{name}' blocks the thread until the database answers, inside a method "
                               + "that was written to release it. Under load the pool fills with threads "
                               + "waiting on a network round trip, and the application stops accepting "
                               + $"work. There is a '{name}Async' for this.", call.Range.StartLine);
                break;
            }
        }
    }
}

public sealed class DapperConcatenatedSqlRule : DotNetFrameworkRuleBase
{
    public override string Key => "QG-CS-SEC-0101";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";
    public override string Name => "A query passed to the data layer should carry parameters, not concatenated values";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!name.StartsWith("Query", StringComparison.Ordinal)
                && !name.StartsWith("Execute", StringComparison.Ordinal))
                continue;

            var arguments = SyntaxQuery.Arguments(call);
            if (arguments.Count == 0)
                continue;
            var sql = arguments[0];
            var built = sql.Kind == NodeKind.InterpolatedString
                        || (sql.Kind == NodeKind.Binary && sql.Text == "+"
                            && sql.DescendantsAndSelf().Any(n => n.Kind == NodeKind.StringLiteral)
                            && sql.DescendantsAndSelf().Any(n => n.Kind == NodeKind.Identifier));
            if (!built)
                continue;
            // a query built from constants only is still one string, and nothing outside decides it
            if (sql.DescendantsAndSelf().All(n => n.Kind != NodeKind.Identifier
                                                  || context.IsTainted(n) == false && n.Text.All(char.IsUpper)))
                continue;

            context.Report("The statement is assembled from values instead of receiving them as "
                           + "parameters, so whatever those values contain becomes part of the command. "
                           + "Pass them as parameters and let the driver send them separately.",
                call.Range.StartLine);
        }
    }
}

public sealed class HttpClientPerCallRule : DotNetFrameworkRuleBase
{
    public override string Key => "QG-CS-SML-0346";
    public override string Name => "An HTTP client should be reused rather than created per call";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            if (Semantics.TypeResolver.Normalize(creation.Text) != "HttpClient")
                continue;
            var owner = SyntaxQuery.EnclosingFunction(creation);
            if (owner == null)
                continue;
            // one created for the lifetime of the object, in a constructor or a field, is the reuse
            // this rule asks for
            if (owner.Kind == NodeKind.ConstructorDeclaration)
                continue;

            context.Report("A client created here is thrown away with the method, and the socket it "
                           + "opened stays reserved for minutes afterwards. Under any real traffic the "
                           + "machine runs out of ports while the code looks like it is closing "
                           + "everything. Take the client from a factory, or keep one for the "
                           + "lifetime of the service.", creation.Range.StartLine);
        }
    }
}
