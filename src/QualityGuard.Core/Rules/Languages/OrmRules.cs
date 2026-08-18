using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Rules about talking to a database through an object mapper. The mistakes here do not look like
/// mistakes: the code reads correctly, compiles, and passes its tests on a table with ten rows. What
/// changes is how many round trips it makes and how much of the table it drags into memory, and that
/// only shows up in production.
/// </summary>
public static class OrmRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new QueryInsideLoopRule(),
        new SaveInsideLoopRule(),
        new MaterialiseBeforeFilterRule(),
        new IncludeAfterProjectionRule(),
        new RepeatedEnumerationRule(),
        new RawSqlFromValuesRule(),
        new SynchronousQueryInAsyncRule(),
        new CollectionOwnPredicateRule(),
        new WeakKeySizeRule()
    ];
}

public abstract class OrmRuleBase : RuleBase
{
    public override string[] Languages => ["cs", "vb"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "30min";

    /// <summary>
    /// Calls that end a query and send it to the database. Their asynchronous forms are the ones the
    /// mapper provides, and the plain ones exist on collections too, which is why the receiver has to
    /// look like a query before any of them means anything.
    /// </summary>
    protected static readonly string[] Terminals =
    [
        "ToListAsync", "ToArrayAsync", "ToDictionaryAsync", "FirstAsync", "FirstOrDefaultAsync",
        "SingleAsync", "SingleOrDefaultAsync", "LastAsync", "LastOrDefaultAsync", "AnyAsync",
        "AllAsync", "CountAsync", "LongCountAsync", "SumAsync", "MinAsync", "MaxAsync",
        "AverageAsync", "FindAsync", "ExecuteUpdateAsync", "ExecuteDeleteAsync", "LoadAsync"
    ];

    /// <summary>
    /// Operators that only a mapper provides. Where and Select are deliberately absent: they exist on
    /// every sequence, so a list already read from the database goes through them too, and treating
    /// them as a signal reported ordinary in-memory work as a round trip.
    /// </summary>
    protected static readonly string[] Operators =
    [
        "Include", "ThenInclude", "AsNoTracking", "AsNoTrackingWithIdentityResolution",
        "AsQueryable", "AsSplitQuery", "IgnoreQueryFilters", "FromSqlRaw", "FromSqlInterpolated",
        "TagWith", "ExecuteUpdate", "ExecuteDelete"
    ];

    /// <summary>
    /// Words that name a data source. They are matched against the root of the chain — the thing the
    /// call ultimately hangs off — because 'items.Select(...).ToList()' walks a list in memory and
    /// 'context.Comuni.ToList()' walks a table.
    /// </summary>
    private static readonly string[] Sources =
        ["db", "context", "repository", "repo", "store", "uow", "unitofwork", "queryable", "set"];

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>
    /// Whether an expression reads like a query rather than a collection already in memory: it goes
    /// through a mapper's own operators, or through a member whose name says it is a set of rows.
    /// </summary>
    protected static bool LooksLikeQuery(SyntaxNode node)
    {
        var text = node.Text;
        if (text.Length == 0)
            text = SyntaxQuery.DottedName(node);
        if (Operators.Any(op => text.Contains("." + op, StringComparison.Ordinal)))
            return true;

        var root = text.Split('.').FirstOrDefault() ?? string.Empty;
        return Sources.Any(source => root.Contains(source, StringComparison.OrdinalIgnoreCase));
    }
}

public sealed class QueryInsideLoopRule : OrmRuleBase
{
    public override string Key => "QG-CS-PRF-0003";
    public override string Name => "A query should not run once per iteration";
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "45min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            foreach (var call in SyntaxQuery.Invocations(loop))
            {
                var name = SyntaxQuery.InvokedName(call);
                if (!Terminals.Contains(name, StringComparer.Ordinal))
                    continue;
                if (!LooksLikeQuery(call))
                    continue;

                // the finding belongs on the loop: that is what has to change, and it is where the
                // reader is when the shape becomes visible
                context.Report($"'{name}' runs inside this loop, so the database is asked once for "
                               + "every item instead of once for all of them. On a hundred items "
                               + "that is a hundred round trips, and the cost grows with the data "
                               + "rather than with the code. Fetch what the loop needs in one query "
                               + "before it starts.", loop.Range.StartLine);
                break;
            }
        }
    }
}

public sealed class SaveInsideLoopRule : OrmRuleBase
{
    private static readonly string[] Saves = ["SaveChanges", "SaveChangesAsync", "Commit", "CommitAsync"];

    public override string Key => "QG-CS-PRF-0004";
    public override string Name => "Changes should be saved once, not once per item";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            foreach (var call in SyntaxQuery.Invocations(loop))
            {
                if (!Saves.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                    continue;

                context.Report("Every iteration opens a transaction, writes one row and commits it. "
                               + "Collect the changes and save them once: the work becomes one "
                               + "transaction, and a failure half way leaves the data consistent "
                               + "instead of partly written.", call.Range.StartLine);
                break;
            }
        }
    }
}

public sealed class MaterialiseBeforeFilterRule : OrmRuleBase
{
    private static readonly string[] Materialisers =
        ["ToList", "ToArray", "ToListAsync", "ToArrayAsync", "AsEnumerable", "ToHashSet"];

    private static readonly string[] Filters =
    [
        "Where", "First", "FirstOrDefault", "Single", "SingleOrDefault", "Any", "All", "Count",
        "OrderBy", "OrderByDescending", "Skip", "Take", "Last", "LastOrDefault"
    ];

    public override string Key => "QG-CS-PRF-0005";
    public override string Name => "A query should be filtered before it is read";
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!Filters.Contains(name, StringComparer.Ordinal))
                continue;

            // the receiver of the filter is the call that already read everything
            var receiver = call.ChildAt(0);
            var inner = receiver?.OfKind(NodeKind.Invocation).FirstOrDefault();
            if (inner == null)
                continue;
            var read = SyntaxQuery.InvokedName(inner);
            if (!Materialisers.Contains(read, StringComparer.Ordinal) || !LooksLikeQuery(inner))
                continue;

            context.Report($"'{read}' reads the whole set into memory and '{name}' then throws most of "
                           + "it away. The database can do the filtering, and it has the indexes for "
                           + $"it: put '{name}' before '{read}'.", call.Range.StartLine);
        }
    }
}

public sealed class IncludeAfterProjectionRule : OrmRuleBase
{
    public override string Key => "QG-CS-BUG-0147";
    public override string Name => "A projection discards the related data loaded before it";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "Include", "ThenInclude"))
        {
            var receiver = call.ChildAt(0);
            if (receiver == null)
                continue;
            var projected = receiver.OfKind(NodeKind.Invocation)
                .Any(inner => SyntaxQuery.InvokedName(inner) is "Select" or "SelectMany");
            if (!projected)
                continue;

            context.Report("The projection has already decided which columns to read, so this Include "
                           + "is ignored: the related data is not loaded and the property is null at "
                           + "run time. Ask for the related data inside the projection, or move the "
                           + "Include before it.", call.Range.StartLine);
        }
    }
}

public sealed class RepeatedEnumerationRule : OrmRuleBase
{
    private static readonly string[] Enumerating =
        ["Count", "Any", "First", "FirstOrDefault", "Last", "LastOrDefault", "Sum", "Min", "Max",
         "Average", "ToList", "ToArray", "Contains", "All"];

    public override string Key => "QG-CS-PRF-0006";
    public override string Name => "A sequence should not be walked twice";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var body = SyntaxQuery.Body(function);
            if (body == null)
                continue;

            // locals that hold a query rather than a result: the chain was never read
            var deferred = new Dictionary<string, SyntaxNode>(StringComparer.Ordinal);
            foreach (var declaration in body.OfKind(NodeKind.VariableDeclaration))
            {
                if (declaration.Text.Length == 0)
                    continue;
                var value = declaration.OfKind(NodeKind.Invocation).FirstOrDefault();
                if (value == null || !LooksLikeQuery(value))
                    continue;
                var produced = SyntaxQuery.InvokedName(value);
                if (produced is not ("Where" or "Select" or "SelectMany" or "OrderBy" or "AsQueryable"))
                    continue;
                deferred[declaration.Text] = declaration;
            }
            if (deferred.Count == 0)
                continue;

            foreach (var (name, declaration) in deferred)
            {
                var walks = body.OfKind(NodeKind.Invocation)
                    .Count(call => Enumerating.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal)
                                   && SyntaxQuery.Receiver(call) == name);
                var loops = body.OfKind(NodeKind.Loop)
                    .Count(loop => loop.OfKind(NodeKind.Identifier).Any(i => i.Text == name));
                if (walks + loops < 2)
                    continue;

                context.Report($"'{name}' holds a query, not its result, so every use runs it again — "
                               + $"here {walks + loops} times. Read it once into a list and work with "
                               + "that.", declaration.Range.StartLine);
            }
        }
    }
}

public sealed class RawSqlFromValuesRule : OrmRuleBase
{
    /// <summary>
    /// Calls that hand a string to the database as a command. The list covers the mappers a .NET
    /// codebase actually uses, because each of them names the same operation differently.
    /// </summary>
    private static readonly string[] SqlCalls =
    [
        // Entity Framework
        "FromSqlRaw", "ExecuteSqlRaw", "ExecuteSqlRawAsync", "ExecuteSqlCommand", "ExecuteSqlCommandAsync",
        // Dapper
        "Query", "QueryAsync", "QueryFirst", "QueryFirstAsync", "QueryFirstOrDefault",
        "QueryFirstOrDefaultAsync", "QuerySingle", "QuerySingleAsync", "QuerySingleOrDefault",
        "QuerySingleOrDefaultAsync", "QueryMultiple", "QueryMultipleAsync", "Execute", "ExecuteAsync",
        "ExecuteScalar", "ExecuteScalarAsync", "ExecuteReader", "ExecuteReaderAsync",
        // NHibernate and OrmLite
        "CreateSQLQuery", "CreateQuery", "SqlList", "SqlScalar", "SqlColumn", "ExecuteSql",
        // OrmLite: the name is a LINQ name too, and only the concatenated argument tells them apart
        "Select", "SelectLazy", "SelectNonDefaults", "Single", "SingleById", "Scalar", "Column",
        "ColumnDistinct", "Dictionary", "Lookup", "Exists", "SqlProc"
    ];

    public override string Key => "QG-CS-SEC-0093";
    public override string Name => "A command should not be assembled from values";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Blocker;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!SqlCalls.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;

            // the command is the first string-shaped argument: some overloads put the type first
            var arguments = SyntaxQuery.Arguments(call);
            var command = arguments.FirstOrDefault(Assembled);
            if (command == null)
                continue;

            context.Report("The command is built by joining a value into the text, so whatever that "
                           + "value contains becomes part of the statement — a quote ends the string "
                           + "and the rest is executed. Pass the value as a parameter and leave the "
                           + "text alone.", call.Range.StartLine);
        }
    }

    /// <summary>Whether an argument is a string put together from parts rather than written whole.</summary>
    private static bool Assembled(SyntaxNode argument)
    {
        // in this position a plus is string concatenation: the parts may all be variables, which is
        // exactly the case the rule exists for
        if (argument.Kind == NodeKind.Binary && argument.Text == "+")
            return !argument.OfKind(NodeKind.NumberLiteral).Any();
        if (argument.Kind == NodeKind.Interpolation)
            return argument.Children.Count > 0;
        return argument.Kind == NodeKind.Invocation
               && SyntaxQuery.InvokedName(argument) is "Format" or "Concat" or "Join";
    }
}

public sealed class SynchronousQueryInAsyncRule : OrmRuleBase
{
    /// <summary>Query endings that have an awaitable twin on a mapper's own sets.</summary>
    private static readonly string[] Blocking =
    [
        "ToList", "ToArray", "ToDictionary", "First", "FirstOrDefault", "Single", "SingleOrDefault",
        "Last", "LastOrDefault", "Any", "All", "Count", "LongCount", "Sum", "Min", "Max", "Average",
        "Find", "ExecuteDelete", "ExecuteUpdate", "Load", "Contains"
    ];

    public override string Key => "QG-CS-PRF-0007";
    public override string Name => "A query in an asynchronous method should be awaited";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            if (!function.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "async"))
                continue;
            var body = SyntaxQuery.Body(function);
            if (body == null)
                continue;

            foreach (var call in SyntaxQuery.Invocations(body))
            {
                var name = SyntaxQuery.InvokedName(call);
                if (!Blocking.Contains(name, StringComparer.Ordinal) || !LooksLikeQuery(call))
                    continue;

                context.Report($"'{name}' waits for the database on the calling thread, inside a method "
                               + $"that is already asynchronous. '{name}Async' exists for exactly this "
                               + "and frees the thread while the query runs.", call.Range.StartLine);
            }
        }
    }
}

public sealed class CollectionOwnPredicateRule : OrmRuleBase
{
    /// <summary>The LINQ operator, and the member the collection provides for the same question.</summary>
    private static readonly Dictionary<string, string> Equivalent = new(StringComparer.Ordinal)
    {
        ["All"] = "TrueForAll",
        ["Any"] = "Exists",
        ["FirstOrDefault"] = "Find",
        ["Where"] = "FindAll",
        ["Count"] = "Count"
    };

    /// <summary>Types that answer these questions from their own structure.</summary>
    private static readonly string[] OwnMembers = ["List", "IList", "Array", "Collection"];

    public override string Key => "QG-CS-SML-0477";
    public override string Name => "A collection should answer with its own member";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!Equivalent.TryGetValue(name, out var member))
                continue;
            if (SyntaxQuery.Arguments(call).Count != 1)
                continue;

            // The type has to be resolvable: on a plain sequence the LINQ operator is the only
            // option, and guessing from the name would report every enumerable in the file. It does
            // not have to be declared in the scanned code, because these names belong to the
            // framework and mean one thing.
            var receiver = call.ChildAt(0);
            var type = context.Types.TypeOf(receiver is { Kind: NodeKind.MemberSelect }
                ? receiver.ChildAt(0)
                : receiver);
            if (type is not { Length: > 0 })
                continue;
            var bare = type.Split('<')[0].Split('.').Last().TrimEnd('[', ']');
            if (!OwnMembers.Contains(bare, StringComparer.Ordinal) || name == member)
                continue;

            context.Report($"'{bare}' has '{member}' for this, and it answers from its own storage "
                           + $"instead of walking the sequence through an enumerator that '{name}' "
                           + "sets up.", call.Range.StartLine);
        }
    }
}

public sealed class WeakKeySizeRule : OrmRuleBase
{
    /// <summary>Providers whose default key length is below what is usable today.</summary>
    private static readonly string[] WeakByDefault =
        ["RSACryptoServiceProvider", "DSACryptoServiceProvider"];

    private static readonly string[] Factories = ["Create", "GenerateKey", "KeySize"];

    public override string Key => "QG-CS-SEC-0094";
    public override string Name => "A cryptographic key should be long enough";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            var type = SyntaxQuery.SimpleName(creation.ChildAt(0));
            if (type.Length == 0)
                type = creation.Text;
            if (!WeakByDefault.Contains(type, StringComparer.Ordinal))
                continue;

            var size = SyntaxQuery.Arguments(creation).FirstOrDefault(a => a.Kind == NodeKind.NumberLiteral);
            if (size != null && int.TryParse(size.Text, out var bits) && bits >= 2048)
                continue;

            context.Report(size == null
                ? $"'{type}' defaults to a 1024-bit key, which is inside the range that is factored "
                  + "today with rented hardware. State a length of at least 2048."
                : $"A {size.Text}-bit key is inside the range that is factored today with rented "
                  + "hardware, so whatever it protects is protected only until someone decides it is "
                  + "worth the cost. Use at least 2048 bits.", creation.Range.StartLine);
        }

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, Factories))
        {
            var receiver = SyntaxQuery.Receiver(call);
            if (receiver is not ("RSA" or "DSA" or "System.Security.Cryptography.RSA"))
                continue;
            var size = SyntaxQuery.ArgumentAt(call, 0);
            if (size is not { Kind: NodeKind.NumberLiteral } || !int.TryParse(size.Text, out var bits))
                continue;
            if (bits >= 2048)
                continue;

            context.Report($"A {bits}-bit key is too short for this algorithm: keys of that length are "
                           + "factored today with rented hardware. Use at least 2048 bits.",
                call.Range.StartLine);
        }
    }
}
