using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Analysis;

/// <summary>One step of a source-to-sink data flow, reported alongside the issue.</summary>
public sealed record FlowStep(int Line, string Description);

public sealed class TaintResult
{
    public required IReadOnlySet<string> TaintedIdentifiers { get; init; }
    public required IReadOnlySet<int> TaintedLines { get; init; }
    public required IReadOnlyList<Symbol> TaintedSymbols { get; init; }
    public required IReadOnlyList<SyntaxNode> Sources { get; init; }

    /// <summary>What the rest of the scan knows about untrusted data.</summary>
    public TaintContext Context { get; init; } = TaintContext.Empty;

    /// <summary>Name-based check kept for line/token rules; prefer the expression overload.</summary>
    public bool IsTainted(string identifier) => TaintedIdentifiers.Contains(identifier);

    public bool IsTaintedLine(int line) => TaintedLines.Contains(line);

    /// <summary>True when the expression carries data that originates from outside the program.</summary>
    public bool IsTainted(SyntaxNode? expression)
    {
        if (expression == null)
            return false;
        // an expression of unbounded size is walked once per rule; past a few hundred nodes the
        // answer stops being worth the quadratic cost, and "unknown" keeps the rules silent
        var budget = 512;
        foreach (var node in expression.DescendantsAndSelf())
        {
            if (--budget <= 0)
                return false;
            if (TaintEngine.IsSource(node, Context))
                return true;
            if (node.Kind == NodeKind.Identifier && node.Symbol is { IsTainted: true })
                return true;
            if (node.Kind == NodeKind.Identifier && node.Symbol == null && TaintedIdentifiers.Contains(node.Text))
                return true;
        }
        return false;
    }

    /// <summary>Source → propagation → sink trail for the given sink expression.</summary>
    public IReadOnlyList<FlowStep> FlowTo(SyntaxNode sink)
    {
        var steps = new List<FlowStep>();
        foreach (var call in sink.DescendantsAndSelf().Where(n => n.Kind == NodeKind.Invocation))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (Context.OriginOf(name) is not { } origin)
                continue;
            steps.Add(new FlowStep(origin.Line,
                $"'{name}' returns data that enters the program in {System.IO.Path.GetFileName(origin.File)}"));
        }
        foreach (var node in sink.DescendantsAndSelf())
        {
            if (node.Kind != NodeKind.Identifier || node.Symbol is not { IsTainted: true } symbol)
                continue;
            if (symbol.TaintSource is { } source)
                steps.Add(new FlowStep(source.Line, "external input enters the program here"));
            foreach (var usage in symbol.Usages.Where(u => u.Kind is UsageKind.Declaration or UsageKind.Assignment))
                steps.Add(new FlowStep(usage.Line, $"tainted value stored in '{symbol.Name}'"));
            break;
        }
        steps.Add(new FlowStep(sink.Line, "tainted value reaches this sink"));
        return steps.DistinctBy(s => (s.Line, s.Description)).OrderBy(s => s.Line).ToList();
    }
}

/// <summary>
/// Data-flow pass over the syntax tree: marks the symbols that can hold attacker-controlled values,
/// following declarations, assignments and calls inside the file, and stopping at sanitizers.
/// Working on symbols instead of raw names makes the result scope-correct.
/// </summary>
public static class TaintEngine
{
    private const int MaxPasses = 6;

    private static readonly string[] SourceNames =
    [
        "getenv", "getParameter", "getParameterValues", "getQueryString", "getRequestURI", "getHeader",
        "getInputStream", "getCookies", "getUserPrincipal", "getReader", "readLine", "input", "raw_input",
        "argv", "args", "ARGV", "getRemoteUser", "getPathInfo", "getRequestURL", "getPart"
    ];

    private static readonly string[] SourceMembers =
    [
        "os.environ", "os.getenv", "sys.argv", "System.getenv", "System.getProperty",
        "Request.QueryString", "Request.Query", "Request.Form", "Request.Params", "Request.Body",
        "Request.Headers", "Request.Cookies", "Request.RouteValues", "HttpContext.Request",
        "request.query", "request.params", "request.body", "request.args", "request.form", "request.files",
        "req.query", "req.params", "req.body", "req.headers", "ctx.query", "ctx.params", "ctx.request.body",
        "event.queryStringParameters", "location.search", "location.hash", "document.location",
        "window.name", "navigationManager.Uri", "NavigationManager.Uri", "r.URL", "r.Form", "r.Body",
        "params.Get", "c.Query", "c.Param", "c.PostForm",
        "Request.Url", "Request.Path", "Request.PathAndQuery", "Request.RawUrl",
        "request.url", "request.path", "request.uri", "request.queryString",
        "ctx.request.url", "ctx.request.path"
    ];

    private static readonly string[] Superglobals =
    [
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER", "$_SESSION",
        "_GET", "_POST", "_REQUEST", "_COOKIE", "argv"
    ];

    private static readonly string[] SanitizerNames =
    [
        "escape", "escapeHtml", "escapeShellArg", "escapeshellarg", "escapeshellcmd", "htmlspecialchars",
        "htmlentities", "encodeURIComponent", "encodeURI", "HtmlEncode", "UrlEncode", "JavaScriptEncode",
        "sanitize", "sanitized", "clean", "validate", "isValid", "whitelist", "allowlist", "quote",
        "quoteIdentifier", "parseInt", "parseFloat", "Parse", "TryParse", "ToInt32", "ToInt64", "ToDouble",
        "atoi", "int", "float", "Integer", "Long", "Double", "Regex", "Escape", "hash", "digest", "uuid",
        "Guid", "Base64", "toBase64", "encodeBase64", "getId", "Sanitizer", "Encode"
    ];

    public static TaintResult Analyze(SyntaxTree tree, SemanticModel model, TaintContext? shared = null,
        bool keepExistingMarks = false)
    {
        var context = shared ?? TaintContext.Empty;
        var sources = tree.Root.DescendantsAndSelf().Where(node => IsSource(node, context)).ToList();

        if (!keepExistingMarks)
        {
            foreach (var symbol in model.AllSymbols())
            {
                symbol.IsTainted = false;
                symbol.TaintSource = null;
            }
        }

        for (var pass = 0; pass < MaxPasses; pass++)
        {
            var changed = false;
            foreach (var symbol in model.AllSymbols())
            {
                if (symbol.IsTainted)
                    continue;
                foreach (var usage in symbol.Usages)
                {
                    if (usage.Value == null || !CarriesTaint(usage.Value, context))
                        continue;
                    symbol.IsTainted = true;
                    symbol.TaintSource = SourceIn(usage.Value, context) ?? usage.Value;
                    changed = true;
                    break;
                }
            }
            changed |= PropagateThroughCalls(tree, model, context);
            if (!changed)
                break;
        }

        // flow sensitivity, straight-line form: a variable ends up as clean as its LAST assignment.
        // Without this step a value sanitized between source and sink stayed flagged forever - the
        // exact shape the OWASP Benchmark uses for most of its safe variants. Scoping is per
        // function: two locals sharing a name in different functions must not clean each other
        foreach (var group in tree.Root.OfKind(NodeKind.Assignment)
                     .Where(a => a.ChildAt(0)?.Kind == NodeKind.Identifier)
                     .GroupBy(a => new
                     {
                         Name = a.ChildAt(0)!.Text,
                         Owner = a.Ancestor(NodeKind.FunctionDeclaration)
                                  ?? a.Ancestor(NodeKind.LocalFunction)
                     }))
        {
            var finalValue = group.Last().ChildAt(1);
            var cleaned = finalValue == null
                          || finalValue.Kind is NodeKind.StringLiteral or NodeKind.NumberLiteral
                          || IsSanitized(finalValue)
                          || (finalValue.Kind == NodeKind.Invocation
                              && SanitizerNames.Contains(SyntaxQuery.InvokedName(finalValue),
                                  StringComparer.Ordinal));
            if (!cleaned || group.Key.Owner == null)
                continue;
            foreach (var symbol in model.AllSymbols()
                         .Where(s => s.IsTainted
                                     && s.Name == group.Key.Name
                                     && s.Usages.Count > 0
                                     && s.Usages.All(u =>
                                         group.Key.Owner.Range.ContainsLine(u.Line))))
                symbol.IsTainted = false;
        }

        var tainted = model.AllSymbols().Where(s => s.IsTainted).ToList();
        var names = new HashSet<string>(tainted.Select(s => s.Name), StringComparer.Ordinal);
        var lines = new HashSet<int>();
        foreach (var symbol in tainted)
            foreach (var usage in symbol.Usages)
                lines.Add(usage.Line);
        foreach (var source in sources)
            lines.Add(source.Line);

        return new TaintResult
        {
            TaintedIdentifiers = names,
            TaintedLines = lines,
            TaintedSymbols = tainted,
            Sources = sources,
            Context = context
        };
    }

    /// <summary>Arguments flowing into a function declared in the same file taint its parameters.</summary>
    private static bool PropagateThroughCalls(SyntaxTree tree, SemanticModel model, TaintContext context)
    {
        var functions = SyntaxQuery.Functions(tree.Root)
            .Where(f => !string.IsNullOrEmpty(f.Text))
            .GroupBy(f => f.Text, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        if (functions.Count == 0)
            return false;

        var changed = false;
        foreach (var invocation in SyntaxQuery.Invocations(tree.Root))
        {
            if (!functions.TryGetValue(SyntaxQuery.InvokedName(invocation), out var function))
                continue;
            var parameters = SyntaxQuery.Parameters(function).ToList();
            var arguments = SyntaxQuery.Arguments(invocation);
            for (var i = 0; i < parameters.Count && i < arguments.Count; i++)
            {
                if (!CarriesTaint(arguments[i], context))
                    continue;
                var symbol = model.ScopeOf(function).Lookup(parameters[i].Text);
                if (symbol is null or { IsTainted: true })
                    continue;
                symbol.IsTainted = true;
                symbol.TaintSource = SourceIn(arguments[i], context) ?? arguments[i];
                changed = true;
            }
        }
        return changed;
    }

    /// <summary>
    /// Calls that build the application out of what they are given. 'WebApplication.CreateBuilder(args)'
    /// reads the command line, but what comes back is the host: treating every member of it as
    /// attacker-controlled marked the whole program, starting with its own configuration.
    /// </summary>
    private static readonly string[] HostFactories =
    [
        "CreateBuilder", "CreateDefaultBuilder", "CreateApplicationBuilder", "CreateHostBuilder",
        "CreateSlimBuilder", "CreateEmptyBuilder", "BuildServiceProvider", "AddCommandLine"
    ];

    internal static bool CarriesTaint(SyntaxNode value, TaintContext context)
    {
        if (IsSanitized(value))
            return false;
        if (value.Kind == NodeKind.Invocation
            && HostFactories.Contains(SyntaxQuery.InvokedName(value), StringComparer.Ordinal))
            return false;
        foreach (var node in value.DescendantsAndSelf())
        {
            if (IsSanitized(node) && node != value)
                continue;
            if (IsSource(node, context))
                return true;
            if (node.Kind == NodeKind.Identifier && node.Symbol is { IsTainted: true })
                return true;
        }
        return false;
    }

    private static SyntaxNode? SourceIn(SyntaxNode value, TaintContext context)
        => value.DescendantsAndSelf().FirstOrDefault(node => IsSource(node, context));

    public static bool IsSource(SyntaxNode node, TaintContext? shared = null)
    {
        var context = shared ?? TaintContext.Empty;
        switch (node.Kind)
        {
            case NodeKind.Identifier:
                return Superglobals.Contains(node.Text, StringComparer.Ordinal)
                       || SourceNames.Contains(node.Text, StringComparer.Ordinal);
            case NodeKind.MemberSelect:
            case NodeKind.Index:
                return MatchesMember(SyntaxQuery.DottedName(node));
            case NodeKind.Invocation:
                var dotted = SyntaxQuery.InvokedDottedName(node);
                var simple = SyntaxQuery.InvokedName(node);
                return SourceNames.Contains(simple, StringComparer.Ordinal)
                       || MatchesMember(dotted)
                       || context.ReturnsTainted(simple);
            default:
                return false;
        }
    }

    private static bool MatchesMember(string dotted)
    {
        if (dotted.Length == 0)
            return false;
        foreach (var member in SourceMembers)
        {
            if (dotted.Equals(member, StringComparison.Ordinal)
                || dotted.EndsWith("." + member, StringComparison.Ordinal)
                || dotted.StartsWith(member + ".", StringComparison.Ordinal))
                return true;
        }
        return Superglobals.Any(s => dotted.StartsWith(s, StringComparison.Ordinal));
    }

    /// <summary>A value produced by an escaping, encoding or parsing helper is no longer attacker-shaped.</summary>
    public static bool IsSanitized(SyntaxNode node)
        => node.Kind == NodeKind.Invocation
           && SanitizerNames.Contains(SyntaxQuery.InvokedName(node), StringComparer.OrdinalIgnoreCase);
}
