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

    /// <summary>Name-based check kept for line/token rules; prefer the expression overload.</summary>
    public bool IsTainted(string identifier) => TaintedIdentifiers.Contains(identifier);

    public bool IsTaintedLine(int line) => TaintedLines.Contains(line);

    /// <summary>True when the expression carries data that originates from outside the program.</summary>
    public bool IsTainted(SyntaxNode? expression)
    {
        if (expression == null)
            return false;
        foreach (var node in expression.DescendantsAndSelf())
        {
            if (TaintEngine.IsSource(node))
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
        "params.Get", "c.Query", "c.Param", "c.PostForm"
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

    public static TaintResult Analyze(SyntaxTree tree, SemanticModel model)
    {
        var sources = tree.Root.DescendantsAndSelf().Where(IsSource).ToList();

        foreach (var symbol in model.AllSymbols())
        {
            symbol.IsTainted = false;
            symbol.TaintSource = null;
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
                    if (usage.Value == null || !CarriesTaint(usage.Value))
                        continue;
                    symbol.IsTainted = true;
                    symbol.TaintSource = SourceIn(usage.Value) ?? usage.Value;
                    changed = true;
                    break;
                }
            }
            changed |= PropagateThroughCalls(tree, model);
            if (!changed)
                break;
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
            Sources = sources
        };
    }

    /// <summary>Arguments flowing into a function declared in the same file taint its parameters.</summary>
    private static bool PropagateThroughCalls(SyntaxTree tree, SemanticModel model)
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
                if (!CarriesTaint(arguments[i]))
                    continue;
                var symbol = model.ScopeOf(function).Lookup(parameters[i].Text);
                if (symbol is null or { IsTainted: true })
                    continue;
                symbol.IsTainted = true;
                symbol.TaintSource = SourceIn(arguments[i]) ?? arguments[i];
                changed = true;
            }
        }
        return changed;
    }

    private static bool CarriesTaint(SyntaxNode value)
    {
        if (IsSanitized(value))
            return false;
        foreach (var node in value.DescendantsAndSelf())
        {
            if (IsSanitized(node) && node != value)
                continue;
            if (IsSource(node))
                return true;
            if (node.Kind == NodeKind.Identifier && node.Symbol is { IsTainted: true })
                return true;
        }
        return false;
    }

    private static SyntaxNode? SourceIn(SyntaxNode value)
        => value.DescendantsAndSelf().FirstOrDefault(IsSource);

    public static bool IsSource(SyntaxNode node)
    {
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
                return SourceNames.Contains(SyntaxQuery.InvokedName(node), StringComparer.Ordinal)
                       || MatchesMember(dotted);
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
