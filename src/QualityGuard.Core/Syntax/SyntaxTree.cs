using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax;

public sealed class SyntaxTree
{
    public required SyntaxNode Root { get; init; }
    public required IReadOnlyList<Token> Tokens { get; init; }
    public required SyntaxProfile Profile { get; init; }

    /// <summary>
    /// True when the tree comes from a grammar-driven parser. Rules that depend on precise structure
    /// (nesting, statement boundaries, parameter usage) only run on those trees.
    /// </summary>
    public bool HasDedicatedParser { get; init; }

    /// <summary>
    /// Builds the tree with the dedicated parser of the language when there is one, and with the generic
    /// structural parser otherwise. Dedicated parsers give a real grammar-driven AST.
    /// </summary>
    public static SyntaxTree Build(IReadOnlyList<Token> tokens, LanguageInfo language)
    {
        var profile = SyntaxProfile.For(language.LanguageKey);
        var dedicated = language.LanguageKey is LanguageKeys.CSharp or LanguageKeys.Java
            or LanguageKeys.Go or LanguageKeys.JavaScript or LanguageKeys.TypeScript
            or LanguageKeys.Python;
        var root = language.LanguageKey switch
        {
            LanguageKeys.CSharp => CSharp.CSharpParser.Parse(tokens, language),
            LanguageKeys.Java => CSharp.CSharpParser.Parse(tokens, language, CSharp.CFamilyDialect.Java),
            LanguageKeys.Go => CSharp.CSharpParser.Parse(tokens, language, CSharp.CFamilyDialect.Go),
            LanguageKeys.JavaScript => CSharp.CSharpParser.Parse(tokens, language, CSharp.CFamilyDialect.JavaScript),
            LanguageKeys.TypeScript => CSharp.CSharpParser.Parse(tokens, language, CSharp.CFamilyDialect.TypeScript),
            LanguageKeys.Python => Python.PythonParser.Parse(tokens, language),
            _ => StructureParser.Parse(tokens, profile)
        };
        return new SyntaxTree
        {
            Root = root, Tokens = tokens, Profile = profile, HasDedicatedParser = dedicated
        };
    }

    public IEnumerable<SyntaxNode> Nodes() => Root.DescendantsAndSelf();
}

/// <summary>Ancestor stack maintained while a <see cref="SyntaxVisitor"/> walks the tree.</summary>
public class SyntaxContext
{
    private readonly Stack<SyntaxNode> _ancestors = new();

    public IReadOnlyCollection<SyntaxNode> Ancestors => _ancestors;
    public SyntaxNode? Current { get; private set; }

    internal void Reset()
    {
        _ancestors.Clear();
        Current = null;
    }

    internal void Enter(SyntaxNode node)
    {
        if (Current != null)
            _ancestors.Push(Current);
        Current = node;
    }

    internal void Leave()
    {
        Current = _ancestors.Count > 0 ? _ancestors.Pop() : null;
    }
}

/// <summary>
/// Registration-based tree walker: a visitor subscribes to the node kinds it cares about instead of
/// overriding one method per node type.
/// </summary>
public class SyntaxVisitor<TContext> where TContext : SyntaxContext
{
    private readonly List<(NodeKind? Kind, Action<TContext, SyntaxNode> Handler)> _onEnter = [];
    private readonly List<(NodeKind? Kind, Action<TContext, SyntaxNode> Handler)> _onLeave = [];

    public SyntaxVisitor<TContext> Register(NodeKind kind, Action<TContext, SyntaxNode> handler)
    {
        _onEnter.Add((kind, handler));
        return this;
    }

    public SyntaxVisitor<TContext> RegisterAny(Action<TContext, SyntaxNode> handler)
    {
        _onEnter.Add((null, handler));
        return this;
    }

    public SyntaxVisitor<TContext> RegisterOnLeave(NodeKind kind, Action<TContext, SyntaxNode> handler)
    {
        _onLeave.Add((kind, handler));
        return this;
    }

    public void Scan(TContext context, SyntaxNode root)
    {
        context.Reset();
        Visit(context, root);
    }

    private void Visit(TContext context, SyntaxNode node)
    {
        context.Enter(node);
        Dispatch(_onEnter, context, node);
        foreach (var child in node.Children)
            Visit(context, child);
        Dispatch(_onLeave, context, node);
        context.Leave();
    }

    private static void Dispatch(List<(NodeKind? Kind, Action<TContext, SyntaxNode> Handler)> handlers,
        TContext context, SyntaxNode node)
    {
        foreach (var (kind, handler) in handlers)
        {
            if (kind == null || kind == node.Kind)
                handler(context, node);
        }
    }
}

public sealed class SyntaxVisitor : SyntaxVisitor<SyntaxContext>;
