using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Semantics;

/// <summary>
/// Scope tree plus symbol table for one file. Built once per analysis and shared by every rule,
/// so identifier resolution and value lookups cost nothing per rule.
/// </summary>
public sealed class SemanticModel
{
    private readonly Dictionary<SyntaxNode, Scope> _scopeByNode = new();

    private SemanticModel(Scope fileScope)
    {
        FileScope = fileScope;
    }

    public Scope FileScope { get; }

    public IEnumerable<Symbol> AllSymbols() => FileScope.AllSymbols();

    public Scope ScopeOf(SyntaxNode node)
    {
        for (var current = node; current != null; current = current.Parent)
        {
            if (_scopeByNode.TryGetValue(current, out var scope))
                return scope;
        }
        return FileScope;
    }

    /// <summary>Symbol an identifier node refers to, resolved through the scope chain.</summary>
    public Symbol? Resolve(SyntaxNode identifier)
        => identifier.Symbol ?? ScopeOf(identifier).Lookup(identifier.Text);

    public Symbol? Resolve(string name, SyntaxNode at) => ScopeOf(at).Lookup(name);

    /// <summary>Literal value an expression evaluates to, following effectively-final symbols.</summary>
    public string? StringValueOf(SyntaxNode? expression)
    {
        if (expression == null)
            return null;
        if (expression.Kind == NodeKind.Identifier)
            return Resolve(expression)?.SafeStringValue();
        return SyntaxQuery.ConstantString(expression);
    }

    public static SemanticModel Build(SyntaxTree tree)
    {
        var fileScope = new Scope(ScopeKind.File, tree.Root, null);
        var model = new SemanticModel(fileScope);
        model._scopeByNode[tree.Root] = fileScope;
        new SymbolTableBuilder(model, tree.Profile).Walk(tree.Root, fileScope);
        return model;
    }

    private sealed class SymbolTableBuilder(SemanticModel model, SyntaxProfile profile)
    {
        // assignments already accounted for by their enclosing declaration
        private readonly HashSet<SyntaxNode> _consumed = [];

        /// <summary>
        /// Builds the symbol table in reading order. The traversal keeps its own stack because a
        /// deeply nested file — generated code, a minified script, a page read by the generic parser —
        /// is exactly the input that would overflow a recursive walk.
        /// </summary>
        public void Walk(SyntaxNode root, Scope rootScope)
        {
            var pending = new Stack<(SyntaxNode Node, Scope Scope)>();
            Push(pending, root, rootScope);

            while (pending.Count > 0)
            {
                var (child, scope) = pending.Pop();
                var childScope = scope;
                switch (child.Kind)
                {
                    case NodeKind.ClassDeclaration:
                        childScope = OpenScope(ScopeKind.Class, child, scope);
                        break;
                    case NodeKind.FunctionDeclaration:
                        childScope = OpenScope(ScopeKind.Function, child, scope);
                        DeclareParameters(child, childScope);
                        break;
                    // a function body shares the scope that holds its parameters
                    case NodeKind.Block when child.Parent?.Kind != NodeKind.FunctionDeclaration:
                        childScope = OpenScope(ScopeKind.Block, child, scope);
                        break;
                    case NodeKind.VariableDeclaration:
                        DeclareVariable(child, scope);
                        break;
                    case NodeKind.Assignment when !_consumed.Contains(child):
                        RecordAssignment(child, scope);
                        break;
                    case NodeKind.Identifier:
                        RecordReference(child, scope);
                        break;
                }
                Push(pending, child, childScope);
            }
        }

        private static void Push(Stack<(SyntaxNode, Scope)> pending, SyntaxNode node, Scope scope)
        {
            var children = node.Children;
            for (var i = children.Count - 1; i >= 0; i--)
                pending.Push((children[i], scope));
        }

        private Scope OpenScope(ScopeKind kind, SyntaxNode node, Scope parent)
        {
            var scope = new Scope(kind, node, parent);
            model._scopeByNode[node] = scope;
            return scope;
        }

        private void DeclareParameters(SyntaxNode function, Scope functionScope)
        {
            foreach (var parameter in SyntaxQuery.Parameters(function))
            {
                if (string.IsNullOrEmpty(parameter.Text))
                    continue;
                // the parser records the declared type as a TypeReference; the identifier fallback
                // is for the dialects that carry the type as a plain name
                var type = (parameter.FirstChild(NodeKind.TypeReference)
                            ?? parameter.FirstChild(NodeKind.Identifier))?.Text;
                var symbol = functionScope.Declare(parameter.Text, type);
                symbol.Usages.Add(new Usage(parameter, null, UsageKind.Parameter));
            }
        }

        private void DeclareVariable(SyntaxNode declaration, Scope scope)
        {
            var name = declaration.Text;
            var assignment = declaration.Descendants().FirstOrDefault(d => d.Kind == NodeKind.Assignment);
            var value = assignment?.ChildAt(1);
            if (string.IsNullOrEmpty(name))
                name = SyntaxQuery.DottedName(assignment?.ChildAt(0));

            // Python unpacks into several names at once — 'first, second = pair'. The target is a
            // tuple rather than a single name, and reading only a name declared nothing at all, so
            // every one of those variables was invisible to the rules that follow a value's life.
            // an index is a ListLiteral too — 'counts[key] += 1' — and reading it as a target
            // declared the container afresh, so the value it already held looked unread
            if (assignment?.ChildAt(0) is { Kind: NodeKind.ListLiteral, Text: "tuple" } tuple)
            {
                _consumed.Add(assignment);
                foreach (var target in tuple.ChildrenOf(NodeKind.Identifier))
                {
                    if (target.Text.Length == 0 || target.Text == "_")
                        continue;
                    var unpacked = scope.Declare(target.Text, InferType(declaration, null));
                    unpacked.IsExplicitlyDeclared = true;
                    target.Symbol = unpacked;
                    unpacked.Usages.Add(new Usage(target, assignment.ChildAt(1), UsageKind.Declaration));
                }
                return;
            }

            if (string.IsNullOrEmpty(name))
                return;

            if (assignment != null)
                _consumed.Add(assignment);

            var symbol = scope.Declare(name, InferType(declaration, value));
            symbol.IsExplicitlyDeclared = true;
            var identifier = declaration.Descendants().FirstOrDefault(d => d.Kind == NodeKind.Identifier && d.Text == name)
                             ?? declaration;
            identifier.Symbol = symbol;
            symbol.Usages.Add(new Usage(identifier, value, UsageKind.Declaration));

            // 'Comune roma, milano, firenze;' declares three names and the node carries one. The
            // others were never declared, so nothing that followed them was tracked: every rule
            // about a variable's life saw only the first of the group.
            foreach (var extra in declaration.ChildrenOf(NodeKind.Identifier))
            {
                if (extra == identifier || extra.Text.Length == 0 || extra.Text == name)
                    continue;
                var other = scope.Declare(extra.Text, InferType(declaration, null));
                other.IsExplicitlyDeclared = true;
                extra.Symbol = other;
                other.Usages.Add(new Usage(extra, null, UsageKind.Declaration));
            }
        }

        private void RecordAssignment(SyntaxNode assignment, Scope scope)
        {
            var target = assignment.ChildAt(0);
            var value = assignment.ChildAt(1);
            if (target == null)
                return;

            var name = target.Kind == NodeKind.Identifier ? target.Text : SyntaxQuery.DottedName(target);
            if (string.IsNullOrEmpty(name))
                return;

            var symbol = scope.Lookup(name);
            if (symbol == null)
            {
                // dynamic languages introduce variables on first assignment
                var owner = profile.Style == StructureStyle.Braces ? scope : scope.FunctionScope();
                symbol = owner.Declare(name, InferType(assignment, value));
                symbol.Usages.Add(new Usage(target, value, UsageKind.Declaration));
            }
            else
            {
                symbol.Usages.Add(new Usage(target, value, UsageKind.Assignment));
                symbol.DeclaredType ??= InferType(assignment, value);
            }
            target.Symbol = symbol;
        }

        private void RecordReference(SyntaxNode identifier, Scope scope)
        {
            if (identifier.Symbol != null)
                return;
            var symbol = scope.Lookup(identifier.Text);
            if (symbol == null)
                return;
            identifier.Symbol = symbol;
            symbol.Usages.Add(new Usage(identifier, null, UsageKind.Reference));
        }

        /// <summary>Best-effort type: declared type token, constructed type, or literal kind.</summary>
        private string? InferType(SyntaxNode declaration, SyntaxNode? value)
        {
            if (value != null)
            {
                switch (value.Kind)
                {
                    case NodeKind.ObjectCreation:
                        return value.Text;
                    case NodeKind.StringLiteral:
                        return "string";
                    case NodeKind.NumberLiteral:
                        return value.Text.Contains('.') ? "double" : "int";
                    case NodeKind.BooleanLiteral:
                        return "bool";
                    case NodeKind.Invocation:
                        // the name of the called method is not the type of the result: claiming it
                        // would make every comparison between two such values look impossible.
                        // Resolving the real return type is the job of the type resolver.
                        return null;
                }
            }

            var tokens = declaration.Tokens;
            if (tokens.Count >= 2 && tokens[0].Kind is TokenKind.Identifier or TokenKind.Keyword
                                 && !profile.IsVariableKeyword(tokens[0].Text)
                                 && tokens[1].Kind == TokenKind.Identifier)
                return tokens[0].Text;

            // annotated declarations: name: Type = value
            for (var i = 1; i < tokens.Count - 1; i++)
            {
                if (tokens[i].Kind == TokenKind.Symbol && tokens[i].Text == ":"
                    && tokens[i + 1].Kind is TokenKind.Identifier or TokenKind.Keyword)
                    return tokens[i + 1].Text;
            }
            return null;
        }
    }
}
