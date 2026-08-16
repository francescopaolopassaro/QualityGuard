using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax;

/// <summary>
/// Builds the statement/block skeleton of a file from its tokens, then delegates every statement
/// slice to <see cref="ExpressionParser"/>. Four block styles cover all supported languages.
/// </summary>
public static class StructureParser
{
    /// <summary>
    /// Longest slice still worth parsing as an expression. A statement written by a person never
    /// comes close; what does is a file with no statement terminator the parser recognises — a page
    /// of markup, a minified bundle — where the whole file arrives as one slice and the operator
    /// chain built from it is as deep as the file is long. Past this point the statement keeps its
    /// tokens and gives up on its shape, which is what every rule needs anyway.
    /// </summary>
    private const int MaxExpressionTokens = 512;

    public static SyntaxNode Parse(IReadOnlyList<Token> tokens, SyntaxProfile profile)
    {
        var code = tokens.Where(t => t.Kind != TokenKind.Comment).ToArray();
        var root = new SyntaxNode(NodeKind.TopLevel, "", TextRange.Of(tokens), tokens);
        if (code.Length == 0)
            return root;

        switch (profile.Style)
        {
            case StructureStyle.Braces:
                new BraceParser(code, profile).Fill(root);
                break;
            case StructureStyle.Indentation:
                new IndentParser(code, profile).Fill(root);
                break;
            case StructureStyle.EndKeyword:
                new EndKeywordParser(code, profile).Fill(root);
                break;
            default:
                new FlatParser(code, profile).Fill(root);
                break;
        }
        return root;
    }

    /// <summary>Classifies a statement slice and builds the matching node (header + expression children).</summary>
    internal static SyntaxNode BuildStatement(IReadOnlyList<Token> slice, SyntaxProfile profile)
    {
        var range = TextRange.Of(slice);
        var first = slice[0].Text;
        var kind = ClassifyStatement(slice, profile, out var name);

        var node = new SyntaxNode(kind, name, range, slice);

        switch (kind)
        {
            case NodeKind.FunctionDeclaration:
                node.Add(BuildParameterList(slice, range));
                break;
            case NodeKind.ImportDeclaration:
            case NodeKind.PackageDeclaration:
                break;
            case NodeKind.ClassDeclaration:
                break;
            default:
                var expressionTokens = StripLeadingKeywords(slice, profile, kind);
                if (expressionTokens.Count <= MaxExpressionTokens
                    && ExpressionParser.Parse(expressionTokens) is { } expression)
                    node.Add(expression);
                break;
        }

        if (kind is NodeKind.If or NodeKind.Loop or NodeKind.Match or NodeKind.Catch && node.Text.Length == 0)
            node.Text = first;

        return node;
    }

    /// <summary>
    /// Words that may stand in front of a declaration keyword. Kotlin, Swift and Rust write
    /// 'private const val x', so looking only at the first token of the statement misses the
    /// declaration entirely and leaves it as a nameless expression.
    /// </summary>
    private static readonly string[] LeadingModifiers =
    [
        "public", "private", "protected", "internal", "fileprivate", "open", "final", "sealed",
        "abstract", "static", "const", "lateinit", "override", "expect", "actual", "external",
        "inline", "noinline", "crossinline", "suspend", "operator", "infix", "tailrec", "data",
        "annotation", "companion", "readonly", "weak", "unowned", "lazy", "mutating", "nonmutating",
        "pub", "export", "global", "shared", "class"
    ];

    private static bool DeclaresVariable(IReadOnlyList<Token> slice, SyntaxProfile profile)
    {
        for (var i = 0; i < slice.Count && i < 6; i++)
        {
            var token = slice[i];
            if (token.Kind is not (TokenKind.Identifier or TokenKind.Keyword))
                return false;
            if (profile.IsVariableKeyword(token.Text))
                return true;
            if (!LeadingModifiers.Contains(token.Text, StringComparer.OrdinalIgnoreCase))
                return false;
        }
        return false;
    }

    private static NodeKind ClassifyStatement(IReadOnlyList<Token> slice, SyntaxProfile profile, out string name)
    {
        name = string.Empty;
        var words = slice.Where(t => t.Kind is TokenKind.Identifier or TokenKind.Keyword).ToArray();
        var first = slice[0].Text;

        // A declaration keyword lives in the header of the statement, before the first parenthesis,
        // brace or equals sign. Searching the whole slice reads 'Foo::class.java' as a class called
        // java, and a 'when' branch that mentions fun as a function.
        foreach (var token in slice)
        {
            if (token.Kind == TokenKind.Symbol && token.Text is "=" or "(" or "{")
                break;
            if (profile.IsFunctionKeyword(token.Text) && token.Kind is TokenKind.Identifier or TokenKind.Keyword)
            {
                name = NameAfter(slice, token) ?? string.Empty;
                return NodeKind.FunctionDeclaration;
            }
            if (profile.IsClassKeyword(token.Text) && token.Kind is TokenKind.Identifier or TokenKind.Keyword)
            {
                name = NameAfter(slice, token) ?? string.Empty;
                return NodeKind.ClassDeclaration;
            }
        }

        if (profile.IsImportKeyword(first))
        {
            name = words.Length > 1 ? words[1].Text : string.Empty;
            return first is "package" or "namespace" ? NodeKind.PackageDeclaration : NodeKind.ImportDeclaration;
        }

        switch (LowerIf(first, profile))
        {
            case "if" or "elif" or "elsif" or "unless":
                return NodeKind.If;
            case "else" or "elseif":
                return NodeKind.Else;
            case "for" or "foreach" or "while" or "until" or "do" or "loop" or "repeat":
                return NodeKind.Loop;
            case "switch" or "select" or "match" when slice.Count > 1:
                return NodeKind.Match;
            case "case" or "when" or "default":
                return NodeKind.MatchCase;
            case "return" or "break" or "continue" or "goto" or "throw" or "raise" or "yield" or "exit":
                return NodeKind.Jump;
            case "try" or "begin":
                return NodeKind.Try;
            case "catch" or "except" or "rescue":
                return NodeKind.Catch;
            case "finally" or "ensure":
                return NodeKind.Finally;
        }

        if (DeclaresVariable(slice, profile) || IsTypedDeclaration(slice, profile))
        {
            name = DeclaredName(slice, profile) ?? string.Empty;
            return NodeKind.VariableDeclaration;
        }

        if (profile.CStyleSignatures && LooksLikeSignature(slice, out var signatureName))
        {
            name = signatureName;
            return NodeKind.FunctionDeclaration;
        }

        return NodeKind.ExpressionStatement;
    }

    private static string LowerIf(string text, SyntaxProfile profile)
        => profile.CaseInsensitive ? text.ToLowerInvariant() : text;

    private static string? NameAfter(IReadOnlyList<Token> slice, Token keyword)
    {
        var index = -1;
        for (var i = 0; i < slice.Count; i++)
        {
            if (ReferenceEquals(slice[i], keyword))
            {
                index = i;
                break;
            }
        }
        for (var i = index + 1; i < slice.Count; i++)
        {
            if (slice[i].Kind is TokenKind.Identifier or TokenKind.Keyword)
                return slice[i].Text;
        }
        return null;
    }

    /// <summary>Recognizes <c>Type name = value</c> declarations in statically typed languages.</summary>
    private static bool IsTypedDeclaration(IReadOnlyList<Token> slice, SyntaxProfile profile)
    {
        if (!profile.CStyleSignatures || slice.Count < 3)
            return false;
        if (slice[0].Kind is not (TokenKind.Identifier or TokenKind.Keyword))
            return false;
        var second = slice[1];
        if (second.Kind != TokenKind.Identifier)
            return false;
        var third = slice[2].Text;
        return third is "=" or ";" or "," or ")";
    }

    private static string? DeclaredName(IReadOnlyList<Token> slice, SyntaxProfile profile)
    {
        for (var i = 0; i < slice.Count; i++)
        {
            if (slice[i].Kind != TokenKind.Identifier)
                continue;
            if (profile.IsVariableKeyword(slice[i].Text))
                continue;
            var next = i + 1 < slice.Count ? slice[i + 1].Text : null;
            if (next is "=" or ":" or ";" or "," or null)
                return slice[i].Text;
        }
        return slice.FirstOrDefault(t => t.Kind == TokenKind.Identifier)?.Text;
    }

    /// <summary>Detects a keyword-less method signature such as <c>public User getUser(Connection con)</c>.</summary>
    private static bool LooksLikeSignature(IReadOnlyList<Token> slice, out string name)
    {
        name = string.Empty;
        var openParen = -1;
        for (var i = 1; i < slice.Count; i++)
        {
            if (slice[i].Kind == TokenKind.Symbol && slice[i].Text == "(")
            {
                openParen = i;
                break;
            }
            if (slice[i].Kind == TokenKind.Symbol && slice[i].Text is "=" or ";" or ".")
                return false;
        }
        if (openParen < 2 || slice[openParen - 1].Kind != TokenKind.Identifier)
            return false;
        var beforeName = slice[openParen - 2];
        if (beforeName.Kind is not (TokenKind.Identifier or TokenKind.Keyword) && beforeName.Text is not (">" or "]"))
            return false;
        name = slice[openParen - 1].Text;
        return true;
    }

    private static SyntaxNode BuildParameterList(IReadOnlyList<Token> slice, TextRange range)
    {
        var list = new SyntaxNode(NodeKind.ParameterList, "", range, slice);
        var depth = 0;
        var start = -1;
        for (var i = 0; i < slice.Count; i++)
        {
            var text = slice[i].Text;
            if (slice[i].Kind != TokenKind.Symbol)
                continue;
            if (text == "(")
            {
                depth++;
                if (depth == 1)
                    start = i + 1;
                continue;
            }
            if (text == ")")
            {
                depth--;
                if (depth == 0 && start >= 0)
                {
                    AddParameters(list, slice, start, i);
                    return list;
                }
            }
        }
        return list;
    }

    private static void AddParameters(SyntaxNode list, IReadOnlyList<Token> slice, int start, int end)
    {
        var current = new List<Token>();
        var depth = 0;
        for (var i = start; i < end; i++)
        {
            var token = slice[i];
            if (token.Kind == TokenKind.Symbol)
            {
                if (token.Text is "(" or "[" or "<")
                    depth++;
                else if (token.Text is ")" or "]" or ">")
                    depth--;
                else if (token.Text == "," && depth == 0)
                {
                    AddParameter(list, current);
                    current = [];
                    continue;
                }
            }
            current.Add(token);
        }
        AddParameter(list, current);
    }

    private static void AddParameter(SyntaxNode list, List<Token> tokens)
    {
        if (tokens.Count == 0)
            return;
        // parameter name: last identifier before a default value, otherwise the last identifier
        var equals = tokens.FindIndex(t => t.Kind == TokenKind.Symbol && t.Text == "=");
        var searchable = equals > 0 ? tokens.Take(equals).ToList() : tokens;
        var nameToken = searchable.LastOrDefault(t => t.Kind == TokenKind.Identifier) ?? tokens[0];
        var type = searchable.Count > 1 && !ReferenceEquals(searchable[^1], nameToken)
            ? searchable[^1].Text
            : searchable.Count > 1 ? searchable[0].Text : string.Empty;
        if (searchable.Count > 1 && ReferenceEquals(searchable[^1], nameToken))
            type = searchable[^2].Text;
        var parameter = new SyntaxNode(NodeKind.Parameter, nameToken.Text, TextRange.Of(tokens), tokens.ToArray());
        if (!string.IsNullOrEmpty(type) && type != nameToken.Text)
            parameter.Add(new SyntaxNode(NodeKind.Identifier, type, parameter.Range, parameter.Tokens));
        list.Add(parameter);
    }

    private static IReadOnlyList<Token> StripLeadingKeywords(IReadOnlyList<Token> slice, SyntaxProfile profile,
        NodeKind kind)
    {
        if (kind is NodeKind.If or NodeKind.Loop or NodeKind.Match or NodeKind.Jump or NodeKind.Catch
            or NodeKind.MatchCase or NodeKind.Else or NodeKind.Try or NodeKind.Finally)
        {
            var skip = 1;
            // "else if", "do while", "for each"
            if (slice.Count > 1 && profile.IsBlockKeyword(slice[1].Text))
                skip = 2;
            return slice.Skip(skip).ToArray();
        }
        if (kind == NodeKind.VariableDeclaration && profile.IsVariableKeyword(slice[0].Text))
            return slice.Skip(1).ToArray();
        return slice;
    }

    /// <summary>Shared statement buffer bookkeeping for the concrete block styles.</summary>
    internal abstract class ParserBase
    {
        protected readonly IReadOnlyList<Token> Tokens;
        protected readonly SyntaxProfile Profile;
        protected readonly List<Token> Buffer = [];

        protected ParserBase(IReadOnlyList<Token> tokens, SyntaxProfile profile)
        {
            Tokens = tokens;
            Profile = profile;
        }

        public abstract void Fill(SyntaxNode root);

        protected SyntaxNode? FlushBuffer(SyntaxNode parent)
        {
            if (Buffer.Count == 0)
                return null;
            var statement = BuildStatement(Buffer.ToArray(), Profile);
            parent.Add(statement);
            Buffer.Clear();
            return statement;
        }

        protected static bool OpensBody(SyntaxNode node)
            => node.Kind is NodeKind.FunctionDeclaration or NodeKind.ClassDeclaration or NodeKind.If
                or NodeKind.Else or NodeKind.Loop or NodeKind.Match or NodeKind.MatchCase or NodeKind.Try
                or NodeKind.Catch or NodeKind.Finally;
    }

    internal sealed class BraceParser(IReadOnlyList<Token> tokens, SyntaxProfile profile)
        : ParserBase(tokens, profile)
    {
        /// <summary>Statement that may still take ownership of the next block or single statement.</summary>
        private SyntaxNode? _pendingOwner;

        public override void Fill(SyntaxNode root)
        {
            var scopes = new Stack<SyntaxNode>();
            scopes.Push(root);
            var depth = 0; // parenthesis/bracket depth
            Token? previous = null;

            for (var i = 0; i < Tokens.Count; i++)
            {
                var token = Tokens[i];
                if (token.Kind == TokenKind.Symbol)
                {
                    switch (token.Text)
                    {
                        case "(" or "[":
                            depth++;
                            break;
                        case ")" or "]":
                            depth--;
                            break;
                        case ";" when depth == 0:
                            Flush(scopes);
                            previous = token;
                            continue;
                        case "{" when depth == 0:
                        {
                            var owner = Flush(scopes) ?? _pendingOwner;
                            var block = NewBlock(token, owner, previous);
                            if (owner != null && OpensBody(owner))
                                owner.Add(block);
                            else
                                scopes.Peek().Add(block);
                            scopes.Push(block);
                            _pendingOwner = null;
                            previous = token;
                            continue;
                        }
                        case "}" when depth == 0:
                        {
                            Flush(scopes);
                            if (scopes.Count > 1)
                            {
                                var closed = scopes.Pop();
                                closed.Range = closed.Range with { EndLine = token.Line, EndColumn = token.Column };
                            }
                            _pendingOwner = null;
                            previous = token;
                            continue;
                        }
                    }
                }

                if (depth == 0 && Buffer.Count > 0 && token.Line > Buffer[^1].Line && ShouldBreakLine(token))
                    Flush(scopes);
                previous = token;

                Buffer.Add(token);
            }
            Flush(scopes);
        }

        /// <summary>
        /// Flushes the buffered statement, attaching it to the pending header when that header opened a
        /// braceless body (<c>if (x) return;</c>) instead of to the enclosing block.
        /// </summary>
        private SyntaxNode? Flush(Stack<SyntaxNode> scopes)
        {
            if (Buffer.Count == 0)
                return null;
            var statement = BuildStatement(Buffer.ToArray(), Profile);
            Buffer.Clear();

            if (_pendingOwner != null && !OpensBody(statement))
            {
                _pendingOwner.Add(statement);
                _pendingOwner = null;
                return statement;
            }

            scopes.Peek().Add(statement);
            _pendingOwner = OpensBody(statement) ? statement : null;
            return statement;
        }

        /// <summary>
        /// Distinguishes a real block from an initializer or accessor list, so rules about nesting do not
        /// fire on <c>new X { ... }</c> or <c>{ get; set; }</c>.
        /// </summary>
        private static SyntaxNode NewBlock(Token brace, SyntaxNode? owner, Token? previous)
        {
            var kind = NodeKind.Block;
            var text = string.Empty;
            if (owner == null || !OpensBody(owner))
            {
                if (previous is { Kind: TokenKind.Symbol } p && p.Text is "=" or "," or "(" or "[" or ":")
                    kind = NodeKind.ListLiteral;
                else if (previous is { Kind: TokenKind.Symbol } q && q.Text is ";" or "}")
                    text = "free"; // a block that belongs to no statement
            }
            return new SyntaxNode(kind, text, TextRange.Of(brace, brace), [brace]);
        }

        /// <summary>Automatic statement termination for languages that do not require semicolons.</summary>
        private bool ShouldBreakLine(Token next)
        {
            var last = Buffer[^1];
            if (last.Kind == TokenKind.Symbol && last.Text is "," or "." or "=" or "+" or "-" or "*" or "/" or "&&"
                    or "||" or "?" or ":" or "=>" or "->" or "(" or "[" or "{" or "|" or "&")
                return false;
            if (next.Kind == TokenKind.Symbol && next.Text is "." or "?." or "," or ")" or "]" or "}" or "=>" or "->"
                    or "&&" or "||" or "==" or "+" or "-" or "*" or "/" or ":" or "?" or "=")
                return false;
            if (Profile.IsBlockKeyword(next.Text) && next.Text is "else" or "catch" or "finally" or "when")
                return false;
            return true;
        }
    }

    internal sealed class IndentParser(IReadOnlyList<Token> tokens, SyntaxProfile profile)
        : ParserBase(tokens, profile)
    {
        public override void Fill(SyntaxNode root)
        {
            var scopes = new Stack<(SyntaxNode Node, int Indent)>();
            scopes.Push((root, -1));
            var lines = GroupLogicalLines();

            foreach (var line in lines)
            {
                var indent = line[0].Column - 1;
                while (scopes.Count > 1 && indent <= scopes.Peek().Indent)
                    scopes.Pop();

                Buffer.Clear();
                Buffer.AddRange(line);
                var statement = FlushBuffer(scopes.Peek().Node);
                if (statement == null)
                    continue;

                if (line[^1].Kind == TokenKind.Symbol && line[^1].Text == ":")
                {
                    var block = new SyntaxNode(NodeKind.Block, "", statement.Range, statement.Tokens);
                    statement.Add(block);
                    scopes.Push((block, indent));
                }
            }
        }

        private List<List<Token>> GroupLogicalLines()
        {
            var lines = new List<List<Token>>();
            var current = new List<Token>();
            var depth = 0;
            foreach (var token in Tokens)
            {
                if (current.Count > 0 && token.Line > current[^1].Line && depth == 0)
                {
                    lines.Add(current);
                    current = [];
                }
                if (token.Kind == TokenKind.Symbol)
                {
                    if (token.Text is "(" or "[" or "{")
                        depth++;
                    else if (token.Text is ")" or "]" or "}")
                        depth = Math.Max(0, depth - 1);
                    else if (token.Text == ";" && depth == 0)
                    {
                        current.Add(token);
                        lines.Add(current);
                        current = [];
                        continue;
                    }
                }
                current.Add(token);
            }
            if (current.Count > 0)
                lines.Add(current);
            return lines;
        }
    }

    internal sealed class EndKeywordParser(IReadOnlyList<Token> tokens, SyntaxProfile profile)
        : ParserBase(tokens, profile)
    {
        public override void Fill(SyntaxNode root)
        {
            var scopes = new Stack<SyntaxNode>();
            scopes.Push(root);
            var depth = 0;

            for (var i = 0; i < Tokens.Count; i++)
            {
                var token = Tokens[i];
                if (token.Kind == TokenKind.Symbol)
                {
                    if (token.Text is "(" or "[")
                        depth++;
                    else if (token.Text is ")" or "]")
                        depth--;
                    else if (token.Text is ";" && depth == 0)
                    {
                        CloseOrOpen(scopes);
                        continue;
                    }
                }

                if (depth == 0 && IsEnd(token))
                {
                    FlushBuffer(scopes.Peek());
                    if (scopes.Count > 1)
                    {
                        var closed = scopes.Pop();
                        closed.Range = closed.Range with { EndLine = token.Line, EndColumn = token.Column };
                    }
                    continue;
                }

                if (depth == 0 && Buffer.Count > 0 && token.Line > Buffer[^1].Line)
                    CloseOrOpen(scopes);

                Buffer.Add(token);
            }
            CloseOrOpen(scopes);
        }

        private void CloseOrOpen(Stack<SyntaxNode> scopes)
        {
            var statement = FlushBuffer(scopes.Peek());
            if (statement == null || !OpensBody(statement))
                return;
            if (IsSingleLineModifier(statement))
                return;
            var block = new SyntaxNode(NodeKind.Block, "", statement.Range, statement.Tokens);
            statement.Add(block);
            scopes.Push(block);
        }

        /// <summary>Trailing modifiers such as <c>do_it if ready</c> do not open a block.</summary>
        private static bool IsSingleLineModifier(SyntaxNode statement)
            => statement.Kind is NodeKind.If or NodeKind.Loop
               && statement.Tokens.Count > 0
               && statement.Tokens[0].Kind == TokenKind.Identifier
               && statement.Text.Length == 0
               && statement.Tokens[0].Text is not ("if" or "unless" or "while" or "until");

        private bool IsEnd(Token token)
            => token.Kind is TokenKind.Identifier or TokenKind.Keyword
               && (Profile.CaseInsensitive
                   ? token.Text.Equals("end", StringComparison.OrdinalIgnoreCase)
                   : token.Text == "end");
    }

    internal sealed class FlatParser(IReadOnlyList<Token> tokens, SyntaxProfile profile)
        : ParserBase(tokens, profile)
    {
        public override void Fill(SyntaxNode root)
        {
            var depth = 0;
            foreach (var token in Tokens)
            {
                if (token.Kind == TokenKind.Symbol)
                {
                    if (token.Text is "(" or "[")
                        depth++;
                    else if (token.Text is ")" or "]")
                        depth = Math.Max(0, depth - 1);
                    else if (token.Text == ";" && depth == 0)
                    {
                        FlushBuffer(root);
                        continue;
                    }
                }
                if (depth == 0 && Buffer.Count > 0 && token.Line > Buffer[^1].Line)
                    FlushBuffer(root);
                Buffer.Add(token);
            }
            FlushBuffer(root);
        }
    }
}
