using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax.Python;

/// <summary>
/// Indentation-driven recursive-descent parser for Python. It builds the same generic tree as the
/// C-family parser — declarations, suites, statements and expressions — so every rule and the semantic
/// pass work identically across languages. Parsing is total: unexpected input becomes an
/// <see cref="NodeKind.Unknown"/> node rather than an exception.
/// </summary>
public sealed class PythonParser
{
    private static readonly string[] CompoundKeywords =
    [
        "if", "elif", "else", "for", "while", "with", "try", "except", "finally", "match", "case",
        "def", "class", "async"
    ];

    private static readonly string[] JumpKeywords =
    [
        "return", "raise", "break", "continue", "pass", "yield", "assert", "del", "global", "nonlocal"
    ];

    private static readonly string[] PrefixOperators = ["not", "-", "+", "~", "*", "**", "await"];

    private readonly List<LogicalLine> _lines = [];
    private readonly LanguageInfo _language;
    private int _line;

    private PythonParser(IReadOnlyList<Token> tokens, LanguageInfo language)
    {
        _language = language;
        BuildLogicalLines(tokens);
    }

    public static SyntaxNode Parse(IReadOnlyList<Token> tokens, LanguageInfo language)
    {
        var root = new SyntaxNode(NodeKind.TopLevel, "", TextRange.Of(tokens), tokens);
        var parser = new PythonParser(tokens, language);
        parser.FillSuite(root, -1);
        return root;
    }

    /// <summary>One logical line: its indentation and the tokens it holds, brackets already joined.</summary>
    private sealed record LogicalLine(int Indent, IReadOnlyList<Token> Tokens)
    {
        public Token First => Tokens[0];
    }

    private void BuildLogicalLines(IReadOnlyList<Token> tokens)
    {
        var current = new List<Token>();
        var depth = 0;
        foreach (var token in tokens)
        {
            if (token.Kind == TokenKind.Comment)
                continue;

            if (current.Count > 0 && token.Line > current[^1].Line && depth == 0)
            {
                _lines.Add(new LogicalLine(current[0].Column - 1, current));
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
                    _lines.Add(new LogicalLine(current[0].Column - 1, current));
                    current = [];
                    continue;
                }
            }
            current.Add(token);
        }
        if (current.Count > 0)
            _lines.Add(new LogicalLine(current[0].Column - 1, current));
    }

    private bool AtEnd => _line >= _lines.Count;

    private LogicalLine? Current => AtEnd ? null : _lines[_line];

    /// <summary>Parses every statement indented deeper than <paramref name="parentIndent"/>.</summary>
    private void FillSuite(SyntaxNode parent, int parentIndent)
    {
        var suiteIndent = -1;
        while (!AtEnd)
        {
            var line = _lines[_line];
            if (line.Indent <= parentIndent)
                return;
            if (suiteIndent < 0)
                suiteIndent = line.Indent;
            else if (line.Indent < suiteIndent)
                return;

            var before = _line;
            var statement = ParseStatement(line);
            if (statement != null)
                parent.Add(statement);
            if (_line == before)
                _line++;
        }
    }

    private SyntaxNode? ParseStatement(LogicalLine line)
    {
        var tokens = Strip(line.Tokens);
        if (tokens.Count == 0)
        {
            _line++;
            return null;
        }

        var first = tokens[0];
        if (first.Kind == TokenKind.Symbol && first.Text == "@")
            return ParseDecorated(line);

        var keyword = first.Text;
        if (keyword == "async" && tokens.Count > 1)
            keyword = tokens[1].Text;

        if (keyword == "def")
            return ParseFunction(line, tokens);
        if (keyword == "class")
            return ParseClass(line, tokens);
        if (CompoundKeywords.Contains(keyword, StringComparer.Ordinal))
            return ParseCompound(line, tokens, keyword);
        if (keyword is "import" or "from")
        {
            _line++;
            var name = tokens.Count > 1 ? tokens[1].Text : string.Empty;
            return new SyntaxNode(NodeKind.ImportDeclaration, name, TextRange.Of(tokens), tokens);
        }
        if (JumpKeywords.Contains(keyword, StringComparer.Ordinal))
        {
            _line++;
            var jump = new SyntaxNode(NodeKind.Jump, keyword, TextRange.Of(tokens), tokens);
            if (PythonExpression.Parse(tokens.Skip(1).ToArray(), _language) is { } value)
                jump.Add(value);
            return jump;
        }

        _line++;
        return BuildSimpleStatement(tokens);
    }

    private SyntaxNode BuildSimpleStatement(IReadOnlyList<Token> tokens)
    {
        var expression = PythonExpression.Parse(tokens, _language);
        // Writing through a subscript or an attribute changes something that already exists:
        // 'counts[key] += 1' does not introduce 'counts'. Treating it as a declaration shadowed the
        // real one, and the value the original held then looked as though nobody ever read it.
        var target = expression?.ChildAt(0);
        var declares = (target is null
                        || target.Kind is NodeKind.Identifier or NodeKind.ListLiteral)
                       // a compound operator updates a value that is already there
                       && expression?.Text is null or "=" or ":=";
        var isAssignment = expression is { Kind: NodeKind.Assignment } && declares;
        var kind = isAssignment ? NodeKind.VariableDeclaration : NodeKind.ExpressionStatement;
        var name = isAssignment ? SyntaxQuery.DottedName(expression!.ChildAt(0)) : string.Empty;
        var node = new SyntaxNode(kind, name, TextRange.Of(tokens), tokens);
        if (expression != null)
            node.Add(expression);
        return node;
    }

    private SyntaxNode ParseDecorated(LogicalLine line)
    {
        var decorators = new List<SyntaxNode>();
        while (!AtEnd)
        {
            var tokens = Strip(_lines[_line].Tokens);
            if (tokens.Count == 0 || tokens[0].Text != "@")
                break;
            var name = tokens.Count > 1 ? Dotted(tokens, 1) : string.Empty;
            decorators.Add(new SyntaxNode(NodeKind.Attribute, name, TextRange.Of(tokens), tokens));
            _line++;
        }

        if (AtEnd)
            return decorators.Count > 0 ? decorators[0] : new SyntaxNode(NodeKind.Unknown, "@");

        var declaration = ParseStatement(_lines[_line]) ?? new SyntaxNode(NodeKind.Unknown, "@");
        foreach (var decorator in decorators)
            declaration.Add(decorator);
        _ = line;
        return declaration;
    }

    private SyntaxNode ParseFunction(LogicalLine line, IReadOnlyList<Token> tokens)
    {
        var nameIndex = IndexOf(tokens, "def") + 1;
        var name = nameIndex < tokens.Count ? tokens[nameIndex].Text : string.Empty;
        var node = new SyntaxNode(NodeKind.FunctionDeclaration, name, TextRange.Of(tokens), tokens);
        node.Add(ParseParameters(tokens));
        _line++;
        var body = new SyntaxNode(NodeKind.Block, "", TextRange.Of(tokens), tokens);
        FillSuite(body, line.Indent);
        node.Add(body);
        return node;
    }

    private SyntaxNode ParseClass(LogicalLine line, IReadOnlyList<Token> tokens)
    {
        var nameIndex = IndexOf(tokens, "class") + 1;
        var name = nameIndex < tokens.Count ? tokens[nameIndex].Text : string.Empty;
        var node = new SyntaxNode(NodeKind.ClassDeclaration, name, TextRange.Of(tokens), tokens);
        _line++;
        var body = new SyntaxNode(NodeKind.Block, "", TextRange.Of(tokens), tokens);
        FillSuite(body, line.Indent);
        node.Add(body);
        return node;
    }

    private SyntaxNode ParseCompound(LogicalLine line, IReadOnlyList<Token> tokens, string keyword)
    {
        var kind = keyword switch
        {
            "if" or "elif" => NodeKind.If,
            "else" => NodeKind.Else,
            "for" or "while" => NodeKind.Loop,
            "try" => NodeKind.Try,
            "except" => NodeKind.Catch,
            "finally" => NodeKind.Finally,
            "with" => NodeKind.Using,
            "match" => NodeKind.Match,
            "case" => NodeKind.SwitchSection,
            _ => NodeKind.Block
        };

        var node = new SyntaxNode(kind, keyword, TextRange.Of(tokens), tokens);
        var header = HeaderExpression(tokens, keyword);
        if (PythonExpression.Parse(header, _language) is { } condition)
            node.Add(condition);

        _line++;
        var body = new SyntaxNode(NodeKind.Block, "", TextRange.Of(tokens), tokens);
        FillSuite(body, line.Indent);
        node.Add(body);

        // else, elif, except and finally continue the same statement
        while (!AtEnd && _lines[_line].Indent == line.Indent && IsContinuation(_lines[_line], kind))
        {
            var continuation = ParseStatement(_lines[_line]);
            if (continuation != null)
                node.Add(continuation);
        }
        return node;
    }

    private static bool IsContinuation(LogicalLine line, NodeKind kind)
    {
        var text = line.Tokens[0].Text;
        return kind switch
        {
            NodeKind.If => text is "elif" or "else",
            NodeKind.Loop => text is "else",
            NodeKind.Try => text is "except" or "finally" or "else",
            NodeKind.Catch => text is "except" or "finally" or "else",
            _ => false
        };
    }

    /// <summary>The tokens between the keyword and the trailing colon.</summary>
    private static IReadOnlyList<Token> HeaderExpression(IReadOnlyList<Token> tokens, string keyword)
    {
        var start = keyword == "for" ? IndexOf(tokens, "in") + 1 : 1;
        if (start <= 0)
            start = 1;
        var end = tokens.Count;
        if (end > 0 && tokens[^1].Text == ":")
            end--;
        return start >= end ? [] : tokens.Skip(start).Take(end - start).ToArray();
    }

    private SyntaxNode ParseParameters(IReadOnlyList<Token> tokens)
    {
        var list = new SyntaxNode(NodeKind.ParameterList, "", TextRange.Of(tokens), tokens);
        var open = IndexOf(tokens, "(");
        if (open < 0)
            return list;

        var depth = 0;
        var expectName = true;
        for (var i = open; i < tokens.Count; i++)
        {
            var token = tokens[i];
            if (token.Kind == TokenKind.Symbol)
            {
                switch (token.Text)
                {
                    case "(" or "[" or "{":
                        depth++;
                        continue;
                    case ")" or "]" or "}":
                        depth--;
                        if (depth == 0)
                            return list;
                        continue;
                    case "," when depth == 1:
                        expectName = true;
                        continue;
                    case ":" or "=" when depth == 1:
                        expectName = false;
                        continue;
                }
                continue;
            }

            if (depth != 1 || !expectName || token.Kind is not (TokenKind.Identifier or TokenKind.Keyword))
                continue;
            if (token.Text is "self" or "cls")
            {
                expectName = false;
                continue;
            }
            list.Add(new SyntaxNode(NodeKind.Parameter, token.Text, TextRange.Of(token, token), [token]));
            expectName = false;
        }
        return list;
    }

    private static IReadOnlyList<Token> Strip(IReadOnlyList<Token> tokens)
    {
        var end = tokens.Count;
        while (end > 0 && tokens[end - 1].Kind == TokenKind.Symbol && tokens[end - 1].Text == ";")
            end--;
        return end == tokens.Count ? tokens : tokens.Take(end).ToArray();
    }

    private static int IndexOf(IReadOnlyList<Token> tokens, string text)
    {
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text == text && tokens[i].Kind != TokenKind.String)
                return i;
        }
        return -1;
    }

    private static string Dotted(IReadOnlyList<Token> tokens, int start)
    {
        var name = new System.Text.StringBuilder();
        for (var i = start; i < tokens.Count; i++)
        {
            if (tokens[i].Kind is TokenKind.Identifier or TokenKind.Keyword)
                name.Append(tokens[i].Text);
            else if (tokens[i].Text == ".")
                name.Append('.');
            else
                break;
        }
        return name.ToString();
    }

    internal static string[] Prefixes => PrefixOperators;
}
