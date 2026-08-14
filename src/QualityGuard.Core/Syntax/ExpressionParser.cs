using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax;

/// <summary>
/// Precedence-climbing parser turning a statement's token slice into an expression tree.
/// It is deliberately permissive: anything it cannot classify becomes an <see cref="NodeKind.Unknown"/>
/// node, so a single odd construct never derails the analysis of the rest of the file.
/// </summary>
public sealed class ExpressionParser
{
    private static readonly string[] NullLiterals = ["null", "nil", "None", "NULL", "Nothing", "undefined"];
    private static readonly string[] BooleanLiterals = ["true", "false", "True", "False", "TRUE", "FALSE"];
    private static readonly string[] PrefixOperators =
        ["!", "-", "+", "~", "++", "--", "*", "&", "not", "await", "typeof", "sizeof", "delete", "void", "yield"];
    private static readonly string[] AssignmentOperators =
        ["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", ":=", "<<=", ">>=", "??=", "||=", "&&="];
    private static readonly string[] CreationKeywords = ["new", "make", "malloc", "calloc"];

    private readonly IReadOnlyList<Token> _tokens;
    private int _index;

    private ExpressionParser(IReadOnlyList<Token> tokens)
    {
        _tokens = tokens;
    }

    public static SyntaxNode? Parse(IReadOnlyList<Token> tokens)
    {
        if (tokens.Count == 0)
            return null;
        var parser = new ExpressionParser(tokens);
        var node = parser.ParseExpression(0);
        // trailing garbage (e.g. type modifiers before a declaration) is kept as siblings
        while (!parser.AtEnd)
        {
            var extra = parser.ParseExpression(0);
            if (extra == null)
                break;
            var group = new SyntaxNode(NodeKind.Unknown, "", TextRange.Of(tokens), tokens);
            if (node != null)
                group.Add(node);
            group.Add(extra);
            node = group;
        }
        return node;
    }

    private bool AtEnd => _index >= _tokens.Count;

    private Token? Current => AtEnd ? null : _tokens[_index];

    private Token? Peek(int offset = 1)
        => _index + offset < _tokens.Count ? _tokens[_index + offset] : null;

    private SyntaxNode? ParseExpression(int minPrecedence)
    {
        var left = ParseUnary();
        if (left == null)
            return null;

        while (Current is { } op)
        {
            if (op.Text == "?" && op.Kind == TokenKind.Symbol)
            {
                left = ParseConditional(left);
                continue;
            }

            if (IsAssignment(op))
            {
                var start = _index;
                _index++;
                var right = ParseExpression(0);
                var node = new SyntaxNode(NodeKind.Assignment, op.Text,
                    Span(left, right, start), Slice(left, right, start));
                node.Add(left);
                if (right != null)
                    node.Add(right);
                left = node;
                continue;
            }

            var precedence = Precedence(op);
            if (precedence < 0 || precedence < minPrecedence)
                break;

            var opIndex = _index;
            _index++;
            var rhs = ParseExpression(precedence + 1);
            var binary = new SyntaxNode(NodeKind.Binary, op.Text,
                Span(left, rhs, opIndex), Slice(left, rhs, opIndex));
            binary.Add(left);
            if (rhs != null)
                binary.Add(rhs);
            left = binary;
        }

        return left;
    }

    private SyntaxNode ParseConditional(SyntaxNode condition)
    {
        var start = _index;
        _index++; // '?'
        var whenTrue = ParseExpression(0);
        if (Current is { Text: ":" })
        {
            _index++;
            var whenFalse = ParseExpression(0);
            var node = new SyntaxNode(NodeKind.Conditional, "?:",
                Span(condition, whenFalse, start), Slice(condition, whenFalse, start));
            node.Add(condition);
            if (whenTrue != null)
                node.Add(whenTrue);
            if (whenFalse != null)
                node.Add(whenFalse);
            return node;
        }

        var partial = new SyntaxNode(NodeKind.Conditional, "?",
            Span(condition, whenTrue, start), Slice(condition, whenTrue, start));
        partial.Add(condition);
        if (whenTrue != null)
            partial.Add(whenTrue);
        return partial;
    }

    private SyntaxNode? ParseUnary()
    {
        if (Current is not { } token)
            return null;

        if (IsPrefix(token))
        {
            var start = _index;
            _index++;
            var operand = ParseUnary();
            var kind = Contains(CreationKeywords, token.Text) ? NodeKind.ObjectCreation : NodeKind.Unary;
            var node = new SyntaxNode(kind, token.Text, TextRange.Of(token, token), [token]);
            if (operand != null)
            {
                node.Add(operand);
                node.Range = Span(null, operand, start);
                node.Tokens = Slice(null, operand, start);
                if (kind == NodeKind.ObjectCreation)
                    node.Text = SyntaxQuery.DottedName(operand) is { Length: > 0 } name ? name : token.Text;
            }
            return node;
        }

        if (Contains(CreationKeywords, token.Text))
        {
            _index++;
            var created = ParseUnary();
            var creation = new SyntaxNode(NodeKind.ObjectCreation, token.Text, TextRange.Of(token, token), [token]);
            if (created != null)
            {
                creation.Add(created);
                creation.Text = SyntaxQuery.DottedName(created) is { Length: > 0 } n ? n : token.Text;
            }
            return creation;
        }

        return ParsePostfix(ParsePrimary());
    }

    private SyntaxNode? ParsePostfix(SyntaxNode? node)
    {
        while (node != null && Current is { } token)
        {
            if (token.Kind == TokenKind.Symbol && token.Text is "." or "->" or "::" or "?." or "?->")
            {
                if (Peek() is not { } member || member.Kind is TokenKind.Symbol)
                    break;
                var start = _index;
                _index += 2;
                var memberNode = new SyntaxNode(NodeKind.Identifier, member.Text,
                    TextRange.Of(member, member), [member]);
                var select = new SyntaxNode(NodeKind.MemberSelect, "",
                    Span(node, memberNode, start), Slice(node, memberNode, start));
                select.Add(node);
                select.Add(memberNode);
                select.Text = SyntaxQuery.DottedName(select);
                node = select;
                continue;
            }

            if (token.Text == "(" && token.Kind == TokenKind.Symbol)
            {
                var start = _index;
                var args = ParseArgumentList("(", ")");
                var invocation = new SyntaxNode(NodeKind.Invocation, SyntaxQuery.DottedName(node),
                    Span(node, args, start), Slice(node, args, start));
                invocation.Add(node);
                invocation.Add(args);
                node = invocation;
                continue;
            }

            if (token.Text == "[" && token.Kind == TokenKind.Symbol)
            {
                var start = _index;
                var args = ParseArgumentList("[", "]");
                var index = new SyntaxNode(NodeKind.Index, SyntaxQuery.DottedName(node),
                    Span(node, args, start), Slice(node, args, start));
                index.Add(node);
                index.Add(args);
                node = index;
                continue;
            }

            if (token.Kind == TokenKind.Symbol && token.Text is "++" or "--" or "!")
            {
                var unary = new SyntaxNode(NodeKind.Unary, token.Text, node.Range, node.Tokens);
                unary.Add(node);
                _index++;
                node = unary;
                continue;
            }

            break;
        }

        return node;
    }

    private SyntaxNode ParseArgumentList(string open, string close)
    {
        var startIndex = _index;
        _index++; // consume open
        var list = new SyntaxNode(NodeKind.ArgumentList, open);
        while (!AtEnd && !(Current!.Kind == TokenKind.Symbol && Current.Text == close))
        {
            if (Current.Kind == TokenKind.Symbol && Current.Text == ",")
            {
                _index++;
                continue;
            }
            var before = _index;
            var argument = ParseExpression(0);
            if (argument != null)
                list.Add(argument);
            if (_index == before)
                _index++; // guarantee progress on unexpected input
        }
        if (!AtEnd)
            _index++; // consume close
        var slice = _tokens.Skip(startIndex).Take(_index - startIndex).ToArray();
        list.Tokens = slice;
        list.Range = TextRange.Of(slice);
        return list;
    }

    private SyntaxNode? ParsePrimary()
    {
        if (Current is not { } token)
            return null;

        switch (token.Kind)
        {
            case TokenKind.String:
                _index++;
                return new SyntaxNode(NodeKind.StringLiteral, token.Text, TextRange.Of(token, token), [token]);
            case TokenKind.Number:
                _index++;
                return new SyntaxNode(NodeKind.NumberLiteral, token.Text, TextRange.Of(token, token), [token]);
            case TokenKind.Comment:
                _index++;
                return ParsePrimary();
        }

        if (Contains(BooleanLiterals, token.Text))
        {
            _index++;
            return new SyntaxNode(NodeKind.BooleanLiteral, token.Text, TextRange.Of(token, token), [token]);
        }

        if (Contains(NullLiterals, token.Text))
        {
            _index++;
            return new SyntaxNode(NodeKind.NullLiteral, token.Text, TextRange.Of(token, token), [token]);
        }

        if (token.Kind is TokenKind.Identifier or TokenKind.Keyword)
        {
            _index++;
            return new SyntaxNode(NodeKind.Identifier, token.Text, TextRange.Of(token, token), [token]);
        }

        if (token.Text == "(")
        {
            var start = _index;
            var group = ParseArgumentList("(", ")");
            var lambdaArrow = Current is { Text: "=>" or "->" };
            if (lambdaArrow)
            {
                _index++;
                var body = ParseExpression(0);
                var lambda = new SyntaxNode(NodeKind.Lambda, "=>", group.Range, group.Tokens);
                lambda.Add(group);
                if (body != null)
                {
                    lambda.Add(body);
                    lambda.Range = Span(null, body, start);
                    lambda.Tokens = Slice(null, body, start);
                }
                return lambda;
            }
            var parens = new SyntaxNode(NodeKind.Parenthesized, "", group.Range, group.Tokens);
            foreach (var child in group.Children.ToArray())
                parens.Add(child);
            return parens;
        }

        if (token.Text is "[" or "{")
        {
            var close = token.Text == "[" ? "]" : "}";
            var list = ParseArgumentList(token.Text, close);
            var literal = new SyntaxNode(NodeKind.ListLiteral, token.Text, list.Range, list.Tokens);
            foreach (var child in list.Children.ToArray())
                literal.Add(child);
            return literal;
        }

        _index++;
        return new SyntaxNode(NodeKind.Unknown, token.Text, TextRange.Of(token, token), [token]);
    }

    private static bool IsAssignment(Token token)
        => token.Kind == TokenKind.Symbol && Contains(AssignmentOperators, token.Text);

    private bool IsPrefix(Token token)
    {
        if (!Contains(PrefixOperators, token.Text))
            return false;
        if (token.Text is "*" or "&" or "-" or "+")
        {
            // only a prefix at the start of an expression
            return _index == 0 || _tokens[_index - 1].Kind == TokenKind.Symbol
                && _tokens[_index - 1].Text is not (")" or "]" or "}");
        }
        return true;
    }

    private static int Precedence(Token token)
    {
        if (token.Kind is not (TokenKind.Symbol or TokenKind.Keyword or TokenKind.Identifier))
            return -1;
        return token.Text switch
        {
            "||" or "or" or "orelse" => 1,
            "&&" or "and" or "andalso" => 2,
            "|" => 3,
            "^" => 4,
            "&" => 5,
            "==" or "!=" or "===" or "!==" or "<>" or "is" or "in" or "instanceof" or "as" => 6,
            "<" or ">" or "<=" or ">=" => 7,
            "<<" or ">>" => 8,
            "+" or "-" => 9,
            "*" or "/" or "%" or "//" => 10,
            "**" => 11,
            "??" => 1,
            _ => -1
        };
    }

    private static bool Contains(string[] values, string text)
    {
        for (var i = 0; i < values.Length; i++)
            if (values[i] == text)
                return true;
        return false;
    }

    private TextRange Span(SyntaxNode? left, SyntaxNode? right, int operatorIndex)
        => TextRange.Of(Slice(left, right, operatorIndex));

    private IReadOnlyList<Token> Slice(SyntaxNode? left, SyntaxNode? right, int operatorIndex)
    {
        var tokens = new List<Token>();
        if (left != null)
            tokens.AddRange(left.Tokens);
        if (operatorIndex < _tokens.Count)
            tokens.Add(_tokens[operatorIndex]);
        if (right != null)
            tokens.AddRange(right.Tokens);
        return tokens;
    }
}
