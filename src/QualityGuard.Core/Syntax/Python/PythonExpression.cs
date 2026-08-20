using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax.Python;

/// <summary>
/// Expression parser for Python: precedence climbing with the operators the language actually uses,
/// plus lambdas, conditional expressions, comprehensions, slices and f-string holes.
/// </summary>
internal sealed class PythonExpression
{
    private static readonly string[] AssignmentOperators =
    [
        "=", "+=", "-=", "*=", "/=", "//=", "%=", "**=", "&=", "|=", "^=", ">>=", "<<=", ":="
    ];

    private readonly IReadOnlyList<Token> _tokens;
    private readonly LanguageInfo _language;
    private int _index;

    private PythonExpression(IReadOnlyList<Token> tokens, LanguageInfo language)
    {
        _tokens = tokens;
        _language = language;
    }

    public static SyntaxNode? Parse(IReadOnlyList<Token> tokens, LanguageInfo language)
    {
        if (tokens.Count == 0)
            return null;
        var parser = new PythonExpression(tokens, language);
        var node = parser.ParseCommaSequence();
        while (!parser.AtEnd && node != null)
        {
            var before = parser._index;
            var extra = parser.ParseAssignment();
            if (extra == null || parser._index == before)
                break;
            var group = new SyntaxNode(NodeKind.Unknown, "", node.Range, node.Tokens);
            group.Add(node);
            group.Add(extra);
            node = group;
        }
        return node;
    }

    private bool AtEnd => _index >= _tokens.Count;

    private Token? Current => AtEnd ? null : _tokens[_index];

    private string Text => Current?.Text ?? string.Empty;

    private bool Is(string text) => Current is { Kind: not TokenKind.String } && Text == text;

    private bool IsAny(params string[] values)
        => Current is { Kind: not TokenKind.String } && values.Contains(Text, StringComparer.Ordinal);

    private string PeekText(int offset = 1)
        => _index + offset < _tokens.Count ? _tokens[_index + offset].Text : string.Empty;

    private Token Take() => _tokens[Math.Min(_index++, _tokens.Count - 1)];

    private bool Accept(string text)
    {
        if (!Is(text))
            return false;
        _index++;
        return true;
    }

    private SyntaxNode Node(NodeKind kind, int start, string text = "")
    {
        var end = Math.Max(start, Math.Min(_index, _tokens.Count) - 1);
        var slice = new Token[Math.Max(0, end - start + 1)];
        for (var i = 0; i < slice.Length; i++)
            slice[i] = _tokens[start + i];
        return new SyntaxNode(kind, text, TextRange.Of(slice), slice);
    }

    /// <summary>
    /// A comma-separated sequence, and what it means depends on what follows it.
    ///
    /// Python unpacks with commas — <c>first, second = pair</c> — and returns the same way. Reading
    /// the left side one expression at a time saw the first name, then a comma it could not place,
    /// then an assignment to the last name only: everything before the last name was never declared,
    /// so no rule about a variable's life could see it.
    /// </summary>
    private SyntaxNode? ParseCommaSequence()
    {
        var start = _index;
        var first = ParseConditional();
        if (first == null)
            return null;
        if (!Is(","))
            return FinishAssignment(first, start);

        var items = new List<SyntaxNode> { first };
        while (Accept(","))
        {
            if (AtEnd)
                break;                       // a trailing comma still makes it a tuple
            var before = _index;
            var next = ParseConditional();
            if (next == null || _index == before)
                break;
            items.Add(next);
        }

        var tuple = Node(NodeKind.ListLiteral, start, "tuple");
        foreach (var item in items)
            tuple.Add(item);
        return FinishAssignment(tuple, start);
    }

    /// <summary>Attaches the right-hand side when the sequence turns out to be a target.</summary>
    private SyntaxNode? FinishAssignment(SyntaxNode left, int start)
    {
        if (!IsAny(AssignmentOperators))
            return left;
        var op = Take().Text;
        var right = ParseCommaSequence();
        // the operator is kept: '+=' reads the value it updates, so it cannot be the point where
        // the name comes into existence, and recording it as one made the earlier value look unread
        var node = Node(NodeKind.Assignment, start, op == ":=" ? ":=" : op);
        node.Add(left);
        if (right != null)
            node.Add(right);
        return node;
    }

    private SyntaxNode? ParseAssignment()
    {
        var start = _index;
        var left = ParseConditional();
        if (left == null || !IsAny(AssignmentOperators))
            return left;

        var op = Take().Text;
        var right = ParseAssignment();
        var node = Node(NodeKind.Assignment, start, op == ":=" ? ":=" : "=");
        node.Add(left);
        if (right != null)
            node.Add(right);
        return node;
    }

    /// <summary>Python writes its conditional as <c>value if condition else other</c>.</summary>
    private SyntaxNode? ParseConditional()
    {
        var start = _index;
        var value = ParseBinary(0);
        if (value == null || !Is("if"))
            return value;

        _index++;
        var condition = ParseBinary(0);
        SyntaxNode? otherwise = null;
        if (Accept("else"))
            otherwise = ParseConditional();

        var node = Node(NodeKind.Conditional, start, "if");
        if (condition != null)
            node.Add(condition);
        node.Add(value);
        if (otherwise != null)
            node.Add(otherwise);
        return node;
    }

    private static int Precedence(string op) => op switch
    {
        "or" => 1,
        "and" => 2,
        "in" or "is" or "==" or "!=" or "<" or ">" or "<=" or ">=" or "<>" => 4,
        "|" => 5,
        "^" => 6,
        "&" => 7,
        "<<" or ">>" => 8,
        "+" or "-" => 9,
        "*" or "/" or "//" or "%" or "@" => 10,
        "**" => 12,
        _ => -1
    };

    private SyntaxNode? ParseBinary(int minimum)
    {
        var start = _index;
        var left = ParseUnary();
        if (left == null)
            return null;

        while (!AtEnd)
        {
            var op = Text;
            if (op == "not" && PeekText() == "in")
            {
                _index += 2;
                var operand = ParseBinary(5);
                var membership = Node(NodeKind.Binary, start, "not in");
                membership.Add(left);
                if (operand != null)
                    membership.Add(operand);
                left = membership;
                continue;
            }
            if (op == "is" && PeekText() == "not")
            {
                _index += 2;
                var operand = ParseBinary(5);
                var identity = Node(NodeKind.Binary, start, "is not");
                identity.Add(left);
                if (operand != null)
                    identity.Add(operand);
                left = identity;
                continue;
            }

            var precedence = Precedence(op);
            if (precedence < 0 || precedence < minimum || Current is { Kind: TokenKind.String })
                break;

            _index++;
            var right = ParseBinary(precedence + 1);
            var node = Node(NodeKind.Binary, start, op);
            node.Add(left);
            if (right != null)
                node.Add(right);
            left = node;
        }
        return left;
    }

    private SyntaxNode? ParseUnary()
    {
        if (AtEnd)
            return null;
        var start = _index;

        if (Is("lambda"))
        {
            _index++;
            var lambda = Node(NodeKind.Lambda, start, "lambda");
            var parameters = new SyntaxNode(NodeKind.ParameterList, "", lambda.Range, lambda.Tokens);
            while (!AtEnd && !Is(":"))
            {
                if (Current is { Kind: TokenKind.Identifier })
                    parameters.Add(new SyntaxNode(NodeKind.Parameter, Text, TextRange.Of([Current!])));
                _index++;
            }
            Accept(":");
            lambda.Add(parameters);
            if (ParseConditional() is { } body)
                lambda.Add(body);
            return lambda;
        }

        if (IsAny(PythonParser.Prefixes))
        {
            var op = Take().Text;
            var operand = ParseUnary();
            var node = Node(NodeKind.Unary, start, op);
            if (operand != null)
                node.Add(operand);
            return node;
        }

        return ParsePostfix(ParsePrimary());
    }

    private SyntaxNode? ParsePostfix(SyntaxNode? node)
    {
        while (node != null && !AtEnd)
        {
            if (Is("."))
            {
                _index++;
                if (Current is not { Kind: TokenKind.Identifier or TokenKind.Keyword })
                    break;
                var member = Take();
                var memberNode = new SyntaxNode(NodeKind.Identifier, member.Text,
                    TextRange.Of(member, member), [member]);
                var select = new SyntaxNode(NodeKind.MemberSelect, "", node.Range, node.Tokens);
                select.Add(node);
                select.Add(memberNode);
                select.Text = SyntaxQuery.DottedName(select);
                select.Tokens = node.Tokens.Concat(memberNode.Tokens).ToArray();
                select.Range = TextRange.Of(select.Tokens);
                node = select;
                continue;
            }

            if (Is("("))
            {
                var arguments = ParseSequence("(", ")", NodeKind.ArgumentList);
                var invocation = new SyntaxNode(NodeKind.Invocation, SyntaxQuery.DottedName(node),
                    node.Range, node.Tokens);
                invocation.Add(node);
                invocation.Add(arguments);
                invocation.Tokens = node.Tokens.Concat(arguments.Tokens).ToArray();
                invocation.Range = TextRange.Of(invocation.Tokens);
                node = invocation;
                continue;
            }

            if (Is("["))
            {
                var subscript = ParseSequence("[", "]", NodeKind.ArgumentList);
                var index = new SyntaxNode(NodeKind.Index, SyntaxQuery.DottedName(node), node.Range, node.Tokens);
                index.Add(node);
                foreach (var child in subscript.Children.ToArray())
                    index.Add(child);
                node = index;
                continue;
            }

            break;
        }
        return node;
    }

    private SyntaxNode ParseSequence(string open, string close, NodeKind kind)
    {
        var start = _index;
        var list = new SyntaxNode(kind, open, TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept(open))
            return list;

        while (!AtEnd && !Is(close))
        {
            var before = _index;
            // keyword arguments and dictionary entries
            if (Current is { Kind: TokenKind.Identifier } && PeekText() == "=" && PeekText(2) != "=")
            {
                var keyStart = _index;
                var key = Take().Text;
                Accept("=");
                var entry = Node(NodeKind.NamedArgument, keyStart, key);
                entry.Add(new SyntaxNode(NodeKind.Identifier, key, entry.Range));
                if (ParseConditional() is { } keywordValue)
                    entry.Add(keywordValue);
                list.Add(entry);
            }
            else if (ParseAssignment() is { } element)
            {
                list.Add(element);
                if (Accept(":") && ParseConditional() is { } mapped)
                    list.Add(mapped);
            }

            if (!Accept(",") && _index == before)
                _index++;
        }
        Accept(close);
        var slice = _tokens.Skip(start).Take(_index - start).ToArray();
        list.Tokens = slice;
        list.Range = TextRange.Of(slice);
        return list;
    }

    private SyntaxNode? ParsePrimary()
    {
        if (AtEnd)
            return null;
        var start = _index;
        var token = Current!;

        switch (token.Kind)
        {
            case TokenKind.Number:
                _index++;
                return Node(NodeKind.NumberLiteral, start, token.Text);
            case TokenKind.String:
                _index++;
                return BuildString(start, token);
        }

        switch (token.Text)
        {
            case "True":
            case "False":
                _index++;
                return Node(NodeKind.BooleanLiteral, start, token.Text);
            case "None":
                _index++;
                return Node(NodeKind.NullLiteral, start, "None");
        }

        if (Is("("))
        {
            var group = ParseSequence("(", ")", NodeKind.Parenthesized);
            return group;
        }
        if (Is("["))
            return ParseSequence("[", "]", NodeKind.ListLiteral);
        if (Is("{"))
            return ParseSequence("{", "}", NodeKind.ObjectInitializer);

        if (token.Kind is TokenKind.Identifier or TokenKind.Keyword)
        {
            _index++;
            return Node(NodeKind.Identifier, start, token.Text);
        }

        _index++;
        return Node(NodeKind.Unknown, start, token.Text);
    }

    /// <summary>Formatted strings expose the expressions inside their holes to the data-flow pass.</summary>
    private SyntaxNode BuildString(int start, Token token)
    {
        // only a formatted literal has holes: '"{2,2}"' is a quantifier, and reading it as an
        // expression put every pattern with a count out of reach of the rules
        if (!token.Prefix.Contains('f') && !token.Prefix.Contains('F'))
            return Node(NodeKind.StringLiteral, start, token.Text);

        var holes = ExtractHoles(token.Text).ToArray();
        if (holes.Length == 0)
            return Node(NodeKind.StringLiteral, start, token.Text);

        var node = Node(NodeKind.InterpolatedString, start, token.Text);
        foreach (var hole in holes)
        {
            var tokens = new SourceTokenizer(hole, _language).Tokenize()
                .Where(t => t.Kind != TokenKind.Comment)
                .Select(t => new Token(t.Kind, t.Text, token.Line, token.Column))
                .ToArray();
            if (tokens.Length == 0)
                continue;
            var interpolation = new SyntaxNode(NodeKind.Interpolation, hole, node.Range, node.Tokens);
            if (Parse(tokens, _language) is { } inner)
                interpolation.Add(inner);
            node.Add(interpolation);
        }
        return node;
    }

    private static IEnumerable<string> ExtractHoles(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] != '{')
                continue;
            if (i + 1 < text.Length && text[i + 1] == '{')
            {
                i++;
                continue;
            }
            var depth = 1;
            var startIndex = i + 1;
            var j = startIndex;
            while (j < text.Length && depth > 0)
            {
                if (text[j] == '{')
                    depth++;
                else if (text[j] == '}')
                    depth--;
                j++;
            }
            if (depth != 0)
                yield break;
            var hole = text[startIndex..(j - 1)];
            var format = hole.IndexOf('!');
            if (format < 0)
                format = hole.IndexOf(':');
            if (format > 0)
                hole = hole[..format];
            if (hole.Trim().Length > 0)
                yield return hole;
            i = j - 1;
        }
    }
}
