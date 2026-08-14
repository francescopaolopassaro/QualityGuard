using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax.CSharp;

/// <summary>Grammar variations between the curly-brace languages this parser covers.</summary>
public enum CFamilyDialect
{
    CSharp,
    Java
}

/// <summary>
/// Recursive-descent parser for C# and, with small differences, VB-free .NET sources. It produces a
/// real syntax tree — declarations, members, accessors, statements and expressions — instead of the
/// line-oriented approximation the generic parser builds. Parsing never throws: anything unexpected is
/// consumed into an <see cref="NodeKind.Unknown"/> node so the rest of the file still parses.
/// </summary>
public sealed class CSharpParser
{
    private static readonly string[] Modifiers =
    [
        "public", "private", "protected", "internal", "static", "readonly", "const", "abstract", "virtual",
        "override", "sealed", "async", "partial", "extern", "unsafe", "new", "volatile", "required",
        "file", "implicit", "explicit", "ref"
    ];

    private static readonly string[] TypeKeywords =
    [
        "class", "struct", "interface", "record", "enum", "delegate"
    ];

    private static readonly string[] PredefinedTypes =
    [
        "void", "object", "string", "bool", "byte", "sbyte", "char", "decimal", "double", "float",
        "int", "uint", "long", "ulong", "short", "ushort", "var", "dynamic", "nint", "nuint"
    ];

    private static readonly string[] AccessorNames = ["get", "set", "init", "add", "remove"];

    private static readonly string[] AssignmentOperators =
    [
        "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "??="
    ];

    private static readonly string[] JavaModifiers =
    [
        "public", "private", "protected", "static", "final", "abstract", "synchronized", "native",
        "transient", "volatile", "strictfp", "default", "sealed", "non-sealed"
    ];

    private static readonly string[] JavaTypeKeywords = ["class", "interface", "enum", "record"];

    private readonly IReadOnlyList<Token> _tokens;
    private readonly LanguageInfo _language;
    private readonly CFamilyDialect _dialect;
    private int _index;
    private string _currentType = string.Empty;

    private CSharpParser(IReadOnlyList<Token> tokens, LanguageInfo language, CFamilyDialect dialect)
    {
        _tokens = tokens;
        _language = language;
        _dialect = dialect;
    }

    private bool IsJava => _dialect == CFamilyDialect.Java;

    private string[] ModifierWords => IsJava ? JavaModifiers : Modifiers;

    private string[] TypeWords => IsJava ? JavaTypeKeywords : TypeKeywords;

    private bool IsLambdaArrow => Is("=>") || (IsJava && Is("->"));

    public static SyntaxNode Parse(IReadOnlyList<Token> tokens, LanguageInfo language,
        CFamilyDialect dialect = CFamilyDialect.CSharp)
    {
        var code = tokens.Where(t => t.Kind != TokenKind.Comment).ToArray();
        var root = new SyntaxNode(NodeKind.TopLevel, "", TextRange.Of(tokens), tokens);
        if (code.Length == 0)
            return root;
        new CSharpParser(code, language, dialect).FillCompilationUnit(root);
        return root;
    }

    // ---------------------------------------------------------------- tokens

    private bool AtEnd => _index >= _tokens.Count;

    private Token? Current => AtEnd ? null : _tokens[_index];

    private string Text => Current?.Text ?? string.Empty;

    private Token? Peek(int offset = 1)
        => _index + offset < _tokens.Count ? _tokens[_index + offset] : null;

    private string PeekText(int offset = 1) => Peek(offset)?.Text ?? string.Empty;

    /// <summary>
    /// Text comparison that never matches a string literal: a literal containing a brace must not be
    /// mistaken for the brace itself.
    /// </summary>
    private bool Is(string text) => Current is { Kind: not TokenKind.String } && Text == text;

    private bool IsAny(params string[] values)
        => Current is { Kind: not TokenKind.String } && values.Contains(Text, StringComparer.Ordinal);

    private bool IsIdentifier => Current is { Kind: TokenKind.Identifier };

    private bool IsName => Current is { Kind: TokenKind.Identifier or TokenKind.Keyword };

    private Token Take() => _tokens[Math.Min(_index++, _tokens.Count - 1)];

    private bool Accept(string text)
    {
        if (!Is(text))
            return false;
        _index++;
        return true;
    }

    private void Expect(string text) => Accept(text);

    private int Mark() => _index;

    private SyntaxNode Node(NodeKind kind, int start, string text = "")
    {
        var end = Math.Max(start, Math.Min(_index, _tokens.Count) - 1);
        var slice = new Token[Math.Max(0, end - start + 1)];
        for (var i = 0; i < slice.Length; i++)
            slice[i] = _tokens[start + i];
        return new SyntaxNode(kind, text, TextRange.Of(slice), slice);
    }

    /// <summary>Skips a balanced pair, used for constructs the tree does not need in detail.</summary>
    private void SkipBalanced(string open, string close)
    {
        if (!Accept(open))
            return;
        var depth = 1;
        while (!AtEnd && depth > 0)
        {
            if (Is(open))
                depth++;
            else if (Is(close))
                depth--;
            _index++;
        }
    }

    // ------------------------------------------------------------ structure

    private void FillCompilationUnit(SyntaxNode root)
    {
        while (!AtEnd)
        {
            var before = _index;
            var member = ParseTopLevelMember();
            if (member != null)
                root.Add(member);
            if (_index == before)
                _index++;
        }
    }

    private SyntaxNode? ParseTopLevelMember()
    {
        var start = Mark();
        var attributes = ParseAttributes();

        if (!IsJava && Is("using") && PeekText() != "(" && !IsUsingDeclaration())
            return ParseUsingDirective(start);

        if (IsJava && (Is("import") || Is("package")))
        {
            var isPackage = Is("package");
            _index++;
            var name = new System.Text.StringBuilder();
            while (!AtEnd && !Is(";"))
                name.Append(Take().Text);
            Accept(";");
            return Node(isPackage ? NodeKind.PackageDeclaration : NodeKind.ImportDeclaration, start,
                name.ToString());
        }

        if (Is("namespace"))
            return ParseNamespace(start);

        if (Is("extern") && PeekText() == "alias")
        {
            while (!AtEnd && !Accept(";"))
                _index++;
            return Node(NodeKind.ImportDeclaration, start);
        }

        var modifiers = ParseModifiers();
        if (IsAny(TypeWords))
            return ParseTypeDeclaration(start, attributes, modifiers);

        _index = start;
        return ParseStatement();
    }

    private bool IsUsingDeclaration()
        => PeekText() == "var" || (Peek() is { Kind: TokenKind.Identifier or TokenKind.Keyword }
                                   && PeekText(2) is not ("." or ";" or "="));

    private SyntaxNode ParseUsingDirective(int start)
    {
        Expect("using");
        Accept("static");
        var name = new System.Text.StringBuilder();
        while (!AtEnd && !Is(";"))
            name.Append(Take().Text);
        Accept(";");
        return Node(NodeKind.ImportDeclaration, start, name.ToString());
    }

    private SyntaxNode ParseNamespace(int start)
    {
        Expect("namespace");
        var name = new System.Text.StringBuilder();
        while (!AtEnd && !Is("{") && !Is(";"))
            name.Append(Take().Text);

        var node = Node(NodeKind.PackageDeclaration, start, name.ToString());
        if (Accept(";"))
            return node; // file-scoped namespace

        if (Accept("{"))
        {
            while (!AtEnd && !Is("}"))
            {
                var before = _index;
                var member = ParseTopLevelMember();
                if (member != null)
                    node.Add(member);
                if (_index == before)
                    _index++;
            }
            Accept("}");
        }
        node.Range = node.Range with { EndLine = Current?.Line ?? node.Range.EndLine };
        return node;
    }

    private List<SyntaxNode> ParseAttributes()
    {
        var attributes = new List<SyntaxNode>();
        while (IsJava && Is("@") && Peek() is { Kind: TokenKind.Identifier })
        {
            var annotationStart = Mark();
            _index++;
            var annotation = ParseQualifiedName();
            if (Is("("))
                SkipBalanced("(", ")");
            attributes.Add(Node(NodeKind.Attribute, annotationStart, annotation));
        }

        while (Is("[") && LooksLikeAttribute())
        {
            var start = Mark();
            Expect("[");
            while (!AtEnd && !Is("]"))
            {
                if (IsName)
                {
                    var nameStart = Mark();
                    var name = ParseQualifiedName();
                    if (Is("("))
                        SkipBalanced("(", ")");
                    attributes.Add(Node(NodeKind.Attribute, nameStart, name));
                }
                else
                {
                    _index++;
                }
            }
            Accept("]");
            _ = start;
        }
        return attributes;
    }

    /// <summary>Distinguishes an attribute list from an array or a collection expression.</summary>
    private bool LooksLikeAttribute()
    {
        var next = Peek();
        return next is { Kind: TokenKind.Identifier or TokenKind.Keyword };
    }

    private List<string> ParseModifiers()
    {
        var modifiers = new List<string>();
        while (IsAny(ModifierWords))
        {
            // 'ref' is a modifier only in front of a type or another modifier
            if (!IsJava && Is("ref") && PeekText() is "(" or ";")
                break;
            modifiers.Add(Take().Text);
        }
        return modifiers;
    }

    private SyntaxNode ParseTypeDeclaration(int start, List<SyntaxNode> attributes, List<string> modifiers)
    {
        var keyword = Take().Text;
        if (keyword == "delegate")
            return ParseDelegate(start, attributes, modifiers);

        var name = IsName ? Take().Text : string.Empty;
        if (Is("<"))
            SkipGenericParameters();
        if (Is("("))
            SkipBalanced("(", ")"); // primary constructor of a record

        if (Accept(":") || IsAny("extends", "implements", "permits"))
        {
            while (!AtEnd && !Is("{") && !Is(";") && !Is("where"))
                _index++;
        }
        while (Is("where"))
        {
            while (!AtEnd && !Is("{") && !Is(";"))
                _index++;
        }

        var previousType = _currentType;
        _currentType = name;
        var node = Node(NodeKind.ClassDeclaration, start, name);
        AddDecorations(node, attributes, modifiers);

        if (Accept(";"))
        {
            _currentType = previousType;
            return node;
        }

        var body = ParseTypeBody(keyword == "enum");
        node.Add(body);
        node.Range = node.Range with { EndLine = body.Range.EndLine };
        _currentType = previousType;
        return node;
    }

    private SyntaxNode ParseDelegate(int start, List<SyntaxNode> attributes, List<string> modifiers)
    {
        ParseType();
        var name = IsName ? Take().Text : string.Empty;
        if (Is("<"))
            SkipGenericParameters();
        var node = Node(NodeKind.FunctionDeclaration, start, name);
        AddDecorations(node, attributes, modifiers);
        if (Is("("))
            node.Add(ParseParameterList());
        while (!AtEnd && !Accept(";"))
            _index++;
        return node;
    }

    private SyntaxNode ParseTypeBody(bool isEnum)
    {
        var start = Mark();
        var block = new SyntaxNode(NodeKind.Block, "", TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("{"))
            return block;

        while (!AtEnd && !Is("}"))
        {
            var before = _index;
            var member = isEnum ? ParseEnumMember() : ParseMember();
            if (member != null)
                block.Add(member);
            if (_index == before)
                _index++;
        }
        var closing = Current;
        Accept("}");
        if (closing != null)
            block.Range = block.Range with { EndLine = closing.Line, EndColumn = closing.Column };
        return block;
    }

    private SyntaxNode? ParseEnumMember()
    {
        var start = Mark();
        ParseAttributes();
        if (!IsName)
            return null;
        var name = Take().Text;
        if (Accept("="))
            ParseExpression();
        Accept(",");
        return Node(NodeKind.EnumMember, start, name);
    }

    // -------------------------------------------------------------- members

    private SyntaxNode? ParseMember()
    {
        var start = Mark();
        var attributes = ParseAttributes();
        var modifiers = ParseModifiers();

        if (IsAny(TypeWords))
            return ParseTypeDeclaration(start, attributes, modifiers);

        if (Is("~") && Peek() is { Kind: TokenKind.Identifier })
        {
            _index++;
            var finalizerName = Take().Text;
            SkipBalanced("(", ")");
            var finalizer = Node(NodeKind.FunctionDeclaration, start, "~" + finalizerName);
            AddDecorations(finalizer, attributes, modifiers);
            AddBody(finalizer);
            return finalizer;
        }

        if (Is("event"))
            return ParseEvent(start, attributes, modifiers);

        // constructor: Name ( ... )
        if (IsIdentifier && PeekText() == "(" && Text == _currentType)
        {
            var ctorName = Take().Text;
            var ctor = Node(NodeKind.ConstructorDeclaration, start, ctorName);
            AddDecorations(ctor, attributes, modifiers);
            ctor.Add(ParseParameterList());
            if (Accept(":"))
            {
                // base or this initializer
                if (IsName)
                    _index++;
                if (Is("("))
                    SkipBalanced("(", ")");
            }
            AddBody(ctor);
            return ctor;
        }

        var type = ParseType();

        if (Is("this") && PeekText() == "[")
        {
            _index++;
            var indexer = Node(NodeKind.IndexerDeclaration, start, "this");
            AddDecorations(indexer, attributes, modifiers);
            indexer.Add(type);
            SkipBalanced("[", "]");
            indexer.Add(ParseAccessorList());
            return indexer;
        }

        if (Is("operator"))
        {
            _index++;
            var op = IsName || Current is { Kind: TokenKind.Symbol } ? Take().Text : string.Empty;
            var operatorNode = Node(NodeKind.FunctionDeclaration, start, "operator " + op);
            AddDecorations(operatorNode, attributes, modifiers);
            operatorNode.Add(ParseParameterList());
            AddBody(operatorNode);
            return operatorNode;
        }

        if (!IsName)
        {
            // not a member we understand: consume the statement defensively
            _index = start;
            return ParseStatement();
        }

        var memberName = Take().Text;
        if (Is("<"))
            SkipGenericParameters();

        if (Is("("))
        {
            var method = Node(NodeKind.FunctionDeclaration, start, memberName);
            AddDecorations(method, attributes, modifiers);
            method.Add(type);
            method.Add(ParseParameterList());
            while (Is("where") || Is("throws"))
            {
                while (!AtEnd && !Is("{") && !Is(";") && !Is("=>"))
                    _index++;
            }
            AddBody(method);
            return method;
        }

        if (Is("{"))
        {
            var property = Node(NodeKind.PropertyDeclaration, start, memberName);
            AddDecorations(property, attributes, modifiers);
            property.Add(type);
            property.Add(ParseAccessorList());
            if (Accept("="))
            {
                if (ParseExpression() is { } initializer)
                    property.Add(initializer);
                Accept(";");
            }
            return property;
        }

        if (Is("=>"))
        {
            _index++;
            var property = Node(NodeKind.PropertyDeclaration, start, memberName);
            AddDecorations(property, attributes, modifiers);
            property.Add(type);
            var accessor = new SyntaxNode(NodeKind.Accessor, "get", property.Range, property.Tokens);
            if (ParseExpression() is { } expression)
                accessor.Add(expression);
            property.Add(accessor);
            Accept(";");
            property.Range = property.Range with { EndLine = accessor.Range.EndLine };
            return property;
        }

        // field declaration with one or more declarators
        var field = Node(NodeKind.FieldDeclaration, start, memberName);
        AddDecorations(field, attributes, modifiers);
        field.Add(type);
        field.Add(ParseDeclarator(memberName));
        while (Accept(","))
        {
            if (!IsName)
                break;
            var next = Take().Text;
            field.Add(ParseDeclarator(next));
        }
        Accept(";");
        field.Range = TextRange.Of(SliceFrom(start));
        field.Tokens = SliceFrom(start);
        return field;
    }

    /// <summary>
    /// A declarator becomes either an assignment (when it has an initializer) or a bare identifier, so
    /// the semantic pass sees exactly one declaration per name.
    /// </summary>
    private SyntaxNode ParseDeclarator(string name)
    {
        var start = Mark();
        var identifier = new SyntaxNode(NodeKind.Identifier, name,
            TextRange.Of([_tokens[Math.Max(0, Math.Min(start - 1, _tokens.Count - 1))]]));
        if (!Accept("="))
            return identifier;

        var value = ParseExpression();
        var assignment = new SyntaxNode(NodeKind.Assignment, "=", identifier.Range, SliceFrom(start));
        assignment.Add(identifier);
        if (value != null)
        {
            assignment.Add(value);
            assignment.Range = value.Range;
        }
        assignment.Tokens = SliceFrom(start);
        return assignment;
    }

    private SyntaxNode ParseEvent(int start, List<SyntaxNode> attributes, List<string> modifiers)
    {
        Expect("event");
        var type = ParseType();
        var name = IsName ? Take().Text : string.Empty;
        var node = Node(NodeKind.EventDeclaration, start, name);
        AddDecorations(node, attributes, modifiers);
        node.Add(type);
        if (Is("{"))
            node.Add(ParseAccessorList());
        else
            Accept(";");
        return node;
    }

    private SyntaxNode ParseAccessorList()
    {
        var start = Mark();
        var list = new SyntaxNode(NodeKind.Block, "accessors",
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("{"))
            return list;

        while (!AtEnd && !Is("}"))
        {
            var before = _index;
            ParseAttributes();
            ParseModifiers();
            if (IsAny(AccessorNames))
            {
                var accessorStart = Mark();
                var name = Take().Text;
                var accessor = new SyntaxNode(NodeKind.Accessor, name,
                    TextRange.Of([_tokens[Math.Min(accessorStart, _tokens.Count - 1)]]));
                if (Is("{"))
                    accessor.Add(ParseBlock());
                else if (Accept("=>"))
                {
                    if (ParseExpression() is { } expression)
                        accessor.Add(expression);
                    Accept(";");
                }
                else
                {
                    Accept(";");
                }
                accessor.Tokens = SliceFrom(accessorStart);
                accessor.Range = TextRange.Of(accessor.Tokens);
                list.Add(accessor);
            }
            if (_index == before)
                _index++;
        }
        var closing = Current;
        Accept("}");
        list.Tokens = SliceFrom(start);
        list.Range = closing != null
            ? TextRange.Of(list.Tokens) with { EndLine = closing.Line }
            : TextRange.Of(list.Tokens);
        return list;
    }

    private void AddDecorations(SyntaxNode node, List<SyntaxNode> attributes, List<string> modifiers)
    {
        foreach (var attribute in attributes)
            node.Add(attribute);
        foreach (var modifier in modifiers)
            node.Add(new SyntaxNode(NodeKind.Modifier, modifier, node.Range, []));
    }

    private void AddBody(SyntaxNode member)
    {
        if (Is("{"))
        {
            var body = ParseBlock();
            member.Add(body);
            member.Range = member.Range with { EndLine = body.Range.EndLine };
            return;
        }
        if (Accept("=>"))
        {
            var body = new SyntaxNode(NodeKind.Block, "expression", member.Range, member.Tokens);
            if (ParseExpression() is { } expression)
            {
                var statement = new SyntaxNode(NodeKind.Jump, "return", expression.Range, expression.Tokens);
                statement.Add(expression);
                body.Add(statement);
            }
            Accept(";");
            member.Add(body);
            member.Range = member.Range with { EndLine = body.Range.EndLine };
            return;
        }
        Accept(";"); // abstract, interface or partial member
    }

    private IReadOnlyList<Token> SliceFrom(int start)
    {
        var end = Math.Min(_index, _tokens.Count);
        if (end <= start)
            return [];
        var slice = new Token[end - start];
        for (var i = 0; i < slice.Length; i++)
            slice[i] = _tokens[start + i];
        return slice;
    }

    // ----------------------------------------------------------------- types

    private SyntaxNode ParseType()
    {
        var start = Mark();
        if (IsAny("ref", "out", "in", "params", "scoped", "this"))
            _index++;

        var name = ParseQualifiedName();
        while (true)
        {
            if (Is("?") && PeekText() is not ("?" or ":"))
            {
                _index++;
                name += "?";
                continue;
            }
            if (Is("*"))
            {
                _index++;
                name += "*";
                continue;
            }
            if (Is("[") && (PeekText() == "]" || PeekText() == ","))
            {
                SkipBalanced("[", "]");
                name += "[]";
                continue;
            }
            break;
        }
        return Node(NodeKind.TypeReference, start, name);
    }

    private string ParseQualifiedName()
    {
        var name = new System.Text.StringBuilder();
        if (Is("(")) // tuple type
        {
            SkipBalanced("(", ")");
            return "tuple";
        }
        if (!IsName)
            return string.Empty;

        name.Append(Take().Text);
        while (Is(".") && Peek() is { Kind: TokenKind.Identifier or TokenKind.Keyword })
        {
            _index++;
            name.Append('.').Append(Take().Text);
        }
        if (Is("<") && TryScanGenerics(out var arguments))
            name.Append(arguments);
        return name.ToString();
    }

    private bool TryScanGenerics(out string text)
    {
        text = string.Empty;
        var start = _index;
        var depth = 0;
        var buffer = new System.Text.StringBuilder();
        while (!AtEnd)
        {
            var current = Text;
            if (current == "<")
                depth++;
            else if (current == ">")
                depth--;
            else if (current == ">>")
                depth -= 2; // nested generics tokenized as a shift operator
            else if (current == ">>>")
                depth -= 3;
            else if (current is ";" or "{" or "}" or "(" or ")" or "=" or "&&" or "||")
            {
                _index = start;
                return false;
            }
            buffer.Append(current);
            _index++;
            if (depth <= 0)
            {
                text = buffer.ToString();
                return true;
            }
        }
        _index = start;
        return false;
    }

    private void SkipGenericParameters()
    {
        var depth = 0;
        while (!AtEnd)
        {
            if (Is("<"))
                depth++;
            else if (Is(">"))
                depth--;
            else if (Is(">>"))
                depth -= 2;
            else if (Is(">>>"))
                depth -= 3;
            _index++;
            if (depth <= 0)
                return;
        }
    }

    private SyntaxNode ParseParameterList()
    {
        var start = Mark();
        var list = new SyntaxNode(NodeKind.ParameterList, "",
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("("))
            return list;

        while (!AtEnd && !Is(")"))
        {
            var before = _index;
            ParseAttributes();
            while (IsAny("ref", "out", "in", "params", "this", "scoped", "readonly"))
                _index++;

            var parameterStart = Mark();
            var type = ParseType();
            if (!IsName)
            {
                // the parsed name was the parameter itself (implicit lambda parameter)
                var implicitName = type.Text;
                if (implicitName.Length > 0)
                {
                    var implicitParameter = new SyntaxNode(NodeKind.Parameter, implicitName, type.Range, type.Tokens);
                    list.Add(implicitParameter);
                }
            }
            else
            {
                var name = Take().Text;
                var parameter = Node(NodeKind.Parameter, parameterStart, name);
                parameter.Add(type);
                if (Accept("="))
                {
                    if (ParseExpression() is { } defaultValue)
                        parameter.Add(defaultValue);
                }
                list.Add(parameter);
            }

            if (!Accept(","))
            {
                if (!Is(")") && _index == before)
                    _index++;
            }
        }
        Accept(")");
        list.Tokens = SliceFrom(start);
        list.Range = TextRange.Of(list.Tokens);
        return list;
    }

    // ------------------------------------------------------------ statements

    private SyntaxNode ParseBlock()
    {
        var start = Mark();
        var block = new SyntaxNode(NodeKind.Block, "",
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("{"))
            return block;

        while (!AtEnd && !Is("}"))
        {
            var before = _index;
            var statement = ParseStatement();
            if (statement != null)
                block.Add(statement);
            if (_index == before)
                _index++;
        }
        var closing = Current;
        Accept("}");
        block.Tokens = SliceFrom(start);
        block.Range = TextRange.Of(block.Tokens);
        if (closing != null)
            block.Range = block.Range with { EndLine = closing.Line, EndColumn = closing.Column };
        return block;
    }

    private SyntaxNode? ParseStatement()
    {
        if (AtEnd)
            return null;

        var start = Mark();
        ParseAttributes();

        switch (Text)
        {
            case "{":
                return ParseBlock();
            case ";":
                _index++;
                return Node(NodeKind.ExpressionStatement, start, ";");
            case "if":
                return ParseIf(start);
            case "switch":
                return ParseSwitchStatement(start);
            case "for":
                return ParseFor(start);
            case "foreach":
                return ParseForEach(start);
            case "while":
                return ParseWhile(start);
            case "do":
                return ParseDoWhile(start);
            case "try":
                return ParseTry(start);
            case "using":
                return ParseUsingStatement(start);
            case "lock":
            case "fixed":
                return ParseLock(start);
            case "checked":
            case "unchecked":
            case "unsafe":
                _index++;
                return Is("{") ? ParseBlock() : ParseStatement();
            case "return":
            case "break":
            case "continue":
            case "throw":
            case "goto":
            case "yield":
                return ParseJump(start);
        }

        var modifiers = ParseModifiers();
        if (LooksLikeLocalFunction())
        {
            var type = ParseType();
            var name = Take().Text;
            if (Is("<"))
                SkipGenericParameters();
            var function = Node(NodeKind.LocalFunction, start, name);
            function.Add(type);
            function.Add(ParseParameterList());
            AddBody(function);
            return function;
        }
        _ = modifiers;

        if (TryParseLocalDeclaration(start) is { } declaration)
            return declaration;

        var expression = ParseExpression();
        Accept(";");
        var statement = Node(NodeKind.ExpressionStatement, start);
        if (expression != null)
            statement.Add(expression);
        return statement;
    }

    private bool LooksLikeLocalFunction()
    {
        var start = _index;
        try
        {
            if (!IsName)
                return false;
            ParseType();
            if (!IsIdentifier)
                return false;
            _index++;
            if (Is("<"))
                SkipGenericParameters();
            return Is("(");
        }
        finally
        {
            _index = start;
        }
    }

    private SyntaxNode? TryParseLocalDeclaration(int start)
    {
        var reset = _index;
        if (!IsName)
            return null;

        var type = ParseType();
        if (type.Text.Length == 0 || !IsIdentifier)
        {
            _index = reset;
            return null;
        }

        var name = Text;
        var after = PeekText();
        if (after is not ("=" or ";" or "," or ")"))
        {
            _index = reset;
            return null;
        }

        _index++; // the declared name
        var declaration = new SyntaxNode(NodeKind.VariableDeclaration, name, type.Range, type.Tokens);
        declaration.Add(type);
        declaration.Add(ParseDeclarator(name));
        while (Accept(","))
        {
            if (!IsIdentifier)
                break;
            var next = Take().Text;
            declaration.Add(ParseDeclarator(next));
        }
        Accept(";");
        declaration.Tokens = SliceFrom(start);
        declaration.Range = TextRange.Of(declaration.Tokens);
        return declaration;
    }

    private SyntaxNode ParseIf(int start)
    {
        Expect("if");
        var node = Node(NodeKind.If, start, "if");
        if (Is("("))
        {
            SkipOpenParen();
            if (ParseExpression() is { } condition)
                node.Add(condition);
            Accept(")");
        }
        AddEmbeddedStatement(node);

        if (Is("else"))
        {
            var elseStart = Mark();
            _index++;
            var elseNode = Node(NodeKind.Else, elseStart, "else");
            AddEmbeddedStatement(elseNode);
            node.Add(elseNode);
        }
        return node;
    }

    private void AddEmbeddedStatement(SyntaxNode owner)
    {
        if (Is("{"))
        {
            var block = ParseBlock();
            owner.Add(block);
            owner.Range = owner.Range with { EndLine = block.Range.EndLine };
            return;
        }
        var statement = ParseStatement();
        if (statement == null)
            return;
        var wrapper = new SyntaxNode(NodeKind.Block, "implicit", statement.Range, statement.Tokens);
        wrapper.Add(statement);
        owner.Add(wrapper);
        owner.Range = owner.Range with { EndLine = statement.Range.EndLine };
    }

    private void SkipOpenParen() => Accept("(");

    private SyntaxNode ParseSwitchStatement(int start)
    {
        Expect("switch");
        var node = Node(NodeKind.Match, start, "switch");
        if (Is("("))
        {
            SkipOpenParen();
            if (ParseExpression() is { } subject)
                node.Add(subject);
            Accept(")");
        }

        var body = new SyntaxNode(NodeKind.Block, "", node.Range, node.Tokens);
        if (Accept("{"))
        {
            SyntaxNode? section = null;
            while (!AtEnd && !Is("}"))
            {
                var before = _index;
                if (Is("case") || Is("default"))
                {
                    var caseStart = Mark();
                    var keyword = Take().Text;
                    if (keyword == "case")
                        ParsePattern();
                    if (Is("when"))
                    {
                        _index++;
                        ParseExpression();
                    }
                    Accept(":");
                    section = Node(NodeKind.SwitchSection, caseStart, keyword);
                    body.Add(section);
                }
                else
                {
                    var statement = ParseStatement();
                    if (statement != null)
                        (section ?? body).Add(statement);
                }
                if (_index == before)
                    _index++;
            }
            var closing = Current;
            Accept("}");
            if (closing != null)
                body.Range = body.Range with { EndLine = closing.Line };
        }
        node.Add(body);
        node.Range = node.Range with { EndLine = body.Range.EndLine };
        return node;
    }

    private SyntaxNode ParseFor(int start)
    {
        Expect("for");
        var node = Node(NodeKind.Loop, start, "for");
        if (Accept("("))
        {
            if (!Is(";") && TryParseLocalDeclaration(Mark()) is { } initializer)
                node.Add(initializer);
            else
            {
                if (!Is(";") && ParseExpression() is { } expression)
                    node.Add(expression);
                Accept(";");
            }
            if (!Is(";") && ParseExpression() is { } condition)
                node.Add(condition);
            Accept(";");
            while (!AtEnd && !Is(")"))
            {
                if (ParseExpression() is { } update)
                    node.Add(update);
                if (!Accept(","))
                    break;
            }
            Accept(")");
        }
        AddEmbeddedStatement(node);
        return node;
    }

    private SyntaxNode ParseForEach(int start)
    {
        Expect("foreach");
        var node = Node(NodeKind.Loop, start, "foreach");
        if (Accept("("))
        {
            var type = ParseType();
            var names = new List<string>();
            if (Is("("))
            {
                // deconstruction: foreach (var (key, value) in map)
                Accept("(");
                while (!AtEnd && !Is(")"))
                {
                    if (IsName)
                        names.Add(Take().Text);
                    else
                        _index++;
                }
                Accept(")");
            }
            else if (IsIdentifier)
            {
                names.Add(Take().Text);
            }

            var name = names.FirstOrDefault() ?? string.Empty;
            var variable = new SyntaxNode(NodeKind.VariableDeclaration, name, type.Range, type.Tokens);
            variable.Add(type);
            foreach (var extra in names.Skip(1))
                variable.Add(new SyntaxNode(NodeKind.Identifier, extra, type.Range, type.Tokens));
            node.Add(variable);
            Accept("in");
            if (ParseExpression() is { } sequence)
            {
                node.Add(sequence);
                var assignment = new SyntaxNode(NodeKind.Assignment, "=", sequence.Range, sequence.Tokens);
                assignment.Add(new SyntaxNode(NodeKind.Identifier, name, variable.Range, variable.Tokens));
                assignment.Add(sequence);
                variable.Add(assignment);
            }
            Accept(")");
        }
        AddEmbeddedStatement(node);
        return node;
    }

    private SyntaxNode ParseWhile(int start)
    {
        Expect("while");
        var node = Node(NodeKind.Loop, start, "while");
        if (Accept("("))
        {
            if (ParseExpression() is { } condition)
                node.Add(condition);
            Accept(")");
        }
        AddEmbeddedStatement(node);
        return node;
    }

    private SyntaxNode ParseDoWhile(int start)
    {
        Expect("do");
        var node = Node(NodeKind.Loop, start, "do");
        AddEmbeddedStatement(node);
        Accept("while");
        if (Accept("("))
        {
            if (ParseExpression() is { } condition)
                node.Add(condition);
            Accept(")");
        }
        Accept(";");
        return node;
    }

    private SyntaxNode ParseTry(int start)
    {
        Expect("try");
        var node = Node(NodeKind.Try, start, "try");
        if (Is("{"))
            node.Add(ParseBlock());

        while (Is("catch"))
        {
            var catchStart = Mark();
            _index++;
            var catchNode = Node(NodeKind.Catch, catchStart, "catch");
            if (Is("("))
            {
                Accept("(");
                var type = ParseType();
                catchNode.Add(type);
                if (IsIdentifier)
                {
                    var name = Take().Text;
                    var variable = new SyntaxNode(NodeKind.VariableDeclaration, name, type.Range, type.Tokens);
                    variable.Add(type);
                    catchNode.Add(variable);
                }
                Accept(")");
            }
            if (Is("when"))
            {
                _index++;
                if (Accept("("))
                {
                    ParseExpression();
                    Accept(")");
                }
            }
            if (Is("{"))
            {
                var body = ParseBlock();
                catchNode.Add(body);
                catchNode.Range = catchNode.Range with { EndLine = body.Range.EndLine };
            }
            node.Add(catchNode);
        }

        if (Is("finally"))
        {
            var finallyStart = Mark();
            _index++;
            var finallyNode = Node(NodeKind.Finally, finallyStart, "finally");
            if (Is("{"))
            {
                var body = ParseBlock();
                finallyNode.Add(body);
                finallyNode.Range = finallyNode.Range with { EndLine = body.Range.EndLine };
            }
            node.Add(finallyNode);
        }
        return node;
    }

    private SyntaxNode ParseUsingStatement(int start)
    {
        Expect("using");
        var node = Node(NodeKind.Using, start, "using");
        if (Accept("("))
        {
            if (TryParseLocalDeclaration(Mark()) is { } declaration)
                node.Add(declaration);
            else if (ParseExpression() is { } resource)
                node.Add(resource);
            Accept(")");
            AddEmbeddedStatement(node);
            return node;
        }

        if (TryParseLocalDeclaration(Mark()) is { } inline)
            node.Add(inline);
        return node;
    }

    private SyntaxNode ParseLock(int start)
    {
        var keyword = Take().Text;
        var node = Node(NodeKind.Lock, start, keyword);
        if (Accept("("))
        {
            if (ParseExpression() is { } subject)
                node.Add(subject);
            Accept(")");
        }
        AddEmbeddedStatement(node);
        return node;
    }

    private SyntaxNode ParseJump(int start)
    {
        var keyword = Take().Text;
        if (keyword == "yield" && (Is("return") || Is("break")))
            keyword += " " + Take().Text;
        var node = Node(NodeKind.Jump, start, keyword);
        if (!Is(";") && !AtEnd)
        {
            if (ParseExpression() is { } value)
                node.Add(value);
        }
        Accept(";");
        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        return node;
    }

    // ----------------------------------------------------------- expressions

    private SyntaxNode? ParseExpression() => ParseAssignment();

    private SyntaxNode? ParseAssignment()
    {
        var left = ParseTernary();
        if (left == null || !IsAny(AssignmentOperators))
            return left;

        var op = Take().Text;
        var right = ParseAssignment();
        var node = new SyntaxNode(NodeKind.Assignment, op, left.Range, left.Tokens);
        node.Add(left);
        if (right != null)
        {
            node.Add(right);
            node.Range = new TextRange(left.Range.StartLine, left.Range.StartColumn,
                right.Range.EndLine, right.Range.EndColumn);
            node.Tokens = left.Tokens.Concat(right.Tokens).ToArray();
        }
        return node;
    }

    private SyntaxNode? ParseTernary()
    {
        var condition = ParseBinary(0);
        if (condition == null || !Is("?") || PeekText() == ".")
            return condition;

        _index++;
        var whenTrue = ParseAssignment();
        Accept(":");
        var whenFalse = ParseAssignment();
        var node = new SyntaxNode(NodeKind.Conditional, "?:", condition.Range, condition.Tokens);
        node.Add(condition);
        if (whenTrue != null)
            node.Add(whenTrue);
        if (whenFalse != null)
        {
            node.Add(whenFalse);
            node.Range = new TextRange(condition.Range.StartLine, condition.Range.StartColumn,
                whenFalse.Range.EndLine, whenFalse.Range.EndColumn);
        }
        return node;
    }

    private static int Precedence(string op) => op switch
    {
        "??" => 1,
        "||" => 2,
        "&&" => 3,
        "|" => 4,
        "^" => 5,
        "&" => 6,
        "==" or "!=" => 7,
        "<" or ">" or "<=" or ">=" or "is" or "as" or "instanceof" => 8,
        "<<" or ">>" => 9,
        "+" or "-" => 10,
        "*" or "/" or "%" => 11,
        _ => -1
    };

    private SyntaxNode? ParseBinary(int minimum)
    {
        var left = ParseUnary();
        if (left == null)
            return null;

        while (!AtEnd)
        {
            var op = Text;
            var precedence = Precedence(op);
            if (precedence < 0 || precedence < minimum)
                break;

            _index++;
            SyntaxNode? right;
            if (op is "is" or "instanceof")
                right = ParsePattern();
            else if (op == "as")
                right = ParseType();
            else
                right = ParseBinary(precedence + 1);

            var node = new SyntaxNode(NodeKind.Binary, op, left.Range, left.Tokens);
            node.Add(left);
            if (right != null)
            {
                node.Add(right);
                node.Range = new TextRange(left.Range.StartLine, left.Range.StartColumn,
                    right.Range.EndLine, right.Range.EndColumn);
                node.Tokens = left.Tokens.Concat(right.Tokens).ToArray();
            }
            left = node;
        }
        return left;
    }

    private static readonly string[] PatternKeywords = ["and", "or", "not", "when"];

    private SyntaxNode ParsePattern()
    {
        var start = Mark();
        while (Accept("not"))
        {
            // repeated negation is legal and changes nothing here
        }

        if (Is("("))
        {
            Accept("(");
            while (!AtEnd && !Is(")"))
            {
                var before = _index;
                ParsePattern();
                if (!IsAny("and", "or") && _index == before)
                    _index++;
                else if (IsAny("and", "or"))
                    _index++;
            }
            Accept(")");
            AcceptDesignation();
            return Node(NodeKind.Pattern, start, "group");
        }

        if (Is("null"))
        {
            _index++;
            return Node(NodeKind.Pattern, start, "null");
        }
        if (Is("{"))
        {
            SkipBalanced("{", "}");
            AcceptDesignation();
            return Node(NodeKind.Pattern, start, "property");
        }

        var text = string.Empty;
        if (IsName && !IsAny(PatternKeywords))
            text = ParseQualifiedName();
        else if (Current is { Kind: TokenKind.Number or TokenKind.String })
            text = Take().Text;
        else if (IsAny("<", ">", "<=", ">=", "==", "!="))
        {
            _index++;
            if (Current is { Kind: TokenKind.Number or TokenKind.String } || IsName)
                text = Take().Text;
        }

        if (Is("{"))
            SkipBalanced("{", "}");
        AcceptDesignation();
        while (IsAny("and", "or"))
        {
            _index++;
            ParsePattern();
        }
        return Node(NodeKind.Pattern, start, text);
    }

    /// <summary>Consumes the variable a pattern binds to, without eating a pattern combinator.</summary>
    private void AcceptDesignation()
    {
        if (IsIdentifier && !IsAny(PatternKeywords))
            _index++;
    }

    private SyntaxNode? ParseUnary()
    {
        if (AtEnd)
            return null;
        var start = Mark();

        if (IsAny("!", "-", "+", "~", "++", "--", "await", "&", "*", "^"))
        {
            var op = Take().Text;
            var operand = ParseUnary();
            var node = Node(NodeKind.Unary, start, op);
            if (operand != null)
                node.Add(operand);
            return node;
        }

        if (Is("new"))
            return ParseObjectCreation(start);

        if (Is("(") && LooksLikeCast())
        {
            Accept("(");
            var type = ParseType();
            Accept(")");
            var operand = ParseUnary();
            var cast = Node(NodeKind.Cast, start, type.Text);
            cast.Add(type);
            if (operand != null)
                cast.Add(operand);
            return cast;
        }

        return ParsePostfix(ParsePrimary());
    }

    /// <summary>A parenthesised type followed by an operand, as opposed to a grouped expression.</summary>
    private bool LooksLikeCast()
    {
        var start = _index;
        try
        {
            Accept("(");
            if (!IsName)
                return false;
            var type = ParseType();
            if (type.Text.Length == 0 || !Is(")"))
                return false;
            var next = PeekText();
            return IsPredefined(type.Text)
                   || next is not ("" or ")" or ";" or "," or "." or "*" or "+" or "-" or "/" or "=="
                       or "!=" or "&&" or "||" or "?" or ":" or "]" or "}" or "=");
        }
        finally
        {
            _index = start;
        }
    }

    private static bool IsPredefined(string type)
        => PredefinedTypes.Contains(type.TrimEnd('?', '*', '[', ']'), StringComparer.Ordinal);

    private SyntaxNode ParseObjectCreation(int start)
    {
        Expect("new");
        var typeName = string.Empty;
        if (IsName)
        {
            var type = ParseType();
            typeName = type.Text;
        }

        var node = Node(NodeKind.ObjectCreation, start, typeName);
        if (Is("("))
            node.Add(ParseArgumentList());
        if (Is("["))
        {
            Accept("[");
            var sizes = new List<SyntaxNode>();
            while (!AtEnd && !Is("]"))
            {
                var before = _index;
                if (ParseAssignment() is { } size)
                    sizes.Add(size);
                if (!Accept(",") && _index == before)
                    _index++;
            }
            Accept("]");
            node = Node(NodeKind.ArrayCreation, start, typeName);
            foreach (var size in sizes)
                node.Add(size);
        }
        if (Is("{"))
            node.Add(ParseInitializer());
        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        return node;
    }

    private SyntaxNode ParseInitializer()
    {
        var start = Mark();
        var node = new SyntaxNode(NodeKind.ObjectInitializer, "",
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("{"))
            return node;

        while (!AtEnd && !Is("}"))
        {
            var before = _index;
            if (Is("{"))
            {
                node.Add(ParseInitializer());
            }
            else if (ParseAssignment() is { } element)
            {
                node.Add(element);
            }
            if (!Accept(",") && _index == before)
                _index++;
        }
        Accept("}");
        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        return node;
    }

    private SyntaxNode ParseArgumentList()
    {
        var start = Mark();
        var list = new SyntaxNode(NodeKind.ArgumentList, "",
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("("))
            return list;

        while (!AtEnd && !Is(")"))
        {
            var before = _index;
            while (IsAny("ref", "out", "in"))
                _index++;
            // named argument
            if (IsIdentifier && PeekText() == ":" && PeekText(2) != ":")
                _index += 2;
            if (Is("out") || (IsName && PeekText() == ")" && Is("_")))
                _index++;

            if (ParseAssignment() is { } argument)
                list.Add(argument);
            if (!Accept(",") && _index == before)
                _index++;
        }
        Accept(")");
        list.Tokens = SliceFrom(start);
        list.Range = TextRange.Of(list.Tokens);
        return list;
    }

    private SyntaxNode? ParsePostfix(SyntaxNode? node)
    {
        while (node != null && !AtEnd)
        {
            if (Is(".") || Is("?.") || Is("->"))
            {
                _index++;
                if (!IsName)
                    break;
                var memberStart = Mark();
                var member = Take().Text;
                if (Is("<") && PeekIsGenericCall())
                    SkipGenericParameters();
                var memberNode = Node(NodeKind.Identifier, memberStart, member);
                var select = new SyntaxNode(NodeKind.MemberSelect, "", node.Range, node.Tokens);
                select.Add(node);
                select.Add(memberNode);
                select.Text = SyntaxQuery.DottedName(select);
                select.Range = new TextRange(node.Range.StartLine, node.Range.StartColumn,
                    memberNode.Range.EndLine, memberNode.Range.EndColumn);
                select.Tokens = node.Tokens.Concat(memberNode.Tokens).ToArray();
                node = select;
                continue;
            }

            if (Is("("))
            {
                var arguments = ParseArgumentList();
                var invocation = new SyntaxNode(NodeKind.Invocation, SyntaxQuery.DottedName(node),
                    node.Range, node.Tokens);
                invocation.Add(node);
                invocation.Add(arguments);
                invocation.Range = new TextRange(node.Range.StartLine, node.Range.StartColumn,
                    arguments.Range.EndLine, arguments.Range.EndColumn);
                invocation.Tokens = node.Tokens.Concat(arguments.Tokens).ToArray();
                node = invocation;
                continue;
            }

            if (Is("["))
            {
                var start = Mark();
                SkipBalanced("[", "]");
                var index = Node(NodeKind.Index, start, SyntaxQuery.DottedName(node));
                index.Add(node);
                node = index;
                continue;
            }

            if (Is("++") || Is("--") || Is("!"))
            {
                var start = Mark();
                var op = Take().Text;
                var unary = Node(NodeKind.Unary, start, op);
                unary.Add(node);
                node = unary;
                continue;
            }

            if (Is("{") && node.Kind is NodeKind.ObjectCreation)
            {
                node.Add(ParseInitializer());
                continue;
            }

            if (Is("switch") && PeekText() == "{")
            {
                var start = Mark();
                var switchExpression = ParseSwitchExpression(start);
                switchExpression.Add(node);
                node = switchExpression;
                continue;
            }

            if (Is("with") && PeekText() == "{")
            {
                _index++;
                var initializer = ParseInitializer();
                var withExpression = new SyntaxNode(NodeKind.ObjectCreation, SyntaxQuery.DottedName(node),
                    node.Range, node.Tokens);
                withExpression.Add(node);
                withExpression.Add(initializer);
                node = withExpression;
                continue;
            }

            break;
        }
        return node;
    }

    private bool PeekIsGenericCall()
    {
        var start = _index;
        var result = TryScanGenerics(out _);
        _index = start;
        return result;
    }

    private SyntaxNode? ParsePrimary()
    {
        if (AtEnd)
            return null;
        var start = Mark();
        var token = Current!;

        switch (token.Kind)
        {
            case TokenKind.Number:
                _index++;
                return Node(NodeKind.NumberLiteral, start, token.Text);
            case TokenKind.String:
                _index++;
                return Node(NodeKind.StringLiteral, start, token.Text);
        }

        if (Is("$") && Peek() is { Kind: TokenKind.String })
        {
            _index++;
            var literal = Take();
            return BuildInterpolatedString(start, literal);
        }

        switch (Text)
        {
            case "true":
            case "false":
                _index++;
                return Node(NodeKind.BooleanLiteral, start, token.Text);
            case "null":
                _index++;
                return Node(NodeKind.NullLiteral, start, "null");
            case "throw":
                _index++;
                var thrown = ParseExpression();
                var throwNode = Node(NodeKind.Jump, start, "throw");
                if (thrown != null)
                    throwNode.Add(thrown);
                return throwNode;
            case "typeof":
            case "sizeof":
            case "nameof":
            case "default":
                var keyword = Take().Text;
                var call = Node(NodeKind.Invocation, start, keyword);
                if (Is("("))
                    call.Add(ParseArgumentList());
                return call;
            case "switch":
                return ParseSwitchExpression(start);
            case "stackalloc":
                _index++;
                return ParseUnary() ?? Node(NodeKind.Unknown, start, "stackalloc");
        }

        if (Is("("))
            return ParseParenthesizedOrLambda(start);

        if (Is("["))
        {
            SkipBalanced("[", "]");
            return Node(NodeKind.ListLiteral, start, "collection");
        }

        if (Is("{"))
        {
            // array or collection initializer used as an expression
            var initializer = ParseInitializer();
            var literal = new SyntaxNode(NodeKind.ListLiteral, "initializer", initializer.Range, initializer.Tokens);
            foreach (var element in initializer.Children.ToArray())
                literal.Add(element);
            return literal;
        }

        if (IsName)
        {
            var name = Take().Text;
            if (IsLambdaArrow)
            {
                var arrow = Take().Text;
                var lambda = Node(NodeKind.Lambda, start, arrow);
                var parameters = new SyntaxNode(NodeKind.ParameterList, "", lambda.Range, lambda.Tokens);
                parameters.Add(new SyntaxNode(NodeKind.Parameter, name, lambda.Range, lambda.Tokens));
                lambda.Add(parameters);
                AddLambdaBody(lambda);
                return lambda;
            }
            if (Is("<") && PeekIsGenericCall() && PeekAfterGenericsIsCall())
                SkipGenericParameters();
            return Node(NodeKind.Identifier, start, name);
        }

        _index++;
        return Node(NodeKind.Unknown, start, token.Text);
    }

    private bool PeekAfterGenericsIsCall()
    {
        var start = _index;
        try
        {
            return TryScanGenerics(out _) && (Is("(") || Is("."));
        }
        finally
        {
            _index = start;
        }
    }

    private SyntaxNode ParseSwitchExpression(int start)
    {
        Expect("switch");
        var node = Node(NodeKind.SwitchExpression, start, "switch");
        if (Accept("{"))
        {
            while (!AtEnd && !Is("}"))
            {
                var before = _index;
                var arm = ParsePattern();
                if (Is("when"))
                {
                    _index++;
                    ParseExpression();
                }
                if (Accept("=>") && ParseAssignment() is { } value)
                {
                    var section = new SyntaxNode(NodeKind.SwitchSection, arm.Text, arm.Range, arm.Tokens);
                    section.Add(value);
                    node.Add(section);
                }
                if (!Accept(",") && _index == before)
                    _index++;
            }
            Accept("}");
        }
        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        return node;
    }

    private SyntaxNode ParseParenthesizedOrLambda(int start)
    {
        if (LooksLikeParenthesizedLambda())
        {
            var parameters = ParseParameterList();
            if (!Accept("=>"))
                Accept("->");
            var lambda = Node(NodeKind.Lambda, start, "=>");
            lambda.Add(parameters);
            AddLambdaBody(lambda);
            return lambda;
        }

        Accept("(");
        var inner = ParseAssignment();
        if (Is(","))
        {
            var tuple = Node(NodeKind.Tuple, start, "tuple");
            if (inner != null)
                tuple.Add(inner);
            while (Accept(","))
            {
                if (ParseAssignment() is { } element)
                    tuple.Add(element);
            }
            Accept(")");
            tuple.Tokens = SliceFrom(start);
            tuple.Range = TextRange.Of(tuple.Tokens);
            return tuple;
        }
        Accept(")");
        var node = Node(NodeKind.Parenthesized, start);
        if (inner != null)
            node.Add(inner);
        return node;
    }

    private bool LooksLikeParenthesizedLambda()
    {
        var start = _index;
        var depth = 0;
        while (!AtEnd)
        {
            if (Is("("))
                depth++;
            else if (Is(")"))
            {
                depth--;
                if (depth == 0)
                {
                    _index++;
                    var isLambda = IsLambdaArrow;
                    _index = start;
                    return isLambda;
                }
            }
            else if (Is(";") || Is("{"))
                break;
            _index++;
        }
        _index = start;
        return false;
    }

    private void AddLambdaBody(SyntaxNode lambda)
    {
        if (Is("{"))
        {
            var block = ParseBlock();
            lambda.Add(block);
            lambda.Range = lambda.Range with { EndLine = block.Range.EndLine };
            return;
        }
        if (ParseAssignment() is { } expression)
        {
            lambda.Add(expression);
            lambda.Range = lambda.Range with { EndLine = expression.Range.EndLine };
        }
    }

    /// <summary>
    /// Builds an interpolated string node and parses the expressions inside its holes, so values
    /// interpolated into SQL, HTML or commands are visible to the data-flow analysis.
    /// </summary>
    private SyntaxNode BuildInterpolatedString(int start, Token literal)
    {
        var node = Node(NodeKind.InterpolatedString, start, literal.Text);
        foreach (var hole in ExtractHoles(literal.Text))
        {
            var tokens = new SourceTokenizer(hole, _language).Tokenize()
                .Where(t => t.Kind != TokenKind.Comment)
                .Select(t => new Token(t.Kind, t.Text, literal.Line, literal.Column))
                .ToArray();
            if (tokens.Length == 0)
                continue;
            var inner = new CSharpParser(tokens, _language, _dialect).ParseExpression();
            var interpolation = new SyntaxNode(NodeKind.Interpolation, hole, node.Range, node.Tokens);
            if (inner != null)
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
            var format = hole.IndexOf(':');
            if (format > 0)
                hole = hole[..format];
            if (hole.Trim().Length > 0)
                yield return hole;
            i = j - 1;
        }
    }
}
