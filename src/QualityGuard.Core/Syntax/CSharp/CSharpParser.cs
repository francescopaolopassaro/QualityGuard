using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax.CSharp;

/// <summary>Grammar variations between the curly-brace languages this parser covers.</summary>
public enum CFamilyDialect
{
    CSharp,
    Java,
    Go,
    JavaScript,
    TypeScript,
    Php,
    Kotlin
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

    /// <summary>
    /// Go allows a composite literal after a type name, which collides with the brace that opens the
    /// body of a control statement. While a control header is being parsed the literal form is banned,
    /// exactly as the language specification requires.
    /// </summary>
    private int _compositeLiteralBan;

    /// <summary>
    /// How deep the expression parser currently is. Generated code and machine-written initialisers
    /// nest far past anything a person writes, and a recursive descent that follows them all the way
    /// down runs out of stack — which no catch block can recover from, so it ends the whole run. Past
    /// this depth the parser stops descending and records what is left as one unread node.
    /// </summary>
    private int _expressionDepth;

    private const int MaxExpressionDepth = 40;

    /// <summary>How many blocks deep the parser currently is.</summary>
    private int _blockDepth;

    private const int MaxBlockDepth = 96;

    private CSharpParser(IReadOnlyList<Token> tokens, LanguageInfo language, CFamilyDialect dialect)
    {
        _tokens = tokens;
        _language = language;
        _dialect = dialect;
    }

    private static readonly string[] GoTypeKeywords = ["type"];

    private static readonly string[] JsModifiers =
    [
        "export", "default", "async", "static", "public", "private", "protected", "readonly",
        "abstract", "declare", "override", "accessor"
    ];

    private static readonly string[] JsTypeKeywords = ["class", "interface", "enum", "namespace"];

    private static readonly string[] JsDeclarationKeywords = ["const", "let", "var"];

    /// <summary>
    /// Kotlin puts a great deal in front of a declaration, and all of it is a modifier: what a class
    /// is (data, sealed, enum, annotation), how it may be extended (open, final, abstract), and how a
    /// function behaves (suspend, inline, operator, infix).
    /// </summary>
    private static readonly string[] KotlinModifiers =
    [
        "public", "private", "protected", "internal", "open", "final", "abstract", "override",
        "const", "lateinit", "suspend", "inline", "noinline", "crossinline", "reified", "data",
        "sealed", "annotation", "enum", "companion", "inner", "operator", "infix", "tailrec",
        "external", "vararg", "expect", "actual", "value", "fun"
    ];

    /// <summary>
    /// The words that open a type. 'fun' is not among them: a Kotlin function is parsed on its own
    /// path because the name comes before the type, not after it.
    /// </summary>
    private static readonly string[] KotlinTypeKeywords = ["class", "interface", "object"];

    private bool IsJava => _dialect == CFamilyDialect.Java;

    private bool IsGo => _dialect == CFamilyDialect.Go;

    private bool IsJs => _dialect is CFamilyDialect.JavaScript or CFamilyDialect.TypeScript;

    private bool IsTs => _dialect == CFamilyDialect.TypeScript;

    private bool IsPhp => _dialect == CFamilyDialect.Php;

    private bool IsKotlin => _dialect == CFamilyDialect.Kotlin;

    private string[] ModifierWords => _dialect switch
    {
        CFamilyDialect.Java => JavaModifiers,
        CFamilyDialect.Go => [],
        CFamilyDialect.JavaScript or CFamilyDialect.TypeScript => JsModifiers,
        CFamilyDialect.Kotlin => KotlinModifiers,
        _ => Modifiers
    };

    private string[] TypeWords => _dialect switch
    {
        CFamilyDialect.Java => JavaTypeKeywords,
        CFamilyDialect.Go => GoTypeKeywords,
        CFamilyDialect.JavaScript or CFamilyDialect.TypeScript => JsTypeKeywords,
        CFamilyDialect.Kotlin => KotlinTypeKeywords,
        _ => TypeKeywords
    };

    private bool IsLambdaArrow => Is("=>") || ((IsJava || IsKotlin) && Is("->"));

    public static SyntaxNode Parse(IReadOnlyList<Token> tokens, LanguageInfo language,
        CFamilyDialect dialect = CFamilyDialect.CSharp)
    {
        var code = (IReadOnlyList<Token>)tokens.Where(t => t.Kind != TokenKind.Comment).ToArray();
        var root = new SyntaxNode(NodeKind.TopLevel, "", TextRange.Of(tokens), tokens);
        if (code.Count == 0)
            return root;
        if (dialect == CFamilyDialect.Go)
            code = GoSemicolons.Insert(code);
        else if (dialect is CFamilyDialect.JavaScript or CFamilyDialect.TypeScript)
            code = JsSemicolons.Insert(code);
        else if (dialect == CFamilyDialect.Kotlin)
            code = KotlinSemicolons.Insert(code);
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

        if ((IsJava || IsGo || IsKotlin) && (Is("import") || Is("package")))
        {
            var isPackage = Is("package");
            _index++;
            if (IsGo && Is("("))
            {
                // grouped import block: one node holding every imported path
                var group = Node(NodeKind.ImportDeclaration, start, "imports");
                Accept("(");
                while (!AtEnd && !Is(")"))
                {
                    if (Current is { Kind: TokenKind.String } path)
                        group.Add(new SyntaxNode(NodeKind.ImportDeclaration, path.Text,
                            TextRange.Of(path, path), [path]));
                    _index++;
                }
                Accept(")");
                Accept(";");
                group.Tokens = SliceFrom(start);
                group.Range = TextRange.Of(group.Tokens);
                return group;
            }

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

        if (IsJs && (Is("import") || Is("export")) && !IsExportedDeclaration())
            return ParseJsImportOrExport(start);

        var modifiers = ParseModifiers();
        if (IsJs && Is("function"))
            return ParseJsFunction(start, modifiers);
        if (IsTs && Is("type") && Peek() is { Kind: TokenKind.Identifier })
            return ParseTsTypeAlias(start);
        if (IsKotlin && Is("fun"))
            return ParseKotlinFunction(start, attributes, modifiers);
        if (IsKotlin && (Is("val") || Is("var")))
            return ParseKotlinProperty(start, attributes, modifiers);
        if (IsGo && Is("func"))
            return ParseGoFunction(start);
        if (IsGo && Is("type"))
            return ParseGoTypeDeclaration(start);
        if (IsGo && (Is("var") || Is("const")))
            return ParseGoVariableBlock(start);
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
        // TypeScript and JavaScript spell a decorator the same way Java spells an annotation, and
        // reading '@Field(type => Int)' as a declaration made every repeated decorator in a file
        // look like a member declared twice — reported as a defect, at critical severity.
        while ((IsJava || IsKotlin || IsJs) && Is("@") && Peek() is { Kind: TokenKind.Identifier })
        {
            var annotationStart = Mark();
            _index++;
            var annotation = ParseQualifiedName();
            var node = Node(NodeKind.Attribute, annotationStart, annotation);
            if (Is("("))
                node.Add(ParseArgumentList());
            attributes.Add(node);
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
                    // the arguments belong to the attribute: several rules ask what it was given,
                    // and skipping them made [Obsolete("use X")] indistinguishable from [Obsolete]
                    var node = Node(NodeKind.Attribute, nameStart, name);
                    if (Is("("))
                        node.Add(ParseArgumentList());
                    attributes.Add(node);
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
        // Only C# writes an attribute as '[Name]'. Everywhere else the bracket opens a list, and in
        // PHP and JavaScript a statement can start with one: '[$a, $b] = $pair' unpacks a value, and
        // reading it as an attribute split one assignment into two statements.
        if (_dialect != CFamilyDialect.CSharp)
            return false;

        var next = Peek();
        if (next is not { Kind: TokenKind.Identifier or TokenKind.Keyword })
            return false;
        // An attribute list closes. A '[' that never does belongs to a source being edited, and
        // reading it as one consumed the rest of the file — after which every position was past the
        // end. Look ahead for the bracket, and stop at what an attribute can never contain.
        var depth = 0;
        var parens = 0;
        for (var i = _index; i < _tokens.Count && i < _index + 200; i++)
        {
            var text = _tokens[i].Text;
            if (text == "(")
                parens++;
            else if (text == ")")
            {
                // an attribute carries arguments, so only a parenthesis that closes nothing ends it
                if (parens == 0)
                    return false;
                parens--;
            }
            else if (text == "[")
                depth++;
            else if (text == "]" && --depth == 0)
                return true;
            else if (parens == 0 && text is "{" or ";")
                return false;
        }
        return false;
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
        SyntaxNode? primaryConstructor = null;
        if (Is("("))
        {
            // the primary constructor of a Kotlin class declares the properties of the type, so it is
            // parsed rather than skipped; a record does the same and loses nothing by it
            if (IsKotlin)
                primaryConstructor = ParseParameterList();
            else
                SkipBalanced("(", ")");
        }

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
        if (primaryConstructor != null)
            node.Add(primaryConstructor);

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

    /// <summary>True when export is followed by a declaration rather than by a list or a binding.</summary>
    private bool IsExportedDeclaration()
        => Is("export") && PeekText() is "class" or "function" or "const" or "let" or "var" or "async"
            or "interface" or "enum" or "abstract" or "default" or "namespace" or "type";

    private SyntaxNode ParseJsImportOrExport(int start)
    {
        var isImport = Is("import");
        _index++;
        var name = new System.Text.StringBuilder();
        while (!AtEnd && !Is(";"))
        {
            if (Current is { Kind: TokenKind.String } path)
                name.Append(path.Text);
            _index++;
        }
        Accept(";");
        return Node(isImport ? NodeKind.ImportDeclaration : NodeKind.PackageDeclaration, start,
            name.ToString());
    }

    /// <summary>function declarations, including generators and the async form.</summary>
    private SyntaxNode ParseJsFunction(int start, List<string> modifiers)
    {
        Expect("function");
        Accept("*");
        var name = IsName ? Take().Text : string.Empty;
        if (Is("<"))
            SkipGenericParameters();
        var node = Node(NodeKind.FunctionDeclaration, start, name);
        foreach (var modifier in modifiers)
            node.Add(new SyntaxNode(NodeKind.Modifier, modifier, node.Range));
        if (Is("("))
            node.Add(ParseParameterList());
        SkipTsReturnType();
        AddBody(node);
        return node;
    }

    private SyntaxNode ParseTsTypeAlias(int start)
    {
        Expect("type");
        var name = IsName ? Take().Text : string.Empty;
        if (Is("<"))
            SkipGenericParameters();
        Accept("=");
        var depth = 0;
        while (!AtEnd)
        {
            if (Is("{") || Is("(") || Is("["))
                depth++;
            else if (Is("}") || Is(")") || Is("]"))
                depth--;
            else if (Is(";") && depth <= 0)
                break;
            _index++;
        }
        Accept(";");
        return Node(NodeKind.ClassDeclaration, start, name);
    }

    private void SkipTsReturnType()
    {
        if (!IsTs || !Is(":"))
            return;
        _index++;
        var depth = 0;
        var expectingType = true;
        while (!AtEnd)
        {
            if (Is("{"))
            {
                if (depth == 0 && !expectingType)
                    return; // the body of the function starts here
                SkipBalanced("{", "}");
                expectingType = false;
                continue;
            }
            if (Is("(") || Is("[") || Is("<"))
            {
                depth++;
                expectingType = true;
            }
            else if (Is(")") || Is("]") || Is(">"))
            {
                if (depth == 0)
                    return;
                depth--;
                expectingType = false;
            }
            else if ((Is(";") || Is("=>") || Is("=")) && depth <= 0)
            {
                return;
            }
            else
            {
                expectingType = IsAny("|", "&", ",", ":", "extends", "keyof", "readonly");
            }
            _index++;
        }
    }

    /// <summary>Members of a JavaScript or TypeScript class.</summary>
    private SyntaxNode? ParseJsMember()
    {
        var start = Mark();
        ParseAttributes();
        var modifiers = ParseModifiers();

        if (Accept(";"))
            return null;
        if (IsAny(TypeWords))
            return ParseTypeDeclaration(start, [], modifiers);

        var isAccessor = IsAny("get", "set") && Peek() is { Kind: TokenKind.Identifier or TokenKind.Keyword };
        var accessorKind = isAccessor ? Take().Text : string.Empty;
        Accept("*");
        Accept("#");

        if (!IsName && Current is not { Kind: TokenKind.String })
            return ParseStatement();

        var name = Take().Text;
        if (Is("<"))
            SkipGenericParameters();

        if (Is("("))
        {
            var kind = isAccessor ? NodeKind.Accessor : NodeKind.FunctionDeclaration;
            var member = Node(kind, start, isAccessor ? accessorKind : name);
            foreach (var modifier in modifiers)
                member.Add(new SyntaxNode(NodeKind.Modifier, modifier, member.Range));
            member.Add(ParseParameterList());
            SkipTsReturnType();
            AddBody(member);
            return member;
        }

        var field = Node(NodeKind.FieldDeclaration, start, name);
        foreach (var modifier in modifiers)
            field.Add(new SyntaxNode(NodeKind.Modifier, modifier, field.Range));
        Accept("?");
        Accept("!");
        if (IsTs && Accept(":"))
            field.Add(ParseType());
        if (Accept("="))
        {
            if (ParseExpression() is { } value)
            {
                var assignment = new SyntaxNode(NodeKind.Assignment, "=", field.Range);
                assignment.Add(new SyntaxNode(NodeKind.Identifier, name, field.Range));
                assignment.Add(value);
                field.Add(assignment);
            }
        }
        Accept(";");
        field.Tokens = SliceFrom(start);
        field.Range = TextRange.Of(field.Tokens);
        return field;
    }

    /// <summary>const, let and var declarations, including destructuring.</summary>
    private SyntaxNode ParseJsDeclaration(int start)
    {
        var keyword = Take().Text;
        var node = Node(NodeKind.VariableDeclaration, start, string.Empty);
        while (!AtEnd)
        {
            var names = new List<string>();
            if (Is("{") || Is("["))
            {
                var open = Text;
                var close = open == "{" ? "}" : "]";
                var depth = 0;
                while (!AtEnd)
                {
                    if (Is(open))
                        depth++;
                    else if (Is(close))
                    {
                        depth--;
                        if (depth == 0)
                        {
                            _index++;
                            break;
                        }
                    }
                    else if (IsIdentifier && !Is("as"))
                        names.Add(Text);
                    _index++;
                }
            }
            else if (IsName)
            {
                names.Add(Take().Text);
            }
            else
            {
                break;
            }

            if (names.Count > 0 && node.Text.Length == 0)
                node.Text = names[0];
            Accept("?");
            Accept("!");
            if (IsTs && Accept(":"))
                node.Add(ParseType());

            if (Accept("="))
            {
                var value = ParseAssignment();
                var assignment = new SyntaxNode(NodeKind.Assignment, "=", node.Range);
                assignment.Add(new SyntaxNode(NodeKind.Identifier, names.Count > 0 ? names[0] : string.Empty,
                    node.Range));
                if (value != null)
                    assignment.Add(value);
                node.Add(assignment);
            }
            foreach (var extra in names.Skip(1))
                node.Add(new SyntaxNode(NodeKind.Identifier, extra, node.Range));

            if (!Accept(","))
                break;
        }
        Accept(";");
        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        _ = keyword;
        return node;
    }

    /// <summary>Go named types: the kind follows the name, and struct fields are name/type pairs.</summary>
    private SyntaxNode ParseGoTypeDeclaration(int start)
    {
        Expect("type");
        if (Is("("))
        {
            // grouped type block
            var group = Node(NodeKind.ClassDeclaration, start, "types");
            Accept("(");
            while (!AtEnd && !Is(")"))
            {
                var before = _index;
                if (IsIdentifier)
                    group.Add(ParseGoNamedType(Mark()));
                if (_index == before)
                    _index++;
            }
            Accept(")");
            return group;
        }
        return ParseGoNamedType(start);
    }

    private SyntaxNode ParseGoNamedType(int start)
    {
        var name = IsName ? Take().Text : string.Empty;
        if (Is("["))
            SkipBalanced("[", "]");
        var isStruct = Is("struct");
        var isInterface = Is("interface");
        if (isStruct || isInterface)
            _index++;

        var node = Node(NodeKind.ClassDeclaration, start, name);
        if (!Is("{"))
        {
            // alias to another type
            node.Add(ParseType());
            Accept(";");
            return node;
        }

        var body = ParseGoTypeBody(isInterface);
        node.Add(body);
        node.Range = node.Range with { EndLine = body.Range.EndLine };
        Accept(";");
        return node;
    }

    private SyntaxNode ParseGoTypeBody(bool isInterface)
    {
        var start = Mark();
        var block = new SyntaxNode(NodeKind.Block, "",
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("{"))
            return block;

        while (!AtEnd && !Is("}"))
        {
            var before = _index;
            if (Accept(";"))
                continue;
            if (!IsIdentifier)
            {
                _index++;
                continue;
            }

            var memberStart = Mark();
            var name = Take().Text;
            if (isInterface && Is("("))
            {
                var method = Node(NodeKind.FunctionDeclaration, memberStart, name);
                method.Add(ParseParameterList());
                if (Is("(")) SkipBalanced("(", ")");
                else if (IsName || Is("*") || Is("[")) method.Add(ParseType());
                block.Add(method);
            }
            else
            {
                var field = Node(NodeKind.FieldDeclaration, memberStart, name);
                if (!Is(";") && !Is("}"))
                    field.Add(ParseType());
                if (Current is { Kind: TokenKind.String })
                    _index++; // struct tag
                block.Add(field);
            }
            if (_index == before)
                _index++;
        }
        var closing = Current;
        Accept("}");
        block.Tokens = SliceFrom(start);
        block.Range = TextRange.Of(block.Tokens);
        if (closing != null)
            block.Range = block.Range with { EndLine = closing.Line };
        return block;
    }

    /// <summary>Package-level var and const declarations, single or grouped.</summary>
    private SyntaxNode ParseGoVariableBlock(int start)
    {
        _index++; // var | const
        if (Is("("))
        {
            var group = Node(NodeKind.Block, start, "declarations");
            Accept("(");
            while (!AtEnd && !Is(")"))
            {
                var before = _index;
                if (Accept(";"))
                    continue;
                var declaration = ParseGoSingleVariable(Mark());
                if (declaration != null)
                    group.Add(declaration);
                if (_index == before)
                    _index++;
            }
            Accept(")");
            Accept(";");
            return group;
        }
        return ParseGoSingleVariable(start) ?? Node(NodeKind.Unknown, start);
    }

    private SyntaxNode? ParseGoSingleVariable(int start)
    {
        if (!IsIdentifier)
            return null;
        var name = Take().Text;
        var node = new SyntaxNode(NodeKind.VariableDeclaration, name,
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        while (Accept(","))
        {
            if (IsIdentifier)
                _index++;
        }
        if (!Is("=") && !Is(";") && (IsName || Is("*") || Is("[")))
            node.Add(ParseType());
        if (Accept("="))
        {
            var value = ParseExpression();
            var assignment = new SyntaxNode(NodeKind.Assignment, "=", node.Range);
            assignment.Add(new SyntaxNode(NodeKind.Identifier, name, node.Range));
            if (value != null)
                assignment.Add(value);
            node.Add(assignment);
        }
        Accept(";");
        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        return node;
    }

    /// <summary>Go functions and methods, including the optional receiver.</summary>
    private SyntaxNode ParseGoFunction(int start)
    {
        Expect("func");
        if (Is("("))
            SkipBalanced("(", ")"); // receiver
        var name = IsName ? Take().Text : string.Empty;
        if (Is("["))
            SkipBalanced("[", "]"); // type parameters
        var node = Node(NodeKind.FunctionDeclaration, start, name);
        if (Is("("))
            node.Add(ParseParameterList());
        if (Is("("))
            SkipBalanced("(", ")"); // result list
        else if (IsName || Is("*") || Is("["))
            node.Add(ParseType());
        if (Is("{"))
        {
            var body = ParseBlock();
            node.Add(body);
            node.Range = node.Range with { EndLine = body.Range.EndLine };
        }
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

    // ------------------------------------------------------------- Kotlin

    /// <summary>
    /// A Kotlin function: <c>fun &lt;T&gt; Receiver.name(parameters): Type</c> followed by a block or by
    /// an expression body. The name comes before the type, which is why it cannot go through the
    /// shared member path.
    /// </summary>
    private SyntaxNode ParseKotlinFunction(int start, List<SyntaxNode> attributes, List<string> modifiers)
    {
        Expect("fun");
        if (Is("<"))
            SkipGenericParameters();

        // an extension function names the type it extends before its own name
        var name = IsName ? Take().Text : string.Empty;
        while (Is(".") && Peek() is { Kind: TokenKind.Identifier })
        {
            _index++;
            name = Take().Text;
        }
        if (Is("<"))
            SkipGenericParameters();

        var node = Node(NodeKind.FunctionDeclaration, start, name);
        AddDecorations(node, attributes, modifiers);
        if (Is("("))
            node.Add(ParseParameterList());
        if (Accept(":"))
            node.Add(ParseType());
        while (Is("where"))
        {
            while (!AtEnd && !Is("{") && !Is("=") && !Is(";"))
                _index++;
        }

        if (Accept("="))
        {
            // an expression body is the whole function, so it is kept as the body: every rule that
            // asks what a function does then finds something to read
            var bodyStart = Mark();
            var body = new SyntaxNode(NodeKind.Block, "", node.Range);
            var statement = Node(NodeKind.ExpressionStatement, bodyStart);
            if (ParseExpression() is { } value)
                statement.Add(value);
            statement.Tokens = SliceFrom(bodyStart);
            statement.Range = TextRange.Of(statement.Tokens);
            body.Add(statement);
            body.Range = statement.Range;
            node.Add(body);
            Accept(";");
        }
        else if (Is("{"))
        {
            node.Add(ParseBlock());
        }
        else
        {
            Accept(";"); // a declaration in an interface has no body at all
        }

        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        return node;
    }

    /// <summary>
    /// A Kotlin lambda: an optional parameter list ending in an arrow, then the statements. The
    /// implicit parameter has no declaration at all, which is why the list may be missing.
    /// </summary>
    private SyntaxNode ParseKotlinLambda()
    {
        var start = Mark();
        var lambda = Node(NodeKind.Lambda, start, string.Empty);
        Expect("{");

        // the parameters run up to the arrow, when there is one on the same nesting level
        var arrow = -1;
        var depth = 0;
        for (var i = _index; i < _tokens.Count && i < _index + 40; i++)
        {
            var text = _tokens[i].Text;
            if (text is "{" or "(" or "[")
                depth++;
            else if (text is "}" or ")" or "]")
            {
                if (depth == 0)
                    break;
                depth--;
            }
            else if (text == "->" && depth == 0)
            {
                arrow = i;
                break;
            }
        }

        if (arrow >= 0)
        {
            var parameters = new SyntaxNode(NodeKind.ParameterList, "", TextRange.Of([_tokens[_index]]));
            while (_index < arrow)
            {
                if (IsName)
                {
                    var parameterStart = Mark();
                    var name = Take().Text;
                    var parameter = Node(NodeKind.Parameter, parameterStart, name);
                    if (Accept(":"))
                        parameter.Add(ParseType());
                    parameters.Add(parameter);
                    continue;
                }
                _index++;
            }
            _index = arrow + 1;
            lambda.Add(parameters);
        }

        var body = new SyntaxNode(NodeKind.Block, "", lambda.Range);
        while (!AtEnd && !Is("}"))
        {
            var before = _index;
            var statement = ParseStatement();
            if (statement != null)
                body.Add(statement);
            if (_index == before)
                _index++;
        }
        var closing = Current;
        Accept("}");
        if (closing != null)
            body.Range = body.Range with { EndLine = closing.Line, EndColumn = closing.Column };
        lambda.Add(body);

        lambda.Tokens = SliceFrom(start);
        lambda.Range = TextRange.Of(lambda.Tokens);
        return lambda;
    }

    /// <summary>A val or var, with its optional type, initialiser and accessors.</summary>
    private SyntaxNode ParseKotlinProperty(int start, List<SyntaxNode> attributes, List<string> modifiers,
        bool asField = false)
    {
        Take();
        if (Is("<"))
            SkipGenericParameters();

        // a destructuring declaration names several things at once
        var names = new List<string>();
        if (Accept("("))
        {
            while (!AtEnd && !Is(")"))
            {
                if (IsName)
                    names.Add(Text);
                _index++;
            }
            Accept(")");
        }
        else if (IsName)
        {
            var first = Take().Text;
            // an extension property names its receiver first
            while (Is(".") && Peek() is { Kind: TokenKind.Identifier })
            {
                _index++;
                first = Take().Text;
            }
            names.Add(first);
        }

        // a property of a type is a field: that is what it is, and it keeps the rules about
        // members from reading it as a local variable nobody uses
        var node = Node(asField ? NodeKind.FieldDeclaration : NodeKind.VariableDeclaration, start,
            names.FirstOrDefault() ?? string.Empty);
        AddDecorations(node, attributes, modifiers);
        if (Accept(":"))
            node.Add(ParseType());
        if (Accept("by") && ParseExpression() is { } delegated)
            node.Add(delegated);

        if (Accept("="))
        {
            var value = ParseAssignment();
            var assignment = new SyntaxNode(NodeKind.Assignment, "=", node.Range);
            assignment.Add(new SyntaxNode(NodeKind.Identifier, node.Text, node.Range));
            if (value != null)
                assignment.Add(value);
            node.Add(assignment);
        }
        foreach (var extra in names.Skip(1))
            node.Add(new SyntaxNode(NodeKind.Identifier, extra, node.Range));
        Accept(";");

        // 'get() = ...' and 'set(value) { ... }' belong to the property
        while (Is("get") || Is("set"))
        {
            var accessorStart = Mark();
            var accessorName = Take().Text;
            var accessor = Node(NodeKind.Accessor, accessorStart, accessorName);
            if (Is("("))
                accessor.Add(ParseParameterList());
            if (Accept(":"))
                accessor.Add(ParseType());
            if (Accept("="))
            {
                if (ParseExpression() is { } expression)
                    accessor.Add(expression);
                Accept(";");
            }
            else if (Is("{"))
            {
                accessor.Add(ParseBlock());
            }
            else
            {
                Accept(";");
            }
            node.Add(accessor);
        }

        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        return node;
    }

    /// <summary>
    /// A member of a Kotlin type, or null when the next tokens are not one and the shared path should
    /// have its turn.
    /// </summary>
    private SyntaxNode? ParseKotlinMember(int start, List<SyntaxNode> attributes, List<string> modifiers)
    {
        if (Is("fun"))
            return ParseKotlinFunction(start, attributes, modifiers);
        if (Is("val") || Is("var"))
            return ParseKotlinProperty(start, attributes, modifiers, asField: true);

        if (Is("init") && PeekText() == "{")
        {
            _index++;
            var initializer = Node(NodeKind.ConstructorDeclaration, start, "init");
            AddDecorations(initializer, attributes, modifiers);
            initializer.Add(ParseBlock());
            return initializer;
        }

        if (Is("constructor"))
        {
            _index++;
            var constructor = Node(NodeKind.ConstructorDeclaration, start, _currentType);
            AddDecorations(constructor, attributes, modifiers);
            if (Is("("))
                constructor.Add(ParseParameterList());
            if (Accept(":"))
            {
                // 'this(...)' or 'super(...)' runs another constructor, and the reader has to see it
                var targetStart = Mark();
                var target = IsName ? Take().Text : string.Empty;
                if (Is("("))
                {
                    var call = Node(NodeKind.Invocation, targetStart, target);
                    call.Add(Node(NodeKind.Identifier, targetStart, target));
                    call.Add(ParseArgumentList());
                    constructor.Add(call);
                }
            }
            if (Is("{"))
                constructor.Add(ParseBlock());
            else
                Accept(";");
            return constructor;
        }

        return null;
    }

    /// <summary>
    /// 'when' is Kotlin's multi-way branch. It is recorded as a match, so the rules about unhandled
    /// values and about complexity see it for what it is.
    /// </summary>
    private SyntaxNode ParseKotlinWhen(int start)
    {
        Expect("when");
        var node = Node(NodeKind.Match, start, "when");
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
            while (!AtEnd && !Is("}"))
            {
                var before = _index;
                var branchStart = Mark();
                var isElse = Is("else");

                // the condition runs up to the arrow that introduces the branch
                var guard = 0;
                while (!AtEnd && !Is("}") && !IsLambdaArrow && guard++ < 200)
                {
                    if (Is("(") || Is("[") || Is("{"))
                    {
                        var open = Text;
                        SkipBalanced(open, open == "(" ? ")" : open == "[" ? "]" : "}");
                        continue;
                    }
                    _index++;
                }

                if (IsLambdaArrow)
                {
                    _index++;
                    var section = Node(NodeKind.SwitchSection, branchStart, isElse ? "else" : "case");
                    var branch = Is("{") ? ParseBlock() : ParseStatement();
                    if (branch != null)
                        section.Add(branch);
                    body.Add(section);
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
        Accept(";");
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
            var member = isEnum ? ParseEnumMember() : IsJs ? ParseJsMember() : ParseMember();
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

        if (IsKotlin && ParseKotlinMember(start, attributes, modifiers) is { } kotlinMember)
            return kotlinMember;

        if (IsPhp && ParsePhpMember(start, attributes, modifiers) is { } phpMember)
            return phpMember;

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
                // The base or this initializer runs another constructor with arguments the reader
                // has to see: skipping it made an empty-bodied constructor look like it did nothing.
                var initializerStart = Mark();
                var target = IsName ? Take().Text : string.Empty;
                if (Is("("))
                {
                    var initializer = Node(NodeKind.Invocation, initializerStart, target);
                    initializer.Add(Node(NodeKind.Identifier, initializerStart, target));
                    initializer.Add(ParseArgumentList());
                    ctor.Add(initializer);
                }
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
            // Dart writes the asynchrony marker after the parameter list; leaving it as a statement
            // detached the body from its method, which made every rule about the method blind
            while (IsAny("async", "sync"))
            {
                _index++;
                if (Is("*"))
                    _index++;
            }
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

    /// <summary>
    /// The two shapes PHP writes differently from the rest of the family: a method introduced by the
    /// <c>function</c> keyword rather than by its return type, and a property that is just a variable
    /// with visibility in front of it. Everything else — classes, statements, expressions — already
    /// reads the same way.
    /// </summary>
    private SyntaxNode? ParsePhpMember(int start, List<SyntaxNode> attributes, List<string> modifiers)
    {
        if (Is("const"))
        {
            _index++;
            var constantName = IsName ? Take().Text : string.Empty;
            var constant = Node(NodeKind.FieldDeclaration, start, constantName);
            AddDecorations(constant, attributes, modifiers);
            while (!AtEnd && !Is(";"))
                _index++;
            Accept(";");
            return constant;
        }

        if (Is("function"))
        {
            _index++;
            Accept("&");
            var name = IsName ? Take().Text : string.Empty;
            var method = Node(name == "__construct" ? NodeKind.ConstructorDeclaration
                : NodeKind.FunctionDeclaration, start, name);
            AddDecorations(method, attributes, modifiers);
            method.Add(ParseParameterList());
            if (Accept(":"))
                method.Add(ParseType());
            if (Is(";"))
            {
                // an abstract or interface method has no body
                _index++;
                return method;
            }
            AddBody(method);
            return method;
        }

        // typed or untyped property: `private ?Repo $repo = null;`
        var save = _index;
        if (IsName && !Text.StartsWith('$') && !Is("use"))
            ParseType();
        if (IsName && Text.StartsWith('$'))
        {
            var fieldName = Take().Text;
            var field = Node(NodeKind.FieldDeclaration, start, fieldName);
            AddDecorations(field, attributes, modifiers);
            while (!AtEnd && !Is(";"))
                _index++;
            Accept(";");
            return field;
        }
        _index = save;
        return null;
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
            // an accessor can narrow the visibility of the property — 'private set' is the usual one
            // — and a rule about what callers can reach has to be able to see that
            var accessorModifiers = ParseModifiers();
            if (IsAny(AccessorNames))
            {
                var accessorStart = Mark();
                var name = Take().Text;
                var accessor = new SyntaxNode(NodeKind.Accessor, name,
                    TextRange.Of([_tokens[Math.Min(accessorStart, _tokens.Count - 1)]]));
                foreach (var modifier in accessorModifiers)
                    accessor.Add(new SyntaxNode(NodeKind.Modifier, modifier, accessor.Range));
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

        if (IsGo)
            return ParseGoType(start);
        if (IsJs)
            return ParseJsType(start);
        // PHP writes the nullable marker in front of the type
        if (IsPhp)
            Accept("?");

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

    /// <summary>TypeScript annotations: unions, arrays, generics and object literals.</summary>
    private SyntaxNode ParseJsType(int start)
    {
        var text = new System.Text.StringBuilder();
        var depth = 0;
        while (!AtEnd)
        {
            if (Is("{") || Is("(") || Is("[") || Is("<"))
                depth++;
            else if (Is("}") || Is(")") || Is("]"))
            {
                if (depth == 0)
                    break;
                depth--;
            }
            else if (Is(">") || Is(">>"))
            {
                depth -= Is(">>") ? 2 : 1;
                if (depth < 0)
                    break;
            }
            else if (depth == 0 && (Is("=") || Is(";") || Is(",")))
                break;
            // a function type keeps going after its arrow
            text.Append(Take().Text);
        }
        return Node(NodeKind.TypeReference, start, text.ToString());
    }

    /// <summary>Go types read from the outside in: pointers, slices, maps, channels and functions.</summary>
    private SyntaxNode ParseGoType(int start)
    {
        var prefix = new System.Text.StringBuilder();
        while (!AtEnd)
        {
            if (Is("*") || Is("...") || Is("&"))
            {
                prefix.Append(Take().Text);
                continue;
            }
            if (Is("["))
            {
                SkipBalanced("[", "]");
                prefix.Append("[]");
                continue;
            }
            if (Is("chan"))
            {
                prefix.Append(Take().Text).Append(' ');
                continue;
            }
            if (Is("map"))
            {
                prefix.Append(Take().Text);
                if (Is("["))
                    SkipBalanced("[", "]");
                continue;
            }
            if (Is("func"))
            {
                prefix.Append(Take().Text);
                if (Is("("))
                    SkipBalanced("(", ")");
                continue;
            }
            if (Is("interface") || Is("struct"))
            {
                prefix.Append(Take().Text);
                if (Is("{"))
                    SkipBalanced("{", "}");
                return Node(NodeKind.TypeReference, start, prefix.ToString());
            }
            break;
        }

        var name = ParseQualifiedName();
        return Node(NodeKind.TypeReference, start, prefix + name);
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
            while (!IsJs && !IsGo && !IsKotlin
                   && IsAny("ref", "out", "in", "params", "this", "scoped", "readonly"))
                _index++;

            var parameterStart = Mark();
            if (IsKotlin)
            {
                // 'vararg out: String' and 'val name: String' — the modifiers come first, the name
                // second, and the type after the colon
                while (IsAny("vararg", "val", "var", "noinline", "crossinline", "private", "public",
                           "protected", "internal", "override"))
                    _index++;
                if (IsName)
                {
                    var kotlinName = Take().Text;
                    var kotlinParameter = Node(NodeKind.Parameter, parameterStart, kotlinName);
                    if (Accept(":"))
                        kotlinParameter.Add(ParseType());
                    if (Accept("=") && ParseAssignment() is { } kotlinDefault)
                        kotlinParameter.Add(kotlinDefault);
                    list.Add(kotlinParameter);
                }
                if (!Accept(",") && !Is(")") && _index == before)
                    _index++;
                continue;
            }

            if (IsJs)
            {
                while (IsAny("public", "private", "protected", "readonly"))
                    _index++;
                Accept("...");
                if (Is("{") || Is("["))
                {
                    // destructured parameter: keep the names it binds
                    var open = Text;
                    var close = open == "{" ? "}" : "]";
                    var depth = 0;
                    while (!AtEnd)
                    {
                        if (Is(open))
                            depth++;
                        else if (Is(close))
                        {
                            depth--;
                            if (depth == 0)
                            {
                                _index++;
                                break;
                            }
                        }
                        else if (IsIdentifier)
                            list.Add(new SyntaxNode(NodeKind.Parameter, Text, TextRange.Of([Current!])));
                        _index++;
                    }
                }
                else if (IsName)
                {
                    var jsName = Take().Text;
                    var jsParameter = Node(NodeKind.Parameter, parameterStart, jsName);
                    Accept("?");
                    if (IsTs && Accept(":"))
                        jsParameter.Add(ParseType());
                    if (Accept("=") && ParseAssignment() is { } jsDefault)
                        jsParameter.Add(jsDefault);
                    list.Add(jsParameter);
                }
                if (!Accept(",") && !Is(")") && _index == before)
                    _index++;
                continue;
            }

            if (IsGo)
            {
                // Go writes the name before the type
                var goName = IsIdentifier ? Take().Text : string.Empty;
                if (Is(",") || Is(")"))
                {
                    // a parameter list that only declares types, or a shared type across names
                    if (goName.Length > 0)
                        list.Add(new SyntaxNode(NodeKind.Parameter, goName,
                            TextRange.Of(SliceFrom(parameterStart)), SliceFrom(parameterStart)));
                }
                else
                {
                    var goType = ParseType();
                    var goParameter = Node(NodeKind.Parameter, parameterStart, goName);
                    goParameter.Add(goType);
                    list.Add(goParameter);
                }
                if (!Accept(",") && !Is(")") && _index == before)
                    _index++;
                continue;
            }

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
        if (_blockDepth >= MaxBlockDepth)
            return SkipDeepBlock();

        _blockDepth++;
        try
        {
            return ParseBlockCore();
        }
        finally
        {
            _blockDepth--;
        }
    }

    /// <summary>
    /// Consumes a block nested deeper than the parser will follow. Generated code reaches depths no
    /// person writes, and following them exhausts the stack — which ends the whole run, because a
    /// stack overflow is the one failure no catch block can take back.
    /// </summary>
    private SyntaxNode SkipDeepBlock()
    {
        var start = Mark();
        var depth = 0;
        while (!AtEnd)
        {
            if (Is("{"))
                depth++;
            else if (Is("}"))
            {
                depth--;
                if (depth == 0)
                {
                    _index++;
                    break;
                }
            }
            _index++;
        }
        return Node(NodeKind.Block, start, "…");
    }

    private SyntaxNode ParseBlockCore()
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

    /// <summary>
    /// The PHP statements that are a keyword followed by a name or a path. Left to the expression
    /// parser they break into several nodes on one line, which reads as several statements and made
    /// every file with an import look badly formatted.
    /// </summary>
    private SyntaxNode? ParsePhpStatement(int start)
    {
        var keyword = Text;
        var isImport = keyword is "use" or "require" or "require_once" or "include" or "include_once";
        if (!isImport && keyword is not ("declare" or "global" or "echo" or "print" or "goto"))
            return null;
        // `use` also introduces a trait inside a class and a closure binding: both end at ; or {
        _index++;

        var target = new System.Text.StringBuilder();
        while (!AtEnd && !Is(";") && !Is("{"))
            target.Append(Take().Text);
        Accept(";");

        return isImport
            ? Node(NodeKind.ImportDeclaration, start, target.ToString())
            : Node(NodeKind.ExpressionStatement, start, keyword);
    }

    private SyntaxNode? ParseStatement()
    {
        if (AtEnd)
            return null;

        var start = Mark();
        ParseAttributes();

        if (IsPhp && ParsePhpStatement(start) is { } phpStatement)
            return phpStatement;

        switch (Text)
        {
            case "{":
                return ParseBlock();
            case ";":
                _index++;
                // generated terminators are not empty statements
                return IsGo || IsJs || IsKotlin ? null : Node(NodeKind.ExpressionStatement, start, ";");
            case "if":
                return ParseIf(start);
            case "switch":
                return ParseSwitchStatement(start);
            case "for":
                return IsGo ? ParseGoFor(start) : ParseFor(start);
            case "var" when IsGo:
            case "const" when IsGo:
                return ParseGoVariableBlock(start);
            case "const" when IsJs:
            case "let" when IsJs:
            case "var" when IsJs:
                return ParseJsDeclaration(start);
            case "val" when IsKotlin:
            case "var" when IsKotlin:
                return ParseKotlinProperty(start, [], []);
            case "fun" when IsKotlin:
                return ParseKotlinFunction(start, [], []);
            case "when" when IsKotlin:
                return ParseKotlinWhen(start);
            case "function" when IsJs:
                return ParseJsFunction(start, []);
            case "import" when IsJs:
            case "export" when IsJs:
                return ParseJsImportOrExport(start);
            case "type" when IsGo:
                return ParseGoTypeDeclaration(start);
            case "func" when IsGo && PeekText() != "(":
                return ParseGoFunction(start);
            case "go" when IsGo:
            case "defer" when IsGo:
                var concurrencyKeyword = Take().Text;
                var deferred = Node(NodeKind.ExpressionStatement, start, concurrencyKeyword);
                if (ParseExpression() is { } deferredCall)
                    deferred.Add(deferredCall);
                Accept(";");
                return deferred;
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

        if (IsGo && TryParseGoShortDeclaration(start) is { } shortDeclaration)
            return shortDeclaration;

        if (TryParseLocalDeclaration(start) is { } declaration)
            return declaration;

        var expression = ParseExpression();
        Accept(";");
        var statement = Node(NodeKind.ExpressionStatement, start);
        if (expression != null)
            statement.Add(expression);
        return statement;
    }

    /// <summary>Short variable declarations of the form name := value.</summary>
    private SyntaxNode? TryParseGoShortDeclaration(int start)
    {
        if (!IsIdentifier)
            return null;
        var reset = _index;
        var names = new List<string> { Take().Text };
        while (Accept(","))
        {
            if (!IsIdentifier)
            {
                _index = reset;
                return null;
            }
            names.Add(Take().Text);
        }
        if (!Is(":="))
        {
            _index = reset;
            return null;
        }
        _index++;

        var anchor = TextRange.Of([_tokens[Math.Min(reset, _tokens.Count - 1)]]);
        var declaration = new SyntaxNode(NodeKind.VariableDeclaration, names[0], anchor);
        var value = ParseExpression();
        var assignment = new SyntaxNode(NodeKind.Assignment, "=", anchor);
        assignment.Add(new SyntaxNode(NodeKind.Identifier, names[0], anchor));
        if (value != null)
            assignment.Add(value);
        declaration.Add(assignment);
        foreach (var extra in names.Skip(1))
            declaration.Add(new SyntaxNode(NodeKind.Identifier, extra, anchor));
        Accept(";");
        declaration.Tokens = SliceFrom(start);
        declaration.Range = TextRange.Of(declaration.Tokens);
        return declaration;
    }

    /// <summary>
    /// Words that begin a statement and can never be the type of a local function. Without them
    /// 'await Helper(items)' read as 'await' the return type and 'Helper' the name, which turned an
    /// ordinary call into a declaration — and with it every rule that asks who calls what.
    /// </summary>
    private static readonly string[] NotATypeName =
        ["await", "return", "throw", "yield", "new", "typeof", "sizeof", "nameof", "default",
         "checked", "unchecked", "stackalloc", "delegate"];

    private bool LooksLikeLocalFunction()
    {
        var start = _index;
        try
        {
            if (!IsName || IsAny(NotATypeName))
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
        else if (IsGo)
        {
            _compositeLiteralBan++;
            if (TryParseGoShortDeclaration(Mark()) is { } init)
                node.Add(init);
            if (!Is("{") && ParseExpression() is { } goCondition)
                node.Add(goCondition);
            _compositeLiteralBan--;
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
        else if (IsGo && !Is("{"))
        {
            _compositeLiteralBan++;
            if (ParseExpression() is { } goSubject)
                node.Add(goSubject);
            _compositeLiteralBan--;
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
            if (IsJs && IsAny("const", "let", "var"))
            {
                node.Add(ParseJsDeclaration(Mark()));
            }
            else if (!Is(";") && TryParseLocalDeclaration(Mark()) is { } initializer)
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

    private SyntaxNode ParsePhpForEach(int start, SyntaxNode node)
    {
        if (!Accept("("))
            return node;

        if (ParseExpression() is { } source)
            node.Add(source);
        if (Accept("as"))
        {
            var names = new List<string>();
            while (!AtEnd && !Is(")"))
            {
                if (IsName)
                    names.Add(Take().Text);
                else
                    _index++;
            }
            // the last name is the value; an earlier one is the key
            var name = names.LastOrDefault() ?? string.Empty;
            var variable = Node(NodeKind.VariableDeclaration, start, name);
            foreach (var extra in names)
                variable.Add(Node(NodeKind.Identifier, start, extra));
            node.Add(variable);
        }
        Accept(")");
        AddEmbeddedStatement(node);
        return node;
    }

    private SyntaxNode ParseForEach(int start)
    {
        Expect("foreach");
        var node = Node(NodeKind.Loop, start, "foreach");

        // PHP names the collection first: foreach ($items as $key => $value)
        if (IsPhp)
            return ParsePhpForEach(start, node);

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

    /// <summary>The single Go loop form: condition only, three-clause, or range.</summary>
    private SyntaxNode ParseGoFor(int start)
    {
        Expect("for");
        var node = Node(NodeKind.Loop, start, "for");
        _compositeLiteralBan++;
        while (!AtEnd && !Is("{"))
        {
            var before = _index;
            if (TryParseGoShortDeclaration(Mark()) is { } init)
                node.Add(init);
            else if (Is("range"))
            {
                _index++;
                if (ParseExpression() is { } sequence)
                    node.Add(sequence);
            }
            else if (ParseExpression() is { } part)
                node.Add(part);
            if (!Accept(";") && _index == before)
                _index++;
        }
        _compositeLiteralBan--;
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
            // Go returns several values at once
            while (Accept(","))
            {
                if (ParseExpression() is { } extra)
                    node.Add(extra);
                else
                    break;
            }
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
        if (_expressionDepth >= MaxExpressionDepth)
            return SkipDeepExpression();

        _expressionDepth++;
        try
        {
            return ParseAssignmentCore();
        }
        finally
        {
            _expressionDepth--;
        }
    }

    /// <summary>
    /// Consumes an expression that is nested deeper than the parser will follow, up to the token that
    /// closes it. The result is an Unknown node: rules see that something is there and know they
    /// cannot read it, which is the honest answer.
    /// </summary>
    private SyntaxNode SkipDeepExpression()
    {
        var start = Mark();
        var depth = 0;
        while (!AtEnd)
        {
            var text = Text;
            if (text is "(" or "[" or "{")
                depth++;
            else if (text is ")" or "]" or "}")
            {
                if (depth == 0)
                    break;
                depth--;
            }
            else if (depth == 0 && text is ";" or ",")
            {
                break;
            }
            _index++;
        }
        return Node(NodeKind.Unknown, start, "…");
    }

    private SyntaxNode? ParseAssignmentCore()
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
        "==" or "!=" or "===" or "!==" => 7,
        "<" or ">" or "<=" or ">=" or "is" or "as" or "instanceof" or "in" or "satisfies" => 8,
        "<<" or ">>" or ">>>" => 9,
        "+" or "-" => 10,
        "*" or "/" or "%" => 11,
        "**" => 12,
        _ => -1
    };

    private SyntaxNode? ParseBinary(int minimum)
    {
        // the tokens of the whole expression are a slice of the source, not a new array per operator:
        // building them by concatenation makes a chain of n operators cost n² — and files that
        // concatenate thousands of literals in one statement exist in the wild
        var expressionStart = Mark();
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
            else if (op is "as" or "satisfies")
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
                node.Tokens = SliceFrom(expressionStart);
            }
            left = node;
        }
        return left;
    }

    private static readonly string[] PatternKeywords = ["and", "or", "not", "when"];

    /// <summary>
    /// A pattern, including the <c>and</c> / <c>or</c> chain that may follow it. The combinator is
    /// handled here, once, for every shape of pattern: handling it only in the general branch used to
    /// leave the rest of a chain such as <c>null or { Kind: 3 }</c> to be parsed as statements, which
    /// then showed up as unreachable code and stray semicolons.
    /// </summary>
    private SyntaxNode ParsePattern()
    {
        var start = Mark();
        var pattern = ParsePrimaryPattern(start);
        while (IsAny("and", "or"))
        {
            _index++;
            ParsePattern();
        }
        return pattern;
    }

    private SyntaxNode ParsePrimaryPattern(int start)
    {
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

        // PHP writes '\strlen($x)' to say "the one in the global namespace". The backslash carries
        // no meaning for any rule, and leaving it in the stream ended the expression: 'return' was
        // left without a value and the call became a statement of its own on the same line.
        if (IsPhp && Is("\\"))
        {
            Take();
            return ParseUnary();
        }

        if (IsAny("!", "-", "+", "~", "++", "--", "await", "&", "*", "^")
            || (IsJs && IsAny("typeof", "void", "delete", "yield", "new")))
        {
            var op = Take().Text;
            var operand = ParseUnary();
            var node = Node(NodeKind.Unary, start, op);
            if (operand != null)
                node.Add(operand);
            return node;
        }

        // a new expression is a primary like any other: what follows it — a call, a member, an
        // index — belongs to the object it just built, so it goes through the postfix chain
        if (Is("new") && !IsJs)
            return ParsePostfix(ParseObjectCreation(start));

        if (Is("(") && !IsJs && !IsGo && LooksLikeCast())
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
            node.Add(LooksLikeAnonymousClassBody() ? ParseTypeBody(false) : ParseInitializer());
        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        return node;
    }

    /// <summary>
    /// Whether the braces after a new expression open an anonymous class rather than an object
    /// initializer. The two look alike and mean opposite things: an initializer sets properties, an
    /// anonymous class declares members — and reading the second as the first turns every method it
    /// overrides into a call, which is how a void declaration ends up reported as a void expression.
    /// </summary>
    private bool LooksLikeAnonymousClassBody()
    {
        if (IsJs || IsGo)
            return false;

        var first = Peek();
        if (first == null)
            return false;
        // an annotation or a modifier can only introduce a member
        if (first.Text == "@" || ModifierWords.Contains(first.Text))
            return true;
        // a type followed by a name is a declaration; a name followed by = or : is an initializer
        var second = Peek(2);
        return first.Kind is TokenKind.Identifier or TokenKind.Keyword
               && second is { Kind: TokenKind.Identifier or TokenKind.Keyword };
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
            else if (IsPropertyKey())
            {
                var keyStart = Mark();
                var key = Take().Text;
                Accept(":");
                var entry = new SyntaxNode(NodeKind.Assignment, ":",
                    TextRange.Of([_tokens[Math.Min(keyStart, _tokens.Count - 1)]]));
                entry.Add(new SyntaxNode(NodeKind.Identifier, key, entry.Range));
                if (ParseAssignment() is { } entryValue)
                    entry.Add(entryValue);
                node.Add(entry);
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

    /// <summary>An object literal entry: a name or string followed by a colon.</summary>
    private bool IsPropertyKey()
        => (IsName || Current is { Kind: TokenKind.String or TokenKind.Number })
           && PeekText() == ":";

    private SyntaxNode ParseArgumentList()
    {
        var ban = _compositeLiteralBan;
        _compositeLiteralBan = 0;
        try
        {
            return ParseArgumentListCore();
        }
        finally
        {
            _compositeLiteralBan = ban;
        }
    }

    private SyntaxNode ParseArgumentListCore()
    {
        var start = Mark();
        var list = new SyntaxNode(NodeKind.ArgumentList, "",
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("("))
            return list;

        while (!AtEnd && !Is(")"))
        {
            var before = _index;
            while (!IsJs && !IsGo && IsAny("ref", "out", "in"))
                _index++;
            // named argument
            if (IsIdentifier && PeekText() == ":" && PeekText(2) != ":")
                _index += 2;

            // a discard stands where an argument would be but is not an expression: consuming it
            // here keeps the closing parenthesis in reach, which is what `out _` used to lose
            if (Is("_") && PeekText() is ")" or ",")
            {
                _index++;
                if (!Accept(","))
                    break;
                continue;
            }

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
            if (IsGo && Is(".") && PeekText() == "(")
            {
                // type assertion: value.(Type)
                _index++;
                Accept("(");
                var asserted = Is("type") ? Node(NodeKind.TypeReference, Mark(), "type") : ParseType();
                if (asserted.Text == "type")
                    _index++;
                Accept(")");
                var assertion = new SyntaxNode(NodeKind.Cast, asserted.Text, node.Range, node.Tokens);
                assertion.Add(asserted);
                assertion.Add(node);
                node = assertion;
                continue;
            }

            // PHP reaches a static member with ::, which is the same access for a rule, and joins
            // the parts of a qualified name with a backslash: one name, several separators. Leaving
            // those in the stream ended the expression at each of them, so a single statement was
            // counted as four and reported as a line holding several.
            if (Is(".") || Is("?.") || (Is("->") && !IsKotlin)
                || (IsPhp && (Is("::") || (Is("\\") && Peek() is { Kind: TokenKind.Identifier }))))
            {
                // the operator itself is kept in the node's tokens: without it a null-conditional
                // access reads exactly like a plain one, and a rule about null cannot tell them apart
                var accessOperator = Current;
                _index++;
                var privateMember = IsJs && Accept("#");
                if (!IsName)
                {
                    if (privateMember)
                        continue;
                    break;
                }
                var memberStart = Mark();
                var member = (privateMember ? "#" : string.Empty) + Take().Text;
                if (Is("<") && PeekIsGenericCall())
                    SkipGenericParameters();
                var memberNode = Node(NodeKind.Identifier, memberStart, member);
                var select = new SyntaxNode(NodeKind.MemberSelect, "", node.Range, node.Tokens);
                select.Add(node);
                select.Add(memberNode);
                select.Text = SyntaxQuery.DottedName(select);
                select.Range = new TextRange(node.Range.StartLine, node.Range.StartColumn,
                    memberNode.Range.EndLine, memberNode.Range.EndColumn);
                select.Tokens = accessOperator == null
                    ? node.Tokens.Concat(memberNode.Tokens).ToArray()
                    : node.Tokens.Append(accessOperator).Concat(memberNode.Tokens).ToArray();
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
                Accept("[");
                var arguments = new List<SyntaxNode>();
                while (!AtEnd && !Is("]"))
                {
                    var before = _index;
                    if (ParseAssignment() is { } key)
                        arguments.Add(key);
                    if (!Accept(",") && _index == before)
                        _index++;
                }
                Accept("]");
                var index = Node(NodeKind.Index, start, SyntaxQuery.DottedName(node));
                index.Add(node);
                foreach (var argument in arguments)
                    index.Add(argument);
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

            // Kotlin writes the last argument outside the parentheses when it is a lambda, and
            // 'items.filter { it > 0 }' is how most of the language is written. Read as a block it
            // detached the body from the call, which left every rule about the call blind.
            if (IsKotlin && Is("{")
                && node.Kind is NodeKind.Invocation or NodeKind.Identifier or NodeKind.MemberSelect)
            {
                var lambda = ParseKotlinLambda();
                if (node.Kind == NodeKind.Invocation)
                {
                    (node.FirstChild(NodeKind.ArgumentList) ?? node).Add(lambda);
                    continue;
                }

                var call = new SyntaxNode(NodeKind.Invocation, SyntaxQuery.DottedName(node),
                    node.Range, node.Tokens);
                call.Add(node);
                var arguments = new SyntaxNode(NodeKind.ArgumentList, "", lambda.Range, lambda.Tokens);
                arguments.Add(lambda);
                call.Add(arguments);
                call.Range = new TextRange(node.Range.StartLine, node.Range.StartColumn,
                    lambda.Range.EndLine, lambda.Range.EndColumn);
                node = call;
                continue;
            }

            if (IsGo && Is("{") && _compositeLiteralBan == 0
                && node.Kind is NodeKind.Identifier or NodeKind.MemberSelect or NodeKind.Index)
            {
                var literal = new SyntaxNode(NodeKind.ObjectCreation, SyntaxQuery.DottedName(node),
                    node.Range, node.Tokens);
                literal.Add(node);
                literal.Add(ParseInitializer());
                node = literal;
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

    private SyntaxNode ParseJsFunctionExpression(int start)
    {
        Expect("function");
        Accept("*");
        var name = IsName ? Take().Text : string.Empty;
        var node = Node(NodeKind.Lambda, start, name);
        if (Is("("))
            node.Add(ParseParameterList());
        if (Is("{"))
            node.Add(ParseBlock());
        return node;
    }

    private SyntaxNode? ParsePrimary()
    {
        if (AtEnd)
            return null;
        var start = Mark();
        var token = Current!;

        // a function expression is a value in JavaScript — a callback, an argument, an assignment —
        // and reading it as a call named "function" scattered its body into the argument list
        if (IsJs && token.Text == "function")
            return ParseJsFunctionExpression(start);

        // Kotlin's branches are expressions: 'val label = when (x) { ... }' is ordinary code, and
        // reading it as a call named "when" scattered the branches into an argument list
        if (IsKotlin && token.Text == "when")
            return ParseKotlinWhen(start);
        if (IsKotlin && token.Text == "if")
            return ParseIf(start);
        if (IsKotlin && token.Text == "try")
            return ParseTry(start);

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
                else if (IsJs && keyword != "default" && ParseUnary() is { } operand)
                    call.Add(operand); // operator form, as in typeof value
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
            if (IsTs && Is(":"))
                SkipTsReturnType();
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
                    if (IsTs && Is(":"))
                        SkipTsReturnType(); // an annotated lambda: (x): T => ...
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
