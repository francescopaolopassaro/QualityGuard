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
    Kotlin,
    Scala,
    Rust
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

    /// <summary>The words that open a type. 'fun' is not among them: a Kotlin function is parsed on its own
    /// path because the name comes before the type, not after it.</summary>
    private static readonly string[] KotlinTypeKeywords = ["class", "interface", "object"];

    /// <summary>
    /// Scala spells its declarations the Kotlin way — modifiers in front, the name before the
    /// parameter list — with 'case' marking the special shapes ('case class', 'case object') that
    /// carry structure the rules reason about.
    /// </summary>
    private static readonly string[] ScalaModifiers =
    [
        "private", "protected", "final", "sealed", "abstract", "implicit", "lazy", "case",
        "override", "transient", "volatile", "open"
    ];

    private static readonly string[] ScalaTypeKeywords = ["class", "trait", "object", "enum"];

    private static readonly string[] RustModifiers =
        ["pub", "default"];

    private static readonly string[] RustFunctionPrefixes =
        ["const", "async", "unsafe", "extern", "move"];

    private static readonly string[] RustTypeKeywords =
        ["struct", "enum", "union", "trait", "impl", "mod", "type"];

    private bool IsJava => _dialect == CFamilyDialect.Java;

    private bool IsGo => _dialect == CFamilyDialect.Go;

    private bool IsJs => _dialect is CFamilyDialect.JavaScript or CFamilyDialect.TypeScript;

    private bool IsTs => _dialect == CFamilyDialect.TypeScript;

    private bool IsPhp => _dialect == CFamilyDialect.Php;

    private bool IsKotlin => _dialect == CFamilyDialect.Kotlin;

    private bool IsScala => _dialect == CFamilyDialect.Scala;

    private bool IsRust => _dialect == CFamilyDialect.Rust;

    /// <summary>
    /// Languages whose parameter names come before their types: Kotlin writes
    /// <c>name: Type</c> and so does Scala.
    /// </summary>
    private bool NameBeforeTypeInParameters => IsKotlin || IsScala || IsRust;

    /// <summary>Dialects where a newline ends a statement, so a jump takes nothing from the next line.</summary>
    private bool HasOptionalSemicolons => _dialect is CFamilyDialect.Kotlin or CFamilyDialect.Go
        or CFamilyDialect.JavaScript or CFamilyDialect.TypeScript or CFamilyDialect.Scala;

    private string[] ModifierWords => _dialect switch
    {
        CFamilyDialect.Java => JavaModifiers,
        CFamilyDialect.Go => [],
        CFamilyDialect.JavaScript or CFamilyDialect.TypeScript => JsModifiers,
        CFamilyDialect.Kotlin => KotlinModifiers,
        CFamilyDialect.Scala => ScalaModifiers,
        CFamilyDialect.Rust => RustModifiers,
        _ => Modifiers
    };

    private string[] TypeWords => _dialect switch
    {
        CFamilyDialect.Java => JavaTypeKeywords,
        CFamilyDialect.Go => GoTypeKeywords,
        CFamilyDialect.JavaScript or CFamilyDialect.TypeScript => JsTypeKeywords,
        CFamilyDialect.Kotlin => KotlinTypeKeywords,
        CFamilyDialect.Scala => ScalaTypeKeywords,
        // Rust items are dispatched on their own path: each keyword has its own shape
        CFamilyDialect.Rust => [],
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
        else if (dialect == CFamilyDialect.Scala)
        {
            code = MergeScalaQuotedNames(code);
            code = ScalaSemicolons.Insert(code);
        }
        new CSharpParser(code, language, dialect).FillCompilationUnit(root);
        return root;
    }

    /// <summary>
    /// A Scala quoted name — <c>`enum`</c>, <c>`type`</c> — is one identifier written between
    /// backticks because it collides with a keyword. Left as three tokens it read as an expression,
    /// and the block that followed attached to nothing, so every declaration inside that object was
    /// parsed outside the scope that owned it.
    /// </summary>
    private static IReadOnlyList<Token> MergeScalaQuotedNames(IReadOnlyList<Token> tokens)
    {
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            if (tokens[i].Text != "`" || tokens[i + 2].Text != "`"
                || tokens[i + 1].Kind != TokenKind.Identifier)
                continue;
            var merged = new Token(TokenKind.Identifier, tokens[i + 1].Text,
                tokens[i].Line, tokens[i].Column);
            var result = new List<Token>(tokens.Count - 2);
            result.AddRange(tokens.Take(i));
            result.Add(merged);
            result.AddRange(tokens.Skip(i + 3));
            return MergeScalaQuotedNames(result);
        }
        return tokens;
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

        if ((IsJava || IsGo || IsKotlin || IsScala) && (Is("import") || Is("package")))
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
        if (IsScala && Is("def"))
            return ParseScalaFunction(start, attributes, modifiers);
        if (IsScala && (Is("val") || Is("var")))
            return ParseScalaProperty(start, attributes, modifiers);
        if (IsScala && Is("type") && Peek() is { Kind: TokenKind.Identifier })
            return ParseScalaTypeAlias(start);
        if (IsRust)
        {
            // 'pub(crate)' and 'pub(super)': the visibility carries its scope in parentheses, and
            // leaving them in the stream hid every declaration that used the qualified form
            if (Is("(") && modifiers.Count > 0 && modifiers[^1] == "pub")
                SkipBalanced("(", ")");
            if (Is("use"))
                return ParseRustUse(start);
            if (Is("static") || (Is("const") && PeekText() != "fn"))
                return ParseRustStaticOrConst(start, attributes, modifiers);
            if (IsAny(RustFunctionPrefixes) || Is("fn"))
                return ParseRustFunction(start, attributes, modifiers);
            if (IsAny(RustTypeKeywords))
                return ParseRustItem(start);
            if ((Is("#") || Is("!")) && modifiers.Count == 0 && attributes.Count == 0
                && PeekText() is "[" or "[" )
                return ParseRustMacroRules(start);
        }
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
        while ((IsJava || IsKotlin || IsJs || IsScala) && Is("@") && Peek() is { Kind: TokenKind.Identifier })
        {
            var annotationStart = Mark();
            _index++;
            var annotation = ParseQualifiedName();
            var node = Node(NodeKind.Attribute, annotationStart, annotation);
            if (Is("("))
                node.Add(ParseArgumentList());
            attributes.Add(node);
        }

        // the ASI reconstruction closes an annotation written on its own line with a semicolon: the
        // punctuation belongs to the rebuild, not to the source, and leaving it in detached the
        // annotation from the declaration it decorates
        if (attributes.Count > 0 && IsKotlin)
            Accept(";");

        // Rust writes an attribute as '#[name]' or '#![name]', and a macro definition as
        // 'macro_rules! name { ... }'. Both are decoration as far as the rules are concerned; what
        // matters is that they do not read as expressions.
        while (IsRust && Is("#") && PeekText() is "[" or "!")
        {
            var attributeStart = Mark();
            _index++;
            Accept("!");
            SkipBalanced("[", "]");
            attributes.Add(Node(NodeKind.Attribute, attributeStart, "#"));
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
            // 'fun' is a modifier only in 'fun interface'. Taken as one everywhere else it swallowed
            // the keyword that opens the declaration, so 'internal fun Pointer.read()' was read as a
            // call and the whole file below it became one expression.
            if (IsKotlin && Is("fun") && PeekText() != "interface")
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
        if (IsScala && Is("["))
            SkipBalanced("[", "]");
        SyntaxNode? primaryConstructor = null;
        List<string>? primaryCtorModifiers = null;
        // Kotlin may spell the primary constructor out — 'class E actual constructor(...)',
        // 'class S private constructor(...)', '@Inject constructor(...)'. Stopping at the keyword
        // left the parameter list outside the type, so the class looked empty and everything written
        // after it looked like top-level code.
        if (IsKotlin)
        {
            var probe = _index;
            while (probe < _tokens.Count
                   && (ModifierWords.Contains(_tokens[probe].Text) || _tokens[probe].Text == "@"
                       || (probe > _index && _tokens[probe - 1].Text == "@")))
            {
                // the visibility written on the constructor belongs to the type: dropping it made
                // a singleton-by-private-constructor look like any other class
                if (_tokens[probe].Text != "@")
                    (primaryCtorModifiers ??= []).Add(_tokens[probe].Text);
                probe++;
            }
            if (probe < _tokens.Count && _tokens[probe].Text == "constructor")
            {
                _index = probe + 1;
            }
        }
        if (Is("("))
        {
            // the primary constructor of a Kotlin or Scala class declares the properties of the
            // type, so it is parsed rather than skipped; a record does the same and loses nothing by it
            if (IsKotlin || IsScala)
                primaryConstructor = ParseParameterList();
            else
                SkipBalanced("(", ")");
        }

        List<SyntaxNode>? supertypes = null;
        if (Accept(":") || IsAny("extends", "implements", "permits", "with"))
        {
            // the supertypes say what the type is - a ViewModel, a Comparable, an interface - and
            // rules ask about them by name, so the list is read instead of skipped
            supertypes = ParseSupertypeList();
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
        if (primaryCtorModifiers != null)
            foreach (var modifier in primaryCtorModifiers)
                node.Add(new SyntaxNode(NodeKind.Modifier, modifier, node.Range, []));
        // the keyword that opened the declaration is the only place the tree records what kind of
        // type this is: an interface cannot hold state, an object is a singleton, and several rules
        // ask exactly that question
        if (keyword is "interface" or "trait" or "object")
            node.Add(new SyntaxNode(NodeKind.Modifier, keyword, node.Range, []));
        if (primaryConstructor != null)
            node.Add(primaryConstructor);
        if (supertypes != null)
            foreach (var baseType in supertypes)
                node.Add(baseType);

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

    /// <summary>
    /// The supertypes after <c>:</c> or <c>extends</c>, as dotted or generic types. Kotlin calls the
    /// primary constructor of a base — <c>Base("init")</c> — and Scala joins traits with
    /// <c>with</c>; both spellings are consumed here so the list stays one loop.
    /// </summary>
    private List<SyntaxNode> ParseSupertypeList()
    {
        var bases = new List<SyntaxNode>();
        while (!AtEnd && !Is("{") && !Is(";") && !Is("}") && !Is("where")
               && !IsAny("fun", "val", "var", "class", "object", "interface"))
        {
            var before = _index;
            var type = ParseType();
            if (_index == before)
                _index++;
            else
            {
                bases.Add(type);
                if (Is("(")) // the base is constructed: its arguments carry nothing rules need
                    SkipBalanced("(", ")");
            }
            while (IsAny(",", "&", "extends", "implements", "permits", "with"))
                _index++;
        }
        return bases;
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

        // an extension function names the type it extends before its own name: every part before
        // the last is the receiver, and rules on CoroutineScope helpers have to read it
        var headStart = Mark();
        var name = IsName ? Take().Text : string.Empty;
        var receiverParts = new List<string>();
        var receiverEnd = -1;
        while (true)
        {
            if (Is("<"))
                SkipGenericParameters(); // generics of the part just read, as in List<Int>.head()
            while (Is("?"))              // a nullable receiver, as in String?.isBlank()
                _index++;
            if (!(Is(".") && Peek() is { Kind: TokenKind.Identifier }))
                break;
            receiverEnd = _index;        // the dot closes the receiver segment
            _index++;
            receiverParts.Add(name);
            name = Take().Text;
        }
        if (Is("<"))
            SkipGenericParameters();

        var node = Node(NodeKind.FunctionDeclaration, start, name);
        AddDecorations(node, attributes, modifiers);
        if (receiverParts.Count > 0)
        {
            var last = Math.Max(Math.Min(receiverEnd - 1, _tokens.Count - 1), headStart);
            node.Add(new SyntaxNode(NodeKind.TypeReference, string.Join('.', receiverParts),
                TextRange.Of(_tokens[headStart], _tokens[last])));
        }
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
    /// A Kotlin object expression: <c>object : Super { members }</c> is an anonymous instance, the
    /// Kotlin spelling of what Java writes as <c>new Super() { members }</c>. It is kept as an
    /// object creation with a class body so the shared structural rules see inside it.
    /// </summary>
    private SyntaxNode ParseKotlinObjectExpression(int start)
    {
        Expect("object");
        var node = Node(NodeKind.ObjectCreation, start, string.Empty);
        if (Accept(":"))
        {
            if (ParseType() is { } superType)
            {
                node.Text = superType.Text;
                node.Add(superType);
            }
            while (Is("("))
                node.Add(ParseArgumentList()); // the supertype may be constructed with arguments
        }
        if (Is("{"))
            node.Add(ParseTypeBody(false));
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
        // whether the value can be reassigned is written on the declaration itself, and rules on
        // nullability and dead stores ask exactly that
        var mutability = Take().Text;
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
        node.Add(new SyntaxNode(NodeKind.Modifier, mutability, node.Range, []));
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

    // -------------------------------------------------------------- Scala

    /// <summary>
    /// A Scala function: <c>def name[A](a: A)(b: B): C = body</c>. The name comes first, the type
    /// parameters live in square brackets, there can be several parameter lists one after another,
    /// and the body is either a block or a single expression introduced by '='.
    /// </summary>
    private SyntaxNode ParseScalaFunction(int start, List<SyntaxNode> attributes, List<string> modifiers)
    {
        Expect("def");
        var node = Node(NodeKind.FunctionDeclaration, start, string.Empty);
        AddDecorations(node, attributes, modifiers);

        if (IsName)
            node.Text = Take().Text;
        else if (Current is { Kind: TokenKind.Symbol } && PeekText() is "(" or "[" or ":" or "=")
            node.Text = Take().Text; // an operator definition: def +, def ::, def ++
        while (Is(".") && Peek() is { Kind: TokenKind.Identifier })
        {
            _index++;
            node.Text = Take().Text;
        }
        if (Is("["))
            SkipBalanced("[", "]");

        if (Is("("))
        {
            node.Add(ParseParameterList());
            // several parameter lists in a row are ordinary Scala; the extra ones ride along so
            // their names stay visible to the rules that count parameters
            while (Is("("))
                node.Add(ParseParameterList());
        }
        if (Accept(":"))
            node.Add(ParseType());

        if (Accept("="))
        {
            if (Is("{"))
            {
                node.Add(ParseBlock());
            }
            else
            {
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
        }
        else if (Is("{"))
        {
            node.Add(ParseBlock()); // procedure syntax, kept for older sources
        }
        else
        {
            Accept(";"); // an abstract member has no body at all
        }

        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        return node;
    }

    private SyntaxNode? ParseScalaMember(int start, List<SyntaxNode> attributes, List<string> modifiers)
    {
        if (Is("def"))
            return ParseScalaFunction(start, attributes, modifiers);
        if (Is("val") || Is("var"))
            return ParseScalaProperty(start, attributes, modifiers, asField: true);
        if (Is("type") && Peek() is { Kind: TokenKind.Identifier })
            return ParseScalaTypeAlias(start);
        return null;
    }

    /// <summary>A val or var: the Kotlin shape with a different keyword set around it.</summary>
    private SyntaxNode ParseScalaProperty(int start, List<SyntaxNode> attributes, List<string> modifiers,
        bool asField = false)
    {
        var property = ParseKotlinProperty(start, attributes, modifiers, asField);
        _ = property;
        return property;
    }

    /// <summary><c>type Alias[A] = Definition</c>, read as a named type and no more.</summary>
    private SyntaxNode ParseScalaTypeAlias(int start)
    {
        Expect("type");
        var name = IsName ? Take().Text : string.Empty;
        if (Is("["))
            SkipBalanced("[", "]");
        Accept("=");

        var node = new SyntaxNode(NodeKind.ClassDeclaration, name,
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        var depth = 0;
        while (!AtEnd)
        {
            var current = Text;
            if (current is "(" or "[" or "{")
                depth++;
            else if (current is ")" or "]" or "}")
            {
                if (depth == 0)
                    break;
                depth--;
            }
            else if (depth == 0 && current is ";" or ",")
                break;
            _index++;
        }
        Accept(";");
        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        return node;
    }

    /// <summary>The comprehension loop: <c>for (x &lt;- xs) { … }</c> or <c>for { … } yield e</c>.</summary>
    private SyntaxNode ParseScalaFor(int start)
    {
        Expect("for");
        var node = Node(NodeKind.Loop, start, "for");
        if (Is("("))
        {
            SkipBalanced("(", ")");
        }
        else if (Is("{"))
        {
            SkipBalanced("{", "}");
        }
        if (Accept("yield"))
        {
            if (ParseExpression() is { } produced)
            {
                var wrapper = new SyntaxNode(NodeKind.Block, "implicit", produced.Range, produced.Tokens);
                wrapper.Add(produced);
                node.Add(wrapper);
            }
            return node;
        }
        AddEmbeddedStatement(node);
        return node;
    }

    // --------------------------------------------------------------- Rust

    private SyntaxNode ParseRustUse(int start)
    {
        Expect("use");
        var name = new System.Text.StringBuilder();
        while (!AtEnd && !Is(";"))
            name.Append(Take().Text);
        Accept(";");
        return Node(NodeKind.ImportDeclaration, start, name.ToString());
    }

    /// <summary>
    /// A Rust function: <c>fn name&lt;T&gt;(args) -&gt; Ret</c> with an optional <c>where</c> clause
    /// and a block body. The prefixes in front — const, async, unsafe, extern — say how it runs.
    /// </summary>
    private SyntaxNode ParseRustFunction(int start, List<SyntaxNode> attributes, List<string> modifiers,
        NodeKind kind = NodeKind.FunctionDeclaration)
    {
        while (IsAny(RustFunctionPrefixes))
        {
            var prefix = Take().Text;
            modifiers.Add(prefix);
            Accept("*"); // extern "C" or extern block forms
            if (Current is { Kind: TokenKind.String })
                _index++;
        }
        if (!Accept("fn"))
        {
            _index = start;
            return ParseStatement();
        }

        var name = IsName ? Take().Text : string.Empty;
        if (Is("<"))
            SkipGenericParameters();

        var node = Node(kind, start, name);
        AddDecorations(node, attributes, modifiers);
        if (Is("("))
            node.Add(ParseParameterList());
        if (Accept("->"))
            node.Add(ParseType());
        while (Is("where"))
        {
            while (!AtEnd && !Is("{") && !Is(";"))
                _index++;
        }

        if (Is("{"))
            node.Add(ParseBlock());
        else
            Accept(";");

        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        return node;
    }

    /// <summary>A static or const item: <c>static NAME: Type = value;</c>.</summary>
    private SyntaxNode ParseRustStaticOrConst(int start, List<SyntaxNode> attributes, List<string> modifiers)
    {
        _index++; // static | const
        var name = IsIdentifier ? Take().Text : string.Empty;
        var field = Node(NodeKind.FieldDeclaration, start, name);
        AddDecorations(field, attributes, modifiers);
        if (IsAny("mut"))
            _index++;
        if (Accept(":"))
            field.Add(ParseType());
        if (Accept("=") && ParseExpression() is { } value)
            field.Add(value);
        Accept(";");
        field.Tokens = SliceFrom(start);
        field.Range = TextRange.Of(field.Tokens);
        return field;
    }

    /// <summary><c>let pattern[: Type] = value;</c>, the one binding form inside a function.</summary>
    private SyntaxNode ParseRustLet(int start)
    {
        Expect("let");
        var declaration = new SyntaxNode(NodeKind.VariableDeclaration, "",
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        var names = new List<string>();
        ReadRustPatternNames(names);
        declaration.Text = names.FirstOrDefault() ?? string.Empty;

        if (Accept(":"))
            declaration.Add(ParseType());
        if (Accept("=") && ParseExpression() is { } value)
        {
            var assignment = new SyntaxNode(NodeKind.Assignment, "=", declaration.Range, declaration.Tokens);
            assignment.Add(new SyntaxNode(NodeKind.Identifier, declaration.Text, declaration.Range));
            assignment.Add(value);
            declaration.Add(assignment);
        }
        foreach (var extra in names.Skip(1))
            declaration.Add(new SyntaxNode(NodeKind.Identifier, extra, declaration.Range));

        // 'let Some(x) = y else { return; }' — the let-else fallback is part of the statement
        if (Accept("else"))
        {
            if (Is("{"))
                declaration.Add(ParseBlock());
            else
                ParseStatement();
        }
        Accept(";");
        declaration.Tokens = SliceFrom(start);
        declaration.Range = TextRange.Of(declaration.Tokens);
        return declaration;
    }

    /// <summary>Collects the identifiers a let pattern binds, through tuples and struct patterns.</summary>
    private void ReadRustPatternNames(List<string> names)
    {
        var depth = 0;
        while (!AtEnd)
        {
            var current = Text;
            if (current is "(" or "[" or "{" or "<")
            {
                depth++;
            }
            else if (current is ")" or "]" or "}" or ">")
            {
                if (depth == 0)
                    break;
                depth--;
            }
            else if (depth == 0 && current is "=" or ":" or ";" or "else")
                break;
            else if (IsIdentifier && !IsAny("mut", "ref", "in", "if", "move"))
                names.Add(Text);
            _index++;
        }
    }

    /// <summary>The items a file, module, trait or impl is made of.</summary>
    private SyntaxNode ParseRustItem(int start)
    {
        var keyword = Take().Text;
        switch (keyword)
        {
            case "type":
            {
                var name = IsName ? Take().Text : string.Empty;
                if (Is("<"))
                    SkipGenericParameters();
                Accept("=");
                while (!AtEnd && !Is(";"))
                    _index++;
                Accept(";");
                return Node(NodeKind.ClassDeclaration, start, name);
            }
            case "mod":
            {
                var name = IsName ? Take().Text : string.Empty;
                var node = Node(NodeKind.ClassDeclaration, start, name);
                if (Is("{"))
                {
                    var body = ParseRustItemBody();
                    node.Add(body);
                    node.Range = node.Range with { EndLine = body.Range.EndLine };
                }
                else
                {
                    Accept(";");
                }
                return node;
            }
            case "struct" or "union":
            {
                var name = IsName ? Take().Text : string.Empty;
                var node = Node(NodeKind.ClassDeclaration, start, name);
                if (Is("<"))
                    SkipGenericParameters();
                SkipRustWhereClauses();
                if (Is("("))
                {
                    // tuple struct: positional fields carry no names worth keeping
                    SkipBalanced("(", ")");
                    Accept(";");
                    Accept("where");
                }
                else if (Is("{"))
                {
                    var body = ParseRustStructBody();
                    node.Add(body);
                    node.Range = node.Range with { EndLine = body.Range.EndLine };
                }
                else
                {
                    Accept(";");
                }
                return node;
            }
            case "enum":
            {
                var name = IsName ? Take().Text : string.Empty;
                var node = Node(NodeKind.ClassDeclaration, start, name);
                if (Is("<"))
                    SkipGenericParameters();
                SkipRustWhereClauses();
                var body = ParseRustEnumBody();
                node.Add(body);
                node.Range = node.Range with { EndLine = body.Range.EndLine };
                return node;
            }
            case "trait":
            {
                var name = IsName ? Take().Text : string.Empty;
                var node = Node(NodeKind.ClassDeclaration, start, name);
                if (Is("<"))
                    SkipGenericParameters();
                if (Accept(":"))
                {
                    while (!AtEnd && !Is("{") && !Is("where"))
                        _index++;
                }
                SkipRustWhereClauses();
                var body = ParseRustItemBody();
                node.Add(body);
                node.Range = node.Range with { EndLine = body.Range.EndLine };
                return node;
            }
            case "impl":
            {
                var node = Node(NodeKind.ClassDeclaration, start, "impl");
                if (Is("<"))
                    SkipGenericParameters();

                // 'impl Display for Point' versus 'impl Point': what sits before 'for' is the
                // trait being implemented, and a rule about overrides needs both halves
                var traitName = new System.Text.StringBuilder();
                var typeName = new System.Text.StringBuilder();
                var target = typeName;
                var depth = 0;
                while (!AtEnd)
                {
                    var current = Text;
                    if (current is "(" or "[" or "<")
                        depth++;
                    else if (current is ")" or "]" or ">")
                        depth--;
                    else if (current is "{" or ";")
                        break;
                    else if (depth <= 0 && current == "for")
                    {
                        _index++;
                        (target, var done) = (typeName, true);
                        _ = done;
                        traitName.Append(' ');
                        continue;
                    }
                    target.Append(Take().Text).Append(' ');
                }
                node.Text = ("impl " + traitName + typeName).Trim();

                SkipRustWhereClauses();
                var body = ParseRustItemBody();
                node.Add(body);
                node.Range = node.Range with { EndLine = body.Range.EndLine };
                return node;
            }
            default:
                return Node(NodeKind.Unknown, start, keyword);
        }
    }

    private void SkipRustWhereClauses()
    {
        while (Is("where"))
        {
            while (!AtEnd && !Is("{") && !Is(";"))
                _index++;
        }
    }

    /// <summary>Named fields: <c>{ pub width: u32, }</c>.</summary>
    private SyntaxNode ParseRustStructBody()
    {
        var start = Mark();
        var block = new SyntaxNode(NodeKind.Block, "",
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("{"))
            return block;

        while (!AtEnd && !Is("}"))
        {
            var before = _index;
            if (Accept(","))
                continue;
            var attributes = ParseAttributes();
            var modifiers = ParseModifiers();
            while (IsAny("pub", "readonly"))
                _index++;
            if (IsIdentifier)
            {
                var fieldStart = Mark();
                var name = Take().Text;
                var field = Node(NodeKind.FieldDeclaration, fieldStart, name);
                AddDecorations(field, attributes, modifiers);
                foreach (var modifier in modifiers)
                    field.Add(new SyntaxNode(NodeKind.Modifier, modifier, field.Range));
                if (Accept(":"))
                    field.Add(ParseType());
                block.Add(field);
            }
            if (_index == before)
                _index++;
        }
        Accept("}");
        block.Tokens = SliceFrom(start);
        block.Range = TextRange.Of(block.Tokens);
        return block;
    }

    /// <summary>Variants: <c>{ Add(u32, u32), Move { x: i32 }, Quit }</c>.</summary>
    private SyntaxNode ParseRustEnumBody()
    {
        var start = Mark();
        var block = new SyntaxNode(NodeKind.Block, "",
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("{"))
            return block;

        while (!AtEnd && !Is("}"))
        {
            var before = _index;
            if (Accept(",") || Is("#"))
            {
                if (Is("#"))
                {
                    _index++;
                    Accept("!");
                    SkipBalanced("[", "]");
                }
                if (_index != before)
                    continue;
            }
            if (IsIdentifier)
            {
                var memberStart = Mark();
                var name = Take().Text;
                var member = Node(NodeKind.EnumMember, memberStart, name);
                if (Is("("))
                    SkipBalanced("(", ")");
                else if (Is("{"))
                    SkipBalanced("{", "}");
                if (Accept("=") && ParseExpression() is { } discriminant)
                    member.Add(discriminant);
                block.Add(member);
            }
            if (_index == before)
                _index++;
            Accept(",");
        }
        Accept("}");
        block.Tokens = SliceFrom(start);
        block.Range = TextRange.Of(block.Tokens);
        return block;
    }

    /// <summary>The inside of a mod, trait or impl: functions, constants, types, inner attributes.</summary>
    private SyntaxNode ParseRustItemBody()
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
            var attributes = ParseAttributes();
            var modifiers = ParseModifiers();
            // 'pub(crate) fn …' inside a trait or an impl
            if (Is("(") && modifiers.Count > 0 && modifiers[^1] == "pub")
                SkipBalanced("(", ")");

            SyntaxNode? item = null;
            if (Is("fn"))
                item = ParseRustFunction(Mark(), attributes, modifiers);
            else if (Is("static") || Is("const"))
                item = ParseRustStaticOrConst(Mark(), attributes, modifiers);
            else if (Is("use"))
                item = ParseRustUse(Mark());
            else if (IsAny(RustTypeKeywords))
                item = ParseRustItem(Mark());
            else if (IsAny(RustFunctionPrefixes))
                item = ParseRustFunction(Mark(), attributes, modifiers);
            else if (Is("#"))
            {
                _index++;
                Accept("!");
                SkipBalanced("[", "]");
            }
            else
            {
                var statement = ParseStatement();
                if (statement != null)
                    block.Add(statement);
            }

            if (item != null)
                block.Add(item);
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

    /// <summary><c>macro_rules! name { ... }</c> — consumed whole, it defines rather than executes.</summary>
    private SyntaxNode ParseRustMacroRules(int start)
    {
        while (!AtEnd && !Is("{"))
            _index++;
        SkipBalanced("{", "}");
        Accept(";");
        return Node(NodeKind.Unknown, start, "macro_rules");
    }

    /// <summary>
    /// The arms of a match, from the brace to its closing twin. Scala arms open with 'case', Rust
    /// ones do not; both end each arm at the fat arrow and take a block or a single expression.
    /// </summary>
    private SyntaxNode ParseMatchBody(bool caseKeyword)
    {
        var start = Mark();
        var body = new SyntaxNode(NodeKind.Block, "", TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("{"))
            return body;

        while (!AtEnd && !Is("}"))
        {
            var before = _index;
            var armStart = Mark();
            if (caseKeyword)
                Accept("case");
            if (caseKeyword && IsIdentifier && PeekText() == "=>" && !Is("_"))
            {
                // a variable pattern binds the whole subject: 'case x =>'
            }

            // the pattern runs up to the arrow that introduces the arm
            var guard = 0;
            while (!AtEnd && !Is("}") && !Is("=>") && guard++ < 200)
            {
                if (Is("(") || Is("[") || Is("{"))
                {
                    var open = Text;
                    SkipBalanced(open, open == "(" ? ")" : open == "[" ? "]" : "}");
                    continue;
                }
                if (Is("|"))
                {
                    _index++; // pattern alternatives bind tighter than the arrow
                    continue;
                }
                _index++;
            }

            if (Accept("=>"))
            {
                var section = Node(caseKeyword ? NodeKind.SwitchSection : NodeKind.MatchCase, armStart, "case");
                if (Is("{"))
                    section.Add(ParseBlock());
                else if (ParseStatement() is { } branch)
                    section.Add(branch);
                body.Add(section);
                Accept(",");
            }

            if (_index == before)
                _index++;
        }
        var closing = Current;
        Accept("}");
        body.Tokens = SliceFrom(start);
        body.Range = TextRange.Of(body.Tokens);
        if (closing != null)
            body.Range = body.Range with { EndLine = closing.Line };
        return body;
    }

    /// <summary><c>match expr { … }</c> in statement position: same shape, result discarded.</summary>
    private SyntaxNode ParseRustMatch(int start)
    {
        Expect("match");
        var node = Node(NodeKind.Match, start, "match");
        _compositeLiteralBan++;
        if (!Is("{") && ParseExpression() is { } subject)
            node.Add(subject);
        _compositeLiteralBan--;
        node.Add(ParseMatchBody(caseKeyword: false));
        node.Tokens = SliceFrom(start);
        node.Range = TextRange.Of(node.Tokens);
        Accept(";");
        return node;
    }

    /// <summary><c>for pattern in sequence { … }</c> — the only loop form with a header like this.</summary>
    private SyntaxNode ParseRustFor(int start)
    {
        Expect("for");
        var node = Node(NodeKind.Loop, start, "for");
        var names = new List<string>();
        ReadRustPatternNames(names);
        var name = names.FirstOrDefault() ?? string.Empty;
        var variable = new SyntaxNode(NodeKind.VariableDeclaration, name,
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        foreach (var extra in names)
            variable.Add(new SyntaxNode(NodeKind.Identifier, extra, variable.Range));
        node.Add(variable);
        Accept("in");
        _compositeLiteralBan++;
        if (ParseExpression() is { } sequence)
        {
            node.Add(sequence);
            var assignment = new SyntaxNode(NodeKind.Assignment, "=", sequence.Range, sequence.Tokens);
            assignment.Add(new SyntaxNode(NodeKind.Identifier, name, variable.Range));
            assignment.Add(sequence);
            variable.Add(assignment);
        }
        _compositeLiteralBan--;
        AddEmbeddedStatement(node);
        return node;
    }

    /// <summary>
    /// A Rust closure: pipes around an optional parameter list, then the body. '||' with nothing
    /// between the pipes is the zero-parameter form, and it must not be read as logical-or.
    /// </summary>
    private SyntaxNode ParseRustClosure(int start)
    {
        var lambda = Node(NodeKind.Lambda, start, "|");
        var parameters = new SyntaxNode(NodeKind.ParameterList, "",
            TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (Is("||"))
        {
            _index++;
        }
        else if (Accept("|"))
        {
            while (!AtEnd && !Is("|"))
            {
                var before = _index;
                while (IsAny("mut", "ref", "move"))
                    _index++;
                if ((IsIdentifier || Is("_")) && PeekText() is ":" or "," or "|" or ")")
                {
                    var parameterStart = Mark();
                    var name = Take().Text;
                    var parameter = Node(NodeKind.Parameter, parameterStart, name);
                    if (Accept(":"))
                        parameter.Add(ParseType());
                    parameters.Add(parameter);
                    Accept(",");
                }
                if (_index == before)
                    _index++;
            }
            Accept("|");
        }
        lambda.Add(parameters);
        AddLambdaBody(lambda);
        lambda.Tokens = SliceFrom(start);
        lambda.Range = TextRange.Of(lambda.Tokens);
        return lambda;
    }

    private SyntaxNode ParseTypeBody(bool isEnum)
    {
        var start = Mark();
        var block = new SyntaxNode(NodeKind.Block, "", TextRange.Of([_tokens[Math.Min(start, _tokens.Count - 1)]]));
        if (!Accept("{"))
            return block;

        // a Scala type body may open with its self type: 'trait F { self => … }'
        if (IsScala && IsName && PeekText() == "=>")
            _index += 2;

        while (!AtEnd && !Is("}"))
        {
            var before = _index;
            if (IsScala && ParseScalaMember(Mark(), [], []) is { } scalaMember)
            {
                block.Add(scalaMember);
                continue;
            }
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
        var member = Node(NodeKind.EnumMember, start, name);
        if (Accept("=") && ParseExpression() is { } value)
            member.Add(value);
        Accept(",");
        return member;
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
        if (IsRust)
            return ParseRustType(start);
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
            if (Is("[") && (PeekText() == "]" || PeekText() == "," || IsScala))
            {
                // the commas between the brackets carry the rank: 'int[,]' and 'int[]' are
                // different types, and collapsing them hid every multidimensional signature
                var open = Mark();
                SkipBalanced("[", "]");
                var dims = 0;
                for (var t = open; t < Math.Min(_index, _tokens.Count); t++)
                    if (_tokens[t].Text == ",")
                        dims++;
                name += "[" + new string(',', dims) + "]";
                continue;
            }
            break;
        }
        return Node(NodeKind.TypeReference, start, name);
    }

    private SyntaxNode ParseRustType() => ParseRustType(Mark());

    /// <summary>
    /// A Rust type: references and raw pointers in front, arrays with their length, generic
    /// arguments in angle brackets, function-pointer types, and the lifetime that borrows them.
    /// Read loosely — everything up to the token that cannot be part of a type becomes its text.
    /// </summary>
    private SyntaxNode ParseRustType(int start)
    {
        var text = new System.Text.StringBuilder();
        var depth = 0;
        while (!AtEnd)
        {
            var current = Text;
            if (current is "(" or "[" or "<")
            {
                depth++;
            }
            else if (current is ")" or "]")
            {
                if (depth == 0)
                    break;
                depth--;
            }
            else if (current is ">" or ">>")
            {
                if (depth <= 0)
                    break;
                depth -= current.Length;
            }
            else if (depth == 0
                     && current is "," or ";" or "=" or "{" or "}" or "where" or "->" or ":"
                         or "as" or "in")
            {
                break;
            }
            text.Append(Take().Text).Append(' ');
        }
        return Node(NodeKind.TypeReference, start, text.ToString().TrimEnd());
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

        // 'implicit' marks every parameter that follows it until the list ends, so the flag lives
        // across iterations: resetting it per parameter left all but the first unmarked
        var pendingImplicit = false;
        while (!AtEnd && !Is(")"))
        {
            var before = _index;
            ParseAttributes();
            while (!IsJs && !IsGo && !IsKotlin
                   && IsAny("ref", "out", "in", "params", "this", "scoped", "readonly"))
                _index++;

            var parameterStart = Mark();
            if (IsKotlin || IsScala)
            {
                // 'vararg out: String' and 'val name: String' — the modifiers come first, the name
                // second, and the type after the colon
                while (IsAny("vararg", "val", "var", "noinline", "crossinline", "private", "public",
                           "protected", "internal", "override", "implicit", "using"))
                {
                    pendingImplicit |= Is("implicit");
                    _index++;
                }
                if (IsName || Is("_") && PeekText() == ":")
                {
                    var kotlinName = Take().Text;
                    var kotlinParameter = Node(NodeKind.Parameter, parameterStart, kotlinName);
                    if (pendingImplicit)
                        kotlinParameter.Add(new SyntaxNode(NodeKind.Modifier, "implicit", kotlinParameter.Range));
                    if (Accept(":"))
                    {
                        Accept("=>"); // a by-name parameter passes a thunk: ': => T'
                        kotlinParameter.Add(ParseType());
                        // Scala writes type arguments in square brackets, not angle brackets:
                        // 'fa: F[A]' — leaving them detached broke the list at the first bracket
                        while (IsScala && Is("["))
                            SkipBalanced("[", "]");
                        if (IsScala)
                        {
                            // a Scala type can carry what the shared reader cannot follow — function
                            // arrows, union pipes, refined types — and every token left over would be
                            // read as another parameter of its own
                            var depth = 0;
                            while (!AtEnd && (depth > 0 || !(Is(",") || Is(")") || Is("="))))
                            {
                                if (Is("(") || Is("[") || Is("{"))
                                    depth++;
                                else if (Is(")") || Is("]") || Is("}"))
                                {
                                    if (depth == 0)
                                        break;
                                    depth--;
                                }
                                _index++;
                            }
                        }
                    }
                    if (Accept("=") && ParseAssignment() is { } kotlinDefault)
                        kotlinParameter.Add(kotlinDefault);
                    list.Add(kotlinParameter);
                }
                if (!Accept(",") && !Is(")") && _index == before)
                    _index++;
                continue;
            }

            if (IsRust)
            {
                // '&mut self', 'mut count: usize', '_: f64' — the receiver borrows like the type
                // does, and an unnamed parameter keeps its position
                while (IsAny("mut", "ref", "move", "const"))
                    _index++;
                if (Is("&"))
                {
                    _index++;
                    Accept("mut");
                }
                string? rustName = null;
                if ((IsIdentifier || Is("_")) && PeekText() == ":")
                {
                    rustName = Take().Text;
                }
                else if (Is("self"))
                {
                    Take();
                    rustName = "self";
                }
                else
                {
                    // a parameter the reader cannot name keeps its place in the list: everything up
                    // to the comma belongs to it, and stopping short would read one parameter as two
                    while (!AtEnd && !Is(",") && !Is(")"))
                        _index++;
                }
                var rustParameter = Node(NodeKind.Parameter, parameterStart, rustName ?? "");
                if (rustName != null && Is(":"))
                {
                    _index++;
                    rustParameter.Add(ParseRustType());
                }
                list.Add(rustParameter);
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
                return IsGo || IsJs || IsKotlin || IsScala ? null : Node(NodeKind.ExpressionStatement, start, ";");
            case "if":
                return ParseIf(start);
            case "match" when IsRust:
                return ParseRustMatch(start);
            case "switch":
                return ParseSwitchStatement(start);
            case "for":
                return IsGo ? ParseGoFor(start) : IsScala ? ParseScalaFor(start)
                    : IsRust ? ParseRustFor(start) : ParseFor(start);
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
            case "def" when IsScala:
                return ParseScalaFunction(start, [], []);
            case "val" when IsScala:
            case "var" when IsScala:
                return ParseScalaProperty(start, [], []);
            case "let" when IsRust:
                return ParseRustLet(start);
            case "loop" when IsRust:
            {
                Expect("loop");
                var loopNode = Node(NodeKind.Loop, start, "loop");
                AddEmbeddedStatement(loopNode);
                return loopNode;
            }
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
            case "use" when IsRust:
                return ParseRustUse(start);
            case "move" when IsRust && PeekText() == "|":
                _index++;
                return ParseRustClosure(start);
            case "fn" when IsRust:
                return ParseRustFunction(start, [], [], NodeKind.LocalFunction);
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
            case "assert" when IsJava || IsKotlin:
            {
                // an assertion is a guarded jump, not an identifier followed by stray statements:
                // leaving the pieces apart fed every expression rule on the line after it
                _index++;
                var assertion = Node(NodeKind.Jump, start, "assert");
                if (ParseExpression() is { } condition)
                    assertion.Add(condition);
                if (Accept(":") && ParseExpression() is { } message)
                    assertion.Add(message);
                Accept(";");
                assertion.Tokens = SliceFrom(start);
                assertion.Range = TextRange.Of(assertion.Tokens);
                return assertion;
            }
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
        else if (IsGo || IsRust)
        {
            // no parentheses around the condition: Go and Rust both write 'if x > 5 { … }'
            _compositeLiteralBan++;
            if (IsGo && TryParseGoShortDeclaration(Mark()) is { } init)
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
        else if (IsRust)
        {
            // 'while let Some(x) = it.next() { … }' and the plain form both go bare
            _compositeLiteralBan++;
            if (!Is("{") && ParseExpression() is { } condition)
                node.Add(condition);
            _compositeLiteralBan--;
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
            if (IsScala && Is("{"))
            {
                // 'case e: IOException => …' arms are how Scala spells its handlers
                catchNode.Add(ParseMatchBody(caseKeyword: true));
                node.Add(catchNode);
                continue;
            }
            if (Is("("))
            {
                Accept("(");
                // Kotlin writes the name first and the type after a colon — 'catch (e: IOException)'
                // and 'catch (_: IOException)'. Read as 'Type name' the parser stopped at the colon
                // and left the rest of the clause loose in the enclosing block, where every rule read
                // it as code that runs after the try.
                if (IsKotlin)
                {
                    var name = IsIdentifier || Is("_") ? Take().Text : string.Empty;
                    SyntaxNode? type = null;
                    if (Accept(":"))
                        type = ParseType();
                    if (type != null)
                    {
                        catchNode.Add(type);
                        if (name.Length > 0 && name != "_")
                        {
                            var declared = new SyntaxNode(NodeKind.VariableDeclaration, name, type.Range, type.Tokens);
                            declared.Add(type);
                            catchNode.Add(declared);
                        }
                    }
                }
                else
                {
                    var type = ParseType();
                    catchNode.Add(type);
                    if (IsIdentifier)
                    {
                        var name = Take().Text;
                        var variable = new SyntaxNode(NodeKind.VariableDeclaration, name, type.Range, type.Tokens);
                        variable.Add(type);
                        catchNode.Add(variable);
                    }
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
        var keywordLine = _tokens[start].Line;
        // 'break' and 'continue' carry a label at most, and in a language without semicolons the
        // statement ends with the line. Reading an expression after them swallowed the brace that
        // closed the block, so everything written after the branch moved inside it — and every rule
        // that reasons about what follows a jump answered on the wrong shape.
        var carriesNothing = keyword is "break" or "continue"
                             || (!Is(";") && !AtEnd && Current!.Line > keywordLine && HasOptionalSemicolons);
        if (carriesNothing)
        {
            if (keyword is "break" or "continue" && !AtEnd && Current!.Line == keywordLine
                && (Is("@") || IsIdentifier))
            {
                Accept("@");
                if (IsIdentifier)
                    Take();
            }
        }
        else if (!Is(";") && !AtEnd)
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
        ".." or "..=" => 1, // a range binds loosest: '0..n' is one value, not two operands
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
            if (precedence < 0)
            {
                // Scala lets any word or run of punctuation be an infix operator — 'f1 compose f2',
                // 'o1 >>= s'. With an operand on each side it is one expression; ending the chain
                // turned every read on the right into an orphaned statement, and variables read
                // that way looked unused. Reserved words keep their meaning: 'x match { … }' is a
                // branch, not a binary.
                var startsOperand = Peek() is { Kind: TokenKind.Identifier or TokenKind.Number
                        or TokenKind.String } || Is("(");
                if (!IsScala || Current is { Kind: TokenKind.Keyword }
                    || op.Length == 0 || !startsOperand)
                    break;
                precedence = 10;
            }
            else if (precedence < minimum)
            {
                break;
            }

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
            || (IsJs && IsAny("typeof", "void", "delete", "yield", "new"))
            || (IsRust && IsAny("move")))
        {
            var op = Take().Text;
            if (op == "move")
                return ParseUnary(); // 'move |x| …': ownership is a property of the closure
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
        // Scala mixes traits into an instance with 'with', and the braces that follow belong to the
        // anonymous class they build: leaving the mixins unread detached the whole body from the
        // expression that owns it.
        if (IsScala)
        {
            while (Is("with"))
            {
                _index++;
                if (ParseType() is { } mixedIn && Is("["))
                    SkipBalanced("[", "]");
            }
        }
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
            // 'ref', 'out' and 'in' mark an argument only in C#. Everywhere else they are ordinary
            // names — 'in' and 'out' are what every Java stream parameter is called — and eating them
            // here left the closing parenthesis out of reach, so the argument list swallowed the rest
            // of the file and every rule below that line read a tree that was not the code.
            while (_dialect == CFamilyDialect.CSharp && IsAny("ref", "out", "in"))
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
            // Java and Kotlin reach a method without calling it through '::'. Leaving the operator in
            // the stream ended the expression at it, so 'return ArrayList::new;' became a return
            // followed by two statements — and every rule about code after a jump reported the rest
            // of the method as unreachable.
            // Rust writes generic arguments at the call itself — 'size_of::<u8>()': the brackets
            // follow the path separator, and reading them as a comparison split every such call
            // into two expressions.
            if (IsRust && Is("::") && PeekText() == "<"
                && node.Kind is NodeKind.Identifier or NodeKind.MemberSelect)
            {
                var beforeGenerics = _index;
                _index += 2;
                var depth = 1;
                var valid = true;
                while (!AtEnd && depth > 0)
                {
                    var current = Text;
                    if (current is "(" or ";" or "{")
                    {
                        valid = false;
                        break;
                    }
                    if (current == "<")
                        depth++;
                    else if (current is ">" or ">>")
                        depth -= current.Length;
                    _index++;
                }
                if (valid && depth <= 0 && Is("("))
                    continue;
                _index = beforeGenerics;
            }

            if (Is(".") || Is("?.") || (Is("->") && !IsKotlin)
                || ((IsJava || IsKotlin || IsRust) && Is("::"))
                || (IsPhp && (Is("::") || (Is("\\") && Peek() is { Kind: TokenKind.Identifier }))))
            {
                // the operator itself is kept in the node's tokens: without it a null-conditional
                // access reads exactly like a plain one, and a rule about null cannot tell them apart
                var accessOperator = Current;
                _index++;
                var privateMember = IsJs && Accept("#");
                if (accessOperator?.Text == "::" && Is("new"))
                {
                    // 'Type::new' names the constructor; taking it as an ordinary member keeps the
                    // expression whole, which is all a rule needs from it
                    var constructorStart = Mark();
                    var constructorReference = Take().Text;
                    var constructorNode = Node(NodeKind.Identifier, constructorStart, constructorReference);
                    var reference = new SyntaxNode(NodeKind.MemberSelect,
                        node.Text + "::" + constructorReference, node.Range, node.Tokens);
                    reference.Add(node);
                    reference.Add(constructorNode);
                    node = reference;
                    continue;
                }
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
                // a Rust macro is the name, the bang and its brackets — one call
                if (Is("!") && IsRust && PeekText() is "(" or "[" or "{")
                {
                    var bangStart = Mark();
                    _index++;
                    var open = Text;
                    SkipBalanced(open, open == "(" ? ")" : open == "[" ? "]" : "}");
                    var macro = new SyntaxNode(NodeKind.Invocation,
                        node.Kind == NodeKind.Identifier ? node.Text : SyntaxQuery.DottedName(node),
                        node.Range, SliceFrom(bangStart));
                    macro.Add(node);
                    var arguments = new SyntaxNode(NodeKind.ArgumentList, "",
                        TextRange.Of(SliceFrom(bangStart + 1)));
                    macro.Add(arguments);
                    macro.Tokens = SliceFrom(bangStart);
                    macro.Range = TextRange.Of(macro.Tokens);
                    node = macro;
                    continue;
                }
                var start = Mark();
                var op = Take().Text;
                var unary = Node(NodeKind.Unary, start, op);
                unary.Add(node);
                node = unary;
                continue;
            }

            // Rust propagates errors with a bare '?': 'value?' either unwraps or returns. Leaving it
            // in the stream ended every expression at it.
            if (IsRust && Is("?"))
            {
                var questionStart = Mark();
                _index++;
                var tryOperator = Node(NodeKind.Unary, questionStart, "?");
                tryOperator.Add(node);
                node = tryOperator;
                continue;
            }

            // Scala and Rust put the subject of a match in front of the keyword: 'x match { … }'
            // and 'x match { … }' are how both languages write their multi-way branch.
            if ((IsScala || IsRust) && Is("match") && PeekText() == "{")
            {
                var matchStart = Mark();
                _index++;
                var matchNode = Node(NodeKind.Match, matchStart, "match");
                matchNode.Add(node);
                matchNode.Add(ParseMatchBody(caseKeyword: IsScala));
                matchNode.Tokens = SliceFrom(matchStart);
                matchNode.Range = TextRange.Of(matchNode.Tokens);
                Accept(";");
                node = matchNode;
                continue;
            }

            if (Is("{") && node.Kind is NodeKind.ObjectCreation)
            {
                node.Add(ParseInitializer());
                continue;
            }

            // Kotlin and Scala write the last argument outside the parentheses when it is a lambda,
            // and 'items.filter { it > 0 }' is how most of both languages is written. Read as a
            // block it detached the body from the call, which left every rule about the call blind.
            if ((IsKotlin || IsScala) && Is("{")
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

            if ((IsGo || IsRust) && Is("{") && _compositeLiteralBan == 0
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

        // an object expression — 'val counter = object : Runnable { ... }' — builds an anonymous
        // instance: read as a plain identifier it left the ':' orphan and the body detached from
        // the value that owned it
        if (IsKotlin && token.Text == "object" && (PeekText() == ":" || PeekText() == "{"))
            return ParseKotlinObjectExpression(start);

        // Rust branches and matches are expressions too: 'let parity = if n % 2 == 0 { 0 } else { 1 };'
        // is how half of the language decides between two values.
        if (IsRust && token.Text == "if")
            return ParseIf(start);
        if (IsRust && token.Text == "match")
            return ParseRustMatch(start);
        if (IsRust && token.Text == "loop")
        {
            _index++;
            var loopExpression = Node(NodeKind.Loop, start, "loop");
            if (Is("{"))
                loopExpression.Add(ParseBlock());
            return loopExpression;
        }
        if (IsRust && token.Text == "unsafe" && PeekText() == "{")
        {
            _index++;
            return ParseBlock();
        }
        if (IsRust && token.Text == "async")
        {
            _index++;
            Accept("move");
            return Is("{") ? ParseBlock() : ParseUnary() ?? Node(NodeKind.Unknown, start, "async");
        }
        if (IsRust && (token.Text == "|" || token.Text == "||"))
            return ParseRustClosure(start);

        switch (token.Kind)
        {
            case TokenKind.Number:
                _index++;
                return Node(NodeKind.NumberLiteral, start, token.Text);
            case TokenKind.String when IsScala && _index > 0
                                       && _tokens[_index - 1].Kind == TokenKind.Identifier:
            {
                // an interpolator precedes its literal — s"…", f"…", any processor the library has
                // named — and the names it carries between dollars are ordinary reads of locals.
                // Reading the literal alone made every value formatted into a string look unused.
                _index++;
                return BuildScalaInterpolatedString(start, token);
            }
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

    /// <summary>
    /// A Scala interpolated literal carries its reads as '$name' and '${expression}'. The names are
    /// ordinary uses of the locals they cite, and leaving them inside one string token hid every
    /// read from the rules that count them.
    /// </summary>
    private SyntaxNode BuildScalaInterpolatedString(int start, Token literal)
    {
        var node = Node(NodeKind.InterpolatedString, start, literal.Text);
        var text = literal.Text;
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] != '$' || i + 1 >= text.Length)
                continue;

            if (text[i + 1] == '{')
            {
                var depth = 1;
                var j = i + 2;
                while (j < text.Length && depth > 0)
                {
                    if (text[j] == '{')
                        depth++;
                    else if (text[j] == '}')
                        depth--;
                    j++;
                }
                if (depth != 0)
                    continue;
                AddInterpolationHole(node, text[(i + 2)..(j - 1)], literal);
                i = j - 1;
            }
            else if (char.IsLetterOrDigit(text[i + 1]) || text[i + 1] == '_')
            {
                var j = i + 1;
                while (j < text.Length && (char.IsLetterOrDigit(text[j]) || text[j] == '_'))
                    j++;
                AddInterpolationHole(node, text[i..j].TrimStart('$'), literal);
                i = j - 1;
            }
        }
        return node;
    }

    private void AddInterpolationHole(SyntaxNode node, string expression, Token literal)
    {
        var tokens = new SourceTokenizer(expression, _language).Tokenize()
            .Where(t => t.Kind != TokenKind.Comment)
            .Select(t => new Token(t.Kind, t.Text, literal.Line, literal.Column))
            .ToArray();
        if (tokens.Length == 0)
            return;
        var inner = new CSharpParser(tokens, _language, _dialect).ParseExpression();
        var interpolation = new SyntaxNode(NodeKind.Interpolation, expression, node.Range, node.Tokens);
        if (inner != null)
            interpolation.Add(inner);
        node.Add(interpolation);
    }
}



