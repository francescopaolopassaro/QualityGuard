namespace QualityGuard.Core.Tokenization;

public static class BuiltInLanguages
{
    private static readonly StringDelimiter[] DoubleQuoted = [new("\"", "\"")];
    private static readonly StringDelimiter[] SingleDouble = [new("\"", "\""), new("'", "'")];
    private static readonly StringDelimiter[] JsStrings = [new("\"", "\""), new("'", "'"), new("`", "`")];

    /// <summary>
    /// Java text blocks open with three quotes; the longer form must be tried first, or every
    /// text block would read as an empty string followed by stray source.
    /// </summary>
    private static readonly StringDelimiter[] JavaStrings =
        [new("\"\"\"", "\"\"\""), new("\"", "\""), new("'", "'")];

    public static readonly LanguageInfo CSharp = new(
        "cs", [".cs"],
        ["abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked", "class", "const",
            "continue", "decimal", "default", "delegate", "do", "double", "else", "enum", "event", "explicit",
            "extern", "false", "finally", "fixed", "float", "for", "foreach", "goto", "if", "implicit", "in", "int",
            "interface", "internal", "is", "lock", "long", "namespace", "new", "null", "object", "operator", "out",
            "override", "params", "private", "protected", "public", "readonly", "ref", "return", "sbyte", "sealed",
            "short", "sizeof", "stackalloc", "static", "string", "struct", "switch", "this", "throw", "true", "try",
            "typeof", "uint", "ulong", "unchecked", "unsafe", "ushort", "using", "virtual", "void", "volatile",
            "while", "async", "await", "record", "init", "required", "var"],
        ["if", "else", "for", "foreach", "while", "do", "case", "switch", "catch", "&&", "||", "??", "?"],
        "//", "/*", "*/",
        [new("\"", "\""), new("@\"", "\""), new("$\"", "\""), new("$@\"", "\""), new("@$\"", "\""), new("'", "'"), new("\"\"\"", "\"\"\"")],
        HashComments: false, NestingBlockComments: false, LineDirectives: true);

    public static readonly LanguageInfo Java = new(
        "java", [".java"],
        ["abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue",
            "default", "do", "double", "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if",
            "implements", "import", "instanceof", "int", "interface", "long", "native", "new", "package", "private",
            "protected", "public", "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this",
            "throw", "throws", "transient", "try", "void", "volatile", "while", "record", "sealed", "permits"],
        ["if", "else", "for", "while", "do", "case", "switch", "catch", "&&", "||", "?"],
        "//", "/*", "*/",
        JavaStrings,
        HashComments: false, NestingBlockComments: false);

    public static readonly LanguageInfo JavaScript = new(
        "js", [".js", ".jsx", ".mjs", ".cjs"],
        ["await", "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do",
            "else", "enum", "export", "extends", "false", "finally", "for", "function", "if", "implements", "import",
            "in", "instanceof", "interface", "let", "new", "null", "package", "private", "protected", "public",
            "return", "static", "super", "switch", "this", "throw", "true", "try", "typeof", "var", "void", "while",
            "with", "yield"],
        ["if", "else", "for", "while", "do", "case", "switch", "catch", "&&", "||", "??", "?"],
        "//", "/*", "*/",
        JsStrings,
        HashComments: false, NestingBlockComments: false);

    public static readonly LanguageInfo TypeScript = new(
        "ts", [".ts", ".tsx", ".mts", ".cts"],
        ["abstract", "any", "as", "asserts", "async", "await", "boolean", "break", "case", "catch", "class", "const",
            "constructor", "continue", "debugger", "declare", "default", "delete", "do", "else", "enum", "export",
            "extends", "false", "finally", "for", "from", "function", "get", "if", "implements", "import", "in",
            "infer", "instanceof", "interface", "is", "keyof", "let", "module", "namespace", "never", "new", "null",
            "number", "object", "package", "private", "protected", "public", "readonly", "require", "return", "set",
            "static", "string", "super", "switch", "symbol", "this", "throw", "true", "try", "type", "typeof",
            "undefined", "unique", "unknown", "var", "void", "while", "with", "yield"],
        ["if", "else", "for", "while", "do", "case", "switch", "catch", "&&", "||", "??", "?"],
        "//", "/*", "*/",
        JsStrings,
        HashComments: false, NestingBlockComments: false);

    public static readonly LanguageInfo Python = new(
        "py", [".py", ".pyw"],
        ["and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else",
            "except", "False", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "None",
            "nonlocal", "not", "or", "pass", "raise", "return", "True", "try", "while", "with", "yield", "match",
            "case"],
        ["if", "elif", "while", "for", "case", "except", "and", "or", "not"],
        "#", null, null,
        [new("\"\"\"", "\"\"\""), new("'''", "'''"), new("\"", "\""), new("'", "'")],
        HashComments: true, NestingBlockComments: false);

    public static readonly LanguageInfo Cpp = new(
        "cpp", [".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx", ".inl"],
        ["alignas", "alignof", "and", "asm", "auto", "bool", "break", "case", "catch", "char", "char8_t", "char16_t",
            "char32_t", "class", "const", "constexpr", "const_cast", "continue", "decltype", "default", "delete",
            "do", "double", "dynamic_cast", "else", "enum", "explicit", "export", "extern", "false", "float", "for",
            "friend", "goto", "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept", "not",
            "nullptr", "operator", "or", "private", "protected", "public", "register", "reinterpret_cast", "return",
            "short", "signed", "sizeof", "static", "static_assert", "static_cast", "struct", "switch", "template",
            "this", "thread_local", "throw", "true", "try", "typedef", "typeid", "typename", "union", "unsigned",
            "using", "virtual", "void", "volatile", "wchar_t", "while", "concept", "requires", "co_await", "co_return",
            "co_yield"],
        ["if", "else", "for", "while", "do", "case", "switch", "catch", "&&", "||", "?"],
        "//", "/*", "*/",
        SingleDouble,
        HashComments: false, NestingBlockComments: true, LineDirectives: true);

    public static readonly LanguageInfo C = new(
        "c", [".c", ".h"],
        ["auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern",
            "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return", "short",
            "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile",
            "while", "_Bool", "_Complex", "_Imaginary"],
        ["if", "else", "for", "while", "do", "case", "switch", "&&", "||", "?"],
        "//", "/*", "*/",
        SingleDouble,
        HashComments: false, NestingBlockComments: false, LineDirectives: true);

    public static readonly LanguageInfo Php = new(
        "php", [".php"],
        ["abstract", "and", "array", "as", "break", "callable", "case", "catch", "class", "clone", "const",
            "continue", "declare", "default", "do", "echo", "else", "elseif", "empty", "enddeclare", "endfor",
            "endforeach", "endif", "endswitch", "endwhile", "enum", "eval", "exit", "extends", "final", "finally",
            "fn", "for", "foreach", "function", "global", "goto", "if", "implements", "include", "include_once",
            "instanceof", "insteadof", "interface", "isset", "list", "match", "namespace", "new", "or", "print",
            "private", "protected", "public", "readonly", "require", "require_once", "return", "static", "switch",
            "throw", "trait", "try", "unset", "use", "var", "while", "xor", "yield", "int", "float", "string",
            "bool", "true", "false", "null", "mixed", "void", "iterable", "object"],
        ["if", "else", "elseif", "for", "foreach", "while", "do", "case", "switch", "catch", "match", "&&", "||",
            "and", "or"],
        "//", "/*", "*/",
        [new("\"\"\"", "\"\"\""), new("\"", "\""), new("'", "'")],
        HashComments: true, NestingBlockComments: false);

    public static readonly LanguageInfo Go = new(
        "go", [".go"],
        ["break", "case", "chan", "const", "continue", "default", "defer", "else", "fallthrough", "for", "func",
            "go", "goto", "if", "import", "interface", "map", "package", "range", "return", "select", "struct",
            "switch", "type", "var"],
        ["if", "else", "for", "switch", "case", "select", "&&", "||"],
        "//", "/*", "*/",
        [new("\"", "\""), new("`", "`"), new("'", "'")],
        HashComments: false, NestingBlockComments: false);

    public static readonly LanguageInfo Scala = new(
        "scala", [".scala", ".sc"],
        ["abstract", "case", "catch", "class", "def", "do", "else", "extends", "false", "final", "finally",
            "for", "forSome", "if", "implicit", "import", "lazy", "match", "new", "null", "object", "override",
            "package", "private", "protected", "return", "sealed", "super", "this", "throw", "trait", "try",
            "true", "type", "val", "var", "while", "with", "yield", "given", "using", "enum", "then"],
        ["if", "else", "match", "case", "for", "while", "catch", "&&", "||"],
        "//", "/*", "*/",
        [new("\"\"\"", "\"\"\""), new("\"", "\""), new("'", "'")],
        HashComments: false, NestingBlockComments: true);

    public static readonly LanguageInfo Flex = new(
        "flex", [".as", ".mxml"],
        ["as", "break", "case", "catch", "class", "const", "continue", "default", "delete", "do", "dynamic",
            "each", "else", "extends", "false", "final", "finally", "for", "function", "get", "if", "implements",
            "import", "in", "instanceof", "interface", "internal", "is", "namespace", "native", "new", "null",
            "override", "package", "private", "protected", "public", "return", "set", "static", "super", "switch",
            "this", "throw", "true", "try", "typeof", "use", "var", "void", "while", "with"],
        ["if", "else", "for", "while", "switch", "case", "catch", "&&", "||"],
        "//", "/*", "*/",
        [new("\"", "\""), new("'", "'")],
        HashComments: false, NestingBlockComments: false);

    public static readonly LanguageInfo Ruby = new(
        "rb", [".rb", ".rake", ".gemspec", ".podspec"],
        ["__END__", "__FILE__", "__LINE__", "alias", "and", "begin", "break", "case", "class", "def", "defined?",
            "do", "else", "elsif", "end", "ensure", "false", "for", "if", "in", "module", "next", "nil", "not", "or",
            "redo", "rescue", "retry", "return", "self", "super", "then", "true", "undef", "unless", "until", "when",
            "while", "yield"],
        ["if", "elsif", "unless", "while", "until", "for", "case", "when", "and", "or", "&&", "||"],
        "#", "=begin", "=end",
        [new("\"", "\""), new("'", "'")],
        HashComments: true, NestingBlockComments: false);

    public static readonly LanguageInfo Kotlin = new(
        "kt", [".kt", ".kts"],
        ["as", "break", "class", "const", "continue", "do", "else", "enum", "false", "for", "fun", "if", "import",
            "in", "interface", "is", "null", "object", "package", "reified", "return", "super", "this", "throw",
            "true", "try", "typealias", "typeof", "val", "var", "when", "while", "override", "internal", "public",
            "private", "protected", "sealed", "data", "companion", "inline", "suspend", "open"],
        ["if", "else", "for", "while", "do", "when", "catch", "&&", "||", "?"],
        "//", "/*", "*/",
        [new("\"\"\"", "\"\"\""), new("\"", "\""), new("'", "'")],
        HashComments: false, NestingBlockComments: true);

    public static readonly LanguageInfo Swift = new(
        "swift", [".swift"],
        ["as", "associatedtype", "async", "await", "break", "case", "catch", "class", "continue",
            "default", "defer", "deinit", "do", "else", "enum", "extension", "fallthrough", "false",
            "fileprivate", "for", "func", "guard", "if", "import", "in", "init", "inout", "internal",
            "is", "let", "nil", "open", "operator", "private", "protocol", "public", "repeat",
            "required", "rethrows", "return", "self", "static", "struct", "subscript", "super",
            "switch", "throw", "throws", "true", "try", "typealias", "var", "where", "while",
            "lazy", "mutating", "nonmutating", "override", "weak", "unowned", "final", "some", "any",
            "convenience", "indirect", "actor", "nonisolated", "willSet", "didSet", "get", "set"],
        ["if", "else", "for", "while", "repeat", "switch", "guard", "catch", "&&", "||", "??", "?"],
        "//", "/*", "*/",
        [new("\"\"\"", "\"\"\""), new("\"", "\"")],
        HashComments: false, NestingBlockComments: true);

    public static readonly LanguageInfo Basic = new(
        "vb", [".vb"],
        ["AddHandler", "AddressOf", "Alias", "And", "AndAlso", "As", "Boolean", "ByRef", "Byte", "ByVal", "Call",
            "Case", "Catch", "CBool", "CByte", "CChar", "CDate", "CDbl", "CDec", "Char", "CInt", "Class", "CLng",
            "CObj", "Const", "Continue", "CSByte", "CShort", "CSng", "CStr", "CType", "CUInt", "CULng", "CUShort",
            "Date", "Decimal", "Declare", "Default", "Delegate", "Dim", "DirectCast", "Do", "Double", "Each",
            "Else", "ElseIf", "End", "EndIf", "Enum", "Erase", "Error", "Event", "Exit", "False", "Finally",
            "For", "Friend", "Function", "Get", "GetType", "GetXmlNamespace", "Global", "GoSub", "GoTo", "Handles",
            "If", "Implements", "Imports", "In", "Inherits", "Integer", "Interface", "Is", "IsNot", "Let",
            "Lib", "Like", "Long", "Loop", "Me", "Mod", "Module", "MustInherit", "MustOverride", "MyBase",
            "MyClass", "Namespace", "Narrowing", "New", "Next", "Not", "Nothing", "NotInheritable",
            "NotOverridable", "Object", "Of", "On", "Operator", "Option", "Optional", "Or", "OrElse", "Overloads",
            "Overridable", "Overrides", "ParamArray", "Partial", "Private", "Property", "Protected", "Public",
            "RaiseEvent", "ReadOnly", "ReDim", "REM", "RemoveHandler", "Resume", "Return", "SByte", "Select",
            "Set", "Shadows", "Shared", "Short", "Single", "Static", "Step", "Stop", "String", "Structure",
            "Sub", "SyncLock", "Then", "Throw", "To", "True", "Try", "TryCast", "TypeOf", "UInteger", "ULong",
            "UShort", "Using", "Variant", "Wend", "When", "While", "Widening", "With", "WithEvents", "WriteOnly",
            "Xor"],
        ["If", "ElseIf", "For", "ForEach", "While", "Do", "Case", "Catch", "AndAlso", "OrElse", "When"],
        "'", null, null,
        // VB has one string form. The doubled quote inside it is an escape, handled by the
        // tokenizer; declaring '""' as a second delimiter made an empty literal open a string that
        // ran to the next '""' in the file — usually several lines of code later.
        [new("\"", "\"")],
        HashComments: true, NestingBlockComments: false, LineDirectives: true);

    public static readonly LanguageInfo Dart = new(
        "dart", [".dart"],
        ["abstract", "as", "assert", "async", "await", "break", "case", "catch", "class", "const",
         "continue", "covariant", "default", "deferred", "do", "dynamic", "else", "enum", "export",
         "extends", "extension", "external", "factory", "false", "final", "finally", "for", "get",
         "hide", "if", "implements", "import", "in", "interface", "is", "late", "library", "mixin",
         "new", "null", "on", "operator", "part", "required", "rethrow", "return", "sealed", "set",
         "show", "static", "super", "switch", "sync", "this", "throw", "true", "try", "typedef",
         "var", "void", "while", "with", "yield"],
        ["if", "else", "for", "while", "do", "switch", "case", "catch", "&&", "||", "?"],
        "//", "/*", "*/",
        [new("\"", "\""), new("'", "'")],
        HashComments: false, NestingBlockComments: true);

    public static readonly LanguageInfo Css = new(
        "css", [".css", ".less", ".scss", ".sass"],
        [],
        [],
        "//", "/*", "*/",
        [new("\"", "\""), new("'", "'")],
        HashComments: false, NestingBlockComments: false);

    public static readonly LanguageInfo Html = new(
        "html", [".html", ".htm", ".vue", ".hbs", ".xhtml"],
        [],
        [],
        null, "<!--", "-->",
        [new("\"", "\""), new("'", "'")],
        HashComments: false, NestingBlockComments: false);

    public static readonly LanguageInfo Json = new(
        "json", [".json", ".jsonc", ".json5", ".webmanifest"],
        ["true", "false", "null"],
        [],
        "//", "/*", "*/",
        [new("\"", "\"")],
        HashComments: false, NestingBlockComments: false);

    public static readonly LanguageInfo Xml = new(
        "xml", [".xml", ".xsd", ".xsl", ".xslt", ".csproj", ".fsproj", ".vbproj", ".props", ".targets", ".config",
            // '.sln' is deliberately absent: a solution file is not XML, and reading it as XML
            // turned its project list into statements
            ".resx", ".nuspec"],
        [],
        [],
        null, "<!--", "-->",
        [new("\"", "\""), new("'", "'")],
        HashComments: false, NestingBlockComments: false);

    public static readonly LanguageInfo Sql = new(
        "sql", [".sql"],
        ["ADD", "ALL", "ALTER", "AND", "AS", "ASC", "BETWEEN", "BY", "CASE", "CHECK", "COLUMN", "CONSTRAINT",
            "CREATE", "DATABASE", "DEFAULT", "DELETE", "DESC", "DISTINCT", "DROP", "ELSE", "EXISTS", "FOREIGN",
            "FROM", "FULL", "GROUP", "HAVING", "IN", "INDEX", "INNER", "INSERT", "INT", "INTO", "IS", "JOIN", "KEY",
            "LEFT", "LIKE", "LIMIT", "NOT", "NULL", "ON", "OR", "ORDER", "OUTER", "PRIMARY", "PROCEDURE", "RIGHT",
            "SELECT", "SET", "TABLE", "THEN", "UNION", "UPDATE", "VALUES", "VARCHAR", "VIEW", "WHEN", "WHERE",
            "WHILE", "WITH"],
        ["CASE", "WHEN", "WHILE", "AND", "OR", "NOT"],
        "--", "/*", "*/",
        [new("'", "'"), new("\"", "\"")],
        HashComments: false, NestingBlockComments: false, CaseInsensitiveKeywords: true);

    public static readonly LanguageInfo Shell = new(
        "sh", [".sh", ".bash", ".zsh", ".ksh"],
        ["if", "then", "else", "elif", "fi", "for", "in", "do", "done", "while", "until", "case", "esac",
            "function", "select", "time", "local", "export", "return", "exit", "readonly", "set", "unset", "shift",
            "declare", "typeset", "trap", "break", "continue", "source", "alias", "unset"],
        ["if", "elif", "while", "until", "for", "case", "&&", "||", "then"],
        "#", null, null,
        [new("\"", "\""), new("'", "'")],
        HashComments: true, NestingBlockComments: false);

    public static readonly LanguageInfo Terraform = new(
        "tf", [".tf", ".tfvars"],
        ["resource", "data", "variable", "output", "locals", "local", "module", "provider", "terraform", "backend",
            "required_providers", "required_version", "provisioner", "connection", "lifecycle", "dynamic", "count",
            "for_each", "depends_on", "import", "moved", "check", "override"],
        ["if", "else", "for", "for_each", "count", "depends_on"],
        "#", "/*", "*/",
        [new("\"", "\""), new("'", "'")],
        HashComments: true, NestingBlockComments: false);

    public static readonly LanguageInfo Docker = new(
        "dk", [".dockerfile", ".containerfile"],
        ["FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT", "VOLUME",
            "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL", "AS"],
        [],
        "#", null, null,
        [new("\"", "\""), new("'", "'")],
        HashComments: true, NestingBlockComments: false, CaseInsensitiveKeywords: true);

    public static readonly LanguageInfo CloudFormation = new(
        "cf", [".template", ".cfn"],
        ["AWSTemplateFormatVersion", "Description", "Metadata", "Parameters", "Mappings", "Conditions",
            "Transform", "Resources", "Outputs", "Type", "Properties"],
        [],
        "#", null, null,
        [new("\"", "\""), new("'", "'")],
        HashComments: true, NestingBlockComments: false);

    public static readonly LanguageInfo Arm = new(
        "ar", [".az.json", ".arm.json"],
        ["$schema", "contentVersion", "parameters", "variables", "resources", "outputs", "functions", "apiVersion",
            "type", "name", "location", "properties", "dependsOn"],
        [],
        null, null, null,
        [new("\"", "\""), new("'", "'")],
        HashComments: false, NestingBlockComments: false);

    public static readonly LanguageInfo Kubernetes = new(
        "k8", [".yaml", ".yml"],
        [],
        [],
        "#", null, null,
        [new("\"", "\""), new("'", "'"), new("|", "")],
        HashComments: true, NestingBlockComments: false);

    public static readonly LanguageInfo Rust = new(
        "rs", [".rs"],
        ["as", "async", "await", "box", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
            "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
            "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "union", "unsafe",
            "use", "where", "while"],
        ["if", "else", "for", "while", "loop", "match", "&&", "||"],
        "//", "/*", "*/",
        [new("\"\"\"", "\"\"\""), new("\"", "\""), new("'", "'"), new("r#\"", "\"#"), new("r\"", "\"")],
        HashComments: false, NestingBlockComments: true, HasLifetimes: true);

    /// <summary>Razor views and Blazor components: HTML markup interleaved with C# code blocks.</summary>
    public static readonly LanguageInfo Razor = new(
        "raz", [".cshtml", ".razor", ".vbhtml"],
        ["await", "bool", "case", "catch", "class", "else", "false", "finally", "for", "foreach", "if", "in",
            "int", "new", "null", "return", "string", "switch", "true", "try", "using", "var", "while"],
        ["if", "else", "for", "foreach", "while", "switch", "catch", "&&", "||"],
        "//", "@*", "*@",
        [new("\"", "\""), new("'", "'")],
        HashComments: false, NestingBlockComments: false);

    /// <summary>XAML dialects used by WPF, WinUI, MAUI and Avalonia.</summary>
    public static readonly LanguageInfo Xaml = new(
        "xaml", [".xaml", ".axaml"],
        [],
        [],
        null, "<!--", "-->",
        [new("\"", "\""), new("'", "'")],
        HashComments: false, NestingBlockComments: false);

    public static IReadOnlyList<LanguageInfo> All { get; } =
    [
        CSharp,
        Java,
        JavaScript,
        TypeScript,
        Python,
        Cpp,
        C,
        Php,
        Go,
        Ruby,
        Scala,
        Flex,
        Kotlin,
        Swift,
        Basic,
        Dart,
        Css,
        Html,
        Json,
        Xml,
        Sql,
        Shell,
        Terraform,
        Docker,
        Kubernetes,
        CloudFormation,
        Arm,
        Rust,
        Razor,
        Xaml
    ];

    public static LanguageRecognizer Recognizer { get; } = new(All);
}