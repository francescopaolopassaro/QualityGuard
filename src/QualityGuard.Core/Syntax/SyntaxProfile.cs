using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax;

public enum StructureStyle
{
    /// <summary>Blocks delimited by curly braces (C family, JSON, HCL).</summary>
    Braces,

    /// <summary>Blocks opened by a trailing colon and delimited by indentation (Python, YAML).</summary>
    Indentation,

    /// <summary>Blocks opened by a keyword and closed by <c>end</c> (Ruby, VB.NET).</summary>
    EndKeyword,

    /// <summary>No nesting: every logical line is a statement (shell, SQL, Dockerfile, markup).</summary>
    Flat
}

/// <summary>
/// Per-language knobs the structural parser needs. Everything else is inferred from the token stream,
/// so a new language only has to declare how it spells declarations.
/// </summary>
public sealed record SyntaxProfile(
    StructureStyle Style,
    string[] FunctionKeywords,
    string[] ClassKeywords,
    string[] ImportKeywords,
    string[] VariableKeywords,
    string[] BlockKeywords,
    bool CStyleSignatures = false,
    bool CaseInsensitive = false)
{
    public static readonly SyntaxProfile Default = new(
        StructureStyle.Flat, [], [], [], [], []);

    private static readonly string[] CFamilyControl =
        ["if", "else", "for", "foreach", "while", "do", "switch", "match", "try", "catch", "finally",
         "using", "lock", "synchronized", "unsafe", "case", "default", "when", "loop", "select"];

    private static readonly Dictionary<string, SyntaxProfile> Profiles = new(StringComparer.OrdinalIgnoreCase)
    {
        [LanguageKeys.CSharp] = new(StructureStyle.Braces,
            ["void", "delegate", "operator"], ["class", "struct", "interface", "enum", "record"],
            ["using"], ["var", "const"], CFamilyControl, CStyleSignatures: true),
        [LanguageKeys.Java] = new(StructureStyle.Braces,
            ["void"], ["class", "interface", "enum", "record"],
            ["import", "package"], ["var", "final"], CFamilyControl, CStyleSignatures: true),
        [LanguageKeys.JavaScript] = new(StructureStyle.Braces,
            ["function"], ["class"], ["import", "require", "export"], ["var", "let", "const"],
            CFamilyControl),
        [LanguageKeys.TypeScript] = new(StructureStyle.Braces,
            ["function"], ["class", "interface", "enum", "type", "namespace"],
            ["import", "require", "export"], ["var", "let", "const"], CFamilyControl),
        [LanguageKeys.Go] = new(StructureStyle.Braces,
            ["func"], ["type", "struct", "interface"], ["import", "package"], ["var", "const"],
            CFamilyControl),
        [LanguageKeys.Kotlin] = new(StructureStyle.Braces,
            ["fun"], ["class", "object", "interface", "enum", "data"], ["import", "package"],
            ["val", "var"], CFamilyControl),
        [LanguageKeys.Rust] = new(StructureStyle.Braces,
            ["fn"], ["struct", "enum", "trait", "impl", "mod"], ["use", "extern"], ["let", "const", "static"],
            CFamilyControl),
        [LanguageKeys.Php] = new(StructureStyle.Braces,
            ["function"], ["class", "interface", "trait", "enum"], ["use", "require", "include", "namespace"],
            ["var", "const"], CFamilyControl),
        [LanguageKeys.C] = new(StructureStyle.Braces,
            ["void"], ["struct", "union", "enum"], ["include"], ["const", "static"],
            CFamilyControl, CStyleSignatures: true),
        [LanguageKeys.Cpp] = new(StructureStyle.Braces,
            ["void"], ["class", "struct", "union", "enum", "namespace"], ["include", "using"],
            ["const", "static", "auto"], CFamilyControl, CStyleSignatures: true),
        [LanguageKeys.Css] = new(StructureStyle.Braces, [], [], ["import"], [], []),
        [LanguageKeys.Terraform] = new(StructureStyle.Braces,
            [], ["resource", "data", "module", "provider", "variable", "output"], [], ["locals"], []),
        [LanguageKeys.CloudFormation] = new(StructureStyle.Braces, [], [], [], [], []),
        [LanguageKeys.Arm] = new(StructureStyle.Braces, [], [], [], [], []),
        [LanguageKeys.Python] = new(StructureStyle.Indentation,
            ["def", "async"], ["class"], ["import", "from"], [],
            ["if", "elif", "else", "for", "while", "with", "try", "except", "finally", "match", "case"]),
        [LanguageKeys.Kubernetes] = new(StructureStyle.Indentation, [], [], [], [], []),
        [LanguageKeys.Ruby] = new(StructureStyle.EndKeyword,
            ["def", "lambda", "proc"], ["class", "module"], ["require", "require_relative", "load"], [],
            ["if", "unless", "while", "until", "for", "case", "begin", "do", "rescue", "ensure", "else", "elsif"]),
        [LanguageKeys.Basic] = new(StructureStyle.EndKeyword,
            ["sub", "function"], ["class", "module", "structure", "interface", "enum"], ["imports"],
            ["dim", "const"],
            ["if", "for", "while", "do", "select", "try", "catch", "finally", "else", "elseif", "using", "with"],
            CaseInsensitive: true),
        [LanguageKeys.Shell] = new(StructureStyle.Flat, ["function"], [], ["source"], [], []),
        [LanguageKeys.Sql] = new(StructureStyle.Flat, ["procedure", "function"], ["table", "view"], [], ["declare"], []),
        [LanguageKeys.Razor] = new(StructureStyle.Braces,
            ["function"], ["class"], ["using", "inject", "page"], ["var", "let", "const"], CFamilyControl),
        [LanguageKeys.Xaml] = SyntaxProfile.Default,
        [LanguageKeys.Docker] = SyntaxProfile.Default,
        [LanguageKeys.Html] = SyntaxProfile.Default,
        [LanguageKeys.Xml] = SyntaxProfile.Default
    };

    public static SyntaxProfile For(string languageKey)
        => Profiles.TryGetValue(languageKey, out var profile) ? profile : Default;

    public bool IsFunctionKeyword(string word) => Match(FunctionKeywords, word);

    public bool IsClassKeyword(string word) => Match(ClassKeywords, word);

    public bool IsImportKeyword(string word) => Match(ImportKeywords, word);

    public bool IsVariableKeyword(string word) => Match(VariableKeywords, word);

    public bool IsBlockKeyword(string word) => Match(BlockKeywords, word);

    private bool Match(string[] words, string word)
    {
        for (var i = 0; i < words.Length; i++)
        {
            if (CaseInsensitive
                ? string.Equals(words[i], word, StringComparison.OrdinalIgnoreCase)
                : words[i] == word)
                return true;
        }
        return false;
    }
}
