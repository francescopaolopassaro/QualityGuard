namespace QualityGuard.Core.Tokenization;

public sealed record StringDelimiter(string Start, string End)
{
    /// <summary>
    /// A verbatim literal takes its content as written: no backslash escapes. That is the '@' form,
    /// not simply any prefix — '$"..."' is prefixed and still escapes.
    /// </summary>
    public bool IsVerbatim => Start.Contains('@');

    /// <summary>
    /// An interpolated literal carries expressions between braces, and those expressions can contain
    /// quotes of their own. The reader has to follow the braces to know where the literal ends.
    /// </summary>
    public bool IsInterpolated => Start.Contains('$') || Prefix.Contains('f') || Prefix.Contains('F');

    /// <summary>The letters in front of the quote, empty when the literal has none.</summary>
    public string Prefix => new(Start.TakeWhile(char.IsLetter).ToArray());

    /// <summary>
    /// A raw literal keeps its backslashes: 'r"\d"' is a backslash and a 'd', not an escape. Reading it
    /// as an escape dropped the backslash, which left every regular expression written the raw way —
    /// which is how patterns are written — as a different pattern than the one in the file.
    /// </summary>
    public bool IsRaw => Prefix.Contains('r') || Prefix.Contains('R');
}

public static class LanguageKeys
{
    public const string CSharp = "cs";
    public const string Java = "java";
    public const string JavaScript = "js";
    public const string TypeScript = "ts";
    public const string Python = "py";
    public const string Cpp = "cpp";
    public const string C = "c";
    public const string Php = "php";
    public const string Go = "go";
    public const string Ruby = "rb";
    public const string Kotlin = "kt";
    public const string Swift = "swift";
    public const string Basic = "vb";
    public const string Dart = "dart";
    public const string Css = "css";
    public const string Json = "json";
    public const string Html = "html";
    public const string Xml = "xml";
    public const string Sql = "sql";
    public const string Shell = "sh";
    public const string Terraform = "tf";
    public const string Docker = "dk";
    public const string Kubernetes = "k8";
    public const string CloudFormation = "cf";
    public const string Arm = "ar";
    public const string Rust = "rs";
    public const string Razor = "raz";
    public const string Xaml = "xaml";
}

public sealed record LanguageInfo(
    string LanguageKey,
    string[] Extensions,
    HashSet<string> Keywords,
    HashSet<string> ControlFlowKeywords,
    string? LineComment,
    string? BlockCommentStart,
    string? BlockCommentEnd,
    StringDelimiter[] StringDelimiters,
    bool HashComments,
    bool NestingBlockComments,
    bool CaseInsensitiveKeywords = false,
    bool LineDirectives = false)
{
    public bool MatchesExtension(string path)
    {
        var ext = System.IO.Path.GetExtension(path);
        return Extensions.Contains(ext, StringComparer.OrdinalIgnoreCase);
    }
}

public sealed class LanguageRecognizer
{
    private readonly Dictionary<string, LanguageInfo> _byExtension;
    private readonly LanguageInfo? _docker;
    private readonly LanguageInfo? _cloudFormation;

    public LanguageRecognizer(IEnumerable<LanguageInfo> languages)
    {
        _byExtension = new Dictionary<string, LanguageInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var lang in languages)
        {
            foreach (var ext in lang.Extensions)
                _byExtension[ext] = lang;
            if (lang.LanguageKey == LanguageKeys.Docker)
                _docker = lang;
            if (lang.LanguageKey == LanguageKeys.CloudFormation)
                _cloudFormation = lang;
        }
    }

    public LanguageInfo? Recognize(string path)
    {
        var ext = System.IO.Path.GetExtension(path);
        if (_byExtension.TryGetValue(ext, out var lang))
            return lang;

        var name = System.IO.Path.GetFileName(path);
        if (name.Equals("Dockerfile", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Containerfile", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("Dockerfile.", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("Containerfile.", StringComparison.OrdinalIgnoreCase))
            return _docker;

        return null;
    }

    /// <summary>
    /// The language of a file whose content has already been read. A cluster manifest and a cloud
    /// template share the extension .yaml and are read by different rules, so the extension alone
    /// sends every template to the wrong set of rules — and templates are almost never named
    /// anything else.
    /// </summary>
    public LanguageInfo? Recognize(string path, string content)
    {
        var language = Recognize(path);
        if (language?.LanguageKey == LanguageKeys.Kubernetes && _cloudFormation != null
            && DeclaresCloudTemplate(content))
            return _cloudFormation;
        return language;
    }

    private static bool DeclaresCloudTemplate(string content)
        => content.Contains("AWSTemplateFormatVersion", StringComparison.Ordinal)
           || content.Contains("Type: AWS::", StringComparison.Ordinal)
           || content.Contains("Type: \"AWS::", StringComparison.Ordinal)
           || content.Contains("Type: 'AWS::", StringComparison.Ordinal);
}