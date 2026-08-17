using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Analysis;

/// <summary>What the analysis knows about one type declared anywhere in the scanned code.</summary>
public sealed class TypeInfo
{
    public required string Name { get; init; }
    public required string File { get; init; }
    public required SyntaxNode Node { get; init; }
    public required IReadOnlyList<string> BaseNames { get; init; }
    public required IReadOnlyList<string> MemberNames { get; init; }

    /// <summary>Declared type of each member, when the declaration states one.</summary>
    public required IReadOnlyDictionary<string, string> MemberTypes { get; init; }

    public required bool IsInterface { get; init; }

    public override string ToString() => $"{Name} ({File})";
}

/// <summary>
/// Cross-file view of the code under analysis: which types exist, what they inherit from, which names
/// are declared and which are used anywhere. Rules that need to look beyond the current file — dead
/// members, inheritance depth, hidden base members — read it instead of guessing.
/// </summary>
public sealed class ProjectIndex
{
    private readonly Dictionary<string, List<TypeInfo>> _types = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _declaredFunctions = new(StringComparer.Ordinal);
    private readonly HashSet<string> _invoked = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _referenced = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _returnTypes = new(StringComparer.Ordinal);
    private readonly HashSet<string> _ambiguousReturns = new(StringComparer.Ordinal);

    public static ProjectIndex Empty { get; } = new();

    public IReadOnlyCollection<TypeInfo> Types => _types.Values.SelectMany(t => t).ToList();

    public static ProjectIndex Build(IEnumerable<FileAnalysis> analyses)
    {
        var index = new ProjectIndex();
        foreach (var analysis in analyses)
            index.Add(analysis);
        return index;
    }

    private void Add(FileAnalysis analysis)
    {
        var root = analysis.Tree.Root;

        foreach (var type in root.OfKind(NodeKind.ClassDeclaration))
        {
            if (type.Text.Length == 0)
                continue;
            var info = new TypeInfo
            {
                Name = type.Text,
                File = analysis.File.Path,
                Node = type,
                BaseNames = BaseNamesOf(type),
                MemberNames = type.OfKind(NodeKind.FunctionDeclaration, NodeKind.PropertyDeclaration,
                        NodeKind.FieldDeclaration)
                    .Where(m => m.Ancestor(NodeKind.ClassDeclaration) == type && m.Text.Length > 0)
                    .Select(m => m.Text)
                    .ToList(),
                MemberTypes = MemberTypesOf(type),
                IsInterface = type.Tokens.Any(t => t.Text == "interface")
            };
            if (!_types.TryGetValue(info.Name, out var list))
                _types[info.Name] = list = [];
            list.Add(info);
        }

        foreach (var function in root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (function.Text.Length == 0)
                continue;
            _declaredFunctions[function.Text] = _declaredFunctions.GetValueOrDefault(function.Text) + 1;

            var returned = function.FirstChild(NodeKind.TypeReference)?.Text;
            if (string.IsNullOrEmpty(returned))
                continue;
            if (_returnTypes.TryGetValue(function.Text, out var known) && known != returned)
                _ambiguousReturns.Add(function.Text);
            else
                _returnTypes[function.Text] = returned;
        }

        foreach (var call in root.OfKind(NodeKind.Invocation))
            _invoked.Add(SyntaxQuery.InvokedName(call));

        foreach (var identifier in root.OfKind(NodeKind.Identifier))
            _referenced[identifier.Text] = _referenced.GetValueOrDefault(identifier.Text) + 1;

        AddTemplateReferences(analysis);
    }

    /// <summary>
    /// Records the names a template mentions. A view binds code by naming it — '@onclick="Save"',
    /// '{{ total }}', 'th:text="${name}"' — and none of that reaches a syntax tree the engine builds
    /// for markup. Without this, every handler a page calls looked like code nobody reaches.
    /// </summary>
    private void AddTemplateReferences(FileAnalysis analysis)
    {
        if (analysis.Tree.HasDedicatedParser)
            return;
        var language = analysis.File.Language?.LanguageKey ?? string.Empty;
        if (!TemplateLanguages.Contains(language, StringComparer.OrdinalIgnoreCase))
            return;

        foreach (var token in analysis.Tokens)
        {
            if (token.Kind is not (Tokenization.TokenKind.Identifier or Tokenization.TokenKind.String))
                continue;
            foreach (var word in Words(token.Text))
                _referenced[word] = _referenced.GetValueOrDefault(word) + 1;
        }
    }

    /// <summary>Languages whose files are templates over code written elsewhere.</summary>
    private static readonly string[] TemplateLanguages =
        ["html", "raz", "razor", "cshtml", "vbhtml", "xaml", "aspx", "ascx", "jsp", "vue", "xml",
         "svelte", "twig", "blade", "erb", "hbs", "mustache", "jinja"];

    /// <summary>
    /// The identifier-shaped words inside a piece of markup. A binding is written among punctuation
    /// the markup owns, so the text is cut on everything that cannot be part of a name.
    /// </summary>
    private static IEnumerable<string> Words(string text)
    {
        var start = -1;
        for (var i = 0; i <= text.Length; i++)
        {
            var isName = i < text.Length && (char.IsLetterOrDigit(text[i]) || text[i] == '_');
            if (isName && start < 0)
                start = i;
            else if (!isName && start >= 0)
            {
                if (i - start > 2)
                    yield return text[start..i];
                start = -1;
            }
        }
    }

    private static IReadOnlyDictionary<string, string> MemberTypesOf(SyntaxNode type)
    {
        var types = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var member in type.OfKind(NodeKind.FunctionDeclaration, NodeKind.PropertyDeclaration,
                     NodeKind.FieldDeclaration))
        {
            if (member.Ancestor(NodeKind.ClassDeclaration) != type || member.Text.Length == 0)
                continue;
            var declared = member.FirstChild(NodeKind.TypeReference)?.Text;
            if (!string.IsNullOrEmpty(declared))
                types[member.Text] = declared;
        }
        return types;
    }

    /// <summary>Base types named in the declaration, whether or not they are declared in this code.</summary>
    private static IReadOnlyList<string> BaseNamesOf(SyntaxNode type)
    {
        var names = new List<string>();
        var afterMarker = false;
        foreach (var token in type.Tokens)
        {
            if (token.Text is ":" or "extends" or "implements")
            {
                afterMarker = true;
                continue;
            }
            if (token.Text is "{" or "where")
                break;
            if (!afterMarker)
                continue;
            if (token.Kind is Tokenization.TokenKind.Identifier && token.Text.Length > 0)
                names.Add(token.Text);
        }
        return names;
    }

    public TypeInfo? FindType(string name)
        => _types.TryGetValue(name, out var list) ? list[0] : null;

    public IReadOnlyList<TypeInfo> FindTypes(string name)
        => _types.TryGetValue(name, out var list) ? list : [];

    /// <summary>How far the type sits from the root of its declared hierarchy, within this code.</summary>
    public int InheritanceDepth(TypeInfo type, int guard = 0)
    {
        if (guard > 12)
            return guard;
        var deepest = 0;
        foreach (var baseName in type.BaseNames)
        {
            if (FindType(baseName) is not { } parent || parent == type)
                continue;
            deepest = Math.Max(deepest, 1 + InheritanceDepth(parent, guard + 1));
        }
        return deepest;
    }

    /// <summary>
    /// Members declared by the ancestors of the type. Interfaces are skipped by default: implementing a
    /// contract is not the same as hiding an inherited implementation.
    /// </summary>
    public IReadOnlyCollection<string> InheritedMembers(TypeInfo type, bool includeInterfaces = false,
        int guard = 0)
    {
        var members = new HashSet<string>(StringComparer.Ordinal);
        if (guard > 12)
            return members;
        foreach (var baseName in type.BaseNames)
        {
            if (FindType(baseName) is not { } parent || parent == type)
                continue;
            if (parent.IsInterface && !includeInterfaces)
                continue;
            foreach (var member in parent.MemberNames)
                members.Add(member);
            foreach (var member in InheritedMembers(parent, includeInterfaces, guard + 1))
                members.Add(member);
        }
        return members;
    }

    /// <summary>Declared type of a member of a known type, following the base chain.</summary>
    public string? MemberType(string typeName, string memberName, int guard = 0)
    {
        if (guard > 8 || FindType(typeName) is not { } info)
            return null;
        if (info.MemberTypes.TryGetValue(memberName, out var declared))
            return declared;
        foreach (var baseName in info.BaseNames)
        {
            if (MemberType(baseName, memberName, guard + 1) is { } inherited)
                return inherited;
        }
        return null;
    }

    /// <summary>Return type of a function declared once in the scanned code.</summary>
    public string? ReturnType(string functionName)
        => !_ambiguousReturns.Contains(functionName) && _returnTypes.TryGetValue(functionName, out var type)
            ? type
            : null;

    public bool IsCalledAnywhere(string name) => _invoked.Contains(name);

    public int ReferenceCount(string name) => _referenced.GetValueOrDefault(name);

    public bool IsDeclaredMoreThanOnce(string typeName) => FindTypes(typeName).Count > 1;
}
