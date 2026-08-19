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
    private readonly Dictionary<string, IReadOnlyList<string>> _parameterNames = new(StringComparer.Ordinal);
    private readonly HashSet<string> _ambiguousParameters = new(StringComparer.Ordinal);
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

            // The names a function calls its parameters, kept only while one answer is possible: two
            // functions with the same name and different signatures make any conclusion about a call
            // site a guess, and a rule that reads them has to know that.
            var parameters = function.FirstChild(NodeKind.ParameterList)?
                .ChildrenOf(NodeKind.Parameter)
                .Select(p => p.Text)
                .Where(n => n.Length > 0)
                .ToList();
            if (parameters is { Count: > 0 })
            {
                if (_parameterNames.TryGetValue(function.Text, out var seen) && !seen.SequenceEqual(parameters))
                    _ambiguousParameters.Add(function.Text);
                else
                    _parameterNames[function.Text] = parameters;
            }

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
    /// <summary>
    /// True when at least one template was read. A rule that asks "does anything reach this member"
    /// needs to know: the answer for a code-behind lives in the markup beside it, and a scan
    /// narrowed to source files never sees it.
    /// </summary>
    public bool SawTemplates { get; private set; }

    private readonly Dictionary<string, int> _templateNames = new(StringComparer.Ordinal);

    /// <summary>
    /// How many times a template mentions the name. A rule about reachability needs this on its own:
    /// counting every identifier in the project instead means a common field name like '_mapper'
    /// looks referenced because another class has one too.
    /// </summary>
    public int TemplateReferenceCount(string name) => _templateNames.GetValueOrDefault(name);

    private void AddTemplateReferences(FileAnalysis analysis)
    {
        // A Razor component is one class written in two files: the markup names members declared in
        // the code-behind, and the code-behind uses members declared in '@code'. The file is parsed
        // as C# and is still a template, so the check on the parser has to come second — with it
        // first, every field a component only touches from its markup read as unused.
        var language = analysis.File.Language?.LanguageKey ?? string.Empty;
        if (!TemplateLanguages.Contains(language, StringComparer.OrdinalIgnoreCase))
            return;

        SawTemplates = true;
        foreach (var token in analysis.Tokens)
        {
            if (token.Kind is not (Tokenization.TokenKind.Identifier or Tokenization.TokenKind.String))
                continue;
            foreach (var word in Words(token.Text))
            {
                _referenced[word] = _referenced.GetValueOrDefault(word) + 1;
                _templateNames[word] = _templateNames.GetValueOrDefault(word) + 1;
            }
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
            if (string.IsNullOrEmpty(declared))
                continue;
            // Overloads share a name and need not share a return type: Gson declares both a
            // 'toJson' that answers with a string and one that writes and answers with nothing.
            // Recording whichever came last made every call to the first look like a use of a void
            // result. When they disagree the type of the name is not knowable from the name.
            if (types.TryGetValue(member.Text, out var already) && already != declared)
            {
                types[member.Text] = string.Empty;
                continue;
            }
            if (!types.ContainsKey(member.Text) || types[member.Text].Length > 0)
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

    /// <summary>
    /// The parameter names of a function declared once in the scan, in order. Nothing when the scan
    /// saw the name more than once with different parameters, because then the call site is unknown.
    /// </summary>
    public IReadOnlyList<string>? ParameterNames(string functionName)
        => !_ambiguousParameters.Contains(functionName)
           && _parameterNames.TryGetValue(functionName, out var names)
            ? names
            : null;

    /// <summary>Whether the scan read a function with this name anywhere, however it is reached.</summary>
    public bool IsDeclared(string name) => _declaredFunctions.ContainsKey(name);

    /// <summary>Whether the scan saw any code at all, as opposed to markup and configuration only.</summary>
    public bool SawCode => _declaredFunctions.Count > 0;

    public int ReferenceCount(string name) => _referenced.GetValueOrDefault(name);

    public bool IsDeclaredMoreThanOnce(string typeName) => FindTypes(typeName).Count > 1;
}
