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
        }

        foreach (var call in root.OfKind(NodeKind.Invocation))
            _invoked.Add(SyntaxQuery.InvokedName(call));

        foreach (var identifier in root.OfKind(NodeKind.Identifier))
            _referenced[identifier.Text] = _referenced.GetValueOrDefault(identifier.Text) + 1;
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

    public bool IsCalledAnywhere(string name) => _invoked.Contains(name);

    public int ReferenceCount(string name) => _referenced.GetValueOrDefault(name);

    public bool IsDeclaredMoreThanOnce(string typeName) => FindTypes(typeName).Count > 1;
}
