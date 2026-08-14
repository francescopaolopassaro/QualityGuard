using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Semantics;

public enum UsageKind
{
    Declaration,
    Parameter,
    Assignment,
    Reference
}

/// <summary>One appearance of a symbol, with the value assigned to it when there is one.</summary>
public sealed record Usage(SyntaxNode Identifier, SyntaxNode? Value, UsageKind Kind)
{
    public int Line => Identifier.Line;
}

public enum ScopeKind
{
    File,
    Class,
    Function,
    Block
}

public sealed class Scope
{
    private readonly Dictionary<string, Symbol> _symbols = new(StringComparer.Ordinal);

    public Scope(ScopeKind kind, SyntaxNode node, Scope? parent)
    {
        Kind = kind;
        Node = node;
        Parent = parent;
        parent?.Children.Add(this);
    }

    public ScopeKind Kind { get; }
    public SyntaxNode Node { get; }
    public Scope? Parent { get; }
    public List<Scope> Children { get; } = [];
    public IReadOnlyDictionary<string, Symbol> Symbols => _symbols;

    public Symbol Declare(string name, string? declaredType)
    {
        if (_symbols.TryGetValue(name, out var existing))
            return existing;
        var symbol = new Symbol(name, declaredType, this);
        _symbols[name] = symbol;
        return symbol;
    }

    public Symbol? Lookup(string name)
    {
        for (var scope = this; scope != null; scope = scope.Parent)
        {
            if (scope._symbols.TryGetValue(name, out var symbol))
                return symbol;
        }
        return null;
    }

    public IEnumerable<Symbol> AllSymbols()
        => _symbols.Values.Concat(Children.SelectMany(c => c.AllSymbols()));

    /// <summary>Closest enclosing function scope, or the file scope.</summary>
    public Scope FunctionScope()
    {
        for (var scope = this; scope != null; scope = scope.Parent)
        {
            if (scope.Kind is ScopeKind.Function or ScopeKind.File)
                return scope;
        }
        return this;
    }
}

/// <summary>
/// A named program element (variable, parameter, field) together with every usage found in the file.
/// Rules use it to answer "what value does this name hold here?" instead of matching raw text.
/// </summary>
public sealed class Symbol
{
    private bool _resolvingValue;

    internal Symbol(string name, string? declaredType, Scope scope)
    {
        Name = name;
        DeclaredType = declaredType;
        Scope = scope;
    }

    public string Name { get; }
    public string? DeclaredType { get; internal set; }
    public Scope Scope { get; }
    public List<Usage> Usages { get; } = [];

    /// <summary>Set by the taint pass when the symbol can hold attacker-controlled data.</summary>
    public bool IsTainted { get; internal set; }

    /// <summary>Node that introduced the taint, used to report the source of a flow.</summary>
    public SyntaxNode? TaintSource { get; internal set; }

    public bool IsParameter => Usages.Any(u => u.Kind == UsageKind.Parameter);

    /// <summary>True when the name was introduced by a declaration statement, not by an assignment.</summary>
    public bool IsExplicitlyDeclared { get; internal set; }

    public IEnumerable<Usage> UsagesBefore(int line) => Usages.Where(u => u.Line < line);

    public IEnumerable<Usage> Assignments
        => Usages.Where(u => u.Kind is UsageKind.Assignment or UsageKind.Declaration && u.Value != null);

    /// <summary>
    /// The value of the symbol when it is effectively final: assigned once, either at the declaration
    /// or by a single later assignment. Anything reassigned or coming from a parameter returns null,
    /// which keeps rules that inspect values free of false positives.
    /// </summary>
    public SyntaxNode? SafeValue()
    {
        Usage? candidate = null;
        foreach (var usage in Usages)
        {
            switch (usage.Kind)
            {
                case UsageKind.Parameter:
                    return null;
                case UsageKind.Declaration when usage.Value != null:
                    if (candidate != null)
                        return null;
                    candidate = usage;
                    break;
                case UsageKind.Assignment when candidate == null:
                    candidate = usage;
                    break;
                case UsageKind.Assignment:
                    return null;
            }
        }
        return candidate?.Value;
    }

    /// <summary>Literal string held by the symbol, when it can be resolved with certainty.</summary>
    public string? SafeStringValue()
    {
        if (_resolvingValue)
            return null;
        _resolvingValue = true;
        try
        {
            return SyntaxQuery.ConstantString(SafeValue());
        }
        finally
        {
            _resolvingValue = false;
        }
    }

    public override string ToString() => $"{Name}:{DeclaredType ?? "?"} ({Usages.Count} usages)";
}
