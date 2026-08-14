using QualityGuard.Core.Semantics;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax;

public readonly record struct TextRange(int StartLine, int StartColumn, int EndLine, int EndColumn)
{
    public static readonly TextRange Empty = new(0, 0, 0, 0);

    public static TextRange Of(Token first, Token last)
        => new(first.Line, first.Column, last.Line, last.Column + last.Text.Length);

    public static TextRange Of(IReadOnlyList<Token> tokens)
        => tokens.Count == 0 ? Empty : Of(tokens[0], tokens[^1]);

    public bool ContainsLine(int line) => line >= StartLine && line <= EndLine;

    public int LineCount => EndLine - StartLine + 1;

    public override string ToString() => $"{StartLine}:{StartColumn}-{EndLine}:{EndColumn}";
}

public enum NodeKind
{
    TopLevel,
    Unknown,

    // declarations
    PackageDeclaration,
    ImportDeclaration,
    Annotation,
    Attribute,
    AttributeList,
    Modifier,
    ClassDeclaration,
    EnumMember,
    FunctionDeclaration,
    LocalFunction,
    ConstructorDeclaration,
    PropertyDeclaration,
    IndexerDeclaration,
    EventDeclaration,
    Accessor,
    FieldDeclaration,
    ParameterList,
    Parameter,
    TypeReference,
    VariableDeclaration,

    // statements
    Block,
    ExpressionStatement,
    If,
    Else,
    Loop,
    Match,
    MatchCase,
    SwitchSection,
    Using,
    Lock,
    Label,
    Jump,
    Try,
    Catch,
    Finally,

    // expressions
    Assignment,
    Binary,
    Unary,
    Invocation,
    ObjectCreation,
    MemberSelect,
    Index,
    ArgumentList,
    Lambda,
    Conditional,
    Parenthesized,
    ListLiteral,
    ObjectInitializer,
    AnonymousObject,
    ArrayCreation,
    Cast,
    InterpolatedString,
    Interpolation,
    Tuple,
    Pattern,
    SwitchExpression,
    Range,
    Identifier,
    StringLiteral,
    NumberLiteral,
    BooleanLiteral,
    NullLiteral
}

/// <summary>
/// Language-agnostic syntax node. A single node type with a <see cref="NodeKind"/> keeps the tree
/// usable across every supported language without one class hierarchy per grammar.
/// </summary>
public sealed class SyntaxNode
{
    private readonly List<SyntaxNode> _children = [];

    public SyntaxNode(NodeKind kind, string text = "", TextRange range = default,
        IReadOnlyList<Token>? tokens = null)
    {
        Kind = kind;
        Text = text;
        Range = range;
        Tokens = tokens ?? [];
    }

    public NodeKind Kind { get; }
    public string Text { get; internal set; }
    public TextRange Range { get; internal set; }
    public IReadOnlyList<Token> Tokens { get; internal set; }
    public SyntaxNode? Parent { get; private set; }
    public IReadOnlyList<SyntaxNode> Children => _children;

    /// <summary>Resolved symbol, set by the semantic pass on identifier nodes.</summary>
    public Symbol? Symbol { get; set; }

    public int Line => Range.StartLine;
    public int EndLine => Range.EndLine;

    public void Add(SyntaxNode child)
    {
        child.Parent = this;
        _children.Add(child);
        if (Range.Equals(TextRange.Empty))
            Range = child.Range;
        else if (child.Range.EndLine > Range.EndLine)
            Range = Range with { EndLine = child.Range.EndLine, EndColumn = child.Range.EndColumn };
    }

    public IEnumerable<SyntaxNode> Descendants()
    {
        foreach (var child in _children)
        {
            yield return child;
            foreach (var nested in child.Descendants())
                yield return nested;
        }
    }

    public IEnumerable<SyntaxNode> DescendantsAndSelf()
    {
        yield return this;
        foreach (var node in Descendants())
            yield return node;
    }

    public IEnumerable<SyntaxNode> Ancestors()
    {
        var current = Parent;
        while (current != null)
        {
            yield return current;
            current = current.Parent;
        }
    }

    public SyntaxNode? Ancestor(params NodeKind[] kinds)
        => Ancestors().FirstOrDefault(a => kinds.Contains(a.Kind));

    public IEnumerable<SyntaxNode> ChildrenOf(NodeKind kind)
        => _children.Where(c => c.Kind == kind);

    public SyntaxNode? FirstChild(NodeKind kind)
        => _children.FirstOrDefault(c => c.Kind == kind);

    public SyntaxNode? ChildAt(int index)
        => index >= 0 && index < _children.Count ? _children[index] : null;

    public IEnumerable<SyntaxNode> OfKind(NodeKind kind)
        => Descendants().Where(n => n.Kind == kind);

    public IEnumerable<SyntaxNode> OfKind(params NodeKind[] kinds)
        => Descendants().Where(n => kinds.Contains(n.Kind));

    /// <summary>Source text of the node rebuilt from its tokens (single line, normalized spacing).</summary>
    public string SourceText() => string.Join(' ', Tokens.Select(t => t.Text));

    public override string ToString() => $"{Kind}('{Text}') @{Range}";
}
