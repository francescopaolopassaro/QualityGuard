namespace QualityGuard.Core.Tokenization;

public enum TokenKind
{
    Identifier,
    Keyword,
    Number,
    String,
    Comment,
    Symbol
}

public sealed class Token
{
    public Token(TokenKind kind, string text, int line, int column)
    {
        Kind = kind;
        Text = text;
        Line = line;
        Column = column;
    }

    public TokenKind Kind { get; }
    public string Text { get; }
    public int Line { get; }
    public int Column { get; }

    public override string ToString() => $"{Kind}({Line}:{Column}) '{Text}'";
}