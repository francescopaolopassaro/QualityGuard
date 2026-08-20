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
    public Token(TokenKind kind, string text, int line, int column, string prefix = "")
    {
        Kind = kind;
        Text = text;
        Line = line;
        Column = column;
        Prefix = prefix;
    }

    public TokenKind Kind { get; }
    public string Text { get; }
    public int Line { get; }
    public int Column { get; }

    /// <summary>
    /// Letters written in front of a string literal, when the language has them: 'r' for a raw
    /// literal, 'f' for a formatted one. Empty for every other token. The parser needs it because the
    /// two read the same once the quotes are gone, and only one of them holds expressions.
    /// </summary>
    public string Prefix { get; }

    public override string ToString() => $"{Kind}({Line}:{Column}) '{Text}'";
}