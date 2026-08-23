using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax.CSharp;

/// <summary>
/// Scala ends a statement at the line break unless the next line plainly continues it, the way
/// Kotlin does. This rebuilds the terminators the language leaves out, so the shared brace parser
/// can read Scala the way it reads Java and TypeScript.
/// </summary>
public static class ScalaSemicolons
{
    /// <summary>Keywords that can be the last word of a statement.</summary>
    private static readonly string[] EndingKeywords =
    [
        "return", "break", "continue", "true", "false", "null", "this", "super", "_", "yield"
    ];

    /// <summary>
    /// Operators that cannot start a statement, so a line beginning with one is the tail of the
    /// line before it. The generator arrow and the comprehension arrow are the ones Scala adds to
    /// the usual set.
    /// </summary>
    private static readonly string[] ContinuationOperators =
    [
        ".", "?.", "?:", ",", "->", "=>", "<-", "+", "-", "*", "/", "%", "&&", "||", "==", "!=",
        "<", ">", "<=", ">=", "=", "+=", "-=", "*=", "/=", "%=", "?", ":", "|", "&", "^", "::",
        "++", "--", "##", "#"
    ];

    /// <summary>Words that carry on a declaration or a chain written over several lines.</summary>
    private static readonly string[] ContinuationWords =
    [
        "else", "catch", "finally", "with", "extends", "yield", "match", "then", "in", "is",
        "as", "by", "where"
    ];

    public static IReadOnlyList<Token> Insert(IReadOnlyList<Token> tokens)
    {
        var result = new List<Token>(tokens.Count + 32);
        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            result.Add(token);

            var next = i + 1 < tokens.Count ? tokens[i + 1] : null;
            if (next == null || next.Line == token.Line || !EndsStatement(token))
                continue;
            if (ContinuesOnNextLine(next))
                continue;

            result.Add(new Token(TokenKind.Symbol, ";", token.Line, token.Column + token.Text.Length));
        }
        return result;
    }

    private static bool EndsStatement(Token token) => token.Kind switch
    {
        TokenKind.Identifier or TokenKind.Number or TokenKind.String => true,
        TokenKind.Keyword => EndingKeywords.Contains(token.Text, StringComparer.Ordinal),
        TokenKind.Symbol => token.Text is ")" or "]" or "}",
        _ => false
    };

    private static bool ContinuesOnNextLine(Token next)
    {
        if (next.Kind == TokenKind.Symbol)
        {
            // an opening delimiter on the next line belongs to the call or the block before it;
            // a brace can also open a body, and a stray semicolon in front of it is harmless either
            // way, so both shapes stay unsplit
            if (next.Text is "(" or "[" or "{" or ")" or "]" or "}")
                return true;
            return ContinuationOperators.Contains(next.Text, StringComparer.Ordinal);
        }
        return next.Kind == TokenKind.Keyword
               && ContinuationWords.Contains(next.Text, StringComparer.Ordinal);
    }
}
