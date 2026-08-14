using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax.CSharp;

/// <summary>
/// JavaScript ends most statements at the line break. This rebuilds the terminators the way the
/// language does — a statement ends at the end of a line unless the next line continues the
/// expression — so the shared parser can treat JavaScript like the other brace languages.
/// </summary>
public static class JsSemicolons
{
    private static readonly string[] EndingKeywords =
    [
        "return", "break", "continue", "true", "false", "null", "undefined", "this", "super"
    ];

    private static readonly string[] ContinuationOperators =
    [
        ".", "?.", ",", "=>", "+", "-", "*", "/", "%", "&&", "||", "??", "==", "!=", "===", "!==",
        "<", ">", "<=", ">=", "=", "+=", "-=", "*=", "/=", "?", ":", "|", "&", "^", "instanceof", "in",
        "as", "extends", "implements"
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
        TokenKind.Symbol => token.Text is ")" or "]" or "}" or "++" or "--",
        _ => false
    };

    private static bool ContinuesOnNextLine(Token next)
    {
        if (next.Kind == TokenKind.Symbol)
        {
            // a closing delimiter continues the expression that opened it
            if (next.Text is "(" or "[" or "{" or "`" or ")" or "]")
                return true;
            return ContinuationOperators.Contains(next.Text, StringComparer.Ordinal);
        }
        return next.Kind == TokenKind.Keyword
               && next.Text is "instanceof" or "in" or "as" or "extends" or "implements";
    }
}
