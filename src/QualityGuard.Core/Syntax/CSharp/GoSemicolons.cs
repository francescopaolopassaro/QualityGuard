using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Syntax.CSharp;

/// <summary>
/// Go terminates statements at the end of a line, following the same rule its own scanner applies:
/// a semicolon is inserted when the line ends with a token that can end a statement. Rebuilding that
/// step here lets the shared C-family parser treat Go like the other brace languages.
/// </summary>
public static class GoSemicolons
{
    private static readonly string[] ClosingKeywords =
    [
        "return", "break", "continue", "fallthrough", "true", "false", "nil", "iota"
    ];

    public static IReadOnlyList<Token> Insert(IReadOnlyList<Token> tokens)
    {
        var result = new List<Token>(tokens.Count + 32);
        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            result.Add(token);

            var next = i + 1 < tokens.Count ? tokens[i + 1] : null;
            if (next == null || next.Line == token.Line)
                continue;
            if (!EndsStatement(token))
                continue;
            // a line break before an opening brace still belongs to the same header
            if (next.Kind == TokenKind.Symbol && next.Text is "{" or "," or "." or ")" or "]")
                continue;

            result.Add(new Token(TokenKind.Symbol, ";", token.Line, token.Column + token.Text.Length));
        }
        return result;
    }

    private static bool EndsStatement(Token token) => token.Kind switch
    {
        TokenKind.Identifier or TokenKind.Number or TokenKind.String => true,
        TokenKind.Keyword => ClosingKeywords.Contains(token.Text, StringComparer.Ordinal),
        TokenKind.Symbol => token.Text is ")" or "]" or "}" or "++" or "--",
        _ => false
    };
}
