namespace QualityGuard.Core.Rules;

/// <summary>
/// Guard for the "everything a user reads is English" rule: rule names, messages and fix guidance are
/// checked against markers of the other language spoken around this project.
/// </summary>
public static class EnglishGuard
{
    private static readonly string[] Markers =
    [
        "perche", "perché", "quindi", "della", "delle", "degli", "questo", "questa", "queste", "sono",
        "deve", "devono", "viene", "vengono", "utilizzare", "stringa", "errore", "errori", "regola",
        "linguaggio", "sicurezza", "codice", "valore", "aggiungere", "rimuovere", "controllare",
        "invece", "senza", "sempre", "anche", "oppure", "nessun", "nessuna", "consigliato"
    ];

    public static bool IsEnglish(string? text) => FindMarker(text) == null;

    /// <summary>Returns the offending word, or null when the text looks English.</summary>
    public static string? FindMarker(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;

        foreach (var word in text.Split([' ', '\n', '\r', '\t', '.', ',', ';', ':', '(', ')', '\'', '"', '!', '?'],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var marker in Markers)
            {
                if (string.Equals(word, marker, StringComparison.OrdinalIgnoreCase))
                    return marker;
            }
        }
        return null;
    }
}
