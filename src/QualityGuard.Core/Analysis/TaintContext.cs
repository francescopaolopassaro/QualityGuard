namespace QualityGuard.Core.Analysis;

/// <summary>
/// What the whole scan has learned about untrusted data, shared with the per-file pass.
/// Functions whose result carries attacker-controlled data behave as sources at every call site, in
/// any file, which is what makes the analysis interprocedural.
/// </summary>
public sealed class TaintContext
{
    public static TaintContext Empty { get; } = new();

    /// <summary>Names of functions that return a value derived from untrusted input.</summary>
    public HashSet<string> TaintedFunctions { get; } = new(StringComparer.Ordinal);

    /// <summary>File and line where each of those functions picks the data up.</summary>
    public Dictionary<string, (string File, int Line)> Origins { get; } = new(StringComparer.Ordinal);

    public bool ReturnsTainted(string functionName) => TaintedFunctions.Contains(functionName);

    public bool Remember(string functionName, string file, int line)
    {
        if (!TaintedFunctions.Add(functionName))
            return false;
        Origins[functionName] = (file, line);
        return true;
    }

    public (string File, int Line)? OriginOf(string functionName)
        => Origins.TryGetValue(functionName, out var origin) ? origin : null;
}
