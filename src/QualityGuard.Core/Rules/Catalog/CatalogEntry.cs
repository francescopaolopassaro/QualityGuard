using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Catalog;

/// <summary>Which nodes a matcher looks at.</summary>
public enum MatchTarget
{
    Invocation,
    Creation,
    Member,
    Identifier,
    String,
    Assignment,
    Declaration,
    Parameter,
    Line
}

/// <summary>
/// One declarative detection clause. All populated fields must hold for a node to be reported, so a
/// rule stays readable as a handful of data lines instead of a class.
/// </summary>
public sealed record MatchSpec(
    MatchTarget Target,
    string[] Names,
    string[] Dotted,
    string[] Receivers,
    string[] Contains,
    string[] ArgLiterals,
    string[] WithoutArgs,
    string[] Requires,
    string[] Absent,
    string? LinePattern,
    int? ArgCount,
    int? ArgIndex,
    bool ArgTainted,
    bool ArgDynamic,
    bool LiteralValue,
    bool ArgNotLiteral,
    bool ResultUnused,
    string? Message)
{
    public static MatchSpec From(YamlMap map)
    {
        var target = ResolveTarget(map);
        return new MatchSpec(
            target,
            Names: map.Strings(TargetKey(target)).Concat(map.Strings("names")).Distinct().ToArray(),
            Dotted: map.Strings("dotted"),
            Receivers: map.Strings("receiver"),
            Contains: map.Strings("contains"),
            ArgLiterals: map.Strings("argLiterals"),
            WithoutArgs: map.Strings("withoutArgs"),
            Requires: map.Strings("requires"),
            Absent: map.Strings("absent"),
            LinePattern: map.Str("line") ?? map.Str("pattern"),
            ArgCount: map.Number("argCount"),
            ArgIndex: map.Number("argIndex"),
            ArgTainted: map.Flag("argTainted"),
            ArgDynamic: map.Flag("argDynamic"),
            LiteralValue: map.Flag("literalValue"),
            ArgNotLiteral: map.Flag("argNotLiteral"),
            ResultUnused: map.Flag("resultUnused"),
            Message: map.Str("message"));
    }

    private static MatchTarget ResolveTarget(YamlMap map)
    {
        if (map.Str("target") is { Length: > 0 } explicitTarget
            && Enum.TryParse<MatchTarget>(explicitTarget, true, out var parsed))
            return parsed;
        foreach (var target in Enum.GetValues<MatchTarget>())
        {
            if (map.ContainsKey(TargetKey(target)))
                return target;
        }
        return MatchTarget.Invocation;
    }

    private static string TargetKey(MatchTarget target) => target switch
    {
        MatchTarget.Invocation => "invocation",
        MatchTarget.Creation => "creation",
        MatchTarget.Member => "member",
        MatchTarget.Identifier => "identifier",
        MatchTarget.String => "string",
        MatchTarget.Assignment => "assignTo",
        MatchTarget.Declaration => "declaredType",
        MatchTarget.Parameter => "parameterType",
        _ => "line"
    };
}

/// <summary>A rule as written in the YAML catalog: metadata, English description and detection clauses.</summary>
public sealed class CatalogEntry
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    public required string[] Languages { get; init; }
    public required string Category { get; init; }
    public Severity Severity { get; init; }
    public IssueKind Kind { get; init; }
    public string Effort { get; init; } = "10min";
    public string[] Tags { get; init; } = [];
    public int[] Cwe { get; init; } = [];
    public string[] Owasp { get; init; } = [];
    public string Message { get; init; } = string.Empty;
    public required RuleDescription Description { get; init; }
    public IReadOnlyList<MatchSpec> Detect { get; init; } = [];

    /// <summary>
    /// Porting state. <c>ready</c> is the default; <c>planned</c> marks a catalog rule that is mapped and
    /// documented but whose detection needs analysis the engine does not perform yet, so it carries no
    /// clauses and reports nothing; <c>superseded</c> marks one that was retired because another rule
    /// reports the same defect, and names it in <see cref="SupersededBy"/>.
    /// </summary>
    public string Status { get; init; } = "ready";

    /// <summary>True when the entry was produced by the catalog generator rather than written by hand.</summary>
    public bool Generated { get; init; }

    /// <summary>The rule that took over, for an entry whose status is <c>superseded</c>.</summary>
    public string? SupersededBy { get; init; }

    public bool IsPlanned => string.Equals(Status, "planned", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when the entry documents a check the engine no longer runs on its own, because another
    /// rule reports the same line. The documentation stays so the identifier keeps its meaning, and
    /// the number is never handed to a different check.
    /// </summary>
    public bool IsSuperseded => string.Equals(Status, "superseded", StringComparison.OrdinalIgnoreCase);

    /// <summary>Entries without detection clauses only carry documentation for a hand-written rule.</summary>
    public bool IsDocumentationOnly => Detect.Count == 0;

    public static CatalogEntry From(YamlMap map)
    {
        var key = map.Text("key");
        var category = map.Str("category") ?? CategoryFromKey(key);
        var name = map.Text("name");
        var detect = map.Maps("detect").Select(MatchSpec.From).ToList();
        if (map.Map("detect") is { } single)
            detect.Add(MatchSpec.From(single));

        return new CatalogEntry
        {
            Key = key,
            Name = name,
            Languages = map.Strings("languages"),
            Category = category,
            Severity = ParseSeverity(map.Str("severity"), category),
            Kind = ParseKind(map.Str("type"), category),
            Effort = map.Str("effort") ?? DefaultEffort(category),
            Tags = map.Strings("tags"),
            Cwe = map.Integers("cwe"),
            Owasp = map.Strings("owasp"),
            Message = map.Str("message") ?? name,
            Status = map.Str("status") ?? "ready",
            SupersededBy = map.Str("superseded_by"),
            Generated = map.Flag("generated"),
            Description = new RuleDescription(
                Summary: map.Str("summary") ?? name,
                WhyIsThisAnIssue: map.Text("why"),
                HowToFix: map.Text("fix"),
                Impact: map.Str("impact"),
                Example: BuildExample(map),
                References: map.Strings("references")),
            Detect = detect
        };
    }

    private static CodeExample? BuildExample(YamlMap map)
    {
        var bad = map.Str("bad");
        var good = map.Str("good");
        if (bad == null && good == null)
            return null;
        var language = map.Strings("languages").FirstOrDefault() ?? "text";
        return new CodeExample(language, bad ?? string.Empty, good ?? string.Empty);
    }

    private static string CategoryFromKey(string key)
    {
        var parts = key.Split('-');
        return parts.Length >= 3 ? parts[2] : "SML";
    }

    private static Severity ParseSeverity(string? text, string category)
    {
        if (Enum.TryParse<Severity>(text, true, out var severity))
            return severity;
        return category switch
        {
            "SEC" => Severity.Critical,
            "BUG" => Severity.Major,
            "PRF" => Severity.Major,
            "CNV" => Severity.Minor,
            _ => Severity.Major
        };
    }

    private static IssueKind ParseKind(string? text, string category)
    {
        if (Enum.TryParse<IssueKind>(text, true, out var kind))
            return kind;
        return category switch
        {
            "SEC" => IssueKind.Vulnerability,
            "BUG" => IssueKind.Bug,
            _ => IssueKind.CodeSmell
        };
    }

    private static string DefaultEffort(string category) => category switch
    {
        "SEC" => "20min",
        "BUG" => "15min",
        "CNV" => "5min",
        _ => "10min"
    };
}
