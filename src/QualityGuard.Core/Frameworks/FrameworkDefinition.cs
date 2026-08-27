namespace QualityGuard.Core.Frameworks;

/// <summary>
/// Defines a framework's type system, method return types, and API patterns.
/// Loaded from YAML files in Rules/Catalog/frameworks/.
/// </summary>
public sealed class FrameworkDefinition
{
    public string Name { get; init; } = "";
    public string Language { get; init; } = "";
    public string[] Aliases { get; init; } = [];
    public TypeMapping[] Types { get; init; } = [];
    public MethodReturnMapping[] MethodReturns { get; init; } = [];
    public ChainPattern[] Chains { get; init; } = [];
    public SinkSourceMapping[] Sinks { get; init; } = [];
    public SinkSourceMapping[] Sources { get; init; } = [];
    public SanitizerMapping[] Sanitizers { get; init; } = [];
}

public sealed class TypeMapping
{
    public string Name { get; init; } = "";
    public string[] Extends { get; init; } = [];
    public string[] Implements { get; init; } = [];
    public bool IsAbstract { get; init; }
}

public sealed class MethodReturnMapping
{
    /// <summary>Receiver type (e.g. "AbstractAssert", "Logger").</summary>
    public string Receiver { get; init; } = "";

    /// <summary>Method name (e.g. "isEqualTo", "info").</summary>
    public string Method { get; init; } = "";

    /// <summary>Return type name (e.g. "AbstractAssert", "void").</summary>
    public string Returns { get; init; } = "";

    /// <summary>If true, the return type is the same as the receiver (fluent API).</summary>
    public bool ReturnsSelf { get; init; }
}

public sealed class ChainPattern
{
    /// <summary>Entry point method (e.g. "assertThat", "given").</summary>
    public string Entry { get; init; } = "";

    /// <summary>Receiver type of the entry (e.g. "Assertions").</summary>
    public string? Receiver { get; init; }

    /// <summary>Return type of the entry (e.g. "AbstractAssert").</summary>
    public string Returns { get; init; } = "";

    /// <summary>Methods that can be chained on the return type.</summary>
    public string[] ChainMethods { get; init; } = [];
}

public sealed class SinkSourceMapping
{
    /// <summary>Method or constructor name (e.g. "exec", "format").</summary>
    public string Method { get; init; } = "";

    /// <summary>Receiver type, null for any.</summary>
    public string? Receiver { get; init; }

    /// <summary>Argument indices that are sinks (0-based).</summary>
    public int[] Args { get; init; } = [0];

    /// <summary>What kind of sink: "command", "sql", "path", "xss", etc.</summary>
    public string Kind { get; init; } = "";
}

public sealed class SanitizerMapping
{
    public string Method { get; init; } = "";
    public string? Receiver { get; init; }
    public string Kind { get; init; } = "";
}
