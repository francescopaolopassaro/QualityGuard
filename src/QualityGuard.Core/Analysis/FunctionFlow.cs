using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Analysis;

/// <summary>
/// Value-level taint tracking within a single function body.
///
/// Unlike line-based taint (which marks every line referencing a tainted symbol), this walks
/// statements IN ORDER and tracks how each assignment TRANSFORMS the taint state. A variable
/// assigned from a source starts Tainted; passing it through any method call moves it to
/// Sanitized; assigning a literal moves it to Clean. At any point, the current state determines
/// whether a finding should fire.
///
/// This is the first step toward a full Control Flow Graph: the statement list IS the basic
/// block sequence for straight-line code. Branch handling (if/else unions, loop back-edges)
/// is the next increment.
/// </summary>
public sealed class FunctionFlow
{
    /// <summary>A single operation extracted from a function body.</summary>
    public sealed class Step
    {
        /// <summary>The identifier being written to, empty when the step only reads.</summary>
        public string Target { get; init; } = "";

        /// <summary>Identifiers read by this step.</summary>
        public IReadOnlyList<string> Reads { get; init; } = [];

        /// <summary>True when the right-hand side wraps reads inside a method call.</summary>
        public bool PassesThroughCall { get; init; }

        /// <summary>True when the right-hand side is a pure literal.</summary>
        public bool IsLiteralRhs { get; init; }

        /// <summary>True when the right-hand side directly calls a recognized source.</summary>
        public bool IsDirectSource { get; init; }

        public int Line { get; init; }
        public SyntaxNode Node { get; init; } = null!;
    }

    /// <summary>Taint state of a symbol at a specific point in the flow.</summary>
    public enum TaintState { Unknown, Clean, Tainted, Sanitized }

    private readonly List<Step> _steps;

    public FunctionFlow(List<Step> steps) => _steps = steps;

    /// <summary>All steps in source order.</summary>
    public IReadOnlyList<Step> Steps => _steps;

    /// <summary>
    /// Simulates the flow: walks statements in order, updating each symbol's taint state.
    /// Returns the final state of every symbol after the last statement executes.
    /// </summary>
    public Dictionary<string, TaintState> Evaluate()
    {
        var state = new Dictionary<string, TaintState>(StringComparer.Ordinal);

        foreach (var step in _steps)
        {
            // compute the incoming taint of the right-hand side
            var rhsState = TaintState.Clean;
            foreach (var read in step.Reads)
            {
                var s = state.GetValueOrDefault(read, TaintState.Unknown);
                if (s == TaintState.Tainted || step.IsDirectSource)
                {
                    rhsState = TaintState.Tainted;
                    break;
                }
                if (s == TaintState.Sanitized)
                    rhsState = rhsState == TaintState.Tainted ? TaintState.Tainted : TaintState.Sanitized;
            }
            if (step.IsDirectSource)
                rhsState = TaintState.Tainted;

            // determine the output state based on how the RHS transforms the input
            var newState = (step.PassesThroughCall, step.IsLiteralRhs, rhsState) switch
            {
                (_, true, _) => TaintState.Clean,                          // literal always clean
                (true, _, TaintState.Tainted) => TaintState.Sanitized,     // call sanitizes tainted input
                (true, _, TaintState.Sanitized) => TaintState.Sanitized,   // idempotent
                (true, _, _) => TaintState.Clean,                          // call on clean stays clean
                (_, _, TaintState.Tainted) => TaintState.Tainted,          // direct pass-through keeps taint
                _ => TaintState.Unknown
            };

            if (!string.IsNullOrEmpty(step.Target))
                state[step.Target] = newState;
        }

        return state;
    }
}
