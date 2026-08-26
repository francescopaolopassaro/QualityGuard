using QualityGuard.Core.Analysis;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The FunctionFlow value tracker simulates taint state through ordered statements.
/// Each test pins a transformation pattern: source→sanitized→clean must stay clean,
/// source→sink must stay tainted, literals reset everything.
/// </summary>
public class FunctionFlowTests
{
    private static Dictionary<string, FunctionFlow.TaintState> Eval(
        params (string target, string[] reads, bool call, bool literal, bool source)[] steps)
    {
        var flow = new FunctionFlow(steps.Select(s => new FunctionFlow.Step
        {
            Target = s.target,
            Reads = s.reads,
            PassesThroughCall = s.call,
            IsLiteralRhs = s.literal,
            IsDirectSource = s.source,
            Line = 0,
            Node = null!
        }).ToList());
        return flow.Evaluate();
    }

    [Fact]
    public void Source_directly_taints_the_target()
    {
        var state = Eval(("value", Array.Empty<string>(), false, false, true));
        Assert.Equal(FunctionFlow.TaintState.Tainted, state["value"]);
    }

    [Fact]
    public void A_literal_resets_taint_to_clean()
    {
        var state = Eval(
            ("value", Array.Empty<string>(), false, false, true),
            ("value", Array.Empty<string>(), false, true, false));
        Assert.Equal(FunctionFlow.TaintState.Clean, state["value"]);
    }

    [Fact]
    public void Passing_tainted_through_a_call_sanitizes_it()
    {
        var state = Eval(
            ("value", Array.Empty<string>(), false, false, true),
            ("value", new[] { "value" }, true, false, false));
        Assert.Equal(FunctionFlow.TaintState.Sanitized, state["value"]);
    }

    [Fact]
    public void Direct_passthrough_keeps_taint()
    {
        var state = Eval(
            ("a", Array.Empty<string>(), false, false, true),
            ("b", new[] { "a" }, false, false, false));
        Assert.Equal(FunctionFlow.TaintState.Tainted, state["b"]);
    }

    [Fact]
    public void Clean_input_through_a_call_stays_clean()
    {
        var state = Eval(
            ("name", Array.Empty<string>(), false, true, false),
            ("upper", new[] { "name" }, true, false, false));
        Assert.Equal(FunctionFlow.TaintState.Clean, state["upper"]);
    }
}
