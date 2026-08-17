using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Constructs that are legal, common, and mean something different from what they look like: a number
/// that is not the number it spells, a call that ends the process from inside a library, a value that
/// was never produced. They cross every language, so they live here rather than in a language set.
/// </summary>
public static class ApiUsageRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new OctalLiteralRule(),
        new ProcessExitInLibraryRule(),
        new StandardOutputForLoggingRule(),
        new WildcardImportRule(),
        new SideEffectInsideExpressionRule(),
        new LoopBoundCheckedWithInequalityRule(),
        new ResultOfVoidCallUsedRule()
    ];
}

public abstract class ApiRuleBase : RuleBase
{
    public override string[] Languages => [];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "10min";

    protected static bool HasPreciseTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>
    /// True when the file is the entry point of a program. Writing to the console and ending the
    /// process are what an entry point is for; the same calls inside a library are the problem.
    /// </summary>
    protected static bool IsEntryPoint(IRuleContext context)
    {
        if (context.File.Content.Contains("__main__", StringComparison.Ordinal))
            return true;
        var stem = System.IO.Path.GetFileNameWithoutExtension(context.File.FileName);
        if (stem is "Program" or "Main" or "main" or "cli" or "Cli" or "__main__")
            return true;
        return SyntaxQuery.Functions(context.Root).Any(f => f.Text is "main" or "Main");
    }
}

public sealed class OctalLiteralRule : ApiRuleBase
{
    public override string Key => "QG-ALL-BUG-0033";
    public override string Name => "A number should not be written in octal by accident";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        // Python and Rust require an explicit 0o prefix, so a leading zero cannot surprise anyone
        if (!HasPreciseTree(context) || context.Language.LanguageKey is "py" or "rs")
            return;

        foreach (var number in context.Root.OfKind(NodeKind.NumberLiteral))
        {
            var text = number.Text;
            if (text.Length < 2 || text[0] != '0')
                continue;
            if (!text.Skip(1).All(char.IsAsciiDigit))
                continue;
            if (text.Skip(1).Any(c => c is '8' or '9'))
                continue; // not a valid octal number: the compiler rejects it, no rule needed
            // A Unix permission mask is written in octal on purpose, in every language that has a
            // file API: 0755 means rwxr-xr-x to the reader, and 493 means nothing to anyone.
            if (IsPermissionMask(text))
                continue;

            context.Report(number, $"'{text}' starts with a zero, so the compiler reads it in base 8: "
                                   + $"its value is {Convert.ToInt64(text, 8)}, not {text.TrimStart('0')}. "
                                   + "Drop the leading zero, or write the octal prefix the language "
                                   + "provides so the intent is visible.");
        }
    }

    /// <summary>Whether the literal is a Unix permission mask, which is meant to be read in octal.</summary>
    private static bool IsPermissionMask(string text)
    {
        var digits = text[1..];
        if (digits.Length is < 3 or > 4)
            return false;
        return digits.All(c => c is >= '0' and <= '7');
    }
}

public sealed class ProcessExitInLibraryRule : ApiRuleBase
{
    private static readonly string[] ExitCalls =
        ["exit", "Exit", "_exit", "abort", "halt", "die"];

    private static readonly string[] ExitOwners =
        ["System", "Environment", "os", "sys", "process", "Runtime", "Process"];

    public override string Key => "QG-ALL-SML-0045";
    public override string Name => "A library should not end the process";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || IsEntryPoint(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!ExitCalls.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;
            var owner = SyntaxQuery.Receiver(call);
            if (!ExitOwners.Contains(owner, StringComparer.Ordinal))
                continue;

            context.Report(call, $"'{owner}.{SyntaxQuery.InvokedName(call)}' ends the whole process from "
                                 + "inside a component that does not own it: buffers are not flushed, "
                                 + "callers cannot recover, and a test that reaches this line kills the "
                                 + "runner. Return an error and let the entry point decide.");
        }
    }
}

public sealed class StandardOutputForLoggingRule : ApiRuleBase
{
    private static readonly string[] ConsoleWrites =
        ["println", "print", "printf", "WriteLine", "Write", "log", "warn", "error", "puts"];

    private static readonly string[] ConsoleOwners =
    [
        "System.out", "System.err", "Console", "console", "out", "err", "STDOUT", "STDERR",
        // .NET writes its diagnostics through these two, and they reach the same place
        "Debug", "Trace", "System.Console", "System.Diagnostics.Debug", "System.Diagnostics.Trace"
    ];

    public override string Key => "QG-ALL-SML-0046";
    public override string Name => "Logging should not go straight to the console";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || IsEntryPoint(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!ConsoleWrites.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;
            var owner = SyntaxQuery.Receiver(call);
            if (!ConsoleOwners.Contains(owner, StringComparer.Ordinal))
                continue;

            context.Report(call, "This writes straight to the console, so the message has no level, no "
                                 + "timestamp and no way of being switched off in production. Send it "
                                 + "through the logger the application already configures.");
        }

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "printStackTrace"))
        {
            context.Report(call, "The stack trace goes to the console with nothing around it: no level, "
                                 + "no timestamp, and no record of what the program was doing. Log the "
                                 + "exception through the logger, which keeps the trace and the context "
                                 + "together.");
        }
    }
}

public sealed class WildcardImportRule : ApiRuleBase
{
    public override string Key => "QG-ALL-SML-0047";
    public override string Name => "Imports should name what they bring in";

    public override void Execute(IRuleContext context)
    {
        foreach (var import in context.Root.OfKind(NodeKind.ImportDeclaration))
        {
            var text = import.Text;
            if (!text.EndsWith(".*", StringComparison.Ordinal)
                && !text.EndsWith("import *", StringComparison.Ordinal)
                && !text.Contains("import *", StringComparison.Ordinal))
                continue;

            context.Report(import, "This import brings in every name of the module at once. A name added "
                                   + "upstream can then shadow one of yours without a single line changing "
                                   + "here, and no reader can tell where a symbol comes from. Import the "
                                   + "names you use.");
        }
    }
}

public sealed class SideEffectInsideExpressionRule : ApiRuleBase
{
    public override string Key => "QG-ALL-BUG-0034";
    public override string Name => "A variable changed inside an expression should not be read twice in it";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        // `arr[i++]` and `guard++ < 10` are ordinary: the variable is read once and the order is
        // fixed. The defect is reading the same variable again in the same expression, where the
        // result depends on when the compiler applies the change.
        foreach (var statement in context.Root.OfKind(NodeKind.ExpressionStatement, NodeKind.VariableDeclaration))
        {
            foreach (var unary in statement.OfKind(NodeKind.Unary))
            {
                if (unary.Text is not ("++" or "--"))
                    continue;
                var name = SyntaxQuery.DottedName(unary.ChildAt(0));
                if (name.Length == 0)
                    continue;
                var reads = statement.OfKind(NodeKind.Identifier).Count(i => i.Text == name);
                if (reads < 2)
                    continue;

                context.Report(unary, $"'{name}' is changed by '{unary.Text}' and read again in the same "
                                      + "expression, so the value each read sees depends on the order the "
                                      + "compiler chooses. Change it in its own statement first.");
                break;
            }
        }
    }
}

public sealed class LoopBoundCheckedWithInequalityRule : ApiRuleBase
{
    public override string Key => "QG-ALL-BUG-0035";
    public override string Name => "A counting loop should stop with a comparison, not an inequality";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            var condition = loop.Children.FirstOrDefault(c => c.Kind == NodeKind.Binary && c.Text == "!=");
            if (condition == null)
                continue;
            var counter = SyntaxQuery.DottedName(condition.ChildAt(0));
            if (counter.Length == 0)
                continue;
            // only a loop that counts: an iterator compared with an end marker is a different idiom
            var counts = loop.Children.Any(c => c.Kind == NodeKind.Unary && c.Text is "++" or "--"
                                                && SyntaxQuery.DottedName(c.ChildAt(0)) == counter);
            if (!counts)
                continue;

            context.Report(loop, $"The loop ends only when '{counter}' is exactly equal to the bound. If "
                                 + "anything makes it step over the value — a change of increment, a "
                                 + "modification inside the body — the loop runs past the end. Use < or > "
                                 + "so the bound cannot be missed.");
        }
    }
}

public sealed class ResultOfVoidCallUsedRule : ApiRuleBase
{
    public override string Key => "QG-ALL-BUG-0036";
    public override string Name => "A call that returns nothing should not be used as a value";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.Project.Types.Count == 0)
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var parent = call.Parent;
            if (parent == null || parent.Kind is NodeKind.ExpressionStatement or NodeKind.Block)
                continue;
            // an expression-bodied lambda over a void call is a statement lambda, which is what
            // every Consumer and Runnable in the language is written as
            if (parent.Kind is NodeKind.Lambda)
                continue;
            var name = SyntaxQuery.InvokedName(call);
            if (name.Length == 0)
                continue;
            // the method has to be the one the receiver's type declares: a name-only lookup confuses
            // every same-named method in the scan, starting with Add on the platform collections
            var callee = call.ChildAt(0);
            var ownerType = callee is { Kind: NodeKind.MemberSelect }
                ? context.Types.TypeOf(callee.ChildAt(0))
                : SyntaxQuery.EnclosingType(call)?.Text;
            if (ownerType == null || context.Project.FindType(ownerType) == null)
                continue;
            if (context.Project.MemberType(ownerType, name) is not ("void" or "Unit"))
                continue;
            // `return DoSomething();` inside a void function is a legitimate early exit in C-family code
            if (parent.Kind == NodeKind.Jump && parent.Text.StartsWith("return", StringComparison.Ordinal))
                continue;

            context.Report(call, $"'{name}' returns nothing, so this expression has no value to work with. "
                                 + "Call it as a statement and use the value it produced elsewhere.");
        }
    }
}
