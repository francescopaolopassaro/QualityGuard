using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Constructs the language replaced, kept together because they were found together: each one closes
/// a gap the line-by-line comparison against the reference's published expectations put at the top
/// of the list. None of them is a matter of taste — every one names a form that says the same thing
/// less clearly, or says something subtly different from what the reader will assume.
/// </summary>
public static class JsTsModernRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JsGuardedAccessRule(),
        new JsTypeofUndefinedRule(),
        new JsIndexOfAsContainsRule(),
        new JsIndexOfAsPrefixRule(),
        new JsGlobalReplaceRule(),
        new JsThisCopiedToVariableRule(),
        new JsNestedConditionalRule(),
        new JsBuiltinWithoutProtocolRule(),
        new JsGlobalNumberFunctionRule()
    ];
}

public abstract class JsTsModernRuleBase : RuleBase
{
    public override string[] Languages => ["js", "ts"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>The text of a node as a dotted name, for comparing two halves of an expression.</summary>
    protected static string Spelled(SyntaxNode? node)
        => node is null ? string.Empty
            : node.Kind == NodeKind.MemberSelect ? SyntaxQuery.DottedName(node) : node.Text;
}

public sealed class JsGuardedAccessRule : JsTsModernRuleBase
{
    public override string Key => "QG-JS-SML-0423";
    public override string Name => "A guarded access should use optional chaining";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text != "&&")
                continue;
            var guard = Spelled(binary.ChildAt(0));
            var use = Spelled(binary.ChildAt(1));
            if (guard.Length == 0 || use.Length <= guard.Length)
                continue;
            // 'a && a.b' tests the same subject twice; the language says it once
            if (!use.StartsWith(guard + ".", StringComparison.Ordinal))
                continue;

            context.Report(binary, $"'{guard}' is named twice: once to check it is there and once to "
                                   + "reach through it. Optional chaining says that in one step, and "
                                   + "cannot drift apart when the name changes.");
        }
    }
}

public sealed class JsTypeofUndefinedRule : JsTsModernRuleBase
{
    public override string Key => "QG-JS-SML-0424";
    public override string Name => "Absence should be compared directly";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("===" or "!==" or "==" or "!="))
                continue;
            var left = binary.ChildAt(0);
            var right = binary.ChildAt(1);
            var typeofSide = left is { Kind: NodeKind.Unary, Text: "typeof" } ? left
                : right is { Kind: NodeKind.Unary, Text: "typeof" } ? right : null;
            var other = ReferenceEquals(typeofSide, left) ? right : left;
            if (typeofSide is null || other is not { Kind: NodeKind.StringLiteral })
                continue;
            if (other.Text.Trim('"', '\'') != "undefined")
                continue;

            context.Report(binary, "Asking what type a name has, and then comparing that answer to the "
                                   + "word 'undefined', is a long way round: the value can be compared "
                                   + "to undefined directly. The detour also hides a real difference — "
                                   + "a name that was never declared at all.");
        }
    }
}

public sealed class JsIndexOfAsContainsRule : JsTsModernRuleBase
{
    public override string Key => "QG-JS-SML-0425";
    public override string Name => "A membership test should say so";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("!==" or "===" or "!=" or "==" or ">" or ">=" or "<"))
                continue;
            var call = binary.Children.FirstOrDefault(c => c.Kind == NodeKind.Invocation
                                                           && SyntaxQuery.InvokedName(c) == "indexOf");
            if (call is null)
                continue;
            var bound = binary.Children.FirstOrDefault(c => c != call);
            var literal = bound?.Kind == NodeKind.Unary ? bound.ChildAt(0)?.Text : bound?.Text;
            var negative = bound?.Kind == NodeKind.Unary && bound.Text == "-";
            if (literal is null)
                continue;
            var comparesToMinusOne = negative && literal == "1";
            var comparesToZero = !negative && literal == "0" && binary.Text is ">=" or "<";
            if (!comparesToMinusOne && !comparesToZero)
                continue;

            context.Report(binary, "This looks for a position only to decide whether there is one. The "
                                   + "membership test states that directly, and does not depend on the "
                                   + "reader remembering which side of minus one means present.");
        }
    }
}

public sealed class JsIndexOfAsPrefixRule : JsTsModernRuleBase
{
    public override string Key => "QG-JS-SML-0426";
    public override string Name => "A prefix test should say so";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("===" or "==" or "!==" or "!="))
                continue;
            var call = binary.Children.FirstOrDefault(c => c.Kind == NodeKind.Invocation
                                                           && SyntaxQuery.InvokedName(c) == "indexOf");
            var other = binary.Children.FirstOrDefault(c => c != call);
            if (call is null || other?.Text != "0" || other.Kind != NodeKind.NumberLiteral)
                continue;

            context.Report(binary, "Finding a position and then checking it is zero is a test for a "
                                   + "prefix written the long way. Say it with the prefix test: it "
                                   + "stops at the first difference instead of scanning the whole "
                                   + "string.");
        }
    }
}

public sealed class JsGlobalReplaceRule : JsTsModernRuleBase
{
    public override string Key => "QG-JS-SML-0427";
    public override string Name => "Replacing everywhere should say everywhere";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (SyntaxQuery.InvokedName(call) != "replace")
                continue;
            var pattern = SyntaxQuery.Arguments(call).FirstOrDefault();
            // the tokenizer carries a regular expression's flags back inside the pattern
            if (pattern is null || !pattern.Text.Contains("(?", StringComparison.Ordinal)
                || !pattern.Text.Contains('g'))
                continue;

            context.Report(call, "This replaces every match, and says so only through a flag on the "
                                 + "pattern. The method that replaces everywhere states it in its "
                                 + "name, and takes a plain string when the pattern is not needed.");
        }
    }
}

public sealed class JsThisCopiedToVariableRule : JsTsModernRuleBase
{
    public override string Key => "QG-JS-SML-0428";
    public override string Name => "The surrounding object should not be copied into a name";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            if (assignment.Text != "=")
                continue;
            if (assignment.ChildAt(1)?.Text != "this" || assignment.ChildAt(0) is not { } target)
                continue;
            if (target.Kind != NodeKind.Identifier)
                continue;

            context.Report(assignment, $"'{target.Text}' is a second name for the object this code is "
                                       + "running on, kept because an inner function would otherwise "
                                       + "have its own. An arrow function keeps the original, so the "
                                       + "object has one name again.");
        }
    }
}

public sealed class JsNestedConditionalRule : JsTsModernRuleBase
{
    public override string Key => "QG-JS-SML-0429";
    public override string Name => "A conditional expression should not contain another";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var conditional in context.Root.OfKind(NodeKind.Conditional))
        {
            if (conditional.Parent is null)
                continue;
            for (var node = conditional.Parent; node != null; node = node.Parent)
            {
                if (node.Kind is NodeKind.FunctionDeclaration or NodeKind.Lambda or NodeKind.Block)
                    break;
                if (node.Kind != NodeKind.Conditional)
                    continue;
                context.Report(conditional, "One conditional expression is written inside another, so "
                                            + "the reader has to hold two unfinished questions at once "
                                            + "to work out which value comes back. Lift the inner one "
                                            + "out, or use a statement.");
                break;
            }
        }
    }
}

public sealed class JsBuiltinWithoutProtocolRule : JsTsModernRuleBase
{
    private static readonly string[] Builtins =
    [
        "fs", "path", "http", "https", "crypto", "os", "url", "util", "child_process", "stream",
        "buffer", "events", "net", "zlib", "assert", "querystring", "readline", "worker_threads"
    ];

    public override string Key => "QG-JS-SML-0430";
    public override string Name => "A platform module should be named as one";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (SyntaxQuery.InvokedName(call) != "require")
                continue;
            var argument = SyntaxQuery.Arguments(call).FirstOrDefault();
            if (argument is not { Kind: NodeKind.StringLiteral })
                continue;
            var module = argument.Text.Trim('"', '\'');
            if (!Builtins.Contains(module, StringComparer.Ordinal))
                continue;

            context.Report(call, $"'{module}' is a module the platform provides, and asked for by a "
                                 + "bare name it can be shadowed by a package of the same name "
                                 + "installed alongside. The node: prefix says which one is meant.");
        }
    }
}

public sealed class JsGlobalNumberFunctionRule : JsTsModernRuleBase
{
    private static readonly string[] Globals = ["parseInt", "parseFloat", "isNaN", "isFinite"];

    public override string Key => "QG-JS-SML-0431";
    public override string Name => "The number functions should be reached through Number";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!Globals.Contains(name, StringComparer.Ordinal))
                continue;
            // already qualified: 'Number.isNaN' is the form this rule asks for
            if (SyntaxQuery.Receiver(call).Length > 0)
                continue;

            context.Report(call, $"The global '{name}' converts its argument before deciding, so it "
                                 + $"answers yes to things that are not numbers at all. Number.{name} "
                                 + "asks the question about the value it was given.");
        }
    }
}
