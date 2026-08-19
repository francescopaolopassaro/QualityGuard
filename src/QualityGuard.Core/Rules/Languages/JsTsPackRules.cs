using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// A package of JavaScript and TypeScript checks ported in one pass. What they have in common is
/// that each one is invisible at review time and obvious at run time: a test that silences the whole
/// suite, a regular expression that anchors less than it appears to, a `this` that means the module
/// in one runtime and the global object in another.
/// </summary>
public static class JsTsPackRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JsGlobalThisRule(),
        new JsApplyInsteadOfSpreadRule(),
        new JsUnanchoredAlternativesRule(),
        new JsInconsistentReturnTypeRule(),
        new JsModuleKeywordRule(),
        new JsExclusiveTestRule(),
        new JsSkippedTestRule(),
        new JsListKeyFromIndexRule()
    ];
}

public abstract class JsPackRuleBase : RuleBase
{
    public override string[] Languages => ["js", "ts"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;
}

public sealed class JsGlobalThisRule : JsPackRuleBase
{
    public override string Key => "QG-JS-SML-0083";
    public override string Name => "The global 'this' should not be used";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var access in context.Root.OfKind(NodeKind.MemberSelect))
        {
            if (access.ChildAt(0) is not { Kind: NodeKind.Identifier, Text: "this" })
                continue;
            // inside a class or a function 'this' is the receiver, which is the ordinary use
            if (access.Ancestor(NodeKind.ClassDeclaration) != null
                || SyntaxQuery.EnclosingFunction(access) != null)
                continue;

            context.Report("At the top level 'this' is not the object anyone means: it is the module "
                           + "in one runtime, the global object in another and undefined under strict "
                           + "mode. Name what you want instead.", access.Range.StartLine);
        }
    }
}

public sealed class JsApplyInsteadOfSpreadRule : JsPackRuleBase
{
    public override string Key => "QG-JS-SML-0203";
    public override Severity Severity => Severity.Minor;
    public override string Name => "Spread should be used instead of apply";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (SyntaxQuery.InvokedName(call) != "apply")
                continue;
            var arguments = SyntaxQuery.Arguments(call);
            if (arguments.Count != 2)
                continue;
            // 'apply' with a real receiver rebinds 'this', which spread cannot do
            var first = arguments[0];
            if (first.Kind is not NodeKind.NullLiteral
                && first is not { Kind: NodeKind.Identifier, Text: "null" or "undefined" })
                continue;

            context.Report("This calls the function through 'apply' only to spread an array over its "
                           + "parameters. The spread syntax says that directly, and it keeps working "
                           + "when the function is later given a different receiver.",
                call.Range.StartLine);
        }
    }
}

public sealed class JsUnanchoredAlternativesRule : JsPackRuleBase
{
    public override string Key => "QG-JS-BUG-0061";
    public override IssueKind Kind => IssueKind.Bug;
    public override string Name => "Alternatives should be grouped when the pattern is anchored";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (token.Kind != Tokenization.TokenKind.String)
                continue;
            var pattern = token.Text;
            if (!pattern.Contains('|'))
                continue;
            // the defect is an anchor that binds to one alternative only: '^a|b$' matches anything
            // that starts with a, and anything that ends with b, which is not what it reads as
            var anchoredStart = pattern.StartsWith('^') && !pattern.StartsWith("^(", StringComparison.Ordinal);
            var anchoredEnd = pattern.EndsWith('$') && !pattern.EndsWith(")$", StringComparison.Ordinal);
            if (!anchoredStart && !anchoredEnd)
                continue;
            // a group already around the alternatives is the correct spelling
            if (pattern.Contains("(?:", StringComparison.Ordinal) && pattern.IndexOf('|') > pattern.IndexOf("(?:", StringComparison.Ordinal))
                continue;

            context.Report("The anchor binds to one alternative, not to all of them: this matches "
                           + "anything that starts with the first branch and anything that ends with "
                           + "the last. Put the alternatives in a group so the anchors apply to the "
                           + "whole pattern.", token.Line);
        }
    }
}

public sealed class JsInconsistentReturnTypeRule : JsPackRuleBase
{
    public override string Key => "QG-JS-SML-0111";
    public override string Name => "A function should always answer with the same kind of value";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var returned = function.OfKind(NodeKind.Jump)
                .Where(j => j.Text == "return" && j.ChildAt(0) != null)
                .Where(j => SyntaxQuery.EnclosingFunction(j) == function)
                .Select(j => j.ChildAt(0)!.Kind)
                .Where(k => k is NodeKind.StringLiteral or NodeKind.NumberLiteral
                    or NodeKind.BooleanLiteral or NodeKind.ArrayCreation or NodeKind.ListLiteral)
                .Distinct()
                .ToList();
            if (returned.Count < 2)
                continue;

            context.Report($"'{function.Text}' answers with {returned.Count} different kinds of value "
                           + "depending on the path taken. Every caller then has to test what came "
                           + "back before using it, and the one that does not fails somewhere else.",
                function.Range.StartLine);
        }
    }
}

public sealed class JsModuleKeywordRule : JsPackRuleBase
{
    public override string Key => "QG-JS-SML-0127";
    public override Severity Severity => Severity.Minor;
    public override string[] Languages => ["ts"];
    public override string Name => "A namespace should be declared with 'namespace', not 'module'";

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Text != "module" || tokens[i + 1].Kind != Tokenization.TokenKind.Identifier)
                continue;
            // 'module.exports' and 'module' as a value are the other language's module, not a
            // declaration: the keyword form is followed by a name and then a block
            if (i + 2 >= tokens.Count || tokens[i + 2].Text != "{")
                continue;

            context.Report("'module' means two different things depending on the file it is read in. "
                           + "'namespace' says exactly this one, and leaves the word free for the "
                           + "module system.", tokens[i].Line);
        }
    }
}

public sealed class JsExclusiveTestRule : JsPackRuleBase
{
    public override string Key => "QG-JS-BUG-0070";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string Name => "An exclusive test should not be committed";

    public override void Execute(IRuleContext context)
    {
        if (!LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var chain = SyntaxQuery.InvokedDottedName(call);
            if (!chain.EndsWith(".only", StringComparison.Ordinal))
                continue;
            var subject = chain[..^5];
            if (subject is not ("describe" or "it" or "test" or "context" or "suite" or "fit" or "fdescribe"))
                continue;

            context.Report($"'{chain}' runs this test and silences every other one in the file. On a "
                           + "developer's machine that is the point; committed, it turns the suite "
                           + "green while almost nothing is being checked.", call.Range.StartLine);
        }
    }
}

public sealed class JsSkippedTestRule : JsPackRuleBase
{
    public override string Key => "QG-JS-SML-0058";
    public override string Name => "A skipped test should say why it is skipped";

    public override void Execute(IRuleContext context)
    {
        if (!LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var chain = SyntaxQuery.InvokedDottedName(call);
            var skipped = chain.EndsWith(".skip", StringComparison.Ordinal)
                          || chain is "xit" or "xdescribe" or "xtest";
            if (!skipped)
                continue;
            // a note next to it is the reason the rule asks for
            var line = call.Range.StartLine;
            if (context.Tokens.Any(t => t.Kind == Tokenization.TokenKind.Comment
                                        && t.Line >= line - 2 && t.Line <= line + 1))
                continue;

            context.Report("This test is disabled and nothing says why or until when. A skipped test "
                           + "with no note is indistinguishable from one everybody forgot, and it "
                           + "stays skipped for years.", line);
        }
    }
}

public sealed class JsListKeyFromIndexRule : JsPackRuleBase
{
    public override string Key => "QG-JS-SML-0168";
    public override string Name => "A list item should be keyed by identity, not by position";

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 3; i++)
        {
            // 'key={index}' or 'key={i}' written in markup: the position, not the item
            if (tokens[i].Text != "key" || tokens[i + 1].Text != "=" || tokens[i + 2].Text != "{")
                continue;
            var value = tokens[i + 3].Text;
            if (value is not ("index" or "i" or "idx" or "position"))
                continue;

            context.Report("Keying a list item by its position tells the framework that the item at "
                           + "position two is the same item after a sort or a removal, which it is "
                           + "not: state stays behind on the wrong row. Key by something that "
                           + "identifies the item.", tokens[i].Line);
        }
    }
}
