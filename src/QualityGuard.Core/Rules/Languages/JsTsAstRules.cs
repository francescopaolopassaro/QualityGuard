using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// JavaScript and TypeScript on the syntax tree.
///
/// The language forgives almost everything at parse time, so its defects surface at run time and only
/// on the path nobody exercised: a comparison that coerces, a closure that captured the loop variable,
/// a duplicated key that silently replaced the first one. All of them are visible in the tree, which
/// is why these rules live here rather than in the token-based set.
/// </summary>
public static class JsTsAstRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JsBooleanReturnedThroughIfRule(),
        new JsWithStatementRule(),
        new JsDebuggerStatementRule(),
        new JsBlockingDialogRule(),
        new JsLooseEqualityRule(),
        new JsArrayConstructorRule(),
        new JsPrimitiveWrapperRule(),
        new JsDuplicateMemberRule(),
        new JsDuplicateParameterRule(),
        new JsFunctionInsideLoopRule(),
        new JsUnfilteredForInRule(),
        new JsDefaultParameterNotLastRule(),
        new JsSwitchFallthroughRule()
    ];
}

public abstract class JsAstRuleBase : RuleBase
{
    public override string[] Languages => ["js", "ts"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasPreciseTree(IRuleContext context) => context.Tree.HasDedicatedParser;


    /// <summary>
    /// Constructions, whatever shape the dialect gives them: C# and Java build an ObjectCreation,
    /// while the JavaScript grammar reads `new` as a prefix operator over a call.
    /// </summary>
    protected static IEnumerable<(SyntaxNode Node, string Type)> Constructions(SyntaxNode root)
    {
        foreach (var creation in root.OfKind(NodeKind.ObjectCreation))
            yield return (creation, creation.Text);

        foreach (var unary in root.OfKind(NodeKind.Unary))
        {
            if (unary.Text != "new")
                continue;
            var target = unary.ChildAt(0);
            if (target == null)
                continue;
            var name = target.Kind == NodeKind.Invocation ? SyntaxQuery.InvokedName(target) : target.Text;
            if (name.Length > 0)
                yield return (unary, name);
        }
    }


    /// <summary>
    /// True when the signature destructures a parameter. The pieces of a pattern are separate nodes
    /// and repeat their names in the type annotation, so neither their order nor their uniqueness
    /// says anything — and the pattern often sits several lines below the declaration.
    /// </summary>
    protected static bool HasDestructuredParameter(SyntaxNode function, string[] lines)
    {
        foreach (var parameter in SyntaxQuery.Parameters(function))
        {
            if (parameter.Text.Length == 0 || parameter.Text.Contains('{') || parameter.Text.Contains('['))
                return true;
        }
        // the pattern may sit lines below the declaration, so the list itself is what is read — its
        // tokens stop at the closing parenthesis and never reach the brace of the body
        var list = function.FirstChild(NodeKind.ParameterList);
        var text = list?.SourceText() ?? string.Empty;
        return text.Contains('{') || text.Contains("...");
    }

    /// <summary>The condition of a branch or a loop: the child that is not the body.</summary>
    protected static SyntaxNode? Condition(SyntaxNode owner)
        => owner.Children.FirstOrDefault(c => c.Kind is not (NodeKind.Block or NodeKind.Else
            or NodeKind.ParameterList));
}

public sealed class JsBooleanReturnedThroughIfRule : JsAstRuleBase
{
    public override string Key => "QG-JS-SML-0358";
    public override string Name => "A condition that is already a boolean should be returned directly";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var branch in context.Root.OfKind(NodeKind.If))
        {
            var elseBranch = branch.FirstChild(NodeKind.Else);
            if (elseBranch == null)
                continue;
            if (ReturnedLiteral(branch.FirstChild(NodeKind.Block)) is not { } first
                || ReturnedLiteral(elseBranch.FirstChild(NodeKind.Block) ?? elseBranch) is not { } second)
                continue;
            if (first == second)
                continue; // both branches return the same thing: a different defect, reported elsewhere

            context.Report(branch, "This returns true in one branch and false in the other, so it is the "
                                   + "condition itself. Return the condition — negated if needed — and "
                                   + "the reader sees the rule instead of the plumbing around it.");
        }
    }

    /// <summary>The boolean literal a block returns, when that is all it does.</summary>
    private static string? ReturnedLiteral(SyntaxNode? block)
    {
        if (block == null)
            return null;
        var statements = block.Kind == NodeKind.Block ? block.Children : [block];
        if (statements.Count != 1 || statements[0].Kind != NodeKind.Jump)
            return null;
        var value = statements[0].ChildAt(0);
        return value is { Kind: NodeKind.BooleanLiteral } ? value.Text : null;
    }
}

public sealed class JsWithStatementRule : JsAstRuleBase
{
    public override string Key => "QG-JS-BUG-0112";
    public override string Name => "The with statement should not be used";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            if (token.Text != "with" || token.Kind == Tokenization.TokenKind.String)
                continue;
            // `import x from "y" with { type: "json" }` is an import attribute, not the statement
            if (i + 1 >= tokens.Count || tokens[i + 1].Text != "(")
                continue;

            context.Report("Inside a with block, a name can come from the object or from the scope, and "
                           + "which one wins is decided at run time. Reading the code no longer tells "
                           + "you what it does, and strict mode rejects it outright. Assign the object "
                           + "to a variable and use it explicitly.", token.Line);
        }
    }
}

public sealed class JsDebuggerStatementRule : JsAstRuleBase
{
    public override string Key => "QG-JS-BUG-0113";
    public override string Name => "A debugger statement should not be shipped";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (token.Text != "debugger" || token.Kind == Tokenization.TokenKind.String)
                continue;

            context.Report("A debugger statement stops the application whenever a browser has its tools "
                           + "open — for the user, the page simply freezes. Remove it before the change "
                           + "leaves your machine.", token.Line);
        }
    }
}

public sealed class JsBlockingDialogRule : JsAstRuleBase
{
    private static readonly string[] Dialogs = ["alert", "confirm", "prompt"];

    public override string Key => "QG-JS-SML-0359";
    public override string Name => "A blocking dialog should not be used";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!Dialogs.Contains(name, StringComparer.Ordinal))
                continue;
            var receiver = SyntaxQuery.Receiver(call);
            if (receiver.Length > 0 && receiver is not ("window" or "globalThis" or "self"))
                continue;

            context.Report(call, $"'{name}' freezes the page until the user answers, cannot be styled or "
                                 + "tested, and is blocked outright in some contexts. Use the dialog of "
                                 + "the application.");
        }
    }
}

public sealed class JsLooseEqualityRule : JsAstRuleBase
{
    public override string Key => "QG-JS-BUG-0114";
    public override string Name => "Comparisons should not coerce their operands";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!="))
                continue;
            // `x == null` is the established way of covering null and undefined at once
            if (comparison.Children.Any(c => c.Kind == NodeKind.NullLiteral
                                             || (c.Kind == NodeKind.Identifier && c.Text == "undefined")))
                continue;

            context.Report(comparison, $"'{comparison.Text}' converts its operands before comparing, so "
                                       + "'0' equals 0 and an empty array equals false. Use "
                                       + $"'{comparison.Text}=' and convert explicitly where a conversion "
                                       + "is really wanted.");
        }
    }
}

public sealed class JsArrayConstructorRule : JsAstRuleBase
{
    public override string Key => "QG-JS-BUG-0115";
    public override string Name => "An array should be built with a literal";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var (creation, type) in Constructions(context.Root))
        {
            if (type != "Array")
                continue;
            var call = creation.Kind == NodeKind.Unary ? creation.ChildAt(0)! : creation;
            if (SyntaxQuery.Arguments(call).Count != 1)
                continue;

            context.Report(creation, "new Array(n) creates an array of n empty slots, while new Array(n, m) "
                                     + "creates one holding those two values: the meaning changes with the "
                                     + "number of arguments. Write [] and push, or Array.from when a length "
                                     + "is really needed.");
        }
    }
}

public sealed class JsPrimitiveWrapperRule : JsAstRuleBase
{
    private static readonly string[] Wrappers = ["Number", "String", "Boolean", "Symbol", "BigInt"];

    public override string Key => "QG-JS-BUG-0116";
    public override string Name => "A primitive should not be wrapped in an object";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var (creation, type) in Constructions(context.Root))
        {
            if (!Wrappers.Contains(type, StringComparer.Ordinal))
                continue;

            context.Report(creation, $"new {type}(...) produces an object, not a primitive: it is "
                                     + "always truthy, it fails a strict comparison against the value it "
                                     + $"holds, and typeof answers \"object\". Call {type}(...) "
                                     + "without new to convert.");
        }
    }
}

public sealed class JsDuplicateMemberRule : JsAstRuleBase
{
    public override string Key => "QG-JS-BUG-0117";
    public override string Name => "A class or object literal should not declare a member twice";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var owner in context.Root.OfKind(NodeKind.ClassDeclaration, NodeKind.ObjectInitializer,
                     NodeKind.AnonymousObject, NodeKind.ListLiteral))
        {
            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var member in Members(owner))
            {
                if (member.Name.Length == 0)
                    continue;
                if (seen.TryGetValue(member.Name, out var first))
                {
                    context.Report($"'{member.Name}' is declared again here, so the definition on line "
                                   + $"{first} is replaced without a word from the runtime. One of the two "
                                   + "was meant to have a different name.", member.Line);
                    continue;
                }
                seen[member.Name] = member.Line;
            }
        }
    }

    private static IEnumerable<(string Name, int Line)> Members(SyntaxNode owner)
    {
        foreach (var child in owner.Children)
        {
            switch (child.Kind)
            {
                case NodeKind.FunctionDeclaration:
                case NodeKind.PropertyDeclaration:
                case NodeKind.FieldDeclaration:
                    yield return (child.Text, child.Line);
                    break;
                case NodeKind.Block:
                    foreach (var member in Members(child))
                        yield return member;
                    break;
                // an object literal writes its members as `key : value` assignments
                case NodeKind.Assignment when child.Text == ":" && child.ChildAt(0) is { } key:
                    yield return (key.Text, child.Line);
                    break;
            }
        }
    }
}

public sealed class JsDuplicateParameterRule : JsAstRuleBase
{
    public override string Key => "QG-JS-BUG-0118";
    public override string Name => "A function should not declare the same parameter twice";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        var lines = context.File.Content.Split((char)10);

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            if (HasDestructuredParameter(function, lines))
                continue;

            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var parameter in SyntaxQuery.Parameters(function))
            {
                if (parameter.Text.Length == 0 || seen.Add(parameter.Text))
                    continue;

                context.Report(parameter, $"'{parameter.Text}' is declared twice in this signature. Only "
                                          + "the last one is reachable, so the argument the caller passes "
                                          + "for the first is silently unreachable — and strict mode "
                                          + "rejects the function outright.");
            }
        }
    }
}

public sealed class JsFunctionInsideLoopRule : JsAstRuleBase
{
    public override string Key => "QG-JS-BUG-0119";
    public override string Name => "A function declared in a loop should not capture the loop variable";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            var counters = loop.Children
                .Where(c => c.Kind == NodeKind.VariableDeclaration)
                .SelectMany(c => c.Tokens.Select(t => t.Text))
                .ToHashSet(StringComparer.Ordinal);
            // `let` and `const` give each iteration its own binding, so the capture is safe
            if (counters.Contains("let") || counters.Contains("const"))
                continue;
            var declared = loop.Children
                .Where(c => c.Kind == NodeKind.VariableDeclaration)
                .Select(c => c.Text)
                .Where(name => name.Length > 0)
                .ToHashSet(StringComparer.Ordinal);
            if (declared.Count == 0)
                continue;

            var body = loop.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            foreach (var function in body.OfKind(NodeKind.Lambda, NodeKind.FunctionDeclaration,
                         NodeKind.LocalFunction))
            {
                if (!function.OfKind(NodeKind.Identifier).Any(i => declared.Contains(i.Text)))
                    continue;

                context.Report(function, "This function is created inside the loop and reads the loop "
                                         + "variable, which var shares across every iteration: by the time "
                                         + "the function runs, the variable holds its final value. Declare "
                                         + "the variable with let, or pass the value as an argument.");
                break;
            }
        }
    }
}

public sealed class JsUnfilteredForInRule : JsAstRuleBase
{
    public override string Key => "QG-JS-BUG-0120";
    public override string Name => "A for-in loop should filter inherited properties";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            // `for (k in obj)` keeps `in` as a child identifier, next to the declaration
            if (loop.Text != "for" || !loop.Children.Any(c => c.Kind == NodeKind.Identifier && c.Text == "in"))
                continue;
            var body = loop.FirstChild(NodeKind.Block);
            if (body == null)
                continue;
            // the loop is filtered when its body starts with a guard, or uses hasOwnProperty anywhere
            if (body.Tokens.Any(t => t.Text is "hasOwnProperty" or "hasOwn" or "getOwnPropertyNames"))
                continue;
            if (body.Children.FirstOrDefault() is { Kind: NodeKind.If })
                continue;

            context.Report(loop, "for-in walks the inherited properties too, so anything added to the "
                                 + "prototype — by a library, by a polyfill — appears in the loop. Use "
                                 + "Object.keys, or guard the body with hasOwnProperty.");
        }
    }
}

public sealed class JsDefaultParameterNotLastRule : JsAstRuleBase
{
    public override string Key => "QG-JS-SML-0360";
    public override string Name => "Parameters with a default value should come last";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        var lines = context.File.Content.Split((char)10);

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var parameters = SyntaxQuery.Parameters(function).ToList();
            if (HasDestructuredParameter(function, lines))
                continue;
            var lastWithDefault = -1;
            for (var i = 0; i < parameters.Count; i++)
            {
                if (HasDefault(parameters[i]))
                {
                    lastWithDefault = i;
                    continue;
                }
                if (lastWithDefault < 0 || IsOptional(parameters[i], lines))
                    continue;

                context.Report(parameters[i], $"'{parameters[i].Text}' is required but comes after a "
                                              + "parameter that has a default, so every caller has to pass "
                                              + "the default explicitly just to reach it. Move the "
                                              + "defaults to the end.");
                break;
            }
        }
    }

    /// <summary>
    /// A default is written as `name = value`; the parser keeps the value as a child of the parameter
    /// rather than as an assignment, so the presence of a value is what identifies it.
    /// </summary>
    /// <summary>
    /// TypeScript marks an optional parameter with a question mark after its name. The type parser
    /// consumes the marker, so the declaration is read from the source line instead.
    /// </summary>
    private static bool IsOptional(SyntaxNode parameter, string[] lines)
    {
        if (HasDefault(parameter))
            return true;
        var line = parameter.Line - 1 < lines.Length ? lines[parameter.Line - 1] : string.Empty;
        return line.Contains(parameter.Text + "?", StringComparison.Ordinal)
               || line.Contains("...", StringComparison.Ordinal);
    }

    private static bool HasDefault(SyntaxNode parameter)
        => parameter.OfKind(NodeKind.Assignment).Any()
           || parameter.Children.Any(c => c.Kind is NodeKind.NumberLiteral or NodeKind.StringLiteral
               or NodeKind.BooleanLiteral or NodeKind.NullLiteral or NodeKind.ListLiteral
               or NodeKind.ObjectInitializer or NodeKind.Invocation or NodeKind.Identifier
               or NodeKind.MemberSelect or NodeKind.Unary);
}

public sealed class JsSwitchFallthroughRule : JsAstRuleBase
{
    public override string Key => "QG-JS-BUG-0121";
    public override string Name => "A switch case should end with a jump";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var match in context.Root.OfKind(NodeKind.Match))
        {
            var sections = match.OfKind(NodeKind.SwitchSection, NodeKind.MatchCase).ToList();
            for (var i = 0; i < sections.Count - 1; i++)
            {
                var section = sections[i];
                // an empty case deliberately shares the body of the next one
                if (section.Children.Count == 0)
                    continue;
                if (EndsWithJump(section))
                    continue;

                context.Report(section, "This case runs into the next one, so the code below executes as "
                                        + "well. When that is intended it has to be written down, because "
                                        + "the next reader will assume it is a missing break.");
            }
        }
    }

    private static bool EndsWithJump(SyntaxNode section)
    {
        var last = section.Children.LastOrDefault();
        if (last == null)
            return false;
        if (last.Kind == NodeKind.Jump)
            return true;
        // the body is often a block: a break, a return or a throw anywhere in it means the case
        // cannot reach the next one by accident
        return last.DescendantsAndSelf().Any(n => n.Kind == NodeKind.Jump
                                                  || n.Text.StartsWith("throw", StringComparison.Ordinal));
    }
}
