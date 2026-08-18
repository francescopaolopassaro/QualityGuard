using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// The second JavaScript and TypeScript wave: expressions that the language accepts and that mean
/// something other than what they read as — a bitwise operator standing in for a logical one, a sort
/// with no comparator, a template placeholder inside a quoted string, an assignment to a name the
/// runtime owns.
/// </summary>
public static class JsTsSemanticRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JsSwitchLabelRule(),
        new JsThisAliasRule(),
        new JsBitwiseInConditionRule(),
        new JsAssignmentToSpecialIdentifierRule(),
        new JsBuiltInOverrideRule(),
        new JsSetterReturningValueRule(),
        new JsIndexOfPositiveRule(),
        new JsSortWithoutComparatorRule(),
        new JsGeneratorWithoutYieldRule(),
        new JsThrowLiteralRule(),
        new JsPlaceholderInPlainStringRule(),
        new JsEmptyDestructuringRule(),
        new JsNegatedMembershipRule(),
        new JsNewSymbolRule(),
        new JsBooleanLiteralComparisonRule(),
        // QG-JS-SML-0362 was "a labelled statement should be a loop". The parser leaves a label
        // as a name and a colon, which in TypeScript is also a destructuring rename, a type
        // annotation and a generic argument list broken over lines. It reported all three on a real
        // corpus, so the rule is gone and its number stays retired.
        new JsObjectConstructorRule()
    ];
}

public abstract class JsTsSemanticRuleBase : RuleBase
{
    public override string[] Languages => ["js", "ts"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    /// <summary>
    /// Object creations, in both shapes JavaScript produces: a real ObjectCreation, and the unary
    /// "new" the parser builds over a call.
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
            var name = target.Kind == NodeKind.Invocation
                ? SyntaxQuery.InvokedName(target)
                : SyntaxQuery.SimpleName(target);
            if (name.Length > 0)
                yield return (unary, name);
        }
    }

    /// <summary>
    /// The labels of a block, as (name, line, the statement they label). The parser does not fold a
    /// label into one node: it leaves the name and the colon as two statements, so a label is found
    /// by that pair and the sibling that follows it.
    /// </summary>
    protected static IEnumerable<(string Name, int Line, SyntaxNode? Labelled)> Labels(SyntaxNode block)
    {
        var children = block.Children;
        for (var i = 0; i + 1 < children.Count; i++)
        {
            if (!IsSingle(children[i], NodeKind.Identifier) || !IsSingle(children[i + 1], NodeKind.Unknown))
                continue;
            if (children[i + 1].Children[0].Text != ":")
                continue;
            var labelled = i + 2 < children.Count ? children[i + 2] : null;
            yield return (children[i].Children[0].Text, children[i].Range.StartLine, labelled);
        }
    }

    private static bool IsSingle(SyntaxNode statement, NodeKind kind)
        => statement is { Kind: NodeKind.ExpressionStatement, Children.Count: 1 }
           && statement.Children[0].Kind == kind;

    protected static string SourceLine(IRuleContext context, int line)
    {
        var lines = LanguageRuleSupport.Lines(context);
        return line - 1 >= 0 && line - 1 < lines.Length ? lines[line - 1] : string.Empty;
    }
}

public sealed class JsSwitchLabelRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-BUG-0122";
    public override string Name => "A switch should not contain a label of its own";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var match in context.Root.OfKind(NodeKind.Match))
        {
            foreach (var section in match.OfKind(NodeKind.Block, NodeKind.SwitchSection))
            {
                var children = section.Children;
                for (var i = 1; i < children.Count; i++)
                {
                    // the name has to follow a jump — the end of a finished case. A case that lists
                    // several constants over several lines leaves the same shape, and there the name
                    // is a real case label.
                    if (children[i - 1].Kind != NodeKind.Jump)
                        continue;
                    foreach (var (name, line, _) in Labels(section))
                    {
                        if (line != children[i].Range.StartLine)
                            continue;
                        context.Report($"'{name}:' reads exactly like a case but is a jump target, so "
                                       + "the statements under it belong to the section before it and "
                                       + "never run on their own. A misspelled 'default' becomes a "
                                       + "label like this one, and nothing complains.", line);
                    }
                }
            }
        }
    }
}

public sealed class JsBitwiseInConditionRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-BUG-0123";
    public override string Name => "A condition should not use a bitwise operator";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var branch in context.Root.OfKind(NodeKind.If, NodeKind.Loop, NodeKind.Conditional))
        {
            var condition = branch.ChildAt(0);
            if (condition is not { Kind: NodeKind.Binary })
                continue;
            if (condition.Text is not ("&" or "|"))
                continue;

            var intended = condition.Text == "&" ? "&&" : "||";
            context.Report($"'{condition.Text}' combines the two values bit by bit and produces a "
                           + "number, so the branch is taken when that number is not zero — which is "
                           + $"not the question this code is asking. Write '{intended}'.",
                condition.Range.StartLine);
        }
    }
}

public sealed class JsAssignmentToSpecialIdentifierRule : JsTsSemanticRuleBase
{
    private static readonly string[] Reserved = ["undefined", "NaN", "Infinity", "eval", "arguments"];

    public override string Key => "QG-JS-BUG-0124";
    public override string Name => "A name owned by the runtime should not be assigned";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            if (!assignment.Text.EndsWith('=') || assignment.Text is "==" or "===" or "!=" or "!==")
                continue;
            var target = assignment.ChildAt(0);
            if (target is not { Kind: NodeKind.Identifier })
                continue;
            if (!Reserved.Contains(target.Text))
                continue;
            // 'const { arguments: args } = call' renames a property; it assigns nothing to the name
            var prefix = SourceLine(context, assignment.Range.StartLine);
            var equals = prefix.IndexOf('=');
            if (equals > 0)
                prefix = prefix[..equals];
            if (prefix.Contains('{') || prefix.Contains('[') || prefix.Contains(':'))
                continue;

            context.Report($"'{target.Text}' belongs to the runtime. In strict mode and inside a module "
                           + "this throws; anywhere else the assignment is quietly ignored, so the code "
                           + "that follows works with a value it never received.",
                assignment.Range.StartLine);
        }
    }
}

public sealed class JsBuiltInOverrideRule : JsTsSemanticRuleBase
{
    private static readonly string[] BuiltIns =
    [
        "Object", "Array", "String", "Number", "Boolean", "Function", "Date", "RegExp", "Error",
        "Math", "JSON", "Promise", "Map", "Set", "Symbol", "Proxy", "Reflect"
    ];

    public override string Key => "QG-JS-BUG-0125";
    public override string Name => "A built-in should not be replaced or extended";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            if (assignment.Text != "=")
                continue;
            var target = assignment.ChildAt(0);
            if (target == null)
                continue;

            var dotted = SyntaxQuery.DottedName(target);
            var root = dotted.Split('.')[0];
            if (!BuiltIns.Contains(root))
                continue;
            // only the built-in itself and its prototype: a property on your own instance is fine
            if (dotted != root && !dotted.StartsWith(root + ".prototype", StringComparison.Ordinal))
                continue;

            context.Report($"Changing '{dotted}' changes it for every library in the page, including the "
                           + "ones that assume the standard behaviour. A property added to a prototype "
                           + "also turns up in every for-in loop over an object of that type.",
                assignment.Range.StartLine);
        }
    }
}

public sealed class JsSetterReturningValueRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-BUG-0126";
    public override string Name => "A setter should not return a value";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var accessor in context.Root.OfKind(NodeKind.Accessor, NodeKind.FunctionDeclaration))
        {
            if (!IsSetter(accessor, context))
                continue;
            var body = accessor.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            foreach (var jump in body.OfKind(NodeKind.Jump))
            {
                if (jump.Text != "return" || jump.Children.Count == 0)
                    continue;
                // an Accessor is not a function node, so the ownership question is asked directly
                if (jump.Ancestors().TakeWhile(a => a != accessor)
                    .Any(a => a.Kind is NodeKind.FunctionDeclaration or NodeKind.Lambda))
                    continue;

                context.Report("A setter answers nothing: the value of an assignment is always the value "
                               + "assigned, whatever the setter returns. Anyone reading this expects the "
                               + "returned value to reach the caller, and it never does.",
                    jump.Range.StartLine);
            }
        }
    }

    private static bool IsSetter(SyntaxNode node, IRuleContext context)
    {
        if (node.Kind == NodeKind.Accessor)
            return node.Text == "set";
        var line = SourceLine(context, node.Range.StartLine).TrimStart();
        return line.StartsWith("set ", StringComparison.Ordinal);
    }
}

public sealed class JsIndexOfPositiveRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-BUG-0127";
    public override string Name => "A search result should be tested against zero";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not (">" or "<="))
                continue;
            var call = comparison.ChildAt(0);
            if (call is not { Kind: NodeKind.Invocation })
                continue;
            if (SyntaxQuery.InvokedName(call) is not ("indexOf" or "lastIndexOf" or "findIndex"
                or "findLastIndex" or "search"))
                continue;
            var literal = comparison.ChildAt(1);
            if (literal is not { Kind: NodeKind.NumberLiteral } || literal.Text != "0")
                continue;

            var replacement = comparison.Text == ">" ? ">= 0" : "< 0";
            context.Report("The search answers 0 when the match is at the very beginning, and this "
                           + $"comparison reads that as 'not found'. Use {replacement}, or includes() "
                           + "when only presence matters.", comparison.Range.StartLine);
        }
    }
}

public sealed class JsSortWithoutComparatorRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-BUG-0128";
    public override string Name => "sort should be given a comparison function";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "sort", "toSorted"))
        {
            if (SyntaxQuery.Arguments(call).Count > 0)
                continue;
            var receiver = call.ChildAt(0)?.ChildAt(0);
            if (receiver == null)
                continue;
            // only a receiver that is visibly an array: anything else may be a sort of your own
            var isArray = receiver.Kind == NodeKind.ListLiteral
                          || (receiver.Kind == NodeKind.Invocation
                              && SyntaxQuery.InvokedName(receiver) is "filter" or "map" or "concat"
                                  or "slice" or "split" or "flat" or "from" or "keys" or "values");
            if (!isArray)
                continue;

            context.Report("Without a comparison function the elements are converted to strings and "
                           + "compared as text, so 10 sorts before 9 and every number-shaped list comes "
                           + "back in an order nobody asked for. Pass (a, b) => a - b, or the "
                           + "comparison the data needs.", call.Range.StartLine);
        }
    }
}

public sealed class JsGeneratorWithoutYieldRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-BUG-0129";
    public override string Name => "A generator should yield";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration, NodeKind.Lambda))
        {
            var line = SourceLine(context, function.Range.StartLine);
            if (!line.Contains("function*", StringComparison.Ordinal)
                && !line.Contains("function *", StringComparison.Ordinal)
                && !line.Contains("*" + function.Text + "(", StringComparison.Ordinal))
                continue;

            var body = function.FirstChild(NodeKind.Block);
            if (body == null)
                continue;
            if (body.OfKind(NodeKind.Unary).Any(u => u.Text is "yield" or "yield*"))
                continue;
            if (LanguageRuleSupport.ContainsWord(body.SourceText(), "yield"))
                continue;

            context.Report($"'{function.Text}' is declared as a generator and never yields, so calling "
                           + "it returns an iterator that finishes immediately. Every caller written as "
                           + "a loop over it does nothing at all.", function.Range.StartLine);
        }
    }
}

public sealed class JsThrowLiteralRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-BUG-0130";
    public override string Name => "A literal should not be thrown";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var jump in context.Root.OfKind(NodeKind.Jump))
        {
            if (jump.Text != "throw" || jump.Children.Count == 0)
                continue;
            var thrown = jump.Children[0];
            if (thrown.Kind is not (NodeKind.StringLiteral or NodeKind.NumberLiteral
                or NodeKind.BooleanLiteral or NodeKind.InterpolatedString))
                continue;

            context.Report("What arrives at the catch is a bare value: no message property, no stack, "
                           + "nothing that says where it came from. Throw an Error, which records the "
                           + "line that threw it.", jump.Range.StartLine);
        }
    }
}

public sealed class JsPlaceholderInPlainStringRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-BUG-0131";
    public override string Name => "A placeholder needs a template literal";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (token.Kind != TokenKind.String)
                continue;
            var text = token.Text;
            var at = text.IndexOf("${", StringComparison.Ordinal);
            if (at < 0 || text.IndexOf('}', at) < 0)
                continue;
            // The token keeps no delimiter, and looking for a quote anywhere on the line finds the
            // one written inside a template. The column of the token is where its own delimiter is.
            var source = SourceLine(context, token.Line);
            if (Delimiter(source, token.Column) is not ('\'' or '"'))
                continue;
            // a backtick anywhere on the line means a template is already open somewhere in it, and
            // the quotes that follow may well be its content rather than a string of their own
            if (source.Contains('`'))
                continue;

            context.Report("This string is written with quotes, so the placeholder is never replaced: "
                           + "the text keeps the dollar and the braces exactly as they are. Use "
                           + "backticks.", token.Line);
        }
    }

    /// <summary>The character that opens a string token, read at the token's own column.</summary>
    private static char Delimiter(string line, int column)
    {
        foreach (var index in new[] { column, column - 1 })
        {
            if (index < 0 || index >= line.Length)
                continue;
            if (line[index] is '\'' or '"' or '`')
                return line[index];
        }
        return '\0';
    }
}

public sealed class JsEmptyDestructuringRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-BUG-0132";
    public override string Name => "A destructuring pattern should bind something";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var declaration in context.Root.OfKind(NodeKind.VariableDeclaration))
        {
            var line = SourceLine(context, declaration.Range.StartLine).Replace(" ", string.Empty);
            if (!line.Contains("={}=", StringComparison.Ordinal)
                && !line.Contains("var{}", StringComparison.Ordinal)
                && !line.Contains("let{}", StringComparison.Ordinal)
                && !line.Contains("const{}", StringComparison.Ordinal)
                && !line.Contains("const[]", StringComparison.Ordinal)
                && !line.Contains("let[]", StringComparison.Ordinal))
                continue;

            context.Report("This pattern binds no name, so the declaration introduces nothing. All it "
                           + "still does is throw when the value on the right is null or undefined — "
                           + "which is unlikely to be the intention.", declaration.Range.StartLine);
        }
    }
}

public sealed class JsNegatedMembershipRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-BUG-0133";
    public override string Name => "Negating in or instanceof needs parentheses";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var test in context.Root.OfKind(NodeKind.Binary))
        {
            if (test.Text is not ("in" or "instanceof"))
                continue;
            var left = test.ChildAt(0);
            if (left is not { Kind: NodeKind.Unary } || left.Text != "!")
                continue;

            context.Report($"'!' binds tighter than '{test.Text}', so this asks whether the boolean "
                           + $"'!value' is {test.Text} the right-hand side — never what was meant. Write "
                           + $"!(value {test.Text} target).", test.Range.StartLine);
        }
    }
}

public sealed class JsNewSymbolRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-BUG-0134";
    public override string Name => "Symbol and BigInt should not be called with new";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var (node, type) in Constructions(context.Root))
        {
            if (type is not ("Symbol" or "BigInt"))
                continue;

            context.Report($"'{type}' is not a constructor: calling it with new throws a TypeError on "
                           + $"the spot. Call {type}() without new.", node.Range.StartLine);
        }
    }
}

public sealed class JsBooleanLiteralComparisonRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-SML-0361";
    public override string Name => "A boolean should not be compared to a boolean literal";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "===" or "!=" or "!=="))
                continue;
            var literal = comparison.Children.FirstOrDefault(c => c.Kind == NodeKind.BooleanLiteral);
            if (literal == null)
                continue;
            // the loose forms compare through a conversion and are a different rule's business
            if (comparison.Text is "==" or "!=")
                continue;

            // Only a plain name is reported. In TypeScript 'options.flag === true' and
            // 'fn?.() === true' are how a boolean | undefined is narrowed to a boolean, and the
            // comparison there is doing real work — reporting it is how this rule gets turned off.
            var compared = comparison.Children.FirstOrDefault(c => c != literal);
            if (compared is not { Kind: NodeKind.Identifier })
                continue;

            context.Report($"Comparing against {literal.Text} adds a step that changes nothing. Use the "
                           + "expression itself, or its negation.", comparison.Range.StartLine);
        }
    }
}

public sealed class JsObjectConstructorRule : JsTsSemanticRuleBase
{
    public override string Key => "QG-JS-SML-0363";
    public override string Name => "An object or array should be built with a literal";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var (node, type) in Constructions(context.Root))
        {
            if (type is not ("Object" or "Array"))
                continue;
            // new Array(n) means something else, and another rule already has an opinion about it
            var arguments = node.OfKind(NodeKind.ArgumentList).FirstOrDefault();
            if (type == "Array" && arguments?.Children.Count > 0)
                continue;

            var literal = type == "Object" ? "{}" : "[]";
            context.Report($"'new {type}()' goes through a constructor to produce what '{literal}' "
                           + "produces directly — and the constructor can be replaced at run time, "
                           + "which the literal cannot.", node.Range.StartLine);
        }
    }
}

public sealed class JsThisAliasRule : JsTsSemanticRuleBase
{
    private static readonly string[] Aliases = ["self", "that", "_this", "me", "_self"];

    public override string Key => "QG-JS-SML-0364";
    public override string Name => "this should not be copied into a variable";
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var declaration in context.Root.OfKind(NodeKind.VariableDeclaration))
        {
            if (!Aliases.Contains(declaration.Text))
                continue;
            var assignment = declaration.FirstChild(NodeKind.Assignment);
            var value = assignment?.ChildAt(1);
            if (value == null || SyntaxQuery.SimpleName(value) != "this")
                continue;

            context.Report($"'{declaration.Text}' exists to carry 'this' into a nested function, which "
                           + "an arrow function does by itself — it keeps the 'this' of the place it "
                           + "was written. The alias then survives as a second name for the same "
                           + "object, and the two drift apart.", declaration.Range.StartLine);
        }
    }
}
