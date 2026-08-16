using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Python on the tree. Python accepts a great deal at compile time and fails at run time instead, so
/// most of what is worth reporting here is code that parses perfectly and does something other than
/// what it reads as: an assert that can never fail, a dictionary whose key is written twice, a loop
/// else that always runs.
/// </summary>
public static class PythonAstRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PythonJumpOutsideLoopRule(),
        new PythonInitReturnsValueRule(),
        new PythonDoubledOperatorRule(),
        new PythonNonStringInAllRule(),
        new PythonLoopElseWithoutBreakRule(),
        new PythonDuplicateDictionaryKeyRule(),
        new PythonDuplicateSetElementRule(),
        new PythonAssertOnTupleRule(),
        new PythonInstanceMethodReceiverRule(),
        new PythonClassMethodReceiverRule(),
        new PythonTypeComparisonRule(),
        new PythonSlicingInsteadOfPrefixTestRule(),
        new PythonLambdaAssignedToNameRule(),
        new PythonNestedConditionalRule(),
        new PythonPointlessHandlerRule()
    ];
}

public abstract class PythonAstRuleBase : RuleBase
{
    public override string[] Languages => ["py"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static string SourceLine(IRuleContext context, int line)
    {
        var lines = LanguageRuleSupport.Lines(context);
        return line - 1 >= 0 && line - 1 < lines.Length ? lines[line - 1] : string.Empty;
    }

    /// <summary>
    /// The definition line and, when the parameters run past it, everything up to the closing
    /// parenthesis. A signature spread over several lines is normal in typed Python, and reading
    /// only the first line of it says the function takes no parameters at all.
    /// </summary>
    protected static string Signature(IRuleContext context, int line)
    {
        var lines = LanguageRuleSupport.Lines(context);
        var text = new System.Text.StringBuilder();
        var depth = 0;
        var opened = false;

        for (var i = line - 1; i < lines.Length && i < line + 40; i++)
        {
            var current = lines[i];
            var cut = current.IndexOf('#');
            if (cut >= 0)
                current = current[..cut];
            text.Append(current);

            foreach (var c in current)
            {
                if (c == '(')
                {
                    depth++;
                    opened = true;
                }
                else if (c == ')')
                {
                    depth--;
                }
            }
            if (opened && depth <= 0)
                break;
        }
        return text.ToString();
    }

    /// <summary>
    /// The names between the parentheses of a definition, read from the source. The parser drops
    /// self and cls on purpose — every other rule counts the parameters a caller actually passes —
    /// so the rules about the receiver have to go back to the line that declares it.
    /// </summary>
    protected static IReadOnlyList<string> DeclaredParameters(string definition)
    {
        var open = definition.IndexOf('(');
        if (open < 0)
            return [];

        var depth = 0;
        var current = new System.Text.StringBuilder();
        var names = new List<string>();
        for (var i = open; i < definition.Length; i++)
        {
            var c = definition[i];
            if (c is '(' or '[' or '{')
            {
                depth++;
                if (depth == 1)
                    continue;
            }
            else if (c is ')' or ']' or '}')
            {
                depth--;
                if (depth == 0)
                    break;
            }

            if (depth == 1 && c == ',')
            {
                names.Add(current.ToString());
                current.Clear();
                continue;
            }
            current.Append(c);
        }
        names.Add(current.ToString());

        return names
            .Select(n => n.Split(':')[0].Split('=')[0].Trim())
            .Where(n => n.Length > 0)
            .ToList();
    }

    /// <summary>The decorators written above a definition.</summary>
    protected static IReadOnlyList<string> Decorators(SyntaxNode declaration)
        => declaration.ChildrenOf(NodeKind.Attribute).Select(a => a.Text).ToList();

    /// <summary>
    /// The top-level items of a brace literal, as slices of its tokens. A dictionary and a set are
    /// the same node here, so the caller decides what to do with the colon each item may carry.
    /// </summary>
    protected static List<List<Token>> BraceItems(SyntaxNode literal)
    {
        var items = new List<List<Token>>();
        var tokens = literal.Tokens;
        if (tokens.Count == 0)
            return items;

        var current = new List<Token>();
        var depth = 0;
        foreach (var token in tokens)
        {
            if (token.Text is "(" or "[" or "{")
            {
                depth++;
                if (depth == 1)
                    continue;
            }
            else if (token.Text is ")" or "]" or "}")
            {
                depth--;
                if (depth == 0)
                    break;
            }

            if (depth == 1 && token.Text == ",")
            {
                items.Add(current);
                current = [];
                continue;
            }
            if (depth >= 1)
                current.Add(token);
        }
        items.Add(current);
        return items.Where(i => i.Count > 0).ToList();
    }

    /// <summary>
    /// The key of a dictionary item when it is a single literal, or null. Anything computed is left
    /// alone: two calls that happen to look alike may well produce different keys.
    /// </summary>
    protected static Token? LiteralKey(List<Token> item)
    {
        var colon = item.FindIndex(t => t.Text == ":");
        if (colon != 1)
            return null;
        var key = item[0];
        return key.Kind is TokenKind.String or TokenKind.Number ? key : null;
    }
}

public sealed class PythonJumpOutsideLoopRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-BUG-0132";
    public override string Name => "break and continue belong inside a loop";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var jump in context.Root.OfKind(NodeKind.Jump))
        {
            if (jump.Text is not ("break" or "continue"))
                continue;
            var inLoop = false;
            foreach (var ancestor in jump.Ancestors())
            {
                if (ancestor.Kind == NodeKind.Loop)
                {
                    inLoop = true;
                    break;
                }
                // a nested function starts a new context: the enclosing loop is not its loop
                if (ancestor.Kind is NodeKind.FunctionDeclaration or NodeKind.Lambda)
                    break;
            }
            if (inLoop)
                continue;

            context.Report($"'{jump.Text}' has no loop to act on, so the interpreter refuses the module "
                           + "outright — the file will not even import. Remove it, or move it inside the "
                           + "loop it was meant for.", jump.Range.StartLine);
        }
    }
}

public sealed class PythonInitReturnsValueRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-BUG-0133";
    public override string Name => "__init__ should not return a value";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (method.Text != "__init__")
                continue;
            var body = SyntaxQuery.Body(method);
            if (body == null)
                continue;

            foreach (var jump in body.OfKind(NodeKind.Jump))
            {
                if (jump.Text != "return" || jump.Children.Count == 0)
                    continue;
                if (jump.Children[0].Kind == NodeKind.NullLiteral)
                    continue; // return None is the same as returning nothing
                if (SyntaxQuery.EnclosingFunction(jump) != method)
                    continue;

                context.Report("__init__ prepares the object; the object itself comes from __new__. "
                               + "Returning anything else raises TypeError at construction time, so "
                               + "this fails on the first call.", jump.Range.StartLine);
            }
        }
    }
}

public sealed class PythonDoubledOperatorRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-SML-0243";
    public override string Name => "A prefix operator should not be repeated";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var outer in context.Root.OfKind(NodeKind.Unary))
        {
            if (outer.Text is not ("not" or "~"))
                continue;
            var inner = outer.ChildAt(0);
            if (inner is not { Kind: NodeKind.Unary } || inner.Text != outer.Text)
                continue;

            var replacement = outer.Text == "not" ? "bool(...)" : "the value itself";
            context.Report($"'{outer.Text} {outer.Text}' cancels itself out. If the intent was to force a "
                           + $"boolean, say so with {replacement}; if it was not, one of the two is a "
                           + "typo that reverses the condition.", outer.Range.StartLine);
        }
    }
}

public sealed class PythonNonStringInAllRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-BUG-0134";
    public override string Name => "__all__ should list only names";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            if (SyntaxQuery.SimpleName(assignment.ChildAt(0)) != "__all__")
                continue;
            var value = assignment.ChildAt(1);
            if (value is not { Kind: NodeKind.ListLiteral or NodeKind.Tuple })
                continue;

            foreach (var element in value.Children)
            {
                if (element.Kind is NodeKind.StringLiteral or NodeKind.Identifier
                    or NodeKind.Invocation or NodeKind.MemberSelect or NodeKind.Binary)
                    continue;

                context.Report("__all__ is the list of names a star import exports, and every entry has "
                               + "to be one of those names written as a string. Anything else raises "
                               + "TypeError the moment someone writes 'from this import *'.",
                    element.Range.StartLine);
            }
        }
    }
}

public sealed class PythonLoopElseWithoutBreakRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-BUG-0135";
    public override string Name => "A loop else needs a break to be worth writing";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            var elseNode = loop.FirstChild(NodeKind.Else);
            if (elseNode == null)
                continue;

            var body = loop.FirstChild(NodeKind.Block);
            if (body != null && HasOwnBreak(body))
                continue;

            context.Report("A loop else runs when the loop ends without breaking out of it — and this "
                           + "loop has no break, so the else always runs. Everyone reading it will "
                           + "assume it belongs to an if. Move the statements after the loop.",
                elseNode.Range.StartLine);
        }
    }

    private static bool HasOwnBreak(SyntaxNode body)
    {
        foreach (var jump in body.OfKind(NodeKind.Jump))
        {
            if (jump.Text != "break")
                continue;
            // a break inside a nested loop belongs to that loop, not to this one
            var owner = jump.Ancestors().FirstOrDefault(a => a.Kind is NodeKind.Loop or NodeKind.FunctionDeclaration);
            if (owner != null && owner == body.Parent)
                return true;
        }
        return false;
    }
}

public sealed class PythonDuplicateDictionaryKeyRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-BUG-0136";
    public override string Name => "A dictionary should not repeat a key";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var literal in context.Root.OfKind(NodeKind.ObjectInitializer))
        {
            var items = BraceItems(literal);
            var seen = new Dictionary<string, int>(StringComparer.Ordinal);

            foreach (var item in items)
            {
                var key = LiteralKey(item);
                if (key == null)
                    continue;
                var text = $"{key.Kind}:{key.Text}";
                if (seen.TryGetValue(text, out var first))
                {
                    context.Report($"The key '{key.Text}' is already given on line {first}. The literal "
                                   + "keeps the last value and drops the earlier one without a word, so "
                                   + "one of these two entries does nothing.", key.Line);
                    continue;
                }
                seen[text] = key.Line;
            }
        }
    }
}

public sealed class PythonDuplicateSetElementRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-BUG-0137";
    public override string Name => "A set should not repeat an element";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var literal in context.Root.OfKind(NodeKind.ObjectInitializer))
        {
            var items = BraceItems(literal);
            // one colon anywhere makes it a dictionary, which the key rule covers instead
            if (items.Any(i => i.Any(t => t.Text == ":")))
                continue;

            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var item in items)
            {
                if (item.Count != 1 || item[0].Kind is not (TokenKind.String or TokenKind.Number))
                    continue;
                var text = $"{item[0].Kind}:{item[0].Text}";
                if (seen.TryGetValue(text, out var first))
                {
                    context.Report($"'{item[0].Text}' is already in this set, on line {first}. The "
                                   + "duplicate disappears silently, so the set has one element fewer "
                                   + "than the code appears to build.", item[0].Line);
                    continue;
                }
                seen[text] = item[0].Line;
            }
        }
    }
}

public sealed class PythonAssertOnTupleRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-BUG-0138";
    public override string Name => "assert should not be given a tuple";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var assertion in context.Root.OfKind(NodeKind.Jump))
        {
            if (assertion.Text != "assert")
                continue;
            var argument = assertion.ChildAt(0);
            if (argument is not { Kind: NodeKind.Parenthesized or NodeKind.Tuple })
                continue;
            if (argument.Children.Count < 2)
                continue;
            // the parentheses have to hold a comma at their own level for this to be a tuple
            if (!SourceLine(context, assertion.Range.StartLine).Contains(',', StringComparison.Ordinal))
                continue;

            context.Report("A non-empty tuple is always true, so this assertion can never fail — the "
                           + "check is gone and nothing says so. The message goes after the condition "
                           + "without parentheses: assert condition, \"message\".",
                assertion.Range.StartLine);
        }
    }
}

public sealed class PythonInstanceMethodReceiverRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-CNV-0005";
    public override string Name => "An instance method should take self first";
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            foreach (var method in body.ChildrenOf(NodeKind.FunctionDeclaration))
            {
                var decorators = Decorators(method);
                if (decorators.Any(d => d.Contains("staticmethod", StringComparison.Ordinal)
                                        || d.Contains("classmethod", StringComparison.Ordinal)))
                    continue;

                // Python makes these implicitly static or class methods, whatever the signature says
                if (method.Text is "__new__" or "__init_subclass__" or "__class_getitem__")
                    continue;

                var parameters = DeclaredParameters(Signature(context, method.Range.StartLine));
                var first = parameters.Count == 0 ? string.Empty : parameters[0];
                if (first.Length == 0 || first.StartsWith('*'))
                {
                    context.Report($"'{method.Text}' has no positional parameter to receive the "
                                   + "instance, and Python passes it whether the signature expects it "
                                   + "or not. The first call raises TypeError. Add self, or mark the "
                                   + "method static.", method.Range.StartLine);
                    continue;
                }

                if (first is "self" or "_self" or "cls" or "mcs" or "mcls" or "metacls")
                    continue;

                context.Report($"The first parameter is '{first}', and Python passes the instance into "
                               + "it whatever it is called. Everyone reading the class expects that "
                               + "parameter to be named self; anything else makes every method here "
                               + "look like it takes an extra argument.", method.Range.StartLine);
            }
        }
    }
}

public sealed class PythonClassMethodReceiverRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-CNV-0006";
    public override string Name => "A class method should take cls first";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!Decorators(method).Any(d => d.Contains("classmethod", StringComparison.Ordinal)))
                continue;

            var parameters = DeclaredParameters(Signature(context, method.Range.StartLine));
            if (parameters.Count == 0)
            {
                context.Report($"'{method.Text}' is a class method with no parameter to receive the "
                               + "class, so every call to it raises TypeError.", method.Range.StartLine);
                continue;
            }

            var first = parameters[0];
            if (first is "cls" or "mcs" or "metacls" or "_cls")
                continue;

            context.Report($"A class method receives the class, not an instance, and '{first}' — self "
                           + "above all — says the opposite to whoever reads it. Name it cls.",
                method.Range.StartLine);
        }
    }
}

public sealed class PythonTypeComparisonRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-SML-0244";
    public override string Name => "A type should be checked with isinstance";
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!="))
                continue;
            var call = comparison.Children.FirstOrDefault(
                c => c.Kind == NodeKind.Invocation && SyntaxQuery.InvokedName(c) == "type");
            if (call == null || SyntaxQuery.Arguments(call).Count != 1)
                continue;
            // comparing the types of two values is a different question, and a legitimate one
            if (comparison.Children.Count(c => c.Kind == NodeKind.Invocation
                                               && SyntaxQuery.InvokedName(c) == "type") == 2)
                continue;

            context.Report("Comparing the exact type rejects every subclass, so the check fails for "
                           + "values that are perfectly usable — and passing a subclass is the normal "
                           + "way to extend code in Python. Use isinstance.", comparison.Range.StartLine);
        }
    }
}

public sealed class PythonSlicingInsteadOfPrefixTestRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-SML-0245";
    public override string Name => "A prefix or suffix should be tested with startswith or endswith";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!="))
                continue;
            var sliced = comparison.Children.FirstOrDefault(c => c.Kind == NodeKind.Index);
            var literal = comparison.Children.FirstOrDefault(SyntaxQuery.IsStringLiteral);
            if (sliced == null || literal == null)
                continue;
            if (!sliced.Children.Any(c => c.Kind == NodeKind.Unknown && c.Text == ":"))
                continue;

            context.Report("Slicing takes the length from the code and the value from somewhere else, "
                           + "so the two go out of step the first time the literal changes. "
                           + "startswith and endswith read the length from the text itself.",
                comparison.Range.StartLine);
        }
    }
}

public sealed class PythonLambdaAssignedToNameRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-SML-0246";
    public override string Name => "A named function should be defined with def";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            if (assignment.Text != "=")
                continue;
            var target = assignment.ChildAt(0);
            if (target is not { Kind: NodeKind.Identifier })
                continue;
            if (assignment.ChildAt(1) is not { Kind: NodeKind.Lambda })
                continue;

            context.Report($"'{target.Text}' is a function with a name, written in the one form that "
                           + "does not record it: a traceback through this call shows '<lambda>', and "
                           + "the body cannot grow past one expression. Use def.",
                assignment.Range.StartLine);
        }
    }
}

public sealed class PythonNestedConditionalRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-SML-0247";
    public override string Name => "Conditional expressions should not be nested";
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var conditional in context.Root.OfKind(NodeKind.Conditional))
        {
            var nested = conditional.Children.Any(
                c => c.Kind == NodeKind.Conditional
                     || (c.Kind == NodeKind.Parenthesized && c.Children.Any(n => n.Kind == NodeKind.Conditional)));
            if (!nested)
                continue;

            context.Report("A conditional inside a conditional puts the branches in an order nobody "
                           + "reads correctly the first time, because Python writes the value before "
                           + "the test. Use an if statement, or a lookup keyed on the cases.",
                conditional.Range.StartLine);
        }
    }
}

public sealed class PythonPointlessHandlerRule : PythonAstRuleBase
{
    public override string Key => "QG-PY-SML-0248";
    public override string Name => "A handler that only re-raises should be removed";
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var handler in context.Root.OfKind(NodeKind.Catch))
        {
            var body = handler.FirstChild(NodeKind.Block);
            if (body is not { Children.Count: 1 })
                continue;
            var statement = body.Children[0];
            if (statement.Kind != NodeKind.Jump || statement.Text != "raise" || statement.Children.Count > 0)
                continue;

            // The parser nests each further except inside the one before it, so a handler that has a
            // Catch inside it — or sits inside one — is part of a chain. There the bare raise is the
            // idiom that lets a few exception types through before a wider handler takes the rest,
            // which is exactly the right thing to write.
            if (handler.ChildrenOf(NodeKind.Catch).Any() || handler.Parent?.Kind == NodeKind.Catch)
                continue;
            if (handler.Parent?.ChildrenOf(NodeKind.Finally).Any() == true)
                continue;

            context.Report("This handler catches the exception and immediately lets it go again, which "
                           + "is exactly what would happen without the try. It costs a traceback frame "
                           + "and makes the reader look for the handling that is not there.",
                handler.Range.StartLine);
        }
    }
}
