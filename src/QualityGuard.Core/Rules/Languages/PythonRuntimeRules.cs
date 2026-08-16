using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// The second Python wave: code that imports cleanly and fails, or quietly misbehaves, the first
/// time it runs — a default argument that keeps its value between calls, a condition that is always
/// true, a handler that can never be reached, a key that cannot be hashed.
/// </summary>
public static class PythonRuntimeRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PythonMutableDefaultArgumentRule(),
        new PythonRaiseNonExceptionRule(),
        new PythonDuplicateKeywordArgumentRule(),
        new PythonExitReRaisingRule(),
        new PythonUnreachableHandlerRule(),
        new PythonConstantConditionRule(),
        new PythonInvalidOpenModeRule(),
        new PythonUnhashableKeyRule(),
        new PythonNanComparisonRule(),
        new PythonReturnInGeneratorRule(),
        new PythonExceptionWithoutBaseRule(),
        new PythonShadowedBuiltinRule(),
        new PythonParenthesesAfterKeywordRule()
    ];
}

public abstract class PythonRuntimeRuleBase : RuleBase
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

    /// <summary>The names a class lists as its bases, read from the declaration line.</summary>
    protected static IReadOnlyList<string> BaseNames(IRuleContext context, SyntaxNode type)
    {
        var line = SourceLine(context, type.Range.StartLine);
        var open = line.IndexOf('(');
        var close = line.LastIndexOf(')');
        if (open < 0 || close <= open)
            return [];

        return line[(open + 1)..close]
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(n => n.Split('=')[0].Trim())
            .Where(n => n.Length > 0)
            .ToList();
    }
}

public sealed class PythonMutableDefaultArgumentRule : PythonRuntimeRuleBase
{
    public override string Key => "QG-PY-BUG-0139";
    public override string Name => "A default argument should not be mutable";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration, NodeKind.Lambda))
        {
            var signature = Signature(context, function.Range.StartLine);
            foreach (var (value, offset) in Defaults(signature))
            {
                if (!IsMutable(value))
                    continue;

                context.Report($"The default '{value}' is created once, when the function is defined, "
                               + "and every call that does not pass an argument shares that same "
                               + "object. Anything one call appends to it is still there for the next "
                               + "one. Use None as the default and build the value inside the "
                               + "function.", function.Range.StartLine + offset);
            }
        }
    }

    /// <summary>The definition line and, when the parameters run past it, the lines that follow.</summary>
    private static string Signature(IRuleContext context, int line)
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
            text.Append(current).Append('\n');

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

    /// <summary>Every default value in a signature, with the line it is written on.</summary>
    private static IEnumerable<(string Value, int Line)> Defaults(string signature)
    {
        var open = signature.IndexOf('(');
        if (open < 0)
            yield break;

        var depth = 0;
        var line = 0;
        var afterEquals = false;
        var current = new System.Text.StringBuilder();
        var valueLine = 0;

        for (var i = open; i < signature.Length; i++)
        {
            var c = signature[i];
            if (c == '\n')
            {
                line++;
                continue;
            }
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

            if (depth == 1 && c == ',' )
            {
                if (afterEquals)
                    yield return (current.ToString().Trim(), valueLine);
                current.Clear();
                afterEquals = false;
                continue;
            }
            if (depth == 1 && c == '=' && !afterEquals)
            {
                afterEquals = true;
                valueLine = line;
                current.Clear();
                continue;
            }
            if (afterEquals)
                current.Append(c);
        }

        if (afterEquals && current.Length > 0)
            yield return (current.ToString().Trim(), valueLine);
    }

    /// <summary>Whether a default value is an object that outlives the call.</summary>
    private static bool IsMutable(string value)
    {
        if (value.Length == 0)
            return false;
        if (value.StartsWith('[') || value.StartsWith('{'))
            return value.Length > 1; // an empty literal is the usual accident, and so is a filled one
        foreach (var factory in new[] { "list(", "dict(", "set(", "collections.OrderedDict(", "defaultdict(" })
        {
            if (value.StartsWith(factory, StringComparison.Ordinal))
                return true;
        }
        return false;
    }
}

public sealed class PythonRaiseNonExceptionRule : PythonRuntimeRuleBase
{
    public override string Key => "QG-PY-BUG-0140";
    public override string Name => "Only an exception should be raised";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var jump in context.Root.OfKind(NodeKind.Jump))
        {
            if (jump.Text != "raise" || jump.Children.Count == 0)
                continue;
            var raised = jump.Children[0];
            if (raised.Kind is not (NodeKind.StringLiteral or NodeKind.NumberLiteral
                or NodeKind.BooleanLiteral or NodeKind.ListLiteral))
                continue;

            context.Report("Only something derived from BaseException can be raised: this throws "
                           + "TypeError instead, and the failure the code was trying to report is "
                           + "replaced by one about the reporting.", jump.Range.StartLine);
        }
    }
}

public sealed class PythonDuplicateKeywordArgumentRule : PythonRuntimeRuleBase
{
    public override string Key => "QG-PY-BUG-0141";
    public override string Name => "An argument should be given once";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var list = call.FirstChild(NodeKind.ArgumentList);
            if (list == null)
                continue;

            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var argument in list.Children)
            {
                var name = argument.Kind == NodeKind.NamedArgument
                    ? argument.Text
                    : argument.Kind == NodeKind.Assignment && argument.Text == "="
                        ? SyntaxQuery.SimpleName(argument.ChildAt(0))
                        : string.Empty;
                if (name.Length == 0 || seen.Add(name))
                    continue;

                context.Report($"'{name}' is given twice in this call, which Python refuses with a "
                               + "TypeError before the function even starts.", argument.Range.StartLine);
            }
        }
    }
}

public sealed class PythonExitReRaisingRule : PythonRuntimeRuleBase
{
    public override string Key => "QG-PY-BUG-0142";
    public override string Name => "__exit__ should not re-raise what it was given";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (method.Text != "__exit__")
                continue;
            var body = SyntaxQuery.Body(method);
            if (body == null)
                continue;

            // only the exception this method was handed: raising a new one is how __exit__ reports
            // a problem of its own, and that is a different thing entirely
            var received = SyntaxQuery.Parameters(method).Select(p => p.Text).ToHashSet(StringComparer.Ordinal);

            foreach (var jump in body.OfKind(NodeKind.Jump))
            {
                if (jump.Text != "raise" || jump.Children.Count == 0)
                    continue;
                if (!received.Contains(SyntaxQuery.SimpleName(jump.Children[0])))
                    continue;
                if (SyntaxQuery.EnclosingFunction(jump) != method)
                    continue;

                context.Report("The exception passed to __exit__ is still travelling: it is on its way "
                               + "out of the with block whatever this method does. Raising it again "
                               + "adds a frame and, on Python 3, chains the exception to itself in the "
                               + "traceback. Return a falsy value to let it through.",
                    jump.Range.StartLine);
            }
        }
    }
}

public sealed class PythonUnreachableHandlerRule : PythonRuntimeRuleBase
{
    /// <summary>Exception types and the ones that already cover them.</summary>
    private static readonly Dictionary<string, string[]> CoveredBy = new(StringComparer.Ordinal)
    {
        ["ValueError"] = ["Exception", "BaseException"],
        ["TypeError"] = ["Exception", "BaseException"],
        ["KeyError"] = ["Exception", "BaseException", "LookupError"],
        ["IndexError"] = ["Exception", "BaseException", "LookupError"],
        ["OSError"] = ["Exception", "BaseException"],
        ["IOError"] = ["Exception", "BaseException", "OSError"],
        ["FileNotFoundError"] = ["Exception", "BaseException", "OSError", "IOError"],
        ["ZeroDivisionError"] = ["Exception", "BaseException", "ArithmeticError"],
        ["AttributeError"] = ["Exception", "BaseException"],
        ["RuntimeError"] = ["Exception", "BaseException"],
        ["Exception"] = ["BaseException"]
    };

    public override string Key => "QG-PY-BUG-0143";
    public override string Name => "A handler should be reachable";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var handler in context.Root.OfKind(NodeKind.Catch))
        {
            // the parser nests each further except inside the one before it
            var caught = CaughtTypes(handler);
            if (caught.Count == 0)
                continue;

            foreach (var later in handler.ChildrenOf(NodeKind.Catch))
            {
                foreach (var type in CaughtTypes(later))
                {
                    if (!CoveredBy.TryGetValue(type, out var parents))
                        continue;
                    var wider = caught.FirstOrDefault(c => parents.Contains(c) || c == type);
                    if (wider == null)
                        continue;

                    context.Report($"'{type}' is already caught by the '{wider}' clause above, which "
                                   + "runs first. Nothing ever reaches this handler, so whatever it "
                                   + "does for that case does not happen. Put the specific clause "
                                   + "first.", later.Range.StartLine);
                }
            }
        }
    }

    private static List<string> CaughtTypes(SyntaxNode handler)
    {
        var names = new List<string>();
        foreach (var child in handler.Children)
        {
            if (child.Kind == NodeKind.Identifier)
                names.Add(child.Text);
            else if (child.Kind == NodeKind.Parenthesized || child.Kind == NodeKind.Tuple)
                names.AddRange(child.Children.Where(c => c.Kind == NodeKind.Identifier).Select(c => c.Text));
            else if (child.Kind is NodeKind.Block or NodeKind.Catch)
                break;
        }
        return names;
    }
}

public sealed class PythonConstantConditionRule : PythonRuntimeRuleBase
{
    public override string Key => "QG-PY-BUG-0144";
    public override string Name => "A condition should be able to go both ways";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var branch in context.Root.OfKind(NodeKind.If))
        {
            var condition = branch.ChildAt(0);
            if (condition is not { Kind: NodeKind.NumberLiteral or NodeKind.StringLiteral or NodeKind.ListLiteral })
                continue;

            context.Report($"'{condition.Text}' is the same value every time, so this branch is decided "
                           + "before the program runs — one side of it is dead code that nothing will "
                           + "ever report. If the condition was meant to be a call, it is missing its "
                           + "parentheses.", branch.Range.StartLine);
        }
    }
}

public sealed class PythonInvalidOpenModeRule : PythonRuntimeRuleBase
{
    public override string Key => "QG-PY-BUG-0145";
    public override string Name => "open should be given a mode it understands";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "open"))
        {
            var mode = SyntaxQuery.ArgumentAt(call, 1);
            if (mode is not { Kind: NodeKind.StringLiteral })
                continue;
            var text = mode.Text;
            // A mode is short and made of letters and a plus. Anything else is a fragment of a path
            // or of a message that landed in this position because the call was built from pieces.
            if (text.Length is 0 or > 4 || !text.All(c => char.IsAsciiLetter(c) || c == '+'))
                continue;
            if (!IsInvalid(text))
                continue;

            context.Report($"'{text}' is not a mode open accepts: it raises ValueError before the file "
                           + "is touched. A mode is one of r, w, x, a, followed at most by b or t and "
                           + "by a plus.", call.Range.StartLine);
        }
    }

    private static bool IsInvalid(string mode)
    {
        var actions = 0;
        var kinds = 0;
        var updates = 0;
        foreach (var c in mode)
        {
            switch (c)
            {
                case 'r' or 'w' or 'x' or 'a':
                    actions++;
                    break;
                case 'b' or 't':
                    kinds++;
                    break;
                case '+':
                    updates++;
                    break;
                case 'U':
                    break; // removed in Python 3.11, but a different rule's business
                default:
                    return true;
            }
        }
        return actions != 1 || kinds > 1 || updates > 1;
    }
}

public sealed class PythonUnhashableKeyRule : PythonRuntimeRuleBase
{
    public override string Key => "QG-PY-BUG-0146";
    public override string Name => "A key should be hashable";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var literal in context.Root.OfKind(NodeKind.ObjectInitializer))
        {
            var tokens = literal.Tokens;
            for (var i = 1; i < tokens.Count; i++)
            {
                // the bracket has to be punctuation: '[' as a dictionary key is a string whose
                // text is a bracket, and it is perfectly hashable
                if (tokens[i].Kind != TokenKind.Symbol || tokens[i].Text is not ("[" or "{"))
                    continue;
                // it also has to open an element rather than index one: what precedes it decides
                if (tokens[i - 1].Kind != TokenKind.Symbol || tokens[i - 1].Text is not ("{" or ","))
                    continue;

                var close = Matching(tokens, i);
                if (close < 0 || close + 1 >= tokens.Count || tokens[close + 1].Text != ":")
                    continue;

                context.Report("A list and a dictionary cannot be hashed, so using one as a key raises "
                               + "TypeError the moment this literal is built. Use a tuple, or "
                               + "frozenset for an unordered key.", tokens[i].Line);
            }
        }
    }

    private static int Matching(IReadOnlyList<Token> tokens, int open)
    {
        var depth = 0;
        for (var i = open; i < tokens.Count; i++)
        {
            if (tokens[i].Text is "[" or "{" or "(")
                depth++;
            else if (tokens[i].Text is "]" or "}" or ")")
            {
                depth--;
                if (depth == 0)
                    return i;
            }
        }
        return -1;
    }
}

public sealed class PythonNanComparisonRule : PythonRuntimeRuleBase
{
    public override string Key => "QG-PY-BUG-0147";
    public override string Name => "Not a number is not equal to itself";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "!="))
                continue;
            var nan = comparison.Children.FirstOrDefault(
                c => SyntaxQuery.DottedName(c).EndsWith(".nan", StringComparison.Ordinal)
                     || SyntaxQuery.DottedName(c).EndsWith(".NaN", StringComparison.Ordinal));
            if (nan == null)
                continue;

            context.Report("Not a number compares equal to nothing at all, itself included, so this "
                           + "test answers the same thing whatever the value is. Use isnan.",
                comparison.Range.StartLine);
        }
    }
}

public sealed class PythonReturnInGeneratorRule : PythonRuntimeRuleBase
{
    public override string Key => "QG-PY-BUG-0148";
    public override string Name => "A value returned from a generator is not yielded";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var body = SyntaxQuery.Body(function);
            if (body == null)
                continue;
            var yields = body.OfKind(NodeKind.Unary, NodeKind.Jump)
                .Where(n => n.Text is "yield" or "yield from")
                .Where(n => SyntaxQuery.EnclosingFunction(n) == function)
                .ToList();
            if (yields.Count == 0)
                continue;

            foreach (var jump in body.OfKind(NodeKind.Jump))
            {
                if (jump.Text != "return" || jump.Children.Count == 0)
                    continue;
                if (jump.Children[0].Kind == NodeKind.NullLiteral)
                    continue;
                if (SyntaxQuery.EnclosingFunction(jump) != function)
                    continue;

                context.Report("In a generator a returned value does not reach the caller: it becomes "
                               + "the value attached to StopIteration, which every for loop discards "
                               + "without a word. Yield it, or move the result to a separate function.",
                    jump.Range.StartLine);
            }
        }
    }
}

public sealed class PythonExceptionWithoutBaseRule : PythonRuntimeRuleBase
{
    public override string Key => "QG-PY-SML-0249";
    public override string Name => "A custom exception should derive from Exception";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var name = type.Text;
            if (!name.EndsWith("Error", StringComparison.Ordinal)
                && !name.EndsWith("Exception", StringComparison.Ordinal))
                continue;

            var bases = BaseNames(context, type);
            if (bases.Count > 0)
                continue;

            context.Report($"'{name}' is named like an exception but derives from object, so it cannot "
                           + "be raised at all — the raise fails with a TypeError about the class, not "
                           + "about the problem it was meant to describe.", type.Range.StartLine);
        }
    }
}

public sealed class PythonShadowedBuiltinRule : PythonRuntimeRuleBase
{
    private static readonly string[] Builtins =
    [
        "list", "dict", "set", "tuple", "str", "int", "float", "bool", "bytes", "type", "id",
        "input", "filter", "map", "max", "min", "sum", "len", "next", "iter", "range", "hash",
        "object", "print", "open", "format", "vars", "dir", "all", "any", "abs", "round"
    ];

    public override string Key => "QG-PY-SML-0250";
    public override string Name => "A builtin name should not be reused";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var body = SyntaxQuery.Body(function);
            if (body == null)
                continue;

            // Only a shadowing that breaks something is worth reading. A local called format or id
            // hurts nobody; the same name shadowed in a function that also calls the builtin turns
            // that call into a TypeError, and that is the case this reports.
            var called = body.OfKind(NodeKind.Invocation)
                .Select(SyntaxQuery.InvokedName)
                .Where(n => n.Length > 0)
                .ToHashSet(StringComparer.Ordinal);

            foreach (var declaration in body.OfKind(NodeKind.VariableDeclaration))
            {
                if (!Builtins.Contains(declaration.Text) || !called.Contains(declaration.Text))
                    continue;
                if (SyntaxQuery.EnclosingFunction(declaration) != function)
                    continue;

                context.Report($"'{declaration.Text}' is a builtin, and this hides it for the whole "
                               + "function — including the call to it further down, which reaches the "
                               + "variable instead and fails with an error naming a type nobody wrote.",
                    declaration.Range.StartLine);
            }
        }
    }
}

public sealed class PythonParenthesesAfterKeywordRule : PythonRuntimeRuleBase
{
    private static readonly string[] Keywords = ["not", "del", "assert", "in", "is", "and", "or"];

    public override string Key => "QG-PY-CNV-0007";
    public override string Name => "A keyword is not a function";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (!Keywords.Contains(tokens[i].Text))
                continue;
            if (tokens[i + 1].Text != "(")
                continue;
            // the parenthesis has to touch the keyword: 'not (a and b)' groups a real expression
            if (tokens[i + 1].Column != tokens[i].Column + tokens[i].Text.Length)
                continue;

            context.Report($"'{tokens[i].Text}' is an operator, not a function, and the parentheses "
                           + "make it look like a call. They also stop applying to what a reader "
                           + "expects as soon as a second operand appears.", tokens[i].Line);
        }
    }
}
