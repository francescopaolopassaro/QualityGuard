using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Python checks the default profile turns on, written on the dedicated tree. Every one of them
/// reads a shape the parser actually carries; anything needing real type inference stays silent.
/// </summary>
public static class PythonGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PyDoubleUnaryRule(),
        new PyPrintStatementRule(),
        new PyYieldOutsideFunctionRule(),
        new PyCallOnNonCallableRule(),
        new PyCollectionTypeCastRule(),
        new PyEmptyConstructorCollectionRule(),
        new PyNestedSameCollectionRule(),
        new PySortedInsideReversedRule(),
        new PyReversedIntoDeduplicatorRule(),
        new PySortedWrappedInSetRule(),
        new PyListIndexZeroRule(),
        new PySumEmptyListConcatRule(),
        new PyMapWithLambdaRule(),
    ];
}

public abstract class PyGapRuleBase : RuleBase
{
    internal static string Simple(string? dotted) =>
        (dotted ?? "").Split('.').LastOrDefault() ?? "";
}

public sealed class PyDoubleUnaryRule : PyGapRuleBase
{
    public override string Key => "QG-PY-BUG-0023";
    public override string Name => "'++x' and '--x' are double unary operators in Python";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var unary in context.Root.OfKind(NodeKind.Unary))
        {
            var inner = unary.ChildAt(0);
            if (inner?.Kind != NodeKind.Unary || unary.Text != inner.Text
                || unary.Text is not ("+" or "-"))
                continue;
            context.Report(unary, unary.Text == "+"
                ? "'++x' is +(+x) here, not an increment: write x += 1."
                : "'--x' is -(-x): the value does not change. Decrement with x -= 1.");
        }
    }
}

public sealed class PyPrintStatementRule : PyGapRuleBase
{
    public override string Key => "QG-PY-SML-0029";
    public override string Name => "print is a function since Python 3";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var statement in context.Root.OfKind(NodeKind.ExpressionStatement))
        {
            var head = statement.ChildAt(0);
            if (head is not { Kind: NodeKind.Identifier, Text: "print" })
                continue;
            var next = statement.ChildAt(1);
            if (next is null)
                continue;
            context.Report(statement, "This is the Python 2 print statement: on Python 3 it is a "
                                      + "SyntaxError. Call print(...) as a function.");
        }
    }
}

public sealed class PyYieldOutsideFunctionRule : PyGapRuleBase
{
    public override string Key => "QG-PY-BUG-0034";
    public override string Name => "yield and return belong inside a function";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var yield in context.Root.OfKind(NodeKind.Jump))
        {
            if (yield.Ancestor(NodeKind.FunctionDeclaration) != null)
                continue;
            context.Report(yield, "'yield' outside a function is a SyntaxError: this code never "
                                  + "ran anywhere.");
        }
    }
}

public sealed class PyCallOnNonCallableRule : PyGapRuleBase
{
    public override string Key => "QG-PY-BUG-0053";
    public override string Name => "Literals cannot be called";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            var callee = invocation.ChildAt(0);
            if (callee?.Kind is not (NodeKind.NumberLiteral or NodeKind.StringLiteral))
                continue;
            context.Report(invocation, $"A {callee.Kind.ToString().ToLowerInvariant()} cannot be "
                                       + "called: this raises TypeError as soon as it runs.");
        }
    }
}

public sealed class PyCollectionTypeCastRule : PyGapRuleBase
{
    private static readonly HashSet<string> Casts = new(StringComparer.Ordinal)
        { "list", "tuple", "dict", "set", "frozenset" };

    public override string Key => "QG-PY-SML-0164";
    public override string Name => "Do not wrap a literal in its own constructor";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (!Casts.Contains(Simple(invocation.Text)))
                continue;
            var argument = invocation.FirstChild(NodeKind.ArgumentList)?.Children.FirstOrDefault();
            if (argument == null)
                continue;
            var redundant = Simple(invocation.Text) switch
            {
                "list" => argument.Kind is NodeKind.ListLiteral,
                "tuple" => argument.Kind == NodeKind.Parenthesized || argument.Tokens.Any(t => t.Text == ")"),
                "dict" => argument.OfKind(NodeKind.Assignment).Any(a => a.Text == ":"),
                _ => false,
            };
            if (!redundant)
                continue;
            context.Report(invocation, $"'{Simple(invocation.Text)}(...)' copies a literal of the "
                                       + "same type: write the literal directly.");
        }
    }
}

public sealed class PyEmptyConstructorCollectionRule : PyGapRuleBase
{
    public override string Key => "QG-PY-SML-0165";
    public override string Name => "Use [] and {} instead of list() and dict()";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (Simple(invocation.Text) is not ("list" or "dict"))
                continue;
            var arguments = invocation.FirstChild(NodeKind.ArgumentList);
            if (arguments == null || arguments.Children.Count != 0)
                continue;
            context.Report(invocation, $"{'"'}{Simple(invocation.Text)}(){'"'} builds an empty "
                                       + "collection the long way: [] for lists, {} for dicts.");
        }
    }
}
// ------------------------------------------------------- iterator & collection idioms

public sealed class PyNestedSameCollectionRule : PyGapRuleBase
{
    public override string Key => "QG-PY-SML-0166";
    public override string Name => "Do not wrap a collection in its own constructor";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            var name = Simple(invocation.Text);
            if (name is not ("list" or "set" or "dict" or "tuple"))
                continue;
            var argument = invocation.FirstChild(NodeKind.ArgumentList)?.Children.FirstOrDefault();
            if (argument?.Kind != NodeKind.Invocation || Simple(argument.Text) != name)
                continue;
            context.Report(invocation, $"'{name}({name}(...))' copies twice and changes nothing: "
                                       + "keep the inner call only.");
        }
    }
}

public sealed class PySortedInsideReversedRule : PyGapRuleBase
{
    public override string Key => "QG-PY-SML-0167";
    public override string Name => "reversed(sorted(x)) undoes the sort";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (Simple(invocation.Text) != "reversed")
                continue;
            var argument = invocation.FirstChild(NodeKind.ArgumentList)?.Children.FirstOrDefault();
            if (argument?.Kind != NodeKind.Invocation || Simple(argument.Text) != "sorted")
                continue;
            context.Report(invocation, "'reversed(sorted(x))' throws the ordering away: sort with "
                                       + "the reverse flag instead, or iterate the sorted list "
                                       + "backwards explicitly.");
        }
    }
}

public sealed class PyReversedIntoDeduplicatorRule : PyGapRuleBase
{
    public override string Key => "QG-PY-SML-0168";
    public override string Name => "reversed() before set, sorted or reversed is undone";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (Simple(invocation.Text) is not ("set" or "sorted" or "reversed"))
                continue;
            var argument = invocation.FirstChild(NodeKind.ArgumentList)?.Children.FirstOrDefault();
            if (argument?.Kind != NodeKind.Invocation || Simple(argument.Text) != "reversed")
                continue;
            context.Report(invocation, $"The order '{Simple(argument.Text)}()' produces is ignored by "
                                       + $"{Simple(invocation.Text)}(): drop the reversed call.");
        }
    }
}

public sealed class PySortedWrappedInSetRule : PyGapRuleBase
{
    public override string Key => "QG-PY-SML-0179";
    public override string Name => "set(sorted(x)) discards the sorting";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (Simple(invocation.Text) != "set")
                continue;
            var argument = invocation.FirstChild(NodeKind.ArgumentList)?.Children.FirstOrDefault();
            if (argument?.Kind != NodeKind.Invocation || Simple(argument.Text) != "sorted")
                continue;
            context.Report(invocation, "A set has no order, so wrapping sorted(...) in set(...) "
                                       + "keeps only the deduplication. Sort the set afterwards if "
                                       + "the order matters.");
        }
    }
}

// ------------------------------------------------------------------- index patterns

public sealed class PyListIndexZeroRule : PyGapRuleBase
{
    public override string Key => "QG-PY-BUG-0114";
    public override string Name => "list(...)[0] raises on an empty list";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var index in context.Root.OfKind(NodeKind.Index))
        {
            var callee = index.ChildAt(0);
            if (callee?.Kind != NodeKind.Invocation || Simple(callee.Text) != "list"
                || callee.FirstChild(NodeKind.ArgumentList)?.Children.Count == 0)
                continue;
            var subscript = index.ChildAt(1)?.Text;
            if (subscript is not ("0" or "-1"))
                continue;
            context.Report(index, $"list(...)[{subscript}] throws IndexError whenever the list comes "
                                  + "out empty. Use next(iter(list(...)), None), or check before "
                                  + "indexing.");
        }
    }
}

public sealed class PySumEmptyListConcatRule : PyGapRuleBase
{
    public override string Key => "QG-PY-SML-0212";
    public override string Name => "sum() over lists wants a real start value";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (Simple(invocation.Text) != "sum")
                continue;
            var arguments = invocation.FirstChild(NodeKind.ArgumentList)?.Children.ToList();
            if (arguments is not { Count: 2 })
                continue;
            var start = arguments[1];
            var emptyLiteral = (start.Kind == NodeKind.ListLiteral && start.Children.Count == 0)
                               || (start.Tokens.Count == 2 && start.Text == "[]");
            if (!emptyLiteral)
                continue;
            context.Report(invocation, "sum(lists, []) concatenates through quadratic copying: use "
                                       + "itertools.chain.from_iterable(lists), which is linear.");
        }
    }
}

// ------------------------------------------------------------------------ modern

public sealed class PyMapWithLambdaRule : PyGapRuleBase
{
    public override string Key => "QG-PY-SML-0171";
    public override string Name => "Prefer a comprehension over map with a lambda";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (Simple(invocation.Text) != "map")
                continue;
            var first = invocation.FirstChild(NodeKind.ArgumentList)?.Children.FirstOrDefault();
            if (first?.Kind != NodeKind.Lambda)
                continue;
            context.Report(first, "map(lambda …) reads inside-out compared to the equivalent list "
                                  + "comprehension. Write [f(x) for x in xs] instead.");
        }
    }
}
/// </summary>
public static class PythonGapRuleSet2
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PySystemExitReraisedRule(),
        new PyMethodFieldCapitalizationRule(),
        new PyIterReturnsIteratorRule(),
        new PyAssertAtEndOfExceptRule(),
        new PyFlaskHandlerStatusCodeRule(),
        new PyAsyncBlockingSleepRule(),
        new PyAsyncLambdaHandlerRule(),
        new PySendFileMimetypeRule(),
        new PySortedIndexMinMaxRule(),
        new PyTryExceptFailRule(),
        new PyParametrizeEmptyRule(),
        new PyRaisesAsStatementRule(),
        new PyFailWithoutMessageRule(),
        new PyDuplicateParametrizeCasesRule(),
        new PyPatchWithLambdaReturnRule(),
        new PyImportPytestAliasedRule(),
        new PyTestDefaultParametersRule(),
        new PyNoneComparedToNoneRule(),
    ];
}

public abstract class PyGap2Base : RuleBase
{
    internal static string Simple(string? dotted) =>
        (dotted ?? "").Split('.').LastOrDefault() ?? "";
}

public sealed class PySystemExitReraisedRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0082";
    public override string Name => "SystemExit caught without re-raising swallows the exit";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var catchClause in context.Root.OfKind(NodeKind.Catch))
        {
            var type = Simple(catchClause.FirstChild(NodeKind.TypeReference)?.Text);
            if (type is not ("SystemExit" or "KeyboardInterrupt"))
                continue;
            var reRaised = catchClause.OfKind(NodeKind.Jump).Any(j => j.Text == "raise");
            if (reRaised)
                continue;
            context.Report(catchClause, $"Catching {type} without re-raising keeps the interpreter "
                                       + "alive after it was asked to stop. Re-raise, or handle "
                                       + "cleanup with finally.");
        }
    }
}

public sealed class PyMethodFieldCapitalizationRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0048";
    public override string Name => "A method and a field should not differ only by case";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var fields = type.OfKind(NodeKind.FieldDeclaration).Select(f => f.Text)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var method in type.OfKind(NodeKind.FunctionDeclaration))
            {
                if (method.Text.Length < 3 || !fields.Contains(method.Text))
                    continue;
                context.Report(method, $"'{method.Text}' names both a method and a field of "
                                       + $"'{type.Text}' (case apart). A reader cannot tell which "
                                       + "one an unqualified use resolves to.");
            }
        }
    }
}

public sealed class PyIterReturnsIteratorRule : PyGap2Base
{
    public override string Key => "QG-PY-BUG-0038";
    public override string Name => "__iter__ should return an iterator";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (function.Text != "__iter__")
                continue;
            var yields = function.OfKind(NodeKind.Jump).Any(j => j.Text == "yield");
            var returnsIterator = function.OfKind(NodeKind.Invocation)
                .Any(i => Simple(i.Text) is "iter" or "self");
            if (yields || returnsIterator)
                continue;
            context.Report(function, "An __iter__ without yield must return iter(self) or an "
                                     + "explicit iterator; returning anything else breaks every "
                                     + "for-loop over the type.");
        }
    }
}

public sealed class PyAssertAtEndOfExceptRule : PyGap2Base
{
    public override string Key => "QG-PY-BUG-0064";
    public override string Name => "An assert as last statement of an except hides the failure";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var catchClause in context.Root.OfKind(NodeKind.Catch))
        {
            var body = catchClause.Children.Where(c =>
                c.Kind is NodeKind.ExpressionStatement or NodeKind.Jump).ToList();
            if (body.Count == 0)
                continue;
            var last = body[^1];
            if (last.ChildAt(0)?.Text == "assert")
                context.Report(last, "The handler ends on an assert: with -O the whole block becomes "
                                     + "a no-op and the error vanishes silently. Raise instead.");
        }
    }
}

public sealed class PyFlaskHandlerStatusCodeRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0083";
    public override string Name => "Flask error handlers should set the HTTP status code";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        // this rule is for applications using Flask, not the framework itself
        if (context.File.Path.Contains("flask", StringComparison.OrdinalIgnoreCase))
            return;
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!HasErrorhandler(function))
                continue;
            var returnsTuple = function.OfKind(NodeKind.Tuple).Any();
            var returnsAbort = function.OfKind(NodeKind.Invocation)
                .Any(i => Simple(i.Text) == "abort");
            if (returnsTuple || returnsAbort)
                continue;
            context.Report(function, $"'{function.Text}' handles an HTTP error but never sets a "
                                     + "status code: Flask answers 200 OK for a failure. Return "
                                     + "(body, code) or call abort().");
        }
    }

    private static bool HasErrorhandler(SyntaxNode function)
        => function.ChildrenOf(NodeKind.Attribute)
            .Any(a => a.Text.Contains("errorhandler", StringComparison.OrdinalIgnoreCase));
}

public sealed class PyAsyncBlockingSleepRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0161";
    public override string Name => "time.sleep blocks the event loop inside async code";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!function.Tokens.Any(t => t.Text == "async"))
                continue;
            foreach (var invocation in function.OfKind(NodeKind.Invocation))
            {
                var name = Simple(invocation.Text);
                var blocking = name == "sleep"
                               && !invocation.Tokens.Any(t => t.Text == "await");
                if (!blocking)
                    continue;
                context.Report(invocation, "time.sleep() inside async code freezes the whole event "
                                           + "loop for the sleep duration. Await asyncio.sleep().");
            }
        }
    }
}

public sealed class PyAsyncLambdaHandlerRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0183";
    public override string Name => "An AWS Lambda handler cannot be async";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (function.Text != "handler" && !function.Text.EndsWith("_handler", StringComparison.Ordinal))
                continue;
            if (!function.Tokens.Any(t => t.Text == "async"))
                continue;
            context.Report(function, "The Lambda runtime calls handlers synchronously and ignores "
                                     + "the returned coroutine: the function never completes. Run "
                                     + "asyncio.run(...) inside a plain handler.");
        }
    }
}

public sealed class PySendFileMimetypeRule : PyGap2Base
{
    public override string Key => "QG-PY-BUG-0079";
    public override string Name => "send_file should say what the bytes are";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (Simple(invocation.Text) != "send_file")
                continue;
            var arguments = invocation.FirstChild(NodeKind.ArgumentList);
            var named = arguments?.Descendants()
                .Any(d => d.Kind == NodeKind.NamedArgument
                          && (d.Text.StartsWith("mimetype") || d.Text.StartsWith("download_name")));
            if (named == true)
                continue;
            context.Report(invocation, "send_file() without mimetype guesses from the filename and "
                                       + "answers application/octet-stream: browsers refuse to open "
                                       + "it. Pass mimetype or download_name.");
        }
    }
}

public sealed class PySortedIndexMinMaxRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0210";
    public override string Name => "sorted(...)[0] is min(), [-1] is max()";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var index in context.Root.OfKind(NodeKind.Index))
        {
            var callee = index.ChildAt(0);
            if (callee?.Kind != NodeKind.Invocation || Simple(callee.Text) != "sorted")
                continue;
            var subscript = index.ChildAt(1)?.Text;
            if (subscript is not ("0" or "-1"))
                continue;
            var suggestion = subscript == "0" ? "min()" : "max()";
            context.Report(index, "Sorting the whole sequence to take one end costs n log n for what "
                                  + $"{suggestion} does in one pass.");
        }
    }
}

public sealed class PyTryExceptFailRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0217";
    public override string Name => "Use pytest.raises instead of try/except with fail()";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var catchClause in context.Root.OfKind(NodeKind.Catch))
        {
            if (!catchClause.OfKind(NodeKind.Invocation).Any(i => Simple(i.Text) == "fail"))
                continue;
            context.Report(catchClause, "try/except that ends in fail() reimplements pytest.raises: "
                                        + "the context manager also checks the exception TYPE.");
        }
    }
}

public sealed class PyParametrizeEmptyRule : PyGap2Base
{
    public override string Key => "QG-PY-BUG-0127";
    public override string Name => "@parametrize with an empty list runs the test zero times";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            foreach (var attribute in function.ChildrenOf(NodeKind.Attribute))
            {
                if (!attribute.Text.Contains("parametrize", StringComparison.Ordinal))
                    continue;
                foreach (var literal in attribute.Descendants()
                             .Where(n => n.Kind == NodeKind.ListLiteral))
                {
                    if (literal.Children.Count == 0)
                    {
                        context.Report(attribute, "This parametrize carries no cases: the test below "
                                                  + "is skipped without ever being reported as "
                                                  + "skipped.");
                        break;
                    }
                }
            }
        }
    }
}

public sealed class PyRaisesAsStatementRule : PyGap2Base
{
    public override string Key => "QG-PY-BUG-0128";
    public override string Name => "pytest.raises must wrap the call as a context manager";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tokens.Any(t =>
                t.Kind == TokenKind.Identifier && t.Text == "pytest"))
            return;
        foreach (var statement in context.Root.OfKind(NodeKind.ExpressionStatement))
        {
            var head = statement.ChildAt(0);
            if (head?.Kind != NodeKind.Invocation || Simple(head.Text) != "raises")
                continue;
            context.Report(statement, "Calling raises(...) on its own asserts nothing: the exception "
                                      + "still escapes uncaught. Use 'with pytest.raises(...)'.");
        }
    }
}

public sealed class PyFailWithoutMessageRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0230";
    public override string Name => "pytest.fail should say why";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (Simple(invocation.Text) != "fail")
                continue;
            var arguments = invocation.FirstChild(NodeKind.ArgumentList);
            if (arguments == null || arguments.Children.Count > 0)
                continue;
            context.Report(invocation, "A bare fail() reports a failure nobody can act on: pass the "
                                       + "reason the test could not continue.");
        }
    }
}

public sealed class PyDuplicateParametrizeCasesRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0231";
    public override string Name => "parametrize cases should not repeat";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var attribute in context.Root.OfKind(NodeKind.Attribute))
        {
            if (!attribute.Text.Contains("parametrize", StringComparison.Ordinal))
                continue;
            foreach (var literal in attribute.Descendants()
                         .Where(n => n.Kind == NodeKind.ListLiteral && n.Children.Count > 1))
            {
                var signatures = literal.Children.Select(c => c.SourceText()).ToList();
                if (signatures.Distinct().Count() == signatures.Count)
                    continue;
                context.Report(literal, "This parametrize lists the same case twice: the duplicate "
                                        + "runs again and inflates the pass count without testing "
                                        + "anything new.");
                break;
            }
        }
    }
}

public sealed class PyPatchWithLambdaReturnRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0232";
    public override string Name => "Patch with return_value, not a lambda that only returns";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (Simple(invocation.Text) != "patch")
                continue;
            foreach (var lambda in invocation.Descendants().Where(n => n.Kind == NodeKind.Lambda))
            {
                var body = lambda.ChildAt(lambda.Children.Count - 1);
                if (body?.Kind is NodeKind.Identifier or NodeKind.NumberLiteral
                    or NodeKind.StringLiteral or NodeKind.NullLiteral)
                {
                    context.Report(invocation, "A lambda that only returns a constant is Mock "
                                              + "vocabulary: pass return_value=… so the mock keeps "
                                              + "its recording behaviour.");
                    break;
                }
            }
        }
    }
}

public sealed class PyImportPytestAliasedRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0234";
    public override string Name => "Import pytest under its own name";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var import in context.Root.OfKind(NodeKind.ImportDeclaration))
        {
            if (!import.Text.Contains("pytest", StringComparison.Ordinal)
                || !import.Text.Contains(" as ", StringComparison.Ordinal))
                continue;
            context.Report(import, "Aliasing pytest breaks every reader's expectation and every "
                                   + "snippet copied from the docs. Import it plainly.");
        }
    }
}

public sealed class PyTestDefaultParametersRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0238";
    public override string Name => "Test parameters should not carry defaults";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        if (IsTestFile(context.File.Path))
            return;
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!function.Text.StartsWith("test_", StringComparison.Ordinal))
                continue;
            foreach (var parameter in function.FirstChild(NodeKind.ParameterList)?
                         .ChildrenOf(NodeKind.Parameter) ?? [])
            {
                if (!parameter.Descendants().Any(d => d.Kind == NodeKind.Assignment))
                    continue;
                context.Report(parameter, $"'{parameter.Text}' defaults silently: parametrize is the "
                                          + "tool for feeding variants to a test.");
            }
        }
    }

    private static bool IsTestFile(string path)
        => path.Contains("test", StringComparison.OrdinalIgnoreCase);
}

public sealed class PyNoneComparedToNoneRule : PyGap2Base
{
    public override string Key => "QG-PY-SML-0080";
    public override string Name => "Comparing two constants tells nothing";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["py"];

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("==" or "!=" or "is" or "is not"))
                continue;
            var left = binary.ChildAt(0);
            var right = binary.ChildAt(binary.Children.Count - 1);
            if (left?.Kind != NodeKind.NullLiteral || right?.Kind != NodeKind.NullLiteral)
                continue;
            context.Report(binary, "Both sides are the literal None: the result is decided before "
                                  + "the program runs. One of the operands was meant to be a value.");
        }
    }
}
