using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// PHP on the tree. PHP has a real parser here, so these rules read declarations, catches and calls.
/// Most of what they find is code the interpreter accepts and that behaves differently from how it
/// reads — a reference that survives its loop, a name built from another name, an error silenced by
/// a single character.
/// </summary>
public static class PhpAstRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PhpAssignmentInConditionRule(),
        new PhpRepeatedArgumentRule(),
        new PhpVariableVariableRule(),
        new PhpDeprecatedPredefinedVariableRule(),
        new PhpLegacyConstructorRule(),
        new PhpThisInStaticContextRule(),
        new PhpUnreachableCatchRule(),
        new PhpConstantConditionRule(),
        new PhpThrowNonThrowableRule(),
        new PhpForeachReferenceRule(),
        new PhpRedefinedConstantRule(),
        new PhpSilencedErrorRule(),
        new PhpVarKeywordRule(),
        new PhpMultiplePropertiesRule(),
        new PhpImplicitVisibilityRule(),
        new PhpDefaultArgumentOrderRule(),
        new PhpExitStatementRule(),
        new PhpAliasFunctionRule()
    ];
}

public abstract class PhpAstRuleBase : RuleBase
{
    public override string[] Languages => ["php"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static HashSet<string> Modifiers(SyntaxNode declaration)
        => declaration.ChildrenOf(NodeKind.Modifier)
            .Select(m => m.Text.ToLowerInvariant())
            .ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// Every function in a file. A function written at the top level of a PHP file is a
    /// LocalFunction, not a FunctionDeclaration — only the methods of a class get the latter — so a
    /// rule that iterates one kind quietly ignores half the language.
    /// </summary>
    protected static IEnumerable<SyntaxNode> Functions(SyntaxNode root)
        => root.OfKind(NodeKind.FunctionDeclaration, NodeKind.LocalFunction);

    protected static IEnumerable<SyntaxNode> Members(SyntaxNode type)
        => type.FirstChild(NodeKind.Block)?.Children ?? [];

    /// <summary>
    /// The name a call invokes. In PHP the parser does not always give the invocation an identifier
    /// child — the name is on the node itself — so both places are read.
    /// </summary>
    protected static string CalledName(SyntaxNode call)
    {
        var named = SyntaxQuery.InvokedName(call);
        return named.Length > 0 ? named : call.Text;
    }

    protected static string SourceLine(IRuleContext context, int line)
    {
        var lines = LanguageRuleSupport.Lines(context);
        return line - 1 >= 0 && line - 1 < lines.Length ? lines[line - 1] : string.Empty;
    }
}

public sealed class PhpVariableVariableRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-BUG-0039";
    public override string Name => "A variable name should not be computed";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            // the tokenizer keeps the dollar inside the name, so a variable variable arrives whole
            if (token.Kind is not (TokenKind.Identifier or TokenKind.Keyword))
                continue;
            if (!token.Text.StartsWith("$$", StringComparison.Ordinal))
                continue;

            context.Report("The name of the variable is decided while the program runs, so nothing "
                           + "before that point knows what is being read or written: no editor, no "
                           + "search, no reader. When the name comes from a request it is also a way "
                           + "into every other variable in scope. Use an array keyed on the name.",
                token.Line);
        }
    }
}

public sealed class PhpDeprecatedPredefinedVariableRule : PhpAstRuleBase
{
    private static readonly string[] Removed =
    [
        "HTTP_GET_VARS", "HTTP_POST_VARS", "HTTP_COOKIE_VARS", "HTTP_SERVER_VARS",
        "HTTP_ENV_VARS", "HTTP_POST_FILES", "HTTP_SESSION_VARS", "php_errormsg"
    ];

    public override string Key => "QG-PP-BUG-0040";
    public override string Name => "A variable removed from the language should not be used";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (token.Kind is not (TokenKind.Identifier or TokenKind.Keyword))
                continue;
            if (!Removed.Contains(token.Text.TrimStart('$')))
                continue;

            context.Report($"'{token.Text.TrimStart('$')}' was removed from PHP years ago, so it now reads as an "
                           + "undefined variable: the code takes an empty value and carries on. Use "
                           + "the superglobal that replaced it.", token.Line);
        }
    }
}

public sealed class PhpLegacyConstructorRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-BUG-0041";
    public override string Name => "A constructor should be named __construct";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (type.Text.Length == 0)
                continue;
            var hasModern = Members(type).Any(m => m.Kind == NodeKind.ConstructorDeclaration
                                                   || (m.Kind == NodeKind.FunctionDeclaration
                                                       && m.Text == "__construct"));
            foreach (var method in Members(type))
            {
                if (method.Kind != NodeKind.FunctionDeclaration
                    || !string.Equals(method.Text, type.Text, StringComparison.OrdinalIgnoreCase))
                    continue;

                context.Report(hasModern
                    ? $"'{method.Text}' has the name of its class, which used to make it the "
                      + "constructor. The class already declares __construct, so this method is now "
                      + "an ordinary one that nobody calls."
                    : $"'{method.Text}' is a constructor in the PHP 4 style. Since PHP 8 it is an "
                      + "ordinary method, so the class is now built without running any of this — "
                      + "silently, with every field left unset. Rename it to __construct.",
                    method.Range.StartLine);
            }
        }
    }
}

public sealed class PhpThisInStaticContextRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-BUG-0042";
    public override string Name => "A static method has no instance";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in Functions(context.Root))
        {
            if (!Modifiers(method).Contains("static"))
                continue;
            var body = SyntaxQuery.Body(method);
            if (body == null)
                continue;

            foreach (var identifier in body.OfKind(NodeKind.Identifier))
            {
                // PHP keeps the dollar in the name of a variable
                if (identifier.Text is not ("$this" or "this"))
                    continue;
                if (SyntaxQuery.EnclosingFunction(identifier) != method)
                    continue;

                context.Report($"'{method.Text}' is static, so it runs without an instance and $this "
                               + "does not exist inside it. The call throws as soon as the line is "
                               + "reached. Use self:: or static:: for the class, or drop the static "
                               + "modifier.", identifier.Range.StartLine);
                break;
            }
        }
    }
}

public sealed class PhpUnreachableCatchRule : PhpAstRuleBase
{
    private static readonly Dictionary<string, string[]> CoveredBy = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Exception"] = ["Throwable"],
        ["Error"] = ["Throwable"],
        ["RuntimeException"] = ["Throwable", "Exception"],
        ["LogicException"] = ["Throwable", "Exception"],
        ["InvalidArgumentException"] = ["Throwable", "Exception", "LogicException"],
        ["OutOfRangeException"] = ["Throwable", "Exception", "LogicException"],
        ["TypeError"] = ["Throwable", "Error"],
        ["ValueError"] = ["Throwable", "Error"],
        ["ArithmeticError"] = ["Throwable", "Error"],
        ["DivisionByZeroError"] = ["Throwable", "Error", "ArithmeticError"],
        ["PDOException"] = ["Throwable", "Exception", "RuntimeException"]
    };

    public override string Key => "QG-PP-BUG-0043";
    public override string Name => "A catch clause should be reachable";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var tryNode in context.Root.OfKind(NodeKind.Try))
        {
            var caught = new List<(string Type, int Line)>();
            foreach (var catchNode in tryNode.OfKind(NodeKind.Catch))
            {
                foreach (var type in CaughtTypes(context, catchNode))
                {
                    var wider = caught.FirstOrDefault(
                        c => CoveredBy.TryGetValue(type, out var parents)
                             && (parents.Contains(c.Type, StringComparer.OrdinalIgnoreCase)
                                 || string.Equals(c.Type, type, StringComparison.OrdinalIgnoreCase)));
                    if (wider.Type != null)
                    {
                        context.Report($"'{type}' is already caught by the '{wider.Type}' clause on "
                                       + $"line {wider.Line}, which is tried first. Nothing reaches "
                                       + "this handler, so what it does for that case never happens.",
                            catchNode.Range.StartLine);
                    }
                    caught.Add((type, catchNode.Range.StartLine));
                }
            }
        }
    }

    private static IEnumerable<string> CaughtTypes(IRuleContext context, SyntaxNode catchNode)
    {
        var line = SourceLine(context, catchNode.Range.StartLine);
        var open = line.IndexOf('(');
        var close = line.IndexOf(')', open + 1);
        if (open < 0 || close <= open)
            return [];

        return line[(open + 1)..close]
            .Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.Split('$')[0].Trim().TrimStart('\\'))
            .Where(p => p.Length > 0)
            .ToList();
    }
}

public sealed class PhpConstantConditionRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-BUG-0044";
    public override string Name => "A condition should be able to go both ways";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var branch in context.Root.OfKind(NodeKind.If, NodeKind.Loop))
        {
            var condition = branch.ChildAt(0);
            if (condition is not { Kind: NodeKind.NumberLiteral or NodeKind.StringLiteral })
                continue;
            // while (true) is the deliberate infinite loop, and another rule has an opinion about it
            if (branch.Kind == NodeKind.Loop)
                continue;

            context.Report($"'{condition.Text}' is the same value every time, so this branch is decided "
                           + "before the program runs and one side of it is code nothing will ever "
                           + "execute.", branch.Range.StartLine);
        }
    }
}

public sealed class PhpRepeatedArgumentRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-BUG-0045";
    public override string Name => "The same value should not be passed twice to one call";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var arguments = SyntaxQuery.Arguments(call);
            if (arguments.Count < 2)
                continue;

            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            for (var i = 0; i < arguments.Count; i++)
            {
                var name = SyntaxQuery.DottedName(arguments[i]);
                // Only a variable. Two identical literals are perfectly normal, and a bare word in
                // this position means the parser lost its place in a very long file rather than that
                // the same value was passed twice.
                if (name.Length == 0 || !name.StartsWith('$'))
                    continue;
                if (arguments[i].Kind is not (NodeKind.Identifier or NodeKind.MemberSelect))
                    continue;
                if (seen.TryGetValue(name, out var first))
                {
                    context.Report($"'{name}' is passed as argument {first + 1} and again as argument "
                                   + $"{i + 1}. Either one of the two is meant to be a different "
                                   + "value, or the call takes fewer arguments than it appears to.",
                        call.Range.StartLine);
                    break;
                }
                seen[name] = i;
            }
        }
    }
}

public sealed class PhpAssignmentInConditionRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-BUG-0046";
    public override string Name => "A condition should not assign";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var branch in context.Root.OfKind(NodeKind.If))
        {
            var condition = branch.ChildAt(0);
            if (condition is not { Kind: NodeKind.Assignment } || condition.Text != "=")
                continue;

            context.Report("This condition writes a value and then tests it, which is one character "
                           + "away from a comparison — and reads like one. When it is deliberate the "
                           + "next reader still has to stop and decide whether it was.",
                branch.Range.StartLine);
        }
    }
}

public sealed class PhpThrowNonThrowableRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-BUG-0047";
    public override string Name => "Only a throwable should be thrown";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Blocker;

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
                or NodeKind.BooleanLiteral or NodeKind.ListLiteral))
                continue;

            context.Report("Only an object implementing Throwable can be thrown: this raises a fatal "
                           + "error instead, and the failure the code was reporting is replaced by one "
                           + "about the reporting.", jump.Range.StartLine);
        }
    }
}

public sealed class PhpForeachReferenceRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-BUG-0048";
    public override string Name => "A reference taken by foreach should be released";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!line.Contains("foreach", StringComparison.Ordinal))
                continue;
            var arrow = line.IndexOf("as", StringComparison.Ordinal);
            if (arrow < 0 || !line[arrow..].Contains('&'))
                continue;

            var name = ReferenceName(line[arrow..]);
            if (name.Length == 0)
                continue;
            if (IsUnset(lines, i + 1, name))
                continue;

            context.Report($"'{name}' still points at the last element when the loop ends, so the next "
                           + "loop that reuses the name overwrites that element instead of reading its "
                           + $"own — the classic PHP surprise where the last item is duplicated. Call "
                           + $"unset({name}) after the loop.", i + 1);
        }
    }

    private static string ReferenceName(string text)
    {
        var at = text.IndexOf('&');
        if (at < 0 || at + 1 >= text.Length || text[at + 1] != '$')
            return string.Empty;
        var end = at + 2;
        while (end < text.Length && (char.IsLetterOrDigit(text[end]) || text[end] == '_'))
            end++;
        return text[(at + 1)..end];
    }

    private static bool IsUnset(string[] lines, int from, string name)
    {
        for (var i = from; i < lines.Length; i++)
        {
            if (lines[i].Contains($"unset({name})", StringComparison.Ordinal)
                || lines[i].Contains($"unset( {name}", StringComparison.Ordinal))
                return true;
        }
        return false;
    }
}

public sealed class PhpRedefinedConstantRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-BUG-0049";
    public override string Name => "A constant should be defined once";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        var defined = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "define"))
        {
            var name = SyntaxQuery.ArgumentAt(call, 0);
            if (name is not { Kind: NodeKind.StringLiteral })
                continue;
            // the global function, not a method that happens to be called define
            if (SyntaxQuery.Receiver(call).Length > 0)
                continue;

            if (defined.TryGetValue(name.Text, out var first))
            {
                context.Report($"'{name.Text}' is already defined on line {first}. The second call does "
                               + "nothing except raise a warning, so the constant keeps the first "
                               + "value — which is rarely the one the later line intended.",
                    call.Range.StartLine);
                continue;
            }
            defined[name.Text] = call.Range.StartLine;
        }
    }
}

public sealed class PhpSilencedErrorRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-SEC-0066";
    public override string Name => "An error should not be silenced";
    public override IssueKind Kind => IssueKind.SecurityHotspot;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Symbol || tokens[i].Text != "@")
                continue;
            var next = tokens[i + 1];
            if (next.Column != tokens[i].Column + 1)
                continue;
            if (next.Kind is not (TokenKind.Identifier or TokenKind.Keyword) && next.Text != "$")
                continue;
            // an attribute is written #[...] and a doc tag lives in a comment, so neither reaches here
            if (i > 0 && tokens[i - 1].Text is "#" or "*")
                continue;

            context.Report("The at sign hides every warning and error the expression produces, "
                           + "including the ones nobody anticipated. The code then continues with a "
                           + "value it never checked, and the log has nothing in it. Handle the "
                           + "failure, or check the condition before the call.", tokens[i].Line);
        }
    }
}

public sealed class PhpVarKeywordRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-SML-0111";
    public override string Name => "A property should declare its visibility";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var field in context.Root.OfKind(NodeKind.FieldDeclaration))
        {
            // the parser drops the keyword, so the declaration line is what says it was written
            var line = SourceLine(context, field.Range.StartLine).TrimStart();
            if (!Modifiers(field).Contains("var")
                && !line.StartsWith("var ", StringComparison.Ordinal)
                && !line.StartsWith("var$", StringComparison.Ordinal))
                continue;

            context.Report("'var' is the PHP 4 way of declaring a property and means public. Say "
                           + "public, private or protected, so the reader knows which one was "
                           + "intended rather than inherited from an old habit.", field.Range.StartLine);
        }
    }
}

public sealed class PhpMultiplePropertiesRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-SML-0112";
    public override string Name => "One statement should declare one property";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var field in context.Root.OfKind(NodeKind.FieldDeclaration))
        {
            var line = SourceLine(context, field.Range.StartLine);
            var variables = line.Count(c => c == '$');
            if (variables < 2 || !line.Contains(',') || line.Contains("function", StringComparison.Ordinal))
                continue;

            context.Report("Several properties are declared in one statement, so a type, a default or "
                           + "a comment added to one of them has to be untangled from the rest first.",
                field.Range.StartLine);
        }
    }
}

public sealed class PhpImplicitVisibilityRule : PhpAstRuleBase
{
    private static readonly string[] Visibility = ["public", "private", "protected"];

    public override string Key => "QG-PP-SML-0113";
    public override string Name => "A method should declare its visibility";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            foreach (var method in Members(type))
            {
                if (method.Kind is not (NodeKind.FunctionDeclaration or NodeKind.ConstructorDeclaration))
                    continue;
                var modifiers = Modifiers(method);
                if (modifiers.Overlaps(Visibility) || modifiers.Contains("abstract"))
                    continue;
                var line = SourceLine(context, method.Range.StartLine);
                if (Visibility.Any(v => line.Contains(v, StringComparison.Ordinal)))
                    continue;

                context.Report($"'{method.Text}' declares no visibility, so it is public — and that is "
                               + "a decision about the surface of the class, taken by omission. Say "
                               + "which one it is.", method.Range.StartLine);
            }
        }
    }
}

public sealed class PhpDefaultArgumentOrderRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-SML-0114";
    public override string Name => "Parameters with a default should come last";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var function in Functions(context.Root))
        {
            var line = SourceLine(context, function.Range.StartLine);
            var open = line.IndexOf('(');
            var close = line.LastIndexOf(')');
            if (open < 0 || close <= open)
                continue;

            var parameters = line[(open + 1)..close]
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
            var defaulted = -1;
            for (var i = 0; i < parameters.Count; i++)
            {
                var parameter = parameters[i];
                if (parameter.StartsWith("...", StringComparison.Ordinal))
                    break;
                if (parameter.Contains('='))
                {
                    if (defaulted < 0)
                        defaulted = i;
                    continue;
                }
                if (defaulted < 0)
                    continue;

                context.Report("A parameter with a default is followed by one without, so the default "
                               + "can never be used: every caller has to pass it explicitly to reach "
                               + "the parameter after it.", function.Range.StartLine);
                break;
            }
        }
    }
}

public sealed class PhpExitStatementRule : PhpAstRuleBase
{
    public override string Key => "QG-PP-SML-0115";
    public override string Name => "A library should not end the process";
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        if (LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "exit", "die"))
        {
            // a script that is meant to be run, not included, may legitimately stop
            var inside = call.Ancestors().Any(a => a.Kind is NodeKind.FunctionDeclaration
                or NodeKind.LocalFunction or NodeKind.ClassDeclaration);
            if (!inside)
                continue;

            context.Report("Ending the process from inside a function stops everything: no response is "
                           + "finished, no destructor runs, no test that reaches this line can report "
                           + "what happened. Throw an exception and let the entry point decide.",
                call.Range.StartLine);
        }
    }
}

public sealed class PhpAliasFunctionRule : PhpAstRuleBase
{
    private static readonly Dictionary<string, string> Canonical = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sizeof"] = "count",
        ["is_writeable"] = "is_writable",
        ["join"] = "implode",
        ["key_exists"] = "array_key_exists",
        ["chop"] = "rtrim",
        ["doubleval"] = "floatval",
        ["fputs"] = "fwrite",
        ["ini_alter"] = "ini_set",
        ["is_real"] = "is_float",
        ["print_r"] = "print_r"
    };

    public override string Key => "QG-PP-SML-0116";
    public override string Name => "The canonical name of a function should be used";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = CalledName(call);
            if (!Canonical.TryGetValue(name, out var canonical) || canonical == name)
                continue;
            if (SyntaxQuery.Receiver(call).Length > 0)
                continue; // a method of your own that happens to share the name

            context.Report($"'{name}' is an old alias of '{canonical}'. Two names for one function "
                           + "split every search across the codebase, and only one of them appears in "
                           + "the documentation.", call.Range.StartLine);
        }
    }
}
