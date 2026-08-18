using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// The third JavaScript and TypeScript wave: what the code does with the values it has. A string
/// method whose result is thrown away, a constant assigned again, a typeof compared to a word that
/// can never come back, a union that lists the same type twice.
/// </summary>
public static class JsTsUsageRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        // QG-JS-BUG-0136 was "a constant should not be assigned again". Deciding it needs the
        // scope a name belongs to: the same identifier is const in one function and let in
        // another, and matching by name reported 151 of those on a real corpus. The compiler and
        // every bundler already refuse a real one, so the rule is gone and its number stays retired.
        new JsInvalidTypeofComparisonRule(),
        new JsForInOverArrayRule(),
        new JsSparseArrayRule(),
        new JsSelfAssignmentRule(),
        new JsRedeclaredVariableRule(),
        new JsFunctionConstructorRule(),
        new JsDuplicateUnionMemberRule(),
        new JsObjectShorthandRule(),
        new JsConcatenationInsteadOfTemplateRule(),
        new JsArgumentsObjectRule(),
        new JsNestedTemplateRule(),
        new JsAnyTypeRule(),
        new JsSplitImportRule(),
        new JsLoneAccessorRule()
    ];
}

public abstract class JsTsUsageRuleBase : RuleBase
{
    public override string[] Languages => ["js", "ts"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static string SourceLine(IRuleContext context, int line)
    {
        var lines = LanguageRuleSupport.Lines(context);
        return line - 1 >= 0 && line - 1 < lines.Length ? lines[line - 1] : string.Empty;
    }

    protected static bool IsTypeScript(IRuleContext context)
        => context.File.FileName.EndsWith(".ts", StringComparison.OrdinalIgnoreCase)
           || context.File.FileName.EndsWith(".tsx", StringComparison.OrdinalIgnoreCase);
}

public sealed class JsIgnoredStringResultRule : JsTsUsageRuleBase
{
    /// <summary>String methods that answer with a new string and change nothing.</summary>
    private static readonly string[] Pure =
    [
        "trim", "trimStart", "trimEnd", "toUpperCase", "toLowerCase", "replace", "replaceAll",
        "slice", "substring", "substr", "concat", "padStart", "padEnd", "repeat", "normalize",
        "toLocaleUpperCase", "toLocaleLowerCase"
    ];

    public override string Key => "QG-JS-BUG-0135";
    public override string Name => "The result of a string operation should be used";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var statement in context.Root.OfKind(NodeKind.ExpressionStatement))
        {
            if (statement.Children.Count != 1)
                continue;
            var call = statement.Children[0];
            if (call is not { Kind: NodeKind.Invocation })
                continue;
            if (!Pure.Contains(SyntaxQuery.InvokedName(call)))
                continue;
            // a receiver is required: a bare replace(...) is a function of the file, not a string
            var receiver = SyntaxQuery.Receiver(call);
            if (receiver.Length == 0)
                continue;
            // The statement has to be the whole line. Optional chaining splits an expression into
            // pieces, and the tail of 'const x = a?.b?.trim();' arrives here looking like a
            // statement of its own — with its result very much used.
            var line = SourceLine(context, statement.Range.StartLine).TrimStart();
            if (!line.StartsWith(receiver.Split('.')[0], StringComparison.Ordinal))
                continue;

            context.Report($"'{SyntaxQuery.InvokedName(call)}' returns a new string and leaves the "
                           + "original exactly as it was, so this statement changes nothing at all. "
                           + "Assign the result.", statement.Range.StartLine);
        }
    }
}

public sealed class JsInvalidTypeofComparisonRule : JsTsUsageRuleBase
{
    private static readonly string[] Valid =
    [
        "undefined", "object", "boolean", "number", "bigint", "string", "symbol", "function"
    ];

    public override string Key => "QG-JS-BUG-0137";
    public override string Name => "typeof should be compared to a type it can return";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var comparison in context.Root.OfKind(NodeKind.Binary))
        {
            if (comparison.Text is not ("==" or "===" or "!=" or "!=="))
                continue;
            var typeofSide = comparison.Children.FirstOrDefault(
                c => c is { Kind: NodeKind.Unary, Text: "typeof" });
            var literal = comparison.Children.FirstOrDefault(c => c.Kind == NodeKind.StringLiteral);
            if (typeofSide == null || literal == null)
                continue;
            if (Valid.Contains(literal.Text))
                continue;

            context.Report($"typeof never answers '{literal.Text}', so this comparison is false every "
                           + "time and the branch behind it is unreachable. The answers it can give "
                           + "are undefined, object, boolean, number, bigint, string, symbol and "
                           + "function.", comparison.Range.StartLine);
        }
    }
}

public sealed class JsForInOverArrayRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-BUG-0138";
    public override string Name => "An array should not be walked with for-in";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            var line = SourceLine(context, loop.Range.StartLine);
            if (!line.Contains(" in ", StringComparison.Ordinal))
                continue;
            if (line.Contains(" of ", StringComparison.Ordinal))
                continue;
            // the collection has to be visibly an array
            var source = loop.OfKind(NodeKind.ListLiteral, NodeKind.Invocation)
                .FirstOrDefault(n => n.Kind == NodeKind.ListLiteral
                                     || SyntaxQuery.InvokedName(n) is "map" or "filter" or "concat"
                                         or "slice" or "split");
            if (source == null)
                continue;

            context.Report("for-in walks the keys of an object, so over an array it produces the "
                           + "indexes as strings — and everything a library added to Array.prototype "
                           + "along with them. Use for-of, or forEach.", loop.Range.StartLine);
        }
    }
}

public sealed class JsSparseArrayRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-BUG-0139";
    public override string Name => "An array literal should not have a hole in it";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 1; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Kind != TokenKind.Symbol || tokens[i].Text != ",")
                continue;
            if (tokens[i + 1].Kind != TokenKind.Symbol || tokens[i + 1].Text != ",")
                continue;
            // the pair has to sit inside an array literal, not in an argument list
            if (!InsideArrayLiteral(tokens, i))
                continue;

            context.Report("The two commas leave a hole: the array has an element there that does not "
                           + "exist, which reads as undefined but is skipped by forEach, map and "
                           + "filter — so half the code sees it and half does not. Write the value, or "
                           + "remove the comma.", tokens[i].Line);
        }
    }

    private static bool InsideArrayLiteral(IReadOnlyList<Token> tokens, int index)
    {
        var depth = 0;
        for (var i = index; i >= 0 && index - i < 256; i--)
        {
            var text = tokens[i].Text;
            if (tokens[i].Kind != TokenKind.Symbol)
                continue;
            if (text is "]" or ")" or "}")
                depth++;
            else if (text is "[" or "(" or "{")
            {
                if (depth == 0)
                    return text == "[";
                depth--;
            }
        }
        return false;
    }
}

public sealed class JsSelfAssignmentRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-BUG-0140";
    public override string Name => "A value should not be assigned to itself";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            if (assignment.Text != "=")
                continue;
            // a declaration is not a self-assignment, whatever its initializer looks like
            if (assignment.Parent is { Kind: NodeKind.VariableDeclaration })
                continue;

            var target = PureChain(assignment.ChildAt(0));
            var value = PureChain(assignment.ChildAt(1));
            if (target.Length == 0 || target != value)
                continue;
            // a property taking the parameter of the same name is the constructor idiom
            if (target.StartsWith("this.", StringComparison.Ordinal))
                continue;

            context.Report($"'{target}' is assigned to itself, so the statement does nothing. One of "
                           + "the two names is almost certainly meant to be a different one.",
                assignment.Range.StartLine);
        }
    }

    /// <summary>
    /// The dotted name of a node when it is nothing but identifiers joined by dots. A cast, a call
    /// or an index in the chain gives an empty answer: 'const source = (child as Root).source' is
    /// not a self-assignment, and reading only the last name would say it is.
    /// </summary>
    private static string PureChain(SyntaxNode? node)
    {
        if (node == null)
            return string.Empty;
        if (node.Kind == NodeKind.Identifier)
            return node.Text;
        if (node.Kind != NodeKind.MemberSelect)
            return string.Empty;

        foreach (var part in node.DescendantsAndSelf())
        {
            if (part.Kind is not (NodeKind.MemberSelect or NodeKind.Identifier))
                return string.Empty;
        }
        return SyntaxQuery.DottedName(node);
    }
}

public sealed class JsRedeclaredVariableRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-BUG-0141";
    public override string Name => "A name should be declared once in its scope";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var block in context.Root.OfKind(NodeKind.Block, NodeKind.TopLevel))
        {
            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var declaration in block.ChildrenOf(NodeKind.VariableDeclaration))
            {
                var name = declaration.Text;
                if (name.Length == 0)
                    continue;
                var line = SourceLine(context, declaration.Range.StartLine).TrimStart();
                // only the block-scoped forms: var is allowed to repeat, however unwise that is
                if (!line.StartsWith("let ", StringComparison.Ordinal)
                    && !line.StartsWith("const ", StringComparison.Ordinal))
                    continue;

                if (seen.TryGetValue(name, out var first))
                {
                    context.Report($"'{name}' is already declared on line {first} in this same block, "
                                   + "which a module refuses to load at all — the error arrives before "
                                   + "any of this code runs.", declaration.Range.StartLine);
                    continue;
                }
                seen[name] = declaration.Range.StartLine;
            }
        }
    }
}

public sealed class JsFunctionConstructorRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-SEC-0079";
    public override string Name => "Code should not be built from a string";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var unary in context.Root.OfKind(NodeKind.Unary))
        {
            if (unary.Text != "new")
                continue;
            var target = unary.ChildAt(0);
            var name = target?.Kind == NodeKind.Invocation
                ? SyntaxQuery.InvokedName(target)
                : SyntaxQuery.SimpleName(target);
            if (name != "Function")
                continue;

            context.Report("The Function constructor compiles its argument, so whatever ends up in "
                           + "that string becomes code with the privileges of the page. It also runs "
                           + "in the global scope, ignores every local the reader can see, and is "
                           + "blocked by any content security policy worth having.",
                unary.Range.StartLine);
        }
    }
}

public sealed class JsDuplicateUnionMemberRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-BUG-0142";
    public override string Name => "A union should not list the same type twice";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!IsTypeScript(context) || !HasTree(context))
            return;

        // the parser keeps the whole union in the text of the type reference, which is far more
        // reliable than looking for a pipe on the line — a line can hold several types
        foreach (var type in context.Root.OfKind(NodeKind.TypeReference))
        {
            var text = type.Text;
            if (!text.Contains('|'))
                continue;

            var parts = text.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length < 2)
                continue;

            var seen = new HashSet<string>(StringComparer.Ordinal);
            var repeated = parts.FirstOrDefault(p => !seen.Add(p));
            if (repeated == null)
                continue;

            context.Report($"'{repeated}' appears twice in this union, which says nothing more than "
                           + "listing it once. One of the two was meant to be a different type.",
                type.Range.StartLine);
        }
    }
}

public sealed class JsObjectShorthandRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-SML-0365";
    public override string Name => "A property with the same name as its value should use shorthand";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var literal in context.Root.OfKind(NodeKind.ListLiteral, NodeKind.ObjectInitializer))
        {
            foreach (var property in literal.ChildrenOf(NodeKind.Assignment))
            {
                if (property.Text != ":")
                    continue;
                var name = SyntaxQuery.SimpleName(property.ChildAt(0));
                var value = property.ChildAt(1);
                if (name.Length == 0 || value is not { Kind: NodeKind.Identifier } || value.Text != name)
                    continue;

                context.Report($"'{name}: {name}' says the same thing twice. Write just '{name}'.",
                    property.Range.StartLine);
            }
        }
    }
}

public sealed class JsConcatenationInsteadOfTemplateRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-SML-0366";
    public override string Name => "A message built from parts should be a template literal";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var concatenation in context.Root.OfKind(NodeKind.Binary))
        {
            if (concatenation.Text != "+")
                continue;
            // only the top of the chain, so a long concatenation is reported once
            if (concatenation.Parent is { Kind: NodeKind.Binary, Text: "+" })
                continue;

            var pieces = concatenation.OfKind(NodeKind.StringLiteral, NodeKind.Identifier,
                NodeKind.MemberSelect, NodeKind.Invocation).ToList();
            var literals = pieces.Count(p => p.Kind == NodeKind.StringLiteral);
            if (literals < 2 || pieces.Count - literals < 2)
                continue;

            context.Report("This message is assembled from four pieces or more, so the reader has to "
                           + "rebuild the sentence from the operators. A template literal shows it as "
                           + "it will read.", concatenation.Range.StartLine);
        }
    }
}

public sealed class JsArgumentsObjectRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-SML-0367";
    public override string Name => "Rest parameters should replace the arguments object";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Kind is not (TokenKind.Identifier or TokenKind.Keyword)
                || tokens[i].Text != "arguments")
                continue;
            // a property named arguments, or one being declared, is a different thing
            if (i > 0 && tokens[i - 1].Text == ".")
                continue;
            if (i + 1 < tokens.Count && tokens[i + 1].Text is ":" or "=")
                continue;

            context.Report("The arguments object is array-like and not an array, so it has no map, no "
                           + "filter and no forEach, and it does not exist at all inside an arrow "
                           + "function — where it silently refers to the enclosing one instead. "
                           + "Declare a rest parameter.", tokens[i].Line);
        }
    }
}

public sealed class JsNestedTemplateRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-SML-0368";
    public override string Name => "A template literal should not be nested in another";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var placeholder = line.IndexOf("${", StringComparison.Ordinal);
            if (placeholder < 0)
                continue;
            var close = line.IndexOf('}', placeholder);
            if (close < 0)
                continue;
            if (!line[(placeholder + 2)..close].Contains('`'))
                continue;

            context.Report("A template inside a placeholder of another template puts two levels of "
                           + "escaping on one line, and the reader has to work out which backtick "
                           + "closes which. Compute the inner text into a name first.", i + 1);
        }
    }
}

public sealed class JsAnyTypeRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-SML-0369";
    public override string Name => "The any type gives up the type system";
    public override Severity Severity => Severity.Minor;
    public override string[] Languages => ["ts"];

    public override void Execute(IRuleContext context)
    {
        if (!IsTypeScript(context))
            return;

        var lines = LanguageRuleSupport.Lines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var cut = line.IndexOf("//", StringComparison.Ordinal);
            var code = cut >= 0 ? line[..cut] : line;
            if (!LanguageRuleSupport.ContainsWord(code, "any"))
                continue;
            // only a type position: ": any", "<any>", "as any", "any[]"
            if (!code.Contains(": any", StringComparison.Ordinal)
                && !code.Contains("<any", StringComparison.Ordinal)
                && !code.Contains("as any", StringComparison.Ordinal)
                && !code.Contains("any[]", StringComparison.Ordinal))
                continue;

            context.Report("'any' switches the checker off for this value: every property access on "
                           + "it, every call, every argument built from it goes unverified, and the "
                           + "hole spreads to everything the value touches. Use unknown when the type "
                           + "is genuinely not known, and narrow it before use.", i + 1);
        }
    }
}

public sealed class JsSplitImportRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-SML-0370";
    public override string Name => "Imports from one module should be written once";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        var seen = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var import in context.Root.OfKind(NodeKind.ImportDeclaration))
        {
            var line = SourceLine(context, import.Range.StartLine);
            var from = ModuleName(line);
            if (from.Length == 0)
                continue;
            // a type-only import is a separate statement on purpose
            if (line.Contains("import type", StringComparison.Ordinal))
                continue;

            if (seen.TryGetValue(from, out var first))
            {
                context.Report($"'{from}' is already imported on line {first}. Two import statements "
                               + "for one module mean the reader has to look in two places to know "
                               + "what this file takes from it.", import.Range.StartLine);
                continue;
            }
            seen[from] = import.Range.StartLine;
        }
    }

    private static string ModuleName(string line)
    {
        var from = line.LastIndexOf(" from ", StringComparison.Ordinal);
        var text = from >= 0 ? line[(from + 6)..] : line;
        var start = text.IndexOfAny(['\'', '"']);
        if (start < 0)
            return string.Empty;
        var end = text.IndexOfAny(['\'', '"'], start + 1);
        return end > start ? text[(start + 1)..end] : string.Empty;
    }
}

public sealed class JsLoneAccessorRule : JsTsUsageRuleBase
{
    public override string Key => "QG-JS-SML-0371";
    public override string Name => "A setter without a getter should not exist";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            var getters = new HashSet<string>(StringComparer.Ordinal);
            var setters = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var accessor in body.ChildrenOf(NodeKind.Accessor))
            {
                var name = AccessorName(context, accessor);
                if (name.Length == 0)
                    continue;
                if (accessor.Text == "get")
                    getters.Add(name);
                else if (accessor.Text == "set")
                    setters[name] = accessor.Range.StartLine;
            }

            foreach (var (name, line) in setters)
            {
                if (getters.Contains(name))
                    continue;

                context.Report($"'{name}' can be set and never read, so a caller has no way to check "
                               + "what the assignment did or to put the old value back. Add the "
                               + "getter, or expose a method named for the effect.", line);
            }
        }
    }

    private static string AccessorName(IRuleContext context, SyntaxNode accessor)
    {
        var line = SourceLine(context, accessor.Range.StartLine).Trim();
        var start = line.IndexOf(' ');
        if (start < 0)
            return string.Empty;
        var rest = line[(start + 1)..].TrimStart();
        var end = rest.IndexOfAny(['(', ' ']);
        return end > 0 ? rest[..end] : rest;
    }
}
