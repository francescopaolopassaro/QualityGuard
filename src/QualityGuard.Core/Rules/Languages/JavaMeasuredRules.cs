using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Java rules chosen by measurement: each closes a gap that <c>tools/compare_expectations.py</c>
/// found against an annotated reference corpus, taken from the checks whose expected lines we
/// covered least.
/// </summary>
public static class JavaMeasuredRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JavaControlCharacterInLiteralRule(),
        new JavaCharsetByNameRule(),
        new JavaDefaultEncodingRule(),
        new JavaConstantMathRule(),
        new JavaWeakKeySizeRule(),
        new JavaVolatileCompoundAssignmentRule(),
        new JavaEagerLogArgumentRule(),
        new JavaArrayCopyLoopRule(),
        new JavaSystemTimeInstantRule(),
        new JavaAbsoluteCommandPathRule(),
        new JavaInvalidDateValueRule(),
        new JavaFormatStringRule()
    ];
}

public abstract class JavaMeasuredRuleBase : RuleBase
{
    public override string[] Languages => ["java"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static string CreatedType(SyntaxNode creation)
    {
        var named = SyntaxQuery.SimpleName(creation.ChildAt(0));
        return named.Length > 0 ? named : creation.Text;
    }
}

public sealed class JavaControlCharacterInLiteralRule : JavaMeasuredRuleBase
{
    public override string Key => "QG-JV-BUG-0198";
    public override string Name => "A control character in a literal should be written as an escape";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (token.Kind != TokenKind.String)
                continue;
            var offender = token.Text.FirstOrDefault(IsInvisible);
            if (offender == '\0')
                continue;

            context.Report($"This literal contains the character U+{(int)offender:X4}, which nothing "
                           + "in the editor shows. A reader cannot tell it is there, a diff cannot "
                           + "show it changing, and a comparison against the same text typed by hand "
                           + "fails for no visible reason. Write it as an escape.", token.Line);
        }
    }

    /// <summary>
    /// Characters that carry meaning and show nothing. The ordinary space and the newline of a text
    /// block are excluded: those are visible in their effect and are written on purpose.
    /// </summary>
    private static bool IsInvisible(char c)
    {
        // space, tab, carriage return and newline are written on purpose and show in the layout
        if (c == 32 || c == 9 || c == 13 || c == 10)
            return false;
        if (char.IsControl(c))
            return true;
        // the invisible spaces and joiners that survive a copy out of a document
        return c is (char)0x00A0 or (char)0x200B or (char)0x200C or (char)0x200D
            or (char)0xFEFF or (char)0x2007 or (char)0x202F or (char)0x2060;
    }
}

public sealed class JavaCharsetByNameRule : JavaMeasuredRuleBase
{
    private static readonly Dictionary<string, string> Standard = new(StringComparer.OrdinalIgnoreCase)
    {
        ["UTF-8"] = "StandardCharsets.UTF_8",
        ["UTF8"] = "StandardCharsets.UTF_8",
        ["US-ASCII"] = "StandardCharsets.US_ASCII",
        ["ASCII"] = "StandardCharsets.US_ASCII",
        ["ISO-8859-1"] = "StandardCharsets.ISO_8859_1",
        ["UTF-16"] = "StandardCharsets.UTF_16",
        ["UTF-16BE"] = "StandardCharsets.UTF_16BE",
        ["UTF-16LE"] = "StandardCharsets.UTF_16LE"
    };

    public override string Key => "QG-JV-SML-0452";
    public override string Name => "A standard charset should be named by its constant";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "forName"))
        {
            if (!SyntaxQuery.Receiver(call).Contains("Charset", StringComparison.Ordinal))
                continue;
            var name = SyntaxQuery.ArgumentAt(call, 0);
            if (name is not { Kind: NodeKind.StringLiteral })
                continue;
            if (!Standard.TryGetValue(name.Text, out var constant))
                continue;

            context.Report($"'{name.Text}' is spelled out as a string, so a typo in it becomes an "
                           + $"UnsupportedCharsetException at run time. '{constant}' is checked by the "
                           + "compiler and needs no exception handling.", call.Range.StartLine);
        }
    }
}

public sealed class JavaDefaultEncodingRule : JavaMeasuredRuleBase
{
    private static readonly string[] EncodingSensitiveTypes =
        ["FileReader", "FileWriter", "InputStreamReader", "OutputStreamWriter", "PrintWriter",
         "PrintStream", "Formatter", "Scanner"];

    private static readonly string[] EncodingSensitiveCalls =
        ["getBytes", "toString"];

    public override string Key => "QG-JV-BUG-0199";
    public override string Name => "Text conversion should state its charset";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            var type = CreatedType(creation);
            var relevant = EncodingSensitiveTypes.Contains(type)
                           || (type == "String" && TakesBytes(creation));
            if (!relevant || MentionsCharset(creation))
                continue;

            context.Report($"'{type}' falls back to the platform's default charset, which differs "
                           + "between the machine that wrote the file and the one that reads it — and "
                           + "between a developer's laptop and the server. Pass the charset.",
                creation.Range.StartLine);
        }

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, EncodingSensitiveCalls))
        {
            if (SyntaxQuery.InvokedName(call) == "toString")
                continue; // only getBytes is unambiguous without types
            if (SyntaxQuery.Arguments(call).Count > 0)
                continue;

            context.Report("'getBytes' without a charset encodes with the platform default, so the "
                           + "same string becomes different bytes on a different machine.",
                call.Range.StartLine);
        }
    }

    private static bool TakesBytes(SyntaxNode creation)
    {
        var first = SyntaxQuery.Arguments(creation).FirstOrDefault();
        var name = first == null ? string.Empty : SyntaxQuery.DottedName(first);
        return name.Contains("byte", StringComparison.OrdinalIgnoreCase)
               || name.Contains("Bytes", StringComparison.Ordinal);
    }

    private static bool MentionsCharset(SyntaxNode creation)
        => creation.SourceText().Contains("Charset", StringComparison.Ordinal)
           || creation.SourceText().Contains("UTF", StringComparison.OrdinalIgnoreCase);
}

public sealed class JavaConstantMathRule : JavaMeasuredRuleBase
{
    public override string Key => "QG-JV-BUG-0200";
    public override string Name => "A mathematical call should not have a fixed answer";
    public override IssueKind Kind => IssueKind.Bug;

    /// <summary>A number, including the negative form the parser builds as a unary minus.</summary>
    private static SyntaxNode? NumberLiteral(SyntaxNode node)
    {
        if (node.Kind == NodeKind.NumberLiteral)
            return node;
        if (node is { Kind: NodeKind.Unary, Text: "-" } && node.ChildAt(0) is { Kind: NodeKind.NumberLiteral } inner)
            return inner;
        return null;
    }

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!SyntaxQuery.Receiver(call).EndsWith("Math", StringComparison.Ordinal))
                continue;
            var name = SyntaxQuery.InvokedName(call);
            var arguments = SyntaxQuery.Arguments(call);

            string? answer = null;
            if (arguments.Count == 2 && name is "max" or "min")
            {
                var first = SyntaxQuery.DottedName(arguments[0]);
                if (first.Length > 0 && first == SyntaxQuery.DottedName(arguments[1]))
                    answer = "the same value it was given twice";
            }
            else if (arguments.Count == 1 && NumberLiteral(arguments[0]) is { } literal)
            {
                answer = name switch
                {
                    "abs" or "ceil" or "floor" or "round" or "rint" => $"a value fixed at compile time by {literal.Text}",
                    _ => null
                };
            }
            if (answer == null)
                continue;

            context.Report($"'{name}' here always produces {answer}, so the call computes nothing. "
                           + "Either the wrong variable was passed, or the expression can be written "
                           + "as its result.", call.Range.StartLine);
        }
    }
}

public sealed class JavaWeakKeySizeRule : JavaMeasuredRuleBase
{
    public override string Key => "QG-JV-SEC-0069";
    public override string Name => "A cryptographic key should be long enough";
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "initialize", "setKeySize", "keySize"))
        {
            var size = SyntaxQuery.ArgumentAt(call, 0);
            if (size is not { Kind: NodeKind.NumberLiteral } || !int.TryParse(size.Text, out var bits))
                continue;
            // the RSA and DSA range: an EC key of 256 bits is strong, an RSA one of 256 is not
            var weak = bits is >= 512 and < 2048;
            if (!weak)
                continue;

            context.Report($"A {bits}-bit key is inside the range that is factored today with rented "
                           + "hardware. Whatever it protects is protected only until someone decides "
                           + "it is worth the cost. Use at least 2048 bits for RSA and DSA.",
                call.Range.StartLine);
        }
    }
}

public sealed class JavaVolatileCompoundAssignmentRule : JavaMeasuredRuleBase
{
    public override string Key => "QG-JV-BUG-0201";
    public override string Name => "A volatile field is not made atomic by being volatile";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            var volatiles = body.ChildrenOf(NodeKind.FieldDeclaration)
                .Where(f => f.ChildrenOf(NodeKind.Modifier)
                    .Any(m => m.Text.Equals("volatile", StringComparison.OrdinalIgnoreCase)))
                .Select(f => f.Text)
                .ToHashSet(StringComparer.Ordinal);
            if (volatiles.Count == 0)
                continue;

            foreach (var node in body.OfKind(NodeKind.Unary, NodeKind.Assignment))
            {
                var target = node.Kind == NodeKind.Unary
                    ? SyntaxQuery.SimpleName(node.ChildAt(0))
                    : SyntaxQuery.SimpleName(node.ChildAt(0));
                if (!volatiles.Contains(target))
                    continue;
                var compound = node.Kind == NodeKind.Unary
                    ? node.Text is "++" or "--"
                    : node.Text.Length > 1 && node.Text.EndsWith('=') && node.Text is not ("==" or "!=" or ">=" or "<=");
                if (!compound)
                    continue;

                context.Report($"'{target}' is volatile, which makes every read see the latest value "
                               + "and nothing more. This statement reads, computes and writes, and two "
                               + "threads doing it at once lose one of the updates. Use an atomic type "
                               + "or a lock.", node.Range.StartLine);
            }
        }
    }
}

public sealed class JavaEagerLogArgumentRule : JavaMeasuredRuleBase
{
    private static readonly string[] LogLevels =
        ["trace", "debug", "info", "warn", "error", "fine", "finer", "finest", "config", "severe"];

    public override string Key => "QG-JV-SML-0453";
    public override string Name => "A log message should be built only when it is written";
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (!LogLevels.Contains(name, StringComparer.OrdinalIgnoreCase))
                continue;
            var receiver = SyntaxQuery.Receiver(call);
            if (!receiver.Contains("log", StringComparison.OrdinalIgnoreCase))
                continue;

            var argument = SyntaxQuery.ArgumentAt(call, 0);
            if (argument is not { Kind: NodeKind.Binary } || argument.Text != "+")
                continue;
            if (!argument.OfKind(NodeKind.StringLiteral).Any())
                continue;

            context.Report($"The message is assembled before '{name}' is called, so the concatenation "
                           + "runs even when this level is switched off — which for a debug line is "
                           + "most of the time in production. Pass the parts as arguments and let the "
                           + "logger join them if it needs to.", call.Range.StartLine);
        }
    }
}

public sealed class JavaArrayCopyLoopRule : JavaMeasuredRuleBase
{
    public override string Key => "QG-JV-SML-0454";
    public override string Name => "An array should be copied by the library";
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            var body = loop.FirstChild(NodeKind.Block);
            if (body is not { Children.Count: 1 })
                continue;
            var statement = body.Children[0];
            var assignment = statement.Kind == NodeKind.ExpressionStatement
                ? statement.ChildAt(0)
                : statement;
            if (assignment is not { Kind: NodeKind.Assignment } || assignment.Text != "=")
                continue;
            if (assignment.ChildAt(0) is not { Kind: NodeKind.Index }
                || assignment.ChildAt(1) is not { Kind: NodeKind.Index })
                continue;

            context.Report("This loop copies one array into another, element by element. "
                           + "System.arraycopy does it in one call, with the bounds checked once "
                           + "instead of on every iteration, and says what is happening.",
                loop.Range.StartLine);
        }
    }
}

public sealed class JavaSystemTimeInstantRule : JavaMeasuredRuleBase
{
    public override string Key => "QG-JV-SML-0455";
    public override string Name => "The clock should be read through the type that represents it";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (name is not ("ofEpochMilli" or "ofEpochSecond"))
                continue;
            var argument = SyntaxQuery.ArgumentAt(call, 0);
            if (argument is not { Kind: NodeKind.Invocation })
                continue;
            if (SyntaxQuery.InvokedDottedName(argument) is not ("System.currentTimeMillis"
                or "System.nanoTime"))
                continue;

            context.Report("Reading the clock as a number and converting it back says in two steps "
                           + "what Instant.now() says in one — and the two steps can disagree about "
                           + "the unit.", call.Range.StartLine);
        }
    }
}

public sealed class JavaAbsoluteCommandPathRule : JavaMeasuredRuleBase
{
    public override string Key => "QG-JV-SML-0456";
    public override string Name => "An executable should be found on the path";
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "exec", "command"))
        {
            foreach (var argument in SyntaxQuery.Arguments(call))
            {
                if (argument is not { Kind: NodeKind.StringLiteral })
                    continue;
                var text = argument.Text;
                var absolute = text.StartsWith('/')
                               || (text.Length > 2 && char.IsAsciiLetter(text[0]) && text[1] == ':'
                                   && text[2] is '\\' or '/');
                if (!absolute)
                    continue;

                context.Report($"'{text}' names the executable by its full path, so the code only runs "
                               + "on a machine laid out exactly like this one — and it runs whatever "
                               + "sits at that path, which is a place an attacker with write access "
                               + "will look. Use the command name and let the path resolve it.",
                    call.Range.StartLine);
                break;
            }
        }
    }
}

public sealed class JavaInvalidDateValueRule : JavaMeasuredRuleBase
{
    /// <summary>
    /// The highest value each position of a date constructor accepts. The month starts at zero, which
    /// is the whole reason this mistake is made: December is 11, and 12 is next January.
    /// </summary>
    private static readonly (string Field, int Min, int Max)[] Positions =
    [
        ("year", 0, int.MaxValue), ("month", 0, 11), ("day", 1, 31),
        ("hour", 0, 23), ("minute", 0, 59), ("second", 0, 61)
    ];

    private static readonly string[] DateTypes = ["Date", "GregorianCalendar"];

    public override string Key => "QG-JV-BUG-0038";
    public override string Name => "Invalid Date values should not be used";
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            if (!DateTypes.Contains(CreatedType(creation), StringComparer.Ordinal))
                continue;
            var arguments = SyntaxQuery.Arguments(creation);
            if (arguments.Count < 2)
                continue; // one argument is a timestamp, not a calendar field

            for (var i = 1; i < Math.Min(arguments.Count, Positions.Length); i++)
            {
                if (arguments[i] is not { Kind: NodeKind.NumberLiteral } literal
                    || !int.TryParse(literal.Text, out var value))
                    continue;
                var (field, min, max) = Positions[i];
                if (value >= min && value <= max)
                    continue;

                context.Report($"{value} is not a {field}: the accepted range is {min} to {max}, and "
                               + "the value silently rolls over into the next unit instead of failing. "
                               + "The date the program works with is not the date that was written.",
                    creation.Range.StartLine);
                break;
            }
        }
    }
}

public sealed class JavaFormatStringRule : JavaMeasuredRuleBase
{
    private static readonly string[] FormattingCalls = ["format", "printf", "formatted"];

    /// <summary>Conversions a format string accepts. Anything else after a % is a mistake.</summary>
    private const string Conversions = "bBhHsScCdoxXeEfgGaAtTn%";

    public override string Key => "QG-JV-BUG-0202";
    public override string Name => "A format string should match the arguments it is given";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, FormattingCalls))
        {
            var arguments = SyntaxQuery.Arguments(call);
            if (arguments.Count == 0)
                continue;

            // 'String.format(locale, "...", ...)' puts the format second
            var index = arguments[0].Kind == NodeKind.StringLiteral ? 0 : 1;
            if (index >= arguments.Count)
                continue;
            var format = arguments[index];
            var values = arguments.Count - index - 1;

            if (format.Kind == NodeKind.Binary && format.Text == "+"
                && format.OfKind(NodeKind.StringLiteral).Any())
            {
                context.Report("The format string is assembled by concatenation, so whatever is glued "
                               + "into it is never formatted — and a value carrying a % of its own "
                               + "changes how the rest of the string is read. Put a specifier in the "
                               + "format and pass the value as an argument.", call.Range.StartLine);
                continue;
            }
            if (format.Kind != NodeKind.StringLiteral)
                continue;

            var text = format.Text;
            var (specifiers, positional, invalid) = Read(text);

            if (invalid != null)
            {
                context.Report($"'%{invalid}' is not a conversion this formatter knows, so the call "
                               + "throws at run time instead of producing the string.",
                    call.Range.StartLine);
                continue;
            }
            if (text.Contains("{0}", StringComparison.Ordinal) || text.Contains("{1}", StringComparison.Ordinal))
            {
                context.Report("The placeholders are written the way MessageFormat wants them, and this "
                               + "formatter does not read them: the arguments are dropped and the "
                               + "braces are printed as they stand.", call.Range.StartLine);
                continue;
            }
            if (ContainsEscapedNewline(text))
            {
                context.Report("A literal newline is written into a format string. Use %n, which "
                               + "produces the separator of the platform the program is running on.",
                    call.Range.StartLine);
                continue;
            }
            if (specifiers == 0 && !positional)
            {
                context.Report(values == 0
                    ? "The string holds no format specifier, so formatting it does nothing but cost a "
                      + "call. Use the string itself."
                    : $"The string holds no format specifier, so the {values} argument(s) passed with "
                      + "it are never printed.", call.Range.StartLine);
                continue;
            }
            if (positional)
                continue; // positional specifiers pick their argument, so counting says nothing
            // one array argument carries as many values as it holds, and the engine cannot count
            // them from here: saying anything about the number would be a guess
            if (values == 1 && CarriesSeveralValues(context, arguments[^1]))
                continue;

            if (values > specifiers)
            {
                context.Report($"The format asks for {specifiers} value(s) and {values} are passed, so "
                               + "the last one is never printed. Either it is the wrong call, or a "
                               + "specifier was left out.", call.Range.StartLine);
            }
            else if (values < specifiers)
            {
                context.Report($"The format asks for {specifiers} value(s) and only {values} are "
                               + "passed, so the call throws a MissingFormatArgumentException the "
                               + "first time it runs.", call.Range.StartLine);
            }
        }
    }



    /// <summary>
    /// Whether a single argument stands for the whole list of values: an array written on the spot, or
    /// anything that produces one.
    /// </summary>
    private static bool CarriesSeveralValues(IRuleContext context, SyntaxNode argument)
    {
        // a name may well hold an array. When the type is in reach it settles the question; when it
        // is not, the count is unknown and the rule says nothing.
        if (argument.Kind is NodeKind.Identifier or NodeKind.MemberSelect)
        {
            var type = context.Types.TypeOf(argument);
            return !context.Types.IsKnownType(type) || type!.Contains("[]", StringComparison.Ordinal);
        }
        if (argument.Kind == NodeKind.ObjectCreation && argument.Text.Contains("[]", StringComparison.Ordinal))
            return true;
        if (argument.SourceText().Contains("[ ]", StringComparison.Ordinal)
            || argument.SourceText().Contains("[]", StringComparison.Ordinal))
            return true;
        return argument.OfKind(NodeKind.Invocation)
            .Any(call => SyntaxQuery.InvokedName(call) is "toArray" or "asList" or "values");
    }

    /// <summary>
    /// Whether the format string carries a backslash-n. The two characters are compared by code so no
    /// escape of our own can be mangled on the way into this file.
    /// </summary>
    private static bool ContainsEscapedNewline(string text)
    {
        for (var i = 0; i < text.Length - 1; i++)
        {
            if (text[i] == (char)92 && text[i + 1] == 'n')
                return true;
        }
        return false;
    }

    /// <summary>
    /// Reads a format string: how many values it asks for, whether it picks them by position, and the
    /// first conversion letter that does not exist.
    /// </summary>
    private static (int Specifiers, bool Positional, string? Invalid) Read(string text)
    {
        var specifiers = 0;
        var positional = false;
        for (var i = 0; i < text.Length - 1; i++)
        {
            if (text[i] != '%')
                continue;
            var j = i + 1;
            var digits = 0;
            while (j < text.Length && char.IsAsciiDigit(text[j]))
            {
                j++;
                digits++;
            }
            if (j < text.Length && text[j] == '$' && digits > 0)
            {
                positional = true;
                j++;
            }
            // flags, width and precision sit between the % and the conversion letter
            while (j < text.Length && (char.IsAsciiDigit(text[j]) || text[j] is '-' or '+' or ' ' or '#'
                       or '0' or ',' or '(' or '.'))
                j++;
            if (j >= text.Length)
                return (specifiers, positional, string.Empty);

            var conversion = text[j];
            if (Conversions.IndexOf(conversion) < 0)
                return (specifiers, positional, conversion.ToString());
            if (conversion is not ('%' or 'n'))
                specifiers++;
            i = j;
        }
        return (specifiers, positional, null);
    }
}
