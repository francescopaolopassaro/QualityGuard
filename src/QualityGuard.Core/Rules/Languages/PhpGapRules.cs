using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// PHP checks the default profile turns on. The formatting ones read tokens and lines — that is the
/// whole of what they judge — while the structural ones read declarations, catches and calls on the
/// dedicated tree.
/// </summary>
public static class PhpGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PhpFileEndsWithNewlineRule(),
        new PhpTrailingWhitespaceRule(),
        new PhpShortOpenTagRule(),
        new PhpClosingTagOmittedRule(),
        new PhpUppercaseTrueFalseNullRule(),
        new PhpElseIfKeywordRule(),
        new PhpAndOrOperatorsRule(),
        new PhpRepeatedUnaryOperatorRule(),
        new PhpParentConstructorPhp4Rule(),
        new PhpMixedReturnRule(),
        new PhpSwitchTooFewCasesRule(),
        new PhpCountZeroComparisonRule(),
        new PhpCountNegativeComparisonRule(),
        new PhpModifierOrderRule(),
        new PhpTestClassNameSuffixRule(),
        new PhpSkipWithoutReasonRule(),
    ];
}

public abstract class PhpGapRuleBase : RuleBase
{
    internal static string Simple(string? dotted) =>
        (dotted ?? "").Split('.').LastOrDefault() ?? "";
}

// ------------------------------------------------------------------- file-level

public sealed class PhpFileEndsWithNewlineRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-CNV-0006";
    public override string Name => "Files should end with a newline";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        // the token stream carries no end-of-file marker: only the source can say whether the last
        // line is terminated
        if (context.File.Content.Length == 0 || context.File.Content.EndsWith("\n"))
            return;
        context.Report("The file does not end with a newline: POSIX tools and every diff add a "
                       + "'\\ No newline' marker to the last change for no reason.");
    }
}

public sealed class PhpTrailingWhitespaceRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-CNV-0007";
    public override string Name => "Lines should not end with trailing whitespace";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var reported = 0;
        foreach (var token in context.Tokens)
        {
            if (token.Kind == TokenKind.Comment || reported >= 3)
                continue;
            var text = token.Text;
            if (text.Length > 1 && (text.EndsWith(" ") || text.EndsWith("\t")))
            {
                // only symbols carry position cleanly; whitespace inside strings is content
                if (token.Kind == TokenKind.String)
                    continue;
                reported++;
                context.Report("This line ends with spaces or tabs: they survive in the repository "
                               + "and show up as noise in every blame. Trim them.", token.Line);
            }
        }
    }
}

public sealed class PhpShortOpenTagRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-CNV-0008";
    public override string Name => "Use <?php or <?= to open PHP";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var first = context.Tokens.FirstOrDefault();
        if (first == null || first.Text != "<?")
            return;
        context.Report("The short open tag depends on a php.ini setting and is disabled "
                       + "by default since PHP 7: on a stock server this whole file is "
                       + "served as text. Write '<?php'.", first.Line);
    }
}

public sealed class PhpClosingTagOmittedRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-CNV-0009";
    public override string Name => "Omit ?> in files that contain only PHP";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        // '?>' followed by nothing but whitespace: any stray byte after it is output the script
        // never meant to send, and it breaks header() calls downstream
        var last = context.Tokens.LastOrDefault(t =>
            t.Kind != TokenKind.Comment && t.Text.Trim().Length > 0);
        if (last == null || last.Text != "?>")
            return;
        context.Report("The closing ?> adds an empty line to the output of every include "
                              + "that follows. Drop it — the file ends when the PHP ends.", last.Line);
    }
}

// -------------------------------------------------------------------- tokens

public sealed class PhpUppercaseTrueFalseNullRule : PhpGapRuleBase
{
    private static readonly HashSet<string> Words = new(StringComparer.Ordinal)
        { "TRUE", "FALSE", "NULL", "True", "False", "Null" };

    public override string Key => "QG-PP-CNV-0010";
    public override string Name => "true, false and null should be lower case";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.Identifier))
        {
            if (!Words.Contains(token.Text))
                continue;
            context.Report($"'{token.Text}' works but no PHP style guide spells it that way: use "
                           + "lower-case true, false, null.");
        }
    }
}

public sealed class PhpElseIfKeywordRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-CNV-0011";
    public override string Name => "Use elseif instead of else if";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens.ToList();
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Text is not ("else" or "ELSE")) continue;
            if (tokens[i + 1].Text is not ("if" or "IF")) continue;
            context.Report("'else if' creates a nested block where 'elseif' stays one construct: "
                           + "with braces omitted the two spellings even behave differently. Use "
                           + "'elseif'.", tokens[i].Line);
        }
    }
}

public sealed class PhpAndOrOperatorsRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-CNV-0012";
    public override string Name => "Use && and || instead of and / or";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.Keyword))
        {
            if (token.Text is not ("and" or "or") )
                continue;
            context.Report($"'{$"{token.Text}"}' has lower precedence than assignment: "
                           + "$x = a or b assigns a first and evaluates b alone. Use "
                           + (token.Text == "and" ? "&&" : "||") + ".");
        }
    }
}

public sealed class PhpRepeatedUnaryOperatorRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-BUG-0126";
    public override string Name => "Unary prefix operators should not repeat";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var unary in context.Root.OfKind(NodeKind.Unary))
        {
            var inner = unary.ChildAt(0);
            if (inner?.Kind != NodeKind.Unary || inner.Text != unary.Text
                || unary.Text is not ("!" or "-"))
                continue;
            context.Report(unary, unary.Text == "!"
                ? "'!!$x' converts to bool the long way — write (bool) $x, or drop it in conditions."
                : "'--$x' reads as a decrement that isn't one. Fix the signs.");
        }
    }
}

// ------------------------------------------------------------------ structure

public sealed class PhpParentConstructorPhp4Rule : PhpGapRuleBase
{
    public override string Key => "QG-PP-BUG-0127";
    public override string Name => "PHP 4-style parent constructor calls do nothing";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            foreach (var method in type.OfKind(NodeKind.FunctionDeclaration))
            {
                if (method.Text != type.Text && method.Text != "__construct")
                    continue;
                var php4Call = method.OfKind(NodeKind.Invocation)
                    .FirstOrDefault(i => i.Text == "parent." + type.Text);
                if (php4Call == null)
                    continue;
                context.Report(php4Call, "parent::" + type.Text + "() is the PHP 4 form and runs "
                                         + "nothing since PHP 5. Call parent::__construct().");
            }
        }
    }
}

public sealed class PhpMixedReturnRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-SML-0291";
    public override string Name => "A function should return with or without a value, not both";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var jumps = function.OfKind(NodeKind.Jump).Where(j => j.Text == "return").ToList();
            if (jumps.Count < 2)
                continue;
            var withValue = jumps.Count(j => j.Children.Count > 0);
            if (withValue == 0 || withValue == jumps.Count)
                continue;
            context.Report(function, $"'{function.Text}' returns a value from some paths and bare "
                                     + "null from others: callers checking the result break on the "
                                     + "paths that return nothing.");
        }
    }
}

public sealed class PhpSwitchTooFewCasesRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-SML-0292";
    public override string Name => "A switch should have at least three cases";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var match in context.Root.OfKind(NodeKind.Match))
        {
            var cases = match.OfKind(NodeKind.SwitchSection).Count(s => s.Text == "case");
            if (match.Text != "switch" || cases >= 3 || cases == 0)
                continue;
            context.Report(match, $"Two cases are an if/else written sideways. Replace this switch "
                                  + $"({cases} cases) with an if/elseif chain.");
        }
    }
}

public sealed class PhpCountZeroComparisonRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-SML-0293";
    public override string Name => "Use empty() to test a collection for emptiness";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("==" or "===" or "!=" or "!=="))
                continue;
            foreach (var side in binary.Children)
            {
                if (Simple(side.Text) is not ("count" or "sizeof"))
                    continue;
                var other = binary.Children.FirstOrDefault(c => c != side);
                if (other?.Kind == NodeKind.NumberLiteral && other.Text == "0")
                {
                    context.Report(binary, "'count($x) === 0' restates empty($x): the native test "
                                          + "also answers arrays never initialised.");
                    break;
                }
            }
        }
    }
}

public sealed class PhpCountNegativeComparisonRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-BUG-0128";
    public override string Name => "A count can never be negative";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text is not ("<" or ">=") )
                continue;
            var left = Simple(binary.ChildAt(0)?.Text);
            var right = binary.ChildAt(1);
            var countSide = left is "count" or "sizeof";
            if (binary.Text == ">=")
            {
                (countSide, right) = (right?.Kind == NodeKind.Invocation, binary.ChildAt(0));
                countSide = countSide && Simple(binary.ChildAt(0)?.Text) is "count" or "sizeof"
                            || right?.Kind == NodeKind.NumberLiteral;
                continue;
            }
            if (!countSide || right?.Kind != NodeKind.NumberLiteral || right.Text.TrimStart('-') == ""
                || !right.Text.StartsWith("-"))
                continue;
            context.Report(binary, "'count($x)' is zero or positive: comparing it against a negative "
                                  + "number fixes the outcome before the code runs.");
        }
    }
}

public sealed class PhpModifierOrderRule : PhpGapRuleBase
{
    private static readonly string[] Canonical = ["final", "abstract", "public", "protected", "private", "static"];

    public override string Key => "QG-PP-SML-0294";
    public override string Name => "Declare modifiers in the conventional order";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var member in context.Root.OfKind(NodeKind.FunctionDeclaration)
                     .Concat(context.Root.OfKind(NodeKind.FieldDeclaration)))
        {
            var modifiers = member.ChildrenOf(NodeKind.Modifier)
                .Select(m => m.Text.ToLowerInvariant())
                .Where(Canonical.Contains).ToList();
            if (modifiers.Count < 2)
                continue;
            var positions = modifiers.Select(m => Array.IndexOf(Canonical, m)).ToList();
            if (positions.SequenceEqual(positions.OrderBy(p => p)))
                continue;
            context.Report(member, $"'{string.Join(' ', modifiers)}' reads out of order: visibility "
                                   +"first, then static, with final/abstract leading. Reorder so the "
                                   +"signature scans the same way everywhere.");
        }
    }
}

public sealed class PhpTestClassNameSuffixRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-SML-0295";
    public override string Name => "Test classes should end with Test";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!type.Tokens.Any(t => t.Text.Contains("TestCase")))
                continue;
            if (type.Text.EndsWith("Test", StringComparison.Ordinal)
                || type.Text.EndsWith("TestCase", StringComparison.Ordinal)
                || type.Text.EndsWith("TestTrait", StringComparison.Ordinal))
                continue;
            context.Report(type, $"'{type.Text}' extends TestCase but its name hides that: runners "
                                 + "select files by *Test.php suffix, so these tests may never run. "
                                 + "Rename the class and its file.");
        }
    }
}

public sealed class PhpSkipWithoutReasonRule : PhpGapRuleBase
{
    public override string Key => "QG-PP-SML-0296";
    public override string Name => "Say why a test is skipped";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["php"];

    public override void Execute(IRuleContext context)
    {
        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (Simple(invocation.Text) is not ("markTestSkipped" or "skip"))
                continue;
            var arguments = invocation.FirstChild(NodeKind.ArgumentList);
            if (arguments == null || arguments.Children.Count > 0)
                continue;
            context.Report(invocation, "A skip without a message tells the next reader nothing: by "
                                       + "the time they see it in the report, nobody remembers why. "
                                       + "Pass the reason.");
        }
    }
}
