using QualityGuard.Core.Models;
using QualityGuard.Core.Rules;
using QualityGuard.Core.Semantics;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Java checks the default profile turns on, written on the dedicated tree. Every rule states what
/// it can actually see: a shape the parser does not carry stays silent rather than guessing.
/// </summary>
public static class JavaGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new JavaBaseCatchBeforeDerivedRule(),
        new JavaConstantsOnlyInterfaceRule(),
        new JavaDefaultPackageRule(),
        new JavaPackageDirectoryMismatchRule(),
        new JavaMultipleDeclarationsPerLineRule(),
        new JavaMethodFieldSameNameRule(),
        new JavaMultipleBreaksInLoopRule(),
        new JavaWhileFalseLoopRule(),
        new JavaSynchronizeOnLockObjectRule(),
        new JavaMainSignatureRule(),
        new JavaUnusedStringBuilderRule(),
        new JavaFileDeletePreferredRule(),
        new JavaNullCheckWithInstanceofRule(),
        new JavaGetterWrongFieldRule(),
        new JavaOutputStreamWriteArrayRule(),
        new JavaEqualsNonnullParameterRule(),
        new JavaIdenticalCatchClausesRule(),
        new JavaRedundantStringCastRule(),
        new JavaAbstractPublicConstructorRule(),
        new JavaSetupWithoutSuperRule(),
        new JavaMultilineStringConcatenationRule(),
        new JavaHardcodedMathConstantRule(),
        new JavaAutowiredMultipleConstructorsRule(),
        new JavaBeanDuplicateNamesRule(),
        new JavaProxyingAnnotationNotPublicRule(),
        new JavaValueWithoutPropertySyntaxRule(),
        new JavaAsyncInsideConfigurationRule(),
        new JavaCommentSlashCountRule(),
        new JavaStaticImportBeforeRegularRule(),
        new JavaFieldAssignmentBeforeSuperCallRule(),
        new JavaMixedJunitAssertionsRule(),
        new JavaSimpleTextBlockRule(),
        new JavaEscapeSequenceInTextBlockRule(),
        new JavaAutowiredTooManyRule(),
        new JavaIncompatibleTransactionalRule(),
    ];
}

// ------------------------------------------------------------------- exceptions

public abstract class JavaGapRuleBase : RuleBase
{
    internal static bool HasAttribute(SyntaxNode member, string name) =>
        member.ChildrenOf(NodeKind.Attribute).Any(a => a.Text.EndsWith(name, StringComparison.OrdinalIgnoreCase));

    internal static bool HasAttribute(SyntaxNode member, params string[] names) =>
        names.Any(n => HasAttribute(member, n));

    internal static string Simple(string? dotted) =>
        (dotted ?? "").Split('.').LastOrDefault() ?? "";

    internal static bool IsTestPath(IRuleContext context)
        => Rules.Languages.LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName);

    internal static IReadOnlyList<string> ImportTexts(IRuleContext context)
        => context.Root.OfKind(NodeKind.ImportDeclaration).Select(i => i.Text).ToList();
}

public sealed class JavaBaseCatchBeforeDerivedRule : JavaGapRuleBase
{
    private static readonly Dictionary<string, int> Rank = new(StringComparer.Ordinal)
    {
        ["Throwable"] = 0,
        ["Exception"] = 1,
        ["RuntimeException"] = 2,
        ["IOException"] = 3,
        ["SQLException"] = 3,
        ["FileNotFoundException"] = 4,
    };

    public override string Key => "QG-JV-BUG-0314";
    public override string Name => "The derived catch should come before its base";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var tryStatement in context.Root.OfKind(NodeKind.Try))
        {
            var clauses = tryStatement.ChildrenOf(NodeKind.Catch)
                .Select(c => (Node: c,
                              Type: Simple(c.FirstChild(NodeKind.TypeReference)?.Text),
                              Line: c.Line))
                .Where(c => Rank.ContainsKey(c.Type))
                .ToList();

            for (var i = 0; i < clauses.Count; i++)
            {
                var laterDerived = clauses.Skip(i + 1)
                    .Any(l => Rank[l.Type] > Rank[clauses[i].Type]);
                if (!laterDerived)
                    continue;
                context.Report(clauses[i].Node, $"'catch ({clauses[i].Type})' placed first swallows "
                                               + "the more specific handler written after it. Move "
                                               + "the broad one last.");
                break;
            }
        }
}

}
// ------------------------------------------------------------------ declarations

public sealed class JavaConstantsOnlyInterfaceRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0721";
    public override string Name => "An interface should not be a bag of constants";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!type.Tokens.Any(t => t.Text == "interface"))
                continue;
            var members = type.ChildrenOf(NodeKind.Block).SelectMany(b => b.Children).Where(m =>
                m.Kind is NodeKind.FieldDeclaration or NodeKind.FunctionDeclaration or NodeKind.ClassDeclaration).ToList();
            if (members.Count == 0 || members.Any(m => m.Kind != NodeKind.FieldDeclaration))
                continue;
            context.Report(type, $"'{type.Text}' declares only constants. Implementing it drags them "
                                 + "into the implementer's namespace; use a final class with a private "
                                 + "constructor, or import them where they belong.");
        }
    }
}

public sealed class JavaDefaultPackageRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0722";
    public override string Name => "Types should not live in the unnamed package";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        if (context.Root.Children.Any(c => c.Kind == NodeKind.PackageDeclaration))
            return;
        var firstType = context.Root.Children.FirstOrDefault(c => c.Kind == NodeKind.ClassDeclaration);
        if (firstType == null || IsTestPath(context))
            return;
        context.Report(firstType, $"'{firstType.Text}' sits in the unnamed package: nothing outside it "
                                  + "can import it, and name clashes are invisible until they bite. "
                                  + "Give the file a package declaration.");
    }
}

public sealed class JavaPackageDirectoryMismatchRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0723";
    public override string Name => "The package declaration should match the source directory";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var package = context.Root.ChildrenOf(NodeKind.PackageDeclaration).FirstOrDefault();
        if (package == null || package.Text.Length == 0)
            return;
        var directory = System.IO.Path.GetDirectoryName(context.File.Path)?
            .Replace("\\", "/").Split('/') ?? [];
        var expected = directory.Skip(Math.Max(0, directory.Length - package.Text.Split('.').Length));
        var tail = string.Join("/", expected).ToLowerInvariant();
        if (tail.Length == 0)
            return;
        var declared = package.Text.Replace(".", "/").ToLowerInvariant();
        if (tail.EndsWith(declared, StringComparison.OrdinalIgnoreCase)
            || declared.EndsWith(tail, StringComparison.OrdinalIgnoreCase))
            return;
        context.Report(package, $"The file declares package '{package.Text}' but lives under '"
                                + $"{tail}'. The compiler accepts both only when the classpath hides "
                                + "the mismatch; tools that resolve sources by path will not find it.");
    }
}

public sealed class JavaMultipleDeclarationsPerLineRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-CNV-0008";
    public override string Name => "Declare one variable per line";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var group in context.Root.OfKind(NodeKind.VariableDeclaration)
                     .GroupBy(d => d.Range.StartLine).Where(g => g.Count() > 1))
        {
            context.Report($"Line {group.Key} declares {group.Count()} variables; reading the types "
                           + "and the initialisers side by side is how mistakes slip through. One "
                           + "declaration per line.", group.Key);
        }
    }
}

public sealed class JavaMethodFieldSameNameRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0724";
    public override string Name => "A method and a field should not share a name";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var fields = type.OfKind(NodeKind.FieldDeclaration).Select(f => f.Text).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var method in type.OfKind(NodeKind.FunctionDeclaration))
            {
                if (method.Text.Length > 1 && fields.Contains(method.Text))
                    context.Report(method, $"'{method.Text}' names both this method and a field of "
                                           + $"'{type.Text}'. A reader cannot tell which one an "
                                           + "unqualified use refers to.");
            }
        }
    }
}

// --------------------------------------------------------------------- statements

public sealed class JavaMultipleBreaksInLoopRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0725";
    public override string Name => "A loop should not carry several break or continue statements";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            var direct = loop.OfKind(NodeKind.Jump)
                .Where(j => j.Text is "break" or "continue" && j.Ancestor(NodeKind.Loop) == loop)
                .ToList();
            if (direct.Count(j => j.Text == "break") <= 1 && direct.Count <= 2)
                continue;
            context.Report(loop, $"This loop exits or skips from {direct.Count} places at once. "
                                 + "Extract the body or invert the conditions so the exit reads once.");
        }
    }
}

public sealed class JavaWhileFalseLoopRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-BUG-0315";
    public override string Name => "A while(false) never runs its first pass";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (loop.Text != "while" || loop.ChildAt(0)?.Text != "false")
                continue;
            context.Report(loop, "The condition is the literal false: the body was dead the moment it "
                                 + "was written. Delete it, or say which flag you meant to test.");
        }
    }
}

public sealed class JavaSynchronizeOnLockObjectRule : JavaGapRuleBase
{
    private static readonly HashSet<string> LockTypes = new(StringComparer.Ordinal)
        { "Lock", "ReentrantLock", "ReentrantReadWriteLock", "ReadWriteLock" };

    public override string Key => "QG-JV-BUG-0316";
    public override string Name => "Do not synchronize on a java.util.concurrent.Lock";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var lockFields = context.Root.OfKind(NodeKind.FieldDeclaration)
            .Where(f => LockTypes.Contains(Simple(f.FirstChild(NodeKind.TypeReference)?.Text)))
            .Select(f => f.Text)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var lockStatement in context.Root.OfKind(NodeKind.Lock))
        {
            if (lockStatement.Text != "synchronized")
                continue;
            var subject = lockStatement.ChildAt(0);
            if (subject == null || !lockFields.Contains(subject.Text)
                && !lockFields.Contains(Simple(subject.Text)))
                continue;
            context.Report(lockStatement, $"'{subject.Text}' is a j.u.c Lock: synchronized watches the "
                                          + "monitor, not the lock, so mutual exclusion silently "
                                          + "fails. Use lock()/unlock() around the critical section.");
        }
    }
}



public sealed class JavaMainSignatureRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-BUG-0317";
    public override string Name => "main should be public static void with String[] args";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (function.Text != "main")
                continue;
            var modifiers = function.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToHashSet(StringComparer.Ordinal);
            var parameters = function.FirstChild(NodeKind.ParameterList)?
                .ChildrenOf(NodeKind.Parameter).ToList();
            var parameterType = Simple(parameters?.FirstOrDefault()?.FirstChild(NodeKind.TypeReference)?.Text);
            var right = modifiers.Contains("static") && !modifiers.Contains("private")
                        && parameters is { Count: 1 }
                        && parameterType is "String[]" or "String..." or "String";
            if (right)
                continue;
            context.Report(function, "'main' is found by signature alone: public static void "
                                     + "main(String[] args). Any other spelling compiles and never "
                                     + "runs.");
        }
    }
}

public sealed class JavaUnusedStringBuilderRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0726";
    public override string Name => "StringBuilder output should reach somewhere";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            if (Simple(creation.Text) is not ("StringBuilder" or "StringBuffer"))
                continue;
            var name = creation.Ancestor(NodeKind.VariableDeclaration)?.Text ?? "";
            if (name.Length < 2)
                continue;
            if (context.Tokens.Count(t => t.Kind == TokenKind.Identifier && t.Text == name) > 1)
                continue;
            context.Report(creation, $"Nothing reads '{name}' afterwards: every append built text for "
                                     + "nobody. Log it, write it, or drop the builder.");
        }
    }
}

public sealed class JavaFileDeletePreferredRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0727";
    public override string Name => "Prefer Files.delete over File.delete";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var fileVars = context.Root.OfKind(NodeKind.VariableDeclaration)
            .Where(d => Simple(d.FirstChild(NodeKind.TypeReference)?.Text) == "File")
            .Select(d => d.Text)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var invocation in context.Root.OfKind(NodeKind.Invocation))
        {
            if (Simple(invocation.Text) != "delete" || invocation.Children.Count == 0)
                continue;
            if (!fileVars.Contains(invocation.ChildAt(0)?.Text ?? ""))
                continue;
            context.Report(invocation, "File.delete() reports failure with a bare false. "
                                       + "Files.delete(path) throws with the reason, which is what "
                                       + "the log needs.");
        }
    }
}

public sealed class JavaNullCheckWithInstanceofRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0728";
    public override string Name => "instanceof already answers the null check";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text != "&&" || binary.Children.Count < 2)
                continue;
            var left = binary.ChildAt(0)?.SourceText() ?? "";
            var right = binary.ChildAt(binary.Children.Count - 1);
            if (!left.EndsWith("!= null", StringComparison.Ordinal) || right?.Text != "instanceof")
                continue;
            var subject = right.ChildAt(0)?.Text ?? "";
            if (!left.StartsWith(subject, StringComparison.Ordinal))
                continue;
            context.Report(binary, "instanceof is false for null by definition: the left half "
                                  + "repeats it. Drop the explicit check.");
        }
    }
}

public sealed class JavaGetterWrongFieldRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-BUG-0318";
    public override string Name => "Getters and setters should read the field they are named after";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var fieldNames = type.OfKind(NodeKind.FieldDeclaration).Select(f => f.Text).ToHashSet(StringComparer.Ordinal);
            foreach (var method in type.OfKind(NodeKind.FunctionDeclaration))
            {
                var name = method.Text;
                if (name.Length < 4 || !(name.StartsWith("get") || name.StartsWith("set")))
                    continue;
                var expected = char.ToLowerInvariant(name[3]) + name[4..];
                if (!fieldNames.Contains(expected) || fieldNames.Contains(name, StringComparer.OrdinalIgnoreCase))
                    continue;
                var touched = name.StartsWith("get")
                    ? method.OfKind(NodeKind.Jump).Select(j => j.ChildAt(0)?.Text)
                        .FirstOrDefault(t => t != null && fieldNames.Contains(t))
                    : method.OfKind(NodeKind.Assignment).Select(a => a.ChildAt(0)?.Text)
                        .FirstOrDefault(t => t != null && fieldNames.Contains(t));
                if (touched == null || touched == expected)
                    continue;
                context.Report(method, $"'{name}' touches the field '{touched}' instead of "
                                       + $"'{expected}': either the name lies or the body does, and "
                                       + "both confuse every caller.");
            }
        }
    }
}

public sealed class JavaOutputStreamWriteArrayRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-BUG-0319";
    public override string Name => "An OutputStream subclass should override write(byte[],int,int)";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var tokens = type.Tokens.Select(t => t.Text).ToList();
            var extendsIndex = tokens.IndexOf("extends");
            if (extendsIndex < 0 || extendsIndex + 1 >= tokens.Count
                || !tokens[extendsIndex + 1].Contains("OutputStream"))
                continue;
            var overridesThreeArgWrite = type.OfKind(NodeKind.FunctionDeclaration)
                .Any(f => f.Text == "write"
                          && f.FirstChild(NodeKind.ParameterList)?.ChildrenOf(NodeKind.Parameter).Count() == 3);
            if (overridesThreeArgWrite)
                continue;
            context.Report(type, $"Every write(byte[]) funnels through write(byte[],int,int): without "
                                 + $"that override, buffered writes of '{type.Text}' bypass whatever "
                                 + "the single-byte form implements.");
        }
    }
}

public sealed class JavaEqualsNonnullParameterRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-BUG-0320";
    public override string Name => "equals should accept Object, not an annotated narrower type";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (function.Text != "equals")
                continue;
            var hasNonnull = function.ChildrenOf(NodeKind.Attribute)
                .Any(a => a.Text.Contains("Nonnull", StringComparison.OrdinalIgnoreCase)
                          || a.Text.Contains("NonNull", StringComparison.OrdinalIgnoreCase));
            if (!hasNonnull)
                continue;
            context.Report(function, "equals(Object) is chosen by signature: adding @Nonnull changes "
                                     + "nothing the runtime sees but promises tooling a contract the "
                                     + "method still violates. Drop the annotation.");
        }
    }
}



// ------------------------------------------------------------------ modernisation



public sealed class JavaIdenticalCatchClausesRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0730";
    public override string Name => "Identical catches should become one multi-catch";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var tryStatement in context.Root.OfKind(NodeKind.Try))
        {
            var catches = tryStatement.ChildrenOf(NodeKind.Catch).ToList();
            for (var i = 0; i + 1 < catches.Count; i++)
            {
                var a = catches[i].FirstChild(NodeKind.TypeReference)?.Text ?? "";
                var b = catches[i + 1].FirstChild(NodeKind.TypeReference)?.Text ?? "";
                if (a.Length == 0 || !a.Equals(b, StringComparison.Ordinal))
                    continue;
                if (NormalizedBody(catches[i]) != NormalizedBody(catches[i + 1]))
                    continue;
                context.Report(catches[i + 1], $"Two consecutive handlers catch {a} and run the same "
                                              + "lines. Collapse them into one catch (A | B e).");
            }
        }
    }

    private static string NormalizedBody(SyntaxNode catchNode)
        => string.Join("|", catchNode.OfKind(NodeKind.ExpressionStatement)
            .Select(e => e.SourceText()).Where(t => t.Trim().Length > 0));
}

public sealed class JavaRedundantStringCastRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0731";
    public override string Name => "Casting a value to the type it already has adds noise";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var cast in context.Root.OfKind(NodeKind.Cast))
        {
            var operand = cast.ChildAt(1) ?? cast.ChildAt(0);
            var redundant =
                (cast.Text == "String" && operand?.Kind == NodeKind.StringLiteral)
                || (operand?.Kind == NodeKind.ObjectCreation && Simple(operand.Text) == cast.Text);
            if (!redundant)
                continue;
            context.Report(cast, $"The value already carries type {cast.Text}: the cast tells the "
                                 + "reader something changed when nothing did. Remove it.");
        }
    }
}

public sealed class JavaAbstractPublicConstructorRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0732";
    public override string Name => "An abstract class constructor should not be public";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!type.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "abstract"))
                continue;
            foreach (var constructor in type.OfKind(NodeKind.ConstructorDeclaration))
            {
                if (!constructor.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "public"))
                    continue;
                context.Report(constructor, "Nobody can call this directly — no instance of an "
                                            + "abstract class exists. Give it protected and let the "
                                            + "visibility tell the truth.");
            }
        }
    }
}

public sealed class JavaSetupWithoutSuperRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0733";
    public override string Name => "setUp and tearDown should call their super methods";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!type.Tokens.Any(t => t.Text.Contains("TestCase") || t.Text.Contains("junit.framework")))
                continue;
            foreach (var function in type.OfKind(NodeKind.FunctionDeclaration))
            {
                if (function.Text is not ("setUp" or "tearDown"))
                    continue;
                if (function.OfKind(NodeKind.Invocation)
                        .Any(i => i.Text.StartsWith("super.", StringComparison.Ordinal)))
                    continue;
                context.Report(function, $"'{function.Text}' overrides the runner's lifecycle hook "
                                         + "without calling super(): everything the parent set up is "
                                         + "silently skipped for these tests.");
            }
        }
    }
}

public sealed class JavaMultilineStringConcatenationRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-CNV-0009";
    public override string Name => "A multiline concatenated string wants a text block";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var binary in context.Root.OfKind(NodeKind.Binary))
        {
            if (binary.Text != "+" || binary.Range.StartLine == binary.Range.EndLine)
                continue;
            var literals = binary.Descendants().Where(n => n.Kind == NodeKind.StringLiteral).ToList();
            if (literals.Count < 4)
                continue;
            context.Report(binary, "Three or more quoted pieces joined across lines: a text block "
                                   + "(\"\"\") keeps the content readable and the joins out of the "
                                   + "way.");
            break;
        }
    }
}

public sealed class JavaHardcodedMathConstantRule : JavaGapRuleBase
{
    private const int MinSignificantDigits = 3;

    private sealed record MathConstant(double Value, string Replacement, string Description);

    private static readonly MathConstant[] Constants =
    [
        new(Math.PI, "Math.PI", "pi"),
        new(Math.E, "Math.E", "Euler's number"),
        new(Math.Sqrt(2), "Math.sqrt(2)", "the square root of 2"),
        new(Math.Log(2), "Math.log(2)", "the natural logarithm of 2")
    ];

    public override string Key => "QG-JV-SML-0734";
    public override string Name => "A hardcoded number should use the math constant it approximates";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var literal in context.Root.OfKind(NodeKind.NumberLiteral))
        {
            // the constants are all non-integer, so an integer literal is not an approximation of one
            if (literal.Text.IndexOf('.') < 0)
                continue;
            var normalized = Normalize(literal.Text);
            if (normalized == null)
                continue;
            if (!double.TryParse(normalized, System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out var parsed))
                continue;

            var absolute = Math.Abs(parsed);
            if (absolute == 0.0)
                continue;

            var significant = CountSignificantDigits(normalized);
            if (significant < MinSignificantDigits)
                continue;

            // a value must agree with the constant across every digit it spells out, up to half a
            // unit in the last one: that is the precision the author actually typed
            var tolerance = 5.0 * Math.Pow(10, -significant);
            foreach (var constant in Constants)
            {
                if (Math.Abs(absolute - constant.Value) / constant.Value >= tolerance)
                    continue;

                context.Report(literal, $"'{literal.Text}' is a decimal approximation read from "
                               + $"memory, and it will not stay in step with {constant.Replacement} if "
                               + $"the constant's exact value is revisited. Name the value of "
                               + $"{constant.Description} instead of retyping its digits.");
                break;
            }
        }
    }

    /// <summary>
    /// Makes the literal comparable to the constants: underscores and the type suffix go away, and
    /// hex and scientific notations are not approximations of a named constant, so they are skipped.
    /// </summary>
    private static string? Normalize(string raw)
    {
        var value = raw.Replace("_", "");
        if (value.Length > 0 && "fdFD".IndexOf(value[^1]) >= 0)
            value = value[..^1];
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return null;
        if (value.IndexOf('e', StringComparison.OrdinalIgnoreCase) >= 0)
            return null;
        return value;
    }

    private static int CountSignificantDigits(string normalized)
    {
        var sig = normalized.Replace("-", "").Replace(".", "").TrimStart('0');
        return sig.Length == 0 ? 1 : sig.Length;
    }
}

// ------------------------------------------------------------------------ spring

public sealed class JavaAutowiredMultipleConstructorsRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0735";
    public override string Name => "One @Autowired constructor at most";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var annotated = type.OfKind(NodeKind.ConstructorDeclaration)
                .Where(c => c.ChildrenOf(NodeKind.Attribute)
                    .Any(a => a.Text.Contains("Autowired", StringComparison.OrdinalIgnoreCase)))
                .ToList();
            if (annotated.Count <= 1)
                continue;
            context.Report(annotated[1], $"'{type.Text}' marks {annotated.Count} constructors "
                                         + "@Autowired: Spring refuses the ambiguity at startup. Mark "
                                         + "the one you want, or none when there is a single "
);
        }
    }
}

public sealed class JavaBeanDuplicateNamesRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-BUG-0322";
    public override string Name => "@Bean methods inside one configuration should have distinct names";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            foreach (var group in type.OfKind(NodeKind.FunctionDeclaration)
                         .Where(f => HasAttribute(f, "Bean"))
                         .GroupBy(f => f.Text, StringComparer.OrdinalIgnoreCase)
                         .Where(g => g.Count() > 1))
            {
                context.Report(group.First(), $"Two @Bean methods answer to the name '{group.Key}': "
                                              + "one definition silently replaces the other. Rename "
                                              + "them, or give each a distinct @Bean name.");
            }
        }
    }
}

public sealed class JavaProxyingAnnotationNotPublicRule : JavaGapRuleBase
{
    private static readonly string[] Proxying =
        ["Transactional", "Cacheable", "Async", "Scheduled", "Retryable", "Validated"];

    public override string Key => "QG-JV-BUG-0323";
    public override string Name => "Spring proxying annotations need a public method";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var function in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!HasAttribute(function, Proxying))
                continue;
            if (function.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "public"))
                continue;
            context.Report(function, $"'{function.Text}' relies on a proxy that only intercepts "
                                     + "public entry points: non-public means the annotation never "
                                     + "runs. Make it public, or move the behaviour out of the "
                                     + "annotation.");
        }
    }
}

public sealed class JavaValueWithoutPropertySyntaxRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-BUG-0324";
    public override string Name => "@Value needs a property placeholder or SpEL expression";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var target in context.Root.OfKind(NodeKind.FieldDeclaration)
                     .Concat(context.Root.OfKind(NodeKind.FunctionDeclaration)))
        {
            var attribute = target.ChildrenOf(NodeKind.Attribute)
                .FirstOrDefault(a => Simple(a.Text) == "Value");
            if (attribute == null)
                continue;
            var literal = attribute.Descendants()
                .FirstOrDefault(n => n.Kind == NodeKind.StringLiteral)?.Text ?? "";
            if (literal.Contains('$') || literal.Contains('#'))
                continue;
            context.Report(attribute, $"@Value(\"{literal}\") injects the literal itself, not a "
                                      + "property: wrap the key in ${{…}} (or #{{…}} for SpEL), or "
                                      + "the field always holds this exact text.");
        }
    }
}

public sealed class JavaAsyncInsideConfigurationRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-BUG-0327";
    public override string Name => "@Async has no effect inside a @Configuration class";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!HasAttribute(type, "Configuration"))
                continue;
            foreach (var function in type.OfKind(NodeKind.FunctionDeclaration))
            {
                if (!HasAttribute(function, "Async"))
                    continue;
                context.Report(function, "Configuration classes are proxied by CGLIB, whose async "
                                        + "interceptor does not apply here: the method runs inline. "
                                        + "Move the work to a regular bean.");
            }
        }
    }
}

public sealed class JavaIncompatibleTransactionalRule : JavaGapRuleBase
{
    private const string NotTransactional = "NOT_TRANSACTIONAL";
    private const string DefaultProp = "REQUIRED";

    private static readonly HashSet<string> Props = new(StringComparer.Ordinal)
    {
        "MANDATORY", "NESTED", "NEVER", "NOT_SUPPORTED", "REQUIRED", "REQUIRES_NEW", "SUPPORTS",
    };

    // For a given caller propagation, which callee propagations it cannot enter.
    private static readonly Dictionary<string, HashSet<string>> Incompatible = new(StringComparer.Ordinal)
    {
        [NotTransactional] = new HashSet<string>(new[] { "MANDATORY", "NESTED", "REQUIRED", "REQUIRES_NEW" }),
        ["MANDATORY"] = new HashSet<string>(new[] { "NESTED", "NEVER", "NOT_SUPPORTED", "REQUIRES_NEW" }),
        ["NESTED"] = new HashSet<string>(new[] { "NESTED", "NEVER", "NOT_SUPPORTED", "REQUIRES_NEW" }),
        ["NEVER"] = new HashSet<string>(new[] { "MANDATORY", "NESTED", "REQUIRED", "REQUIRES_NEW" }),
        ["NOT_SUPPORTED"] = new HashSet<string>(new[] { "MANDATORY", "NESTED", "REQUIRED", "REQUIRES_NEW" }),
        ["REQUIRED"] = new HashSet<string>(new[] { "NESTED", "NEVER", "NOT_SUPPORTED", "REQUIRES_NEW" }),
        ["REQUIRES_NEW"] = new HashSet<string>(new[] { "NESTED", "NEVER", "NOT_SUPPORTED", "REQUIRES_NEW" }),
        ["SUPPORTS"] = new HashSet<string>(new[] { "MANDATORY", "NESTED", "NEVER", "NOT_SUPPORTED", "REQUIRED", "REQUIRES_NEW" }),
    };

    public override string Key => "QG-JV-BUG-0329";
    public override string Name => "Incompatible @Transactional propagation between method calls";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var classProp = PropagationOf(type.ChildrenOf(NodeKind.Attribute)) ?? NotTransactional;

            var methods = new Dictionary<string, (string Prop, bool Static, SyntaxNode Node)>();
            foreach (var method in type.OfKind(NodeKind.FunctionDeclaration))
            {
                if (!method.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "public"))
                    continue;
                var prop = PropagationOf(method.ChildrenOf(NodeKind.Attribute)) ?? classProp;
                var isStatic = method.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "static");
                methods[method.Text] = (prop, isStatic, method);
            }
            if (methods.Count == 0)
                continue;
            if (methods.Values.Select(v => v.Prop).Distinct().Count() <= 1)
                continue;

            foreach (var (callerProp, _, caller) in methods.Values)
            {
                var body = caller.FirstChild(NodeKind.Block);
                if (body == null)
                    continue;
                foreach (var call in body.OfKind(NodeKind.Invocation))
                {
                    var calleeName = SyntaxQuery.InvokedName(call);
                    if (!methods.TryGetValue(calleeName, out var callee) || callee.Static)
                        continue;
                    if (!OnThisInstance(call, calleeName))
                        continue;
                    if (Incompatible.TryGetValue(callerProp, out var bad) && bad.Contains(callee.Prop))
                        context.Report(call, $"\"{calleeName}'s\" @Transactional requirement "
                                             + "is incompatible with the one on this method: "
                                             + "entering it changes the transaction the caller "
                                             + "already opened. Align the two propagation values.");
                }
            }
        }
    }

    /// <summary>Propagation declared on the node, or null when no @Transactional sits on it.</summary>
    private static string? PropagationOf(IEnumerable<SyntaxNode> attributes)
    {
        foreach (var attr in attributes)
        {
            var full = attr.Text;
            var javax = full.Contains("javax.transaction", StringComparison.Ordinal);
            var transactional = javax || Simple(full).Contains("Transactional", StringComparison.Ordinal);
            if (!transactional)
                continue;
            var argList = attr.FirstChild(NodeKind.ArgumentList);
            if (argList != null)
            {
                foreach (var assignment in argList.ChildrenOf(NodeKind.Assignment))
                {
                    var left = Simple(assignment.ChildAt(0)?.Text);
                    if (left != "propagation" && left != "value")
                        continue;
                    var right = assignment.ChildAt(1);
                    if (right == null)
                        continue;
                    var value = Simple(right.Text);
                    if (Props.Contains(value))
                        return value;
                }
            }
            return DefaultProp;
        }
        return null;
    }

    /// <summary>True when the call is a bare name or <c>this.name()</c>, never <c>other.name()</c>.</summary>
    private static bool OnThisInstance(SyntaxNode call, string name)
    {
        var receiver = call.ChildAt(0)?.Text ?? "";
        return receiver == name || receiver == "this." + name;
    }
}

// -------------------------------------------------------------------- comments & imports

public sealed class JavaCommentSlashCountRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-CNV-0010";
    public override string Name => "Line comments should keep one consistent number of slashes";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var runs = new List<(int Length, int Line)>();
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.Comment))
        {
            var slashes = token.Text.Length - token.Text.TrimStart('/').Length;
            if (slashes is 2 or 3 or 4 && token.Text.Length > slashes
                && !char.IsWhiteSpace(token.Text[slashes]))
                runs.Add((slashes, token.Line));
        }
        if (runs.Count == 0)
            return;
        var dominant = runs.GroupBy(r => r.Length).OrderByDescending(g => g.Count()).First().Key;
        foreach (var (length, line) in runs.Where(r => r.Length != dominant).Take(3))
            context.Report($"This line comment starts with {length} slashes while the file uses "
                           + $"{dominant}: the odd one out reads as markup from another convention.",
                line);
    }
}

public sealed class JavaStaticImportBeforeRegularRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-CNV-0011";
    public override string Name => "Static imports belong after the plain ones";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var sawRegular = false;
        foreach (var import in context.Root.ChildrenOf(NodeKind.ImportDeclaration))
        {
            var isStatic = import.Tokens.Any(t => t.Text == "static");
            if (!isStatic)
            {
                sawRegular = true;
                continue;
            }
            if (!sawRegular)
                continue;
            context.Report(import, "A static import precedes the regular ones: the grouping readers "
                                   + "expect puts plain imports first, statics last.");
            break;
        }
    }
}

public sealed class JavaFieldAssignmentBeforeSuperCallRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-BUG-0326";
    public override string Name => "Initialize fields after super(), not before";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var constructor in context.Root.OfKind(NodeKind.ConstructorDeclaration))
        {
            var body = constructor.FirstChild(NodeKind.Block);
            if (body == null || body.Children.Count < 2)
                continue;
            var children = body.Children.ToList();
            var superIndex = children.FindIndex(c =>
                c.OfKind(NodeKind.Invocation).Any(i => i.Text.StartsWith("super", StringComparison.Ordinal)));
            if (superIndex <= 0)
                continue;
            var assignsField = children.Take(superIndex)
                .Any(c => c.Kind == NodeKind.ExpressionStatement
                          && c.ChildAt(0)?.Kind == NodeKind.Assignment);
            if (!assignsField)
                continue;
            context.Report(children.First(), "This assignment writes instance state before super() "
                                             + "ran: the superclass sees half-built values if it "
                                             + "calls overridden members. Let the super call come "
                                             + "first.");
        }
    }
}

public sealed class JavaMixedJunitAssertionsRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-CNV-0012";
    public override string Name => "JUnit Jupiter tests should not call JUnit 4 asserts";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        var imports = ImportTexts(context);
        var usesJupiterTests = imports.Any(i => i.Contains("org.junit.jupiter.api.Test"));
        var usesJunit4Assert = imports.Any(i => i.Contains("org.junit.Assert"))
                               && context.Root.OfKind(NodeKind.Invocation)
                                   .Any(i => i.Text.StartsWith("Assert.", StringComparison.Ordinal));
        if (usesJupiterTests && usesJunit4Assert)
            context.Report("These tests run under Jupiter while asserting through JUnit 4's Assert "
                           + "class: two assertion worlds in one suite. Move to Assertions.*.");
    }
}
// ------------------------------------------------------- text blocks & spring extra



public sealed class JavaSimpleTextBlockRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-CNV-0013";
    public override string Name => "A text block for a single-line string adds two wasted quotes";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "1min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t =>
                     t.Kind == TokenKind.String && t.Text.StartsWith("\"\"\"")))
        {
            var inner = token.Text[3..^3];
            if (inner.Contains('\n') || inner.Contains('"') || inner.Trim().Length == 0)
                continue;
            context.Report("This text block holds a single line with nothing a plain literal could "
                           + "not carry: the triple quotes are three characters of ceremony around "
                           + "one string.", token.Line);
        }
    }
}

public sealed class JavaEscapeSequenceInTextBlockRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-SML-0736";
    public override string Name => "Escape sequences inside a text block defeat its purpose";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t =>
                     t.Kind == TokenKind.String && t.Text.StartsWith("\"\"\"")))
        {
            var inner = token.Text[3..^3];
            if (!inner.Contains('\\'))
                continue;
            context.Report("A text block takes newlines and quotes as they are: the escapes inside "
                           + "print themselves literally or re-introduce the noise the block was "
                           + "meant to remove. Write the content raw.", token.Line);
        }
    }
}

public sealed class JavaAutowiredTooManyRule : JavaGapRuleBase
{
    public override string Key => "QG-JV-BUG-0328";
    public override string Name => "Multiple constructors without @Autowired leave Spring guessing";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["java"];

    public override void Execute(IRuleContext context)
    {
        // senza Spring nel progetto l'ambiguita non esiste: due costruttori sono overloading
        if (!ImportTexts(context).Any(i =>
                i.Contains("org.springframework", StringComparison.Ordinal)))
            return;
        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var constructors = type.OfKind(NodeKind.ConstructorDeclaration).ToList();
            if (constructors.Count < 2)
                continue;
            var anyAnnotated = constructors.Any(c =>
                c.ChildrenOf(NodeKind.Attribute)
                    .Any(a => a.Text.Contains("Autowired", StringComparison.OrdinalIgnoreCase)));
            if (anyAnnotated)
                continue;
            context.Report(constructors[0], $"'{type.Text}' offers {constructors.Count} constructors "
                                            + "and none is marked @Autowired: since Spring 5 the "
                                            + "container no longer guesses, and startup fails. Mark "
                                            + "the intended one.");
        }
    }
}
