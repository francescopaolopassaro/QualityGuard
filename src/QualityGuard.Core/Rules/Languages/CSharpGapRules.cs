using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// C# rules written to close a measured gap: each one was found by running the reference analyzer and
/// this engine over the same production projects and reading what only the other one reported.
/// </summary>
public static class CSharpGapRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CsTypeNameCasingRule(),
        new CsDefaultGuidRule(),
        new CsPrivateTypeSealedRule(),
        new CsEmptyDerivedTypeRule(),
        new CsIndexInsteadOfFirstRule(),
        new CsOverloadsTogetherRule(),
        new CsBlockingHostRunRule(),
        new CsUntypedActionResultRule(),
        new CsFieldUsedInOneMethodRule(),
        new CsUnusedPrivateMemberRule(),
        new CsLoopThatOnlyFiltersRule(),
        new CsDisposePatternRule(),
        new CsBranchesReturningTheSubjectRule(),
        new CsArmReturningItsOwnLabelRule(),
        new CsStaticConstructorRule(),
        new CsLogAndRethrowRule(),
        new CsUnassignedAutoPropertyRule(),
        new CsNestedLoopWithoutBracesRule(),
        new CsIgnoredLocalFunctionResultRule(),
        new CsBoundModelValueTypeRule()
    ];
}

public abstract class CSharpGapRuleBase : RuleBase
{
    public override string[] Languages => ["cs"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "10min";

    protected static bool HasTree(IRuleContext context) => context.Tree.HasDedicatedParser;
}

public sealed class CsTypeNameCasingRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-CNV-0010";
    public override string Name => "A type name should be written in Pascal case";
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var name = type.Text;
            if (name.Length < 2 || !char.IsAsciiLetter(name[0]))
                continue;

            var offender = Offence(name);
            if (offender == null)
                continue;

            context.Report(type, $"'{name}' {offender}. A reader picks type names apart by their "
                                 + "capitals, and a run of them reads as one word.");
        }
    }

    /// <summary>
    /// What is wrong with the name, or null when nothing is. Two capitals in a row are allowed at
    /// the end of a two-letter acronym — 'IO', 'Id' — but a longer run hides where a word begins.
    /// </summary>
    private static string? Offence(string name)
    {
        if (char.IsLower(name[0]))
            return "starts with a lower-case letter";
        if (name.Contains('_'))
            return "separates its words with underscores";

        // A run of capitals in the middle of a name hides where the next word begins:
        // 'DocDocumentiWKFModelliFasi' has to be read twice. A run at the end does not — 'OrderDTO'
        // and 'ReportPDF' read cleanly, and naming the suffix that way is a decision a codebase
        // makes once. So only an interior run is reported.
        var run = 0;
        for (var i = 0; i < name.Length; i++)
        {
            if (!char.IsUpper(name[i]))
            {
                run = 0;
                continue;
            }
            run++;
            var atEnd = i == name.Length - 1;
            if (run > 2 && !atEnd)
                return "runs three capitals together in the middle";
        }
        return null;
    }
}

public sealed class CsDefaultGuidRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0478";
    public override string Name => "The empty identifier should be named";
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var creation in context.Root.OfKind(NodeKind.ObjectCreation))
        {
            var type = SyntaxQuery.SimpleName(creation.ChildAt(0));
            if (type.Length == 0)
                type = creation.Text;
            if (type != "Guid")
                continue;

            var arguments = SyntaxQuery.Arguments(creation);
            var empty = arguments.Count == 0
                        || (arguments.Count == 1 && arguments[0] is { Kind: NodeKind.StringLiteral } literal
                            && literal.Text.All(c => c is '0' or '-'));
            if (!empty)
                continue;

            context.Report(creation, "This builds the identifier that means 'none', spelled out. "
                                     + "'Guid.Empty' says it in a word, and a reader does not have to "
                                     + "count the zeroes to be sure.");
        }
    }
}

public sealed class CsPrivateTypeSealedRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0479";
    public override string Name => "A type nobody can inherit should say so";
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var modifiers = type.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (!modifiers.Contains("private"))
                continue;
            if (modifiers.Contains("sealed") || modifiers.Contains("abstract")
                || modifiers.Contains("static") || modifiers.Contains("record"))
                continue;
            // only a class can be sealed, and a nested private one is reachable from its owner alone
            if (type.Ancestor(NodeKind.ClassDeclaration) == null)
                continue;

            context.Report(type, $"'{type.Text}' is private, so nothing outside this type can derive "
                                 + "from it. Sealing it says that, and lets the runtime call its "
                                 + "methods without looking them up.");
        }
    }
}

public sealed class CsEmptyDerivedTypeRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0480";
    public override string Name => "A type that adds nothing should not exist";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body is not { Children.Count: 0 })
                continue;
            // a type with no base declares something new by existing; one that derives adds nothing
            if (!DerivesFromSomething(type, context))
                continue;
            if (type.ChildrenOf(NodeKind.Attribute).Any())
                continue; // an attribute can be the whole point of the type

            context.Report(type, $"'{type.Text}' inherits everything and adds nothing, so every use "
                                 + "of it could name the base instead. Either give it the difference "
                                 + "it was created for, or remove it.");
        }
    }

    private static bool DerivesFromSomething(SyntaxNode type, IRuleContext context)
    {
        var info = context.Project.FindTypes(type.Text).FirstOrDefault(t => t.Node == type);
        return info is { BaseNames.Count: > 0 };
    }
}

public sealed class CsIndexInsteadOfFirstRule : CSharpGapRuleBase
{
    private static readonly string[] Indexable = ["List", "IList", "Array", "Collection", "IReadOnlyList"];

    public override string Key => "QG-CS-SML-0481";
    public override string Name => "An indexed collection should be read by index";
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "First", "Last"))
        {
            if (SyntaxQuery.Arguments(call).Count != 0)
                continue;

            var receiver = call.ChildAt(0);
            var target = receiver is { Kind: NodeKind.MemberSelect } ? receiver.ChildAt(0) : receiver;
            var type = context.Types.TypeOf(target);
            var indexable = type is { Length: > 0 }
                            && Indexable.Contains(type.Split('<')[0].Split('.').Last().TrimEnd('[', ']'),
                                StringComparer.Ordinal);
            // the type of a value read from a query is rarely resolvable, and it is always a list:
            // that is what the call that produced it returns
            if (!indexable && !ReadIntoAList(context, target))
                continue;
            var bare = indexable
                ? type!.Split('<')[0].Split('.').Last().TrimEnd('[', ']')
                : "list";

            var name = SyntaxQuery.InvokedName(call);
            context.Report(call, $"'{bare}' is indexed, so '{name}()' sets up an enumerator to reach "
                                 + $"something the collection can hand over directly. Use "
                                 + (name == "First" ? "'[0]'." : "'[^1]'."));
        }
    }

    /// <summary>
    /// Whether the name was given the result of a call that materialises a sequence. The declaration
    /// says what it holds even when the type does not.
    /// </summary>
    private static bool ReadIntoAList(IRuleContext context, SyntaxNode? target)
    {
        var name = target == null ? string.Empty : SyntaxQuery.SimpleName(target);
        if (name.Length == 0)
            return false;

        foreach (var declaration in context.Root.OfKind(NodeKind.VariableDeclaration))
        {
            if (declaration.Text != name)
                continue;
            return declaration.OfKind(NodeKind.Invocation).Any(call =>
                SyntaxQuery.InvokedName(call) is "ToList" or "ToListAsync" or "ToArray"
                    or "ToArrayAsync");
        }
        return false;
    }
}

public sealed class CsOverloadsTogetherRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0482";
    public override string Name => "Overloads of one method should be written together";
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            var methods = body.ChildrenOf(NodeKind.FunctionDeclaration)
                .Where(m => m.Text.Length > 0)
                .ToList();
            // an interface declares its overloads the same way, and the same reading cost applies
            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            for (var i = 0; i < methods.Count; i++)
            {
                var name = methods[i].Text;
                if (!seen.TryGetValue(name, out var previous))
                {
                    seen[name] = i;
                    continue;
                }
                if (previous == i - 1)
                {
                    seen[name] = i;
                    continue;
                }

                // the finding belongs where the group starts: that is where a reader is when they
                // first meet the name, and where the second one should have been written
                context.Report(methods[previous], $"'{name}' has another overload {i - previous} "
                                                  + "members further down. A reader comparing them "
                                                  + "has to scroll between the two, and a change made "
                                                  + "to one is easy to miss on the other. Put them "
                                                  + "next to each other.");
                seen[name] = i;
            }
        }
    }
}

public sealed class CsBlockingHostRunRule : CSharpGapRuleBase
{
    private static readonly string[] Blocking = ["Run", "Start", "StopAsync", "WaitForShutdown"];

    public override string Key => "QG-CS-SML-0483";
    public override string Name => "The host should be run asynchronously";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            var name = SyntaxQuery.InvokedName(call);
            if (name is not ("Run" or "WaitForShutdown"))
                continue;
            var receiver = SyntaxQuery.Receiver(call);
            if (receiver is not ("app" or "host" or "builder"))
                continue;
            if (SyntaxQuery.Arguments(call).Count > 0)
                continue;

            context.Report(call, $"'{receiver}.{name}()' blocks the thread that started the "
                                 + "application until it shuts down. The asynchronous form frees it, "
                                 + $"and every host offers one: await {receiver}.{name}Async().");
            _ = Blocking;
        }
    }
}

public sealed class CsUntypedActionResultRule : CSharpGapRuleBase
{
    private static readonly string[] Verbs =
        ["HttpGet", "HttpPost", "HttpPut", "HttpPatch", "HttpDelete", "HttpHead", "Route"];

    public override string Key => "QG-CS-SML-0484";
    public override string Name => "An action should state the type it returns";
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var routed = method.ChildrenOf(NodeKind.Attribute)
                .Any(a => Verbs.Contains(a.Text, StringComparer.Ordinal));
            if (!routed)
                continue;

            var returned = method.FirstChild(NodeKind.TypeReference)?.Text;
            if (returned is not ("IActionResult" or "Task<IActionResult>"
                or "ValueTask<IActionResult>" or "ActionResult"))
                continue;
            // an action that only ever answers with a status says nothing worth typing
            var body = SyntaxQuery.Body(method);
            if (body == null || !body.OfKind(NodeKind.Invocation)
                    .Any(c => SyntaxQuery.InvokedName(c) is "Ok" or "Created" or "CreatedAtAction"
                        && SyntaxQuery.Arguments(c).Count > 0))
                continue;

            context.Report(method, $"'{method.Text}' answers with a value but declares only "
                                   + $"'{returned}', so nothing states what that value is — not the "
                                   + "compiler, not the generated documentation, not the client. "
                                   + "Return ActionResult<T> with the type it really produces.");
        }
    }
}

public sealed class CsFieldUsedInOneMethodRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0485";
    public override string Name => "A field used in one method should be a local";
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            var methods = body.Children
                .Where(c => c.Kind is NodeKind.FunctionDeclaration or NodeKind.ConstructorDeclaration
                    or NodeKind.PropertyDeclaration)
                .ToList();
            if (methods.Count < 2)
                continue;

            foreach (var field in body.ChildrenOf(NodeKind.FieldDeclaration))
            {
                var modifiers = field.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
                // 'readonly' is not the question: a field assigned once in the constructor and read
                // by one method is still state the type carries for nobody else
                if (!modifiers.Contains("private") || modifiers.Contains("static")
                    || modifiers.Contains("const"))
                    continue;
                var name = field.Text;
                if (name.Length == 0)
                    continue;

                // the constructor counts: a field it fills and reads, with nobody else looking,
                // is a value that never needed to leave the constructor
                var users = methods
                    .Where(m => m.OfKind(NodeKind.Identifier).Any(i => i.Text == name))
                    .ToList();
                // One user is the plain case. Several are the same case when each of them writes the
                // field before reading it: no call ever sees what another one left, so the value
                // never had to live on the object.
                if (users.Count == 0)
                    continue;
                if (users.Count > 1 && !users.All(m => WrittenBeforeRead(m, name)))
                    continue;
                // written and never read there is a different defect, and another rule says it
                var reads = users[0].OfKind(NodeKind.Identifier)
                    .Count(i => i.Text == name && !WritesTo(i));
                if (reads == 0)
                    continue;
                // A field read before it is written carries state from the previous call — that is
                // what '_disposed' and '_initialized' are for, and they belong to the object. Only a
                // field written first is really a local that escaped its method.
                if (!modifiers.Contains("readonly") && !WrittenBeforeRead(users[0], name))
                    continue;
                // a template beside this file can bind the name, and the markup is not a method
                if (context.Project.TemplateReferenceCount(name) > 0)
                    continue;


                context.Report(field, $"'{name}' is read and written inside one method only, so it "
                                      + "holds state between calls that nothing else uses — and a "
                                      + "second call sees what the first one left. Make it a local.");
            }
        }
    }

    /// <summary>Whether this appearance of the name is the target of an assignment.</summary>
    private static bool WritesTo(SyntaxNode identifier)
    {
        var parent = identifier.Parent;
        if (parent is { Kind: NodeKind.MemberSelect })
            parent = parent.Parent;
        return parent is { Kind: NodeKind.Assignment }
               && parent.Children.FirstOrDefault() is { } left
               && left.DescendantsAndSelf().Contains(identifier);
    }

    /// <summary>
    /// Whether the first thing the method does with the name is write it. Reading first means the
    /// value came from somewhere else, which for a field means the call before this one.
    /// </summary>
    private static bool WrittenBeforeRead(SyntaxNode method, string name)
    {
        foreach (var node in method.DescendantsAndSelf())
        {
            if (node.Kind == NodeKind.Assignment
                && SyntaxQuery.SimpleName(node.ChildAt(0)) == name)
                return true;
            if (node.Kind == NodeKind.Identifier && node.Text == name)
                return false;
        }
        return false;
    }
}

public sealed class CsUnusedPrivateMemberRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0486";
    public override string Name => "A private member nothing reads should be removed";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            foreach (var member in body.Children
                         .Where(c => c.Kind is NodeKind.FieldDeclaration or NodeKind.PropertyDeclaration))
            {
                var modifiers = member.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
                // a member of a private nested type is out of reach from outside whatever it says
                var typeIsPrivate = type.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "private");
                if (!modifiers.Contains("private") && !typeIsPrivate)
                    continue;
                if (member.ChildrenOf(NodeKind.Attribute).Any())
                    continue; // a framework can reach it by name
                var name = member.Text;
                if (name.Length == 0)
                    continue;

                // The tokens are the honest count: a name can be read in places the tree does not
                // record as an identifier — a case label, an attribute argument, a name in a
                // pattern — and a rule that says "delete this" must not be wrong about that.
                // The file's tokens are the honest count: a name can be read where the tree records
                // no identifier — a case label, an attribute argument, a name inside a pattern — and
                // a rule that says "delete this" must not be wrong about that. One mention is the
                // declaration itself; a write is not a read.
                var mentions = context.Tokens.Count(t => t.Text == name);
                // the initialiser on the declaration is part of the declaration, not a write
                var own = member.OfKind(NodeKind.Identifier).Count(i => i.Text == name);
                var writes = body.OfKind(NodeKind.Identifier)
                    .Count(i => i.Text == name && IsAssignmentTarget(i)
                                && !member.DescendantsAndSelf().Contains(i));
                if (mentions - Math.Max(1, own) - writes > 0)
                    continue;
                // The same name may be bound from a template, which no method contains. The
                // comparison has to be against every mention in this file, assignments included,
                // or the write that fills the field looks like a use somewhere else.
                if (context.Project.TemplateReferenceCount(name) > 0)
                    continue;

                context.Report(member, $"Nothing in '{type.Text}' reads '{name}'. It is private, so "
                                       + "nothing outside can either: the declaration and whatever "
                                       + "fills it are work that changes nothing.");
            }
        }
    }

    /// <summary>Whether this appearance of the name is the left-hand side of an assignment.</summary>
    private static bool IsAssignmentTarget(SyntaxNode identifier)
    {
        var parent = identifier.Parent;
        if (parent is { Kind: NodeKind.MemberSelect })
            parent = parent.Parent;
        return parent is { Kind: NodeKind.Assignment } && parent.Children.FirstOrDefault() is { } left
               && left.DescendantsAndSelf().Contains(identifier);
    }
}

public sealed class CsLoopThatOnlyFiltersRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0487";
    public override string Name => "A loop that only selects should say so";
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            if (loop.Text != "foreach")
                continue;
            var body = loop.FirstChild(NodeKind.Block);
            // the whole body is one condition, with nothing after it
            var only = body is { Children.Count: 1 } ? body.Children[0] : null;
            if (only is not { Kind: NodeKind.If })
                continue;
            if (only.FirstChild(NodeKind.Else) != null)
                continue;

            context.Report(loop, "The loop walks everything and the body is one condition, so what it "
                                 + "really says is 'the ones that match'. A filter says that in a "
                                 + "line, and the reader does not have to hold the loop in mind to "
                                 + "see it.");
        }
    }
}

public sealed class CsDisposePatternRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0488";
    public override string Name => "A disposable type should follow the pattern";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            // The base list is not always readable: a generic type carries its parameters in the
            // name, and an interface can extend IDisposable somewhere this scan never sees. What is
            // always visible is the method: a type with Dispose() releases something.
            var body0 = type.FirstChild(NodeKind.Block);
            if (body0 == null)
                continue;
            var disposes = body0.ChildrenOf(NodeKind.FunctionDeclaration)
                .Any(m => m.Text is "Dispose" or "DisposeAsync"
                          && !SyntaxQuery.Parameters(m).Any());
            if (!disposes)
                continue;
            var modifiers = type.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (modifiers.Contains("sealed"))
                continue; // a sealed type cannot be derived from, so the pattern buys nothing

            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;
            var methods = body.ChildrenOf(NodeKind.FunctionDeclaration).ToList();
            var overridable = methods.Any(m => m.Text == "Dispose"
                                               && SyntaxQuery.Parameters(m).Any()
                                               && m.ChildrenOf(NodeKind.Modifier)
                                                   .Any(x => x.Text is "virtual" or "override"));
            if (overridable || methods.All(m => m.Text != "Dispose"))
                continue;

            context.Report(type, $"'{type.Text}' can be derived from and holds something to release, "
                                 + "but offers no way for a derived type to take part: whatever it "
                                 + "adds is never released. Either seal the type, or add the "
                                 + "protected virtual Dispose(bool) the pattern is built on.");
        }
    }
}

public sealed class CsBranchesReturningTheSubjectRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0489";
    public override string Name => "A branch that returns what it was given changes nothing";
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var match in context.Root.OfKind(NodeKind.Match))
        {
            var subject = SyntaxQuery.DottedName(match.ChildAt(0) ?? match);
            if (subject.Length == 0)
                continue;

            var body = match.FirstChild(NodeKind.Block);
            if (body == null)
                continue;
            var sections = body.ChildrenOf(NodeKind.SwitchSection).ToList();
            if (sections.Count < 2)
                continue;

            var unchanged = sections.Count(section => Produces(section) == subject);
            if (unchanged == 0 || unchanged < sections.Count - 1)
                continue;

            context.Report(match, $"Every branch here hands back '{subject}' unchanged, so the whole "
                                  + "expression is the value it started with. Either a branch was "
                                  + "meant to produce something else, or the switch can go.");
        }
    }

    private static string Produces(SyntaxNode section)
    {
        var value = section.Children.LastOrDefault();
        return value == null ? string.Empty : SyntaxQuery.DottedName(value);
    }
}

public sealed class CsArmReturningItsOwnLabelRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0490";
    public override string Name => "A branch that answers with its own label decides nothing";
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var match in context.Root.OfKind(NodeKind.SwitchExpression, NodeKind.Match))
        {
            // a switch expression carries its arms directly; a switch statement wraps them in a block
            var sections = match.ChildrenOf(NodeKind.SwitchSection).ToList();
            if (sections.Count == 0 && match.FirstChild(NodeKind.Block) is { } block)
                sections = block.ChildrenOf(NodeKind.SwitchSection).ToList();
            if (sections.Count < 2)
                continue;

            // an arm that answers with the very value it matched changes nothing: the default
            // covers it, and writing it out suggests a mapping that was meant to be different
            foreach (var section in sections.Where(Mirrors))
            {
                context.Report(section, $"This branch answers with '{section.Text}', the value it "
                                        + "just matched, so it changes nothing that the default "
                                        + "would not. Either it was meant to produce something "
                                        + "else, or it can go.");
            }
        }
    }

    private static bool Mirrors(SyntaxNode section)
    {
        // the arm keeps its label in its own text and its answer as the child
        var label = section.Text;
        var answer = section.Children.Count > 0
            ? SyntaxQuery.DottedName(section.Children[^1])
            : string.Empty;
        return label.Length > 0 && label != "_" && label == answer;
    }
}

public sealed class CsStaticConstructorRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0491";
    public override string Name => "A static field should be initialised where it is declared";
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var constructor in context.Root.OfKind(NodeKind.ConstructorDeclaration))
        {
            if (!constructor.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "static"))
                continue;
            var body = SyntaxQuery.Body(constructor);
            if (body == null || body.Children.Count == 0)
                continue;
            // a static constructor that does real work has a reason to exist
            if (body.Children.Any(c => c.Kind is not (NodeKind.ExpressionStatement or NodeKind.VariableDeclaration)))
                continue;
            if (!body.Children.All(c => c.OfKind(NodeKind.Assignment).Any()))
                continue;

            context.Report(constructor, "A static constructor that only assigns fields makes the type "
                                        + "initialise lazily, and the runtime then checks on every "
                                        + "access whether that has happened yet. Give the fields "
                                        + "their values where they are declared.");
        }
    }
}

public sealed class CsLogAndRethrowRule : CSharpGapRuleBase
{
    private static readonly string[] Logging = ["Log", "LogError", "Error", "Warn", "Fatal", "Write"];

    public override string Key => "QG-CS-SML-0492";
    public override string Name => "A failure should be logged once";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var clause in context.Root.OfKind(NodeKind.Catch))
        {
            var body = clause.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            var logs = body.OfKind(NodeKind.Invocation)
                .Any(c => Logging.Contains(SyntaxQuery.InvokedName(c), StringComparer.Ordinal));
            if (!logs)
                continue;
            var rethrows = body.OfKind(NodeKind.Jump).Any(j => j.Text == "throw");
            if (!rethrows)
                continue;

            context.Report(clause, "The failure is written to the log here and thrown on, so whoever "
                                   + "catches it next logs it again. One incident then appears "
                                   + "several times, with a different stack each time. Either handle "
                                   + "it here or let it travel, not both.");
        }
    }
}

public sealed class CsUnassignedAutoPropertyRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0493";
    public override string Name => "A property nothing writes always answers with nothing";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;
            var typeIsPrivate = type.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "private");
            if (!typeIsPrivate)
                continue; // a public type is filled from outside, and this file cannot see where

            foreach (var property in body.ChildrenOf(NodeKind.PropertyDeclaration))
            {
                var name = property.Text;
                if (name.Length == 0 || property.ChildrenOf(NodeKind.Attribute).Any())
                    continue;
                // an auto-property with a setter and nothing that uses it
                if (property.OfKind(NodeKind.Accessor).All(a => a.Text != "set"))
                    continue;
                // the accessor list is itself a block, so the test has to be whether an accessor
                // has a body of its own: a computed property answers from something else
                if (property.OfKind(NodeKind.Accessor).Any(a => a.FirstChild(NodeKind.Block) != null))
                    continue;

                // the question is who writes it, not who reads it: a property read everywhere and
                // assigned nowhere answers with the default every time
                var written = context.Root.OfKind(NodeKind.Assignment).Any(a =>
                {
                    var target = a.ChildAt(0);
                    if (target == null)
                        return false;
                    var dotted = SyntaxQuery.DottedName(target);
                    return dotted == name || dotted.EndsWith("." + name, StringComparison.Ordinal);
                });
                if (written || context.Project.TemplateReferenceCount(name) > 0)
                    continue;

                context.Report(property, $"Nothing in this file writes '{name}', and the type is "
                                         + "private, so nothing outside can either. Every read gets "
                                         + "the default value, whatever the code around it assumes.");
            }
        }
    }
}

public sealed class CsNestedLoopWithoutBracesRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0494";
    public override string Name => "A loop inside a loop should say where its body ends";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "5min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            // a loop whose body is another loop, with neither of them braced: the indentation is the
            // only thing saying which statements belong to which, and indentation is not the language
            // the parser wraps an unbraced body in a block it marks as implicit, so that is the
            // thing to look for rather than the absence of a block
            var body = loop.FirstChild(NodeKind.Block);
            if (body is not { Text: "implicit" })
                continue;
            var inner = body.Children.LastOrDefault();
            if (inner is not { Kind: NodeKind.Loop })
                continue;
            if (inner.FirstChild(NodeKind.Block) is not { Text: "implicit" })
                continue;

            context.Report(loop, "Neither this loop nor the one inside it is braced, so what belongs "
                                 + "to which is decided by the indentation — and a statement added "
                                 + "later at the same depth joins the inner loop silently. Put the "
                                 + "braces in.");
        }
    }
}

public sealed class CsIgnoredLocalFunctionResultRule : CSharpGapRuleBase
{
    public override string Key => "QG-CS-SML-0495";
    public override string Name => "A function that answers should have its answer read";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var function in context.Root.OfKind(NodeKind.LocalFunction, NodeKind.FunctionDeclaration))
        {
            var name = function.Text;
            if (name.Length == 0)
                continue;
            // only a local function is fully visible here: a method can be called from anywhere
            if (function.Kind == NodeKind.FunctionDeclaration
                && !function.ChildrenOf(NodeKind.Modifier).Any(m => m.Text == "private"))
                continue;

            var returned = function.FirstChild(NodeKind.TypeReference)?.Text;
            if (returned is null or "void" or "Task" or "ValueTask")
                continue;
            // A method that hands back the type it was given is a step in a chain: returning the
            // subject is how a builder lets the next call follow, and ignoring it is the normal way
            // to write one of them on its own line.
            var first = SyntaxQuery.Parameters(function).FirstOrDefault();
            var takes = first?.FirstChild(NodeKind.TypeReference)?.Text;
            if (takes != null && takes == returned)
                continue;

            var calls = SyntaxQuery.Invocations(context.Root)
                .Where(c => SyntaxQuery.InvokedName(c) == name)
                .ToList();
            if (calls.Count == 0)
                continue;
            // every call throws the answer away: the value the function computes reaches nobody
            if (!calls.All(c => c.Parent is { Kind: NodeKind.ExpressionStatement }))
                continue;

            context.Report(function, $"'{name}' works out a {returned} and "
                                     + (calls.Count == 1
                                         ? "its only caller throws it away. "
                                         : $"all {calls.Count} of its callers throw it away. ")
                                     + "Either the answer matters and somebody should be reading it, "
                                     + "or the function should say that it only has an effect.");
        }
    }
}

public sealed class CsBoundModelValueTypeRule : CSharpGapRuleBase
{
    /// <summary>Value types whose default is indistinguishable from a value the caller sent.</summary>
    private static readonly string[] Silent =
        ["int", "long", "short", "byte", "float", "double", "decimal", "bool", "Guid", "DateTime",
         "DateTimeOffset", "TimeSpan", "JsonElement"];

    public override string Key => "QG-CS-BUG-0148";
    public override string Name => "A bound value cannot tell absent from default";
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;
        // the shape only means something where a request is bound to a model
        if (!context.File.Content.Contains("Controller", StringComparison.Ordinal)
            && !context.File.Content.Contains("FromBody", StringComparison.Ordinal))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!type.Text.EndsWith("Request", StringComparison.Ordinal)
                && !type.Text.EndsWith("Model", StringComparison.Ordinal)
                && !type.Text.EndsWith("Dto", StringComparison.Ordinal))
                continue;
            var body = type.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            foreach (var property in body.ChildrenOf(NodeKind.PropertyDeclaration))
            {
                var modifiers = property.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
                if (!modifiers.Contains("public") || modifiers.Contains("required"))
                    continue;
                var declared = property.FirstChild(NodeKind.TypeReference)?.Text;
                if (declared is null || declared.EndsWith('?'))
                    continue;
                if (!Silent.Contains(declared, StringComparer.Ordinal))
                    continue;
                if (property.ChildrenOf(NodeKind.Attribute).Any())
                    continue; // an attribute can already say the value is required

                context.Report(property, $"'{property.Text}' is a {declared}, so a request that "
                                         + "leaves it out arrives with the default and the code "
                                         + "cannot tell that apart from a caller who really sent it. "
                                         + "Make it nullable, or mark it required.");
            }
        }
    }
}
