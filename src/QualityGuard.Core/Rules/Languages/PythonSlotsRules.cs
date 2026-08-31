using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// A class that declares __slots__ promises the runtime that every attribute an instance can
/// carry is listed there. Assigning to an attribute that is not on the list succeeds or fails
/// depending on the ancestors, and when neither a parent nor the class itself provides a
/// __dict__ the assignment raises AttributeError on the spot. Reading __slots__ therefore means
/// reading the ancestors too: a slot inherited from a parent is legal, a parent without
/// __slots__ gives every descendant a __dict__, and an ancestor the file cannot see stops the
/// check, because guessing whether it provides a __dict__ is exactly how false positives are born.
/// </summary>
public static class PythonSlotsRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new PythonSlotsAssignmentRule(),
        new PythonIdentityCachedTypeRule()
    ];
}

public abstract class PythonSlotsRuleBase : PythonAstRuleBase
{
    /// <summary>
    /// Builtins that contribute neither slots nor a __dict__. `object` in particular is the
    /// implicit base of every class without an explicit one; treating it as an unknown external
    /// ancestor would make every __slots__ class unanalysable. Only names on this closed list are
    /// trusted: any other external base stops the check.
    /// </summary>
    protected static readonly HashSet<string> SlotsIgnoredBuiltins = new(StringComparer.Ordinal)
    {
        "object", "list", "tuple", "str", "int", "float", "bool", "dict", "set",
        "frozenset", "bytes", "bytearray", "complex", "range"
    };

    protected static string Mangle(string className, string attribute)
    {
        if (attribute.Length > 2 && attribute.StartsWith("__") && !attribute.EndsWith("__"))
            return "_" + className.TrimStart('_') + "__" + attribute.TrimStart('_');
        return attribute;
    }
}

public sealed class PythonSlotsAssignmentRule : PythonSlotsRuleBase
{
    public override string Key => "QG-PY-SML-0572";
    public override string Name => "An attribute should not be assigned outside the class __slots__";
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Add the attribute name to the class __slots__ list, or if the class genuinely needs arbitrary attributes remove __slots__ so every instance keeps a __dict__.";

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        var classes = context.Root.OfKind(NodeKind.ClassDeclaration).ToList();
        if (classes.Count == 0)
            return;

        var byName = new Dictionary<string, List<SyntaxNode>>(StringComparer.Ordinal);
        foreach (var cls in classes)
        {
            if (!byName.TryGetValue(cls.Text, out var list))
                byName[cls.Text] = list = new List<SyntaxNode>();
            list.Add(cls);
        }

        var memo = new Dictionary<SyntaxNode, SlotInfo?>();

        foreach (var cls in classes)
        {
            var info = Resolve(context, cls, byName, memo);
            if (info == null || info.HasDict || info.Slots == null)
                continue;

            var receiver = ReceiverName(context, cls);
            if (receiver == null)
                continue;

            var body = cls.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            foreach (var method in body.ChildrenOf(NodeKind.FunctionDeclaration))
            {
                var mbody = method.FirstChild(NodeKind.Block);
                if (mbody == null)
                    continue;
                CheckMethodAssignments(context, cls, receiver, info.Slots, mbody);
            }
        }
    }

    private static void CheckMethodAssignments(IRuleContext context, SyntaxNode cls, string receiver,
        HashSet<string> slots, SyntaxNode body)
    {
        foreach (var assignment in WalkAssignments(body))
        {
            var lhs = assignment.Children.FirstOrDefault();
            if (lhs == null || lhs.Kind != NodeKind.MemberSelect)
                continue;

            var recvNode = lhs.Children.FirstOrDefault();
            if (recvNode == null || recvNode.Kind != NodeKind.Identifier || recvNode.Text != receiver)
                continue;

            var attrNode = lhs.Children.LastOrDefault();
            if (attrNode == null || attrNode.Kind != NodeKind.Identifier)
                continue;

            var raw = attrNode.Text;
            var mangled = Mangle(cls.Text, raw);
            if (slots.Contains(raw) || slots.Contains(mangled))
                continue;

            context.Report(assignment,
                $"'{raw}' is assigned to {receiver} but is not in {cls.Text}'s __slots__, so the "
                + "assignment raises AttributeError at runtime. Add it to __slots__ or drop the "
                + "restriction.");
        }
    }

    /// <summary>Assignments of a method body, without descending into nested functions or classes.</summary>
    private static IEnumerable<SyntaxNode> WalkAssignments(SyntaxNode body)
    {
        var stack = new Stack<SyntaxNode>();
        stack.Push(body);
        while (stack.Count > 0)
        {
            var node = stack.Pop();
            if (node.Kind is NodeKind.FunctionDeclaration or NodeKind.ClassDeclaration)
                continue;
            if (node.Kind == NodeKind.Assignment)
                yield return node;
            foreach (var child in node.Children)
                stack.Push(child);
        }
    }

    private static string? ReceiverName(IRuleContext context, SyntaxNode cls)
    {
        var body = cls.FirstChild(NodeKind.Block);
        if (body == null)
            return null;

        foreach (var method in body.ChildrenOf(NodeKind.FunctionDeclaration))
        {
            var parameters = DeclaredParameters(Signature(context, method.Range.StartLine));
            var first = parameters.FirstOrDefault();
            if (first != null && IsIdentifier(first))
                return first;
        }
        return null;
    }

    private static bool IsIdentifier(string text)
        => !string.IsNullOrEmpty(text)
           && (char.IsLetter(text[0]) || text[0] == '_')
           && text.All(c => char.IsLetterOrDigit(c) || c == '_');

    /// <summary>
    /// The slot set of a class once ancestors are read, or null when any ancestor stops the check.
    /// HasDict is true when nothing restricts assignment at all (a parent without __slots__, or a
    /// __dict__ entry somewhere up the chain) and makes the whole class silent.
    /// </summary>
    private static SlotInfo? Resolve(IRuleContext context, SyntaxNode cls,
        Dictionary<string, List<SyntaxNode>> byName, Dictionary<SyntaxNode, SlotInfo?> memo)
    {
        if (memo.TryGetValue(cls, out var existing))
            return existing;

        var own = CollectSlots(context, cls);
        if (own == null)
        {
            memo[cls] = null;
            return null;
        }

        if (own.HasDict)
        {
            memo[cls] = new SlotInfo(new HashSet<string>(StringComparer.Ordinal), true);
            return memo[cls];
        }

        var bases = ParseBases(SourceLine(context, cls.Range.StartLine));
        if (bases == null)
        {
            // a class definition that spans lines, or syntax we cannot read: never guess the base list
            memo[cls] = null;
            return null;
        }

        var slots = new HashSet<string>(own.Slots, StringComparer.Ordinal);
        foreach (var baseName in bases)
        {
            if (SlotsIgnoredBuiltins.Contains(baseName))
                continue;

            if (!byName.TryGetValue(baseName, out var candidates) || candidates.Count != 1)
            {
                // external, dynamically assigned or ambiguously defined parent: cannot inspect it
                memo[cls] = null;
                return null;
            }

            var parent = Resolve(context, candidates[0], byName, memo);
            if (parent == null)
            {
                memo[cls] = null;
                return null;
            }

            if (parent.HasDict)
            {
                memo[cls] = new SlotInfo(new HashSet<string>(StringComparer.Ordinal), true);
                return memo[cls];
            }

            if (parent.Slots != null)
                slots.UnionWith(parent.Slots);
        }

        var result = new SlotInfo(slots, false);
        memo[cls] = result;
        return result;
    }

    /// <summary>Own slots from the last __slots__ assignment, or null when __slots__ is not literal.</summary>
    private static SlotInfo? CollectSlots(IRuleContext context, SyntaxNode cls)
    {
        var body = cls.FirstChild(NodeKind.Block);
        if (body == null)
            return null;

        SlotInfo? found = null;
        foreach (var decl in body.ChildrenOf(NodeKind.VariableDeclaration))
        {
            if (decl.Text != "__slots__")
                continue;

            var assignment = decl.FirstChild(NodeKind.Assignment);
            var value = assignment?.Children.ElementAtOrDefault(1);
            var parsed = ParseSlotsValue(context, value);
            if (parsed == null)
                return null; // the last definition is not a literal: bail rather than guess
            found = parsed;
        }

        return found;
    }

    private static SlotInfo? ParseSlotsValue(IRuleContext context, SyntaxNode? value)
    {
        if (value == null)
            return null;
        return value.Kind switch
        {
            NodeKind.StringLiteral => new SlotInfo(new HashSet<string>(StringComparer.Ordinal) { value.Text }, false),
            NodeKind.ListLiteral or NodeKind.Parenthesized or NodeKind.ObjectInitializer
                => CollectContainer(context, value),
            _ => null
        };
    }

    private static SlotInfo? CollectContainer(IRuleContext context, SyntaxNode container)
    {
        if (container.Kind == NodeKind.ObjectInitializer)
        {
            var children = container.Children.ToList();
            var isDict = children.Count > 0
                         && children.All(c => c.Kind == NodeKind.Assignment && c.Text == ":");
            var slots = new HashSet<string>(StringComparer.Ordinal);
            foreach (var child in children)
            {
                SyntaxNode nameNode = child;
                if (isDict)
                {
                    if (child.Kind != NodeKind.Assignment)
                        return null; // unpacking or a mixed element: bail
                    nameNode = child.Children.FirstOrDefault()!;
                }
                if (!TrySlotName(context, nameNode, out var name) || name == "__dict__")
                    return null;
                slots.Add(name!);
            }
            return new SlotInfo(slots, false);
        }

        var slotsList = new HashSet<string>(StringComparer.Ordinal);
        foreach (var child in container.Children)
        {
            if (!TrySlotName(context, child, out var name) || name == "__dict__")
                return null;
            slotsList.Add(name!);
        }
        return new SlotInfo(slotsList, false);
    }

    /// <summary>
    /// A slot entry is a string literal, or a bare identifier that resolves to exactly one top-level
    /// assignment of a string literal. Anything else (a call, an unresolved or ambiguous name, a
    /// non-string value) bails so the class is treated as unanalysable.
    /// </summary>
    private static bool TrySlotName(IRuleContext context, SyntaxNode? node, out string? name)
    {
        name = null;
        if (node == null)
            return false;
        if (node.Kind == NodeKind.StringLiteral)
        {
            name = node.Text;
            return true;
        }
        if (node.Kind == NodeKind.Identifier)
            return TryResolveSingleString(context, node.Text, out name);
        return false;
    }

    private static bool TryResolveSingleString(IRuleContext context, string name, out string? resolved)
    {
        resolved = null;
        string? found = null;
        foreach (var assignment in context.Root.OfKind(NodeKind.Assignment))
        {
            if (assignment.Ancestors().Any(a => a.Kind is NodeKind.FunctionDeclaration or NodeKind.ClassDeclaration))
                continue; // not at module scope

            var lhs = assignment.Children.FirstOrDefault();
            if (lhs == null || lhs.Kind != NodeKind.Identifier || lhs.Text != name)
                continue;

            var rhs = assignment.Children.ElementAtOrDefault(1);
            if (rhs?.Kind != NodeKind.StringLiteral)
                return false; // a non-string value makes the name unusable as a slot

            if (found != null)
                return false; // assigned more than once: ambiguous
            found = rhs.Text;
        }
        if (found == null)
            return false; // unresolved
        resolved = found;
        return true;
    }

    /// <summary>Bases of "class X(A, B):" read from the source, or null when they span lines.</summary>
    private static List<string>? ParseBases(string line)
    {
        var open = line.IndexOf('(');
        if (open < 0)
            return []; // no explicit base
        var close = line.IndexOf(')', open);
        if (close < 0)
            return null; // definition continues on another line

        var raw = line.Substring(open + 1, close - open - 1);
        var names = new List<string>();
        foreach (var part in raw.Split(','))
        {
            var name = part.Trim();
            var firstWord = name.Split(' ')[0];
            if (firstWord.Length == 0)
                continue;
            if (firstWord.Contains('.'))
                return null; // qualified base we cannot map to a local class
            names.Add(firstWord);
        }
        return names;
    }

    private sealed record SlotInfo(HashSet<string> Slots, bool HasDict);
}

public sealed class PythonIdentityCachedTypeRule : PythonSlotsRuleBase
{
    public override string Key => "QG-PY-SML-0573";
    public override string Name => "An identity comparison against a cached value should use equality instead";
    public override string RemediationEffort => "5min";
    public override string FixAdvice => "The `is` operator tests object identity, but literals and several builtin "
        + "values are cached by the runtime so the same value may or may not be the same object. Compare values "
        + "with `==` (or `!=` for `is not`). Keep `is` only for None, True and False, the three real singletons.";

    private static readonly HashSet<string> CachedConstructors = new(StringComparer.Ordinal)
    {
        "int", "float", "str", "bytes", "bytearray", "tuple", "frozenset", "hash"
    };

    public override void Execute(IRuleContext context)
    {
        if (!HasTree(context))
            return;

        foreach (var bin in context.Root.OfKind(NodeKind.Binary))
        {
            if (bin.Text is not ("is" or "is not"))
                continue;

            var lhs = bin.ChildAt(0);
            var rhs = bin.ChildAt(1);
            if (lhs == null || rhs == null)
                continue;

            if (IsSingleton(lhs) || IsSingleton(rhs))
                continue; // None / True / False are real singletons; `is None` is correct

            if (!IsCached(lhs) && !IsCached(rhs))
                continue;

            var replacement = bin.Text == "is" ? "==" : "!=";
            context.Report(bin,
                $"`{bin.Text}` compares object identity, but one side is a value Python may cache, so the "
                + $"result is not reliable. Use `{replacement}` to compare values.");
        }
    }

    private static bool IsSingleton(SyntaxNode node)
        => node.Kind is NodeKind.NullLiteral or NodeKind.BooleanLiteral;

    private static bool IsCached(SyntaxNode node)
    {
        switch (node.Kind)
        {
            case NodeKind.NumberLiteral:
            case NodeKind.StringLiteral:
            case NodeKind.ObjectInitializer: // a set or dict literal
            case NodeKind.Parenthesized: // a tuple literal, empty or not
                return true;
            case NodeKind.Unary:
                return node.Children.FirstOrDefault()?.Kind == NodeKind.NumberLiteral;
            case NodeKind.Binary:
                // a constant-folded numeric expression such as `1 + 1`
                return node.OfKind(NodeKind.NumberLiteral).Any()
                       && !node.OfKind(NodeKind.Identifier).Any()
                       && !node.OfKind(NodeKind.Invocation).Any()
                       && !node.OfKind(NodeKind.MemberSelect).Any();
            case NodeKind.Invocation:
                return CachedConstructors.Contains(SyntaxQuery.InvokedName(node));
            default:
                return false;
        }
    }
}
