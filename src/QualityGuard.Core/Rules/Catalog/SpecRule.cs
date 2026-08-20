using System.Text.RegularExpressions;
using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Catalog;

/// <summary>
/// Executes a catalog entry against the syntax tree. One class serves every declarative rule, which is
/// what makes porting a whole language catalog a data exercise rather than a coding one.
/// </summary>
public sealed class SpecRule(CatalogEntry entry) : IRule
{
    private readonly Dictionary<string, Regex> _patterns = new(StringComparer.Ordinal);

    public CatalogEntry Entry { get; } = entry;

    public string Key => Entry.Key;
    public string Name => Entry.Name;
    public Severity Severity => Entry.Severity;
    public IssueKind Kind => Entry.Kind;
    public string RemediationEffort => Entry.Effort;
    public string[] Languages => Entry.Languages;
    public RuleDescription Description => Entry.Description;
    public string[] Tags => Entry.Tags;
    public int[] Cwe => Entry.Cwe;
    public string[] Owasp => Entry.Owasp;

    public void Execute(IRuleContext context)
    {
        if (Entry.Scope == "main"
            && Rules.Languages.LanguageRuleSupport.IsTestFile(context.File.Path, context.File.FileName))
            return;

        foreach (var spec in Entry.Detect)
        {
            if (!GuardsHold(context, spec))
                continue;
            switch (spec.Target)
            {
                case MatchTarget.Line:
                    MatchLines(context, spec);
                    break;
                case MatchTarget.String:
                    MatchStrings(context, spec);
                    break;
                case MatchTarget.Identifier:
                    MatchNodes(context, spec, NodeKind.Identifier, n => n.Text);
                    MatchNodes(context, spec, NodeKind.Attribute, n => n.Text);
                    break;
                case MatchTarget.Member:
                    MatchNodes(context, spec, NodeKind.MemberSelect, SyntaxQuery.DottedName);
                    break;
                case MatchTarget.Creation:
                    MatchNodes(context, spec, NodeKind.ObjectCreation, n => n.Text);
                    break;
                case MatchTarget.Assignment:
                    MatchAssignments(context, spec);
                    break;
                case MatchTarget.Declaration:
                    MatchDeclarations(context, spec);
                    break;
                case MatchTarget.Parameter:
                    MatchParameters(context, spec);
                    break;
                default:
                    MatchInvocations(context, spec);
                    break;
            }
        }
    }

    private bool GuardsHold(IRuleContext context, MatchSpec spec)
    {
        var content = context.File.Content;
        if (spec.Requires.Length > 0 && !spec.Requires.Any(r => content.Contains(r, StringComparison.OrdinalIgnoreCase)))
            return false;
        if (spec.Absent.Length > 0 && spec.Absent.Any(a => content.Contains(a, StringComparison.OrdinalIgnoreCase)))
            return false;
        return true;
    }

    private void MatchInvocations(IRuleContext context, MatchSpec spec)
    {
        foreach (var invocation in SyntaxQuery.Invocations(context.Root))
        {
            var simple = SyntaxQuery.InvokedName(invocation);
            var dotted = SyntaxQuery.InvokedDottedName(invocation);
            if (spec.Names.Length > 0 && !Matches(simple, spec.Names))
                continue;
            if (spec.Dotted.Length > 0 && !MatchesDotted(dotted, spec.Dotted))
                continue;
            if (spec.Receivers.Length > 0 && !MatchesDotted(SyntaxQuery.Receiver(invocation), spec.Receivers))
                continue;
            if (spec.ResultUnused && invocation.Parent?.Kind != NodeKind.ExpressionStatement)
                continue;
            if (!ArgumentsMatch(context, invocation, spec))
                continue;
            Report(context, invocation, spec);
        }
    }

    private void MatchNodes(IRuleContext context, MatchSpec spec, NodeKind kind, Func<SyntaxNode, string> nameOf)
    {
        foreach (var node in context.Root.OfKind(kind))
        {
            var name = nameOf(node);
            if (spec.Names.Length > 0 && !Matches(name, spec.Names) && !MatchesDotted(name, spec.Names))
                continue;
            if (spec.Dotted.Length > 0 && !MatchesDotted(name, spec.Dotted))
                continue;
            if (spec.ResultUnused && node.Parent?.Kind != NodeKind.ExpressionStatement)
                continue;
            if (kind == NodeKind.ObjectCreation && !ArgumentsMatch(context, node, spec))
                continue;
            Report(context, node, spec);
        }
    }

    private void MatchStrings(IRuleContext context, MatchSpec spec)
    {
        foreach (var literal in context.Root.OfKind(NodeKind.StringLiteral))
        {
            var fragments = spec.Contains.Length > 0 ? spec.Contains : spec.Names;
            if (fragments.Length > 0 && !fragments.Any(f => literal.Text.Contains(f, StringComparison.OrdinalIgnoreCase)))
                continue;
            Report(context, literal, spec);
        }
    }

    private void MatchAssignments(IRuleContext context, MatchSpec spec)
    {
        foreach (var node in context.Root.OfKind(NodeKind.Assignment, NodeKind.VariableDeclaration))
        {
            var assignment = node.Kind == NodeKind.Assignment
                ? node
                : node.Descendants().FirstOrDefault(d => d.Kind == NodeKind.Assignment);
            if (assignment == null)
                continue;
            var target = SyntaxQuery.DottedName(assignment.ChildAt(0));
            if (target.Length == 0)
                target = node.Text;
            if (spec.Names.Length > 0 && !ContainsAny(target, spec.Names))
                continue;
            var value = assignment.ChildAt(1);
            if (spec.LiteralValue && !SyntaxQuery.IsLiteral(value))
                continue;
            if (spec.Contains.Length > 0)
            {
                var literal = SyntaxQuery.ConstantString(value);
                if (literal == null || !spec.Contains.Any(c => literal.Contains(c, StringComparison.OrdinalIgnoreCase)))
                    continue;
            }
            if (spec.ArgTainted && !context.IsTainted(value))
                continue;
            if (spec.ArgDynamic && !SyntaxQuery.IsDynamicallyBuilt(value))
                continue;
            Report(context, assignment, spec);
        }
    }

    private void MatchDeclarations(IRuleContext context, MatchSpec spec)
    {
        foreach (var symbol in context.Semantics.AllSymbols())
        {
            if (symbol.DeclaredType is not { } type || !Matches(type, spec.Names))
                continue;
            var declaration = symbol.Usages.FirstOrDefault(u => u.Kind is Semantics.UsageKind.Declaration);
            if (declaration != null)
                Report(context, declaration.Identifier, spec);
        }
    }

    private void MatchParameters(IRuleContext context, MatchSpec spec)
    {
        foreach (var parameter in context.Root.OfKind(NodeKind.Parameter))
        {
            var type = (parameter.FirstChild(NodeKind.TypeReference)
                        ?? parameter.FirstChild(NodeKind.Identifier))?.Text;
            if (type == null || !Matches(type, spec.Names))
                continue;
            Report(context, parameter, spec);
        }
    }

    private void MatchLines(IRuleContext context, MatchSpec spec)
    {
        if (spec.LinePattern is not { Length: > 0 } pattern)
            return;
        var regex = _patterns.TryGetValue(pattern, out var cached)
            ? cached
            // case is ignored by default because most catalogue patterns name an API and do not
            // care how it was typed; a rule that is about the case itself opens with '(?-i)'
            : _patterns[pattern] = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // A pattern that recognises the shape of a credential recognises the manual's example just
        // as well, so a rule tagged as hunting for secrets gets the same filters the dedicated
        // secret rules use.
        var hunting = Entry.Tags.Contains("secret", StringComparer.OrdinalIgnoreCase);
        if (hunting && SecretFilters.IsIllustrative(context.File.Path))
            return;

        var lines = context.File.Content.Split('\n');
        var commentOnly = CommentOnlyLines(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (commentOnly.Contains(i + 1))
                continue;
            var found = regex.Match(lines[i]);
            if (!found.Success)
                continue;
            if (hunting && SecretFilters.LooksLikeAPlaceholder(found.Value))
                continue;
            context.Report(spec.Message ?? Entry.Message, i + 1);
        }
    }

    /// <summary>
    /// The lines that hold nothing but a comment. A pattern written for code matches the same words
    /// in prose — '@throws IllegalStateException' in a doc comment, 'name.equals("id")' in an example —
    /// and reporting there says the defect is in documentation, where there is no defect at all.
    /// </summary>
    private static HashSet<int> CommentOnlyLines(IRuleContext context)
    {
        var comments = new HashSet<int>();
        var code = new HashSet<int>();
        foreach (var token in context.Tokens)
        {
            if (token.Kind == Tokenization.TokenKind.Comment)
            {
                var span = token.Text.Count(c => c == '\n');
                for (var line = token.Line; line <= token.Line + span; line++)
                    comments.Add(line);
            }
            else
            {
                code.Add(token.Line);
            }
        }
        comments.ExceptWith(code);
        return comments;
    }

    private bool ArgumentsMatch(IRuleContext context, SyntaxNode call, MatchSpec spec)
    {
        var arguments = SyntaxQuery.Arguments(call);
        if (spec.ArgCount is { } count && arguments.Count != count)
            return false;

        var scoped = spec.ArgIndex is { } index
            ? index < arguments.Count ? [arguments[index]] : Array.Empty<SyntaxNode>()
            : arguments.ToArray();

        if (spec.ArgLiterals.Length > 0)
        {
            var found = scoped.Any(a => context.Semantics.StringValueOf(a) is { } value
                                        && spec.ArgLiterals.Any(l => value.Contains(l, StringComparison.OrdinalIgnoreCase)));
            if (!found)
                return false;
        }
        if (spec.ArgTainted && !scoped.Any(context.IsTainted))
            return false;
        if (spec.ArgDynamic && !scoped.Any(SyntaxQuery.IsDynamicallyBuilt))
            return false;
        if (spec.WithoutArgs.Length > 0)
        {
            var text = string.Join(' ', arguments.Select(a => a.SourceText()));
            if (spec.WithoutArgs.Any(w => text.Contains(w, StringComparison.OrdinalIgnoreCase)))
                return false;
        }
        if (spec.LiteralValue && !scoped.Any(SyntaxQuery.IsLiteral))
            return false;
        if (spec.ArgNotLiteral && !scoped.Any(a => !SyntaxQuery.IsLiteral(a)))
            return false;
        return true;
    }

    private void Report(IRuleContext context, SyntaxNode node, MatchSpec spec)
        => context.Report(node, spec.Message ?? Entry.Message, spec.ArgTainted);

    private static bool Matches(string text, string[] names)
    {
        if (text.Length == 0)
            return false;
        foreach (var name in names)
        {
            if (string.Equals(text, name, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool MatchesDotted(string dotted, string[] candidates)
    {
        if (dotted.Length == 0)
            return false;
        foreach (var candidate in candidates)
        {
            if (dotted.Equals(candidate, StringComparison.OrdinalIgnoreCase)
                || dotted.EndsWith("." + candidate, StringComparison.OrdinalIgnoreCase)
                || dotted.StartsWith(candidate + ".", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool ContainsAny(string text, string[] fragments)
    {
        foreach (var fragment in fragments)
        {
            if (text.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
