using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Components, in the two files they are written in. A component is one class split between the
/// markup and its code-behind, and the framework reaches into it by name: it fills parameters from
/// the query string, calls methods from JavaScript, binds handlers written in the markup. Nothing in
/// the signature says so, which is why these mistakes compile and fail at run time — a parameter that
/// silently stays empty, a call from JavaScript that never arrives.
/// </summary>
public static class BlazorRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new BlazorQueryParameterTypeRule(),
        new BlazorJsInvokableVisibilityRule(),
        new BlazorQueryParameterOutsideRouteRule(),
        new BlazorLambdaInMarkupLoopRule(),
        new BlazorParameterVisibilityRule(),
        new BlazorParameterOnFieldRule(),
        new BlazorAsyncVoidHandlerRule(),
        new BlazorSubscriptionWithoutDisposeRule()
    ];
}

public abstract class BlazorRuleBase : RuleBase
{
    public override string[] Languages => ["cs", "raz"];
    public override IssueKind Kind => IssueKind.Bug;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    /// <summary>Whether an attribute list on the member carries the given name.</summary>
    protected static bool HasAttribute(SyntaxNode member, string name)
        => member.ChildrenOf(NodeKind.Attribute)
            .Any(a => a.Text.Contains(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>The type written in front of a declaration, without its nullable mark.</summary>
    protected static string DeclaredType(SyntaxNode member)
        => (member.FirstChild(NodeKind.TypeReference)?.Text ?? string.Empty).TrimEnd('?');
}

public sealed class BlazorQueryParameterTypeRule : BlazorRuleBase
{
    /// <summary>
    /// The types the framework knows how to read out of a query string. Anything else is left at its
    /// default: the page loads, the parameter is empty, and nothing says why.
    /// </summary>
    private static readonly string[] Supported =
    [
        "bool", "Boolean", "DateTime", "DateOnly", "TimeOnly", "decimal", "Decimal", "double",
        "Double", "float", "Single", "Guid", "int", "Int32", "long", "Int64", "string", "String"
    ];

    public override string Key => "QG-CS-BUG-0096";
    public override string Name => "A parameter read from the query string must have a type the framework can bind";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var property in context.Root.OfKind(NodeKind.PropertyDeclaration))
        {
            if (!HasAttribute(property, "SupplyParameterFromQuery"))
                continue;
            var type = DeclaredType(property).TrimEnd('[', ']');
            if (type.Length == 0 || Supported.Contains(type, StringComparer.Ordinal))
                continue;

            context.Report($"'{property.Text}' is filled from the query string, and '{type}' is not a "
                           + "type the framework can read from one. The property keeps its default "
                           + "value and the page renders as if the parameter had not been passed.",
                property.Range.StartLine);
        }
    }
}

public sealed class BlazorJsInvokableVisibilityRule : BlazorRuleBase
{
    public override string Key => "QG-CS-BUG-0097";
    public override string Name => "A method called from JavaScript must be public";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            if (!HasAttribute(method, "JSInvokable"))
                continue;
            var modifiers = method.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (modifiers.Contains("public"))
                continue;

            context.Report($"'{method.Text}' is marked for JavaScript to call and is not public, so "
                           + "the call fails at run time with nothing in the C# to explain it. Make "
                           + "it public, or take the attribute off if nothing calls it from there.",
                method.Range.StartLine);
        }
    }
}

public sealed class BlazorQueryParameterOutsideRouteRule : BlazorRuleBase
{
    public override string Key => "QG-CS-SML-0340";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string Name => "A query string parameter only reaches a component with a route";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;
        // The route lives in the markup half of the component, as '@page "/…"'. A code-behind is read
        // together with it, so the directive is looked for in the whole component rather than in the
        // file that happens to hold the property.
        if (context.Project.TemplateReferenceCount("page") > 0)
            return;

        foreach (var property in context.Root.OfKind(NodeKind.PropertyDeclaration))
        {
            if (!HasAttribute(property, "SupplyParameterFromQuery"))
                continue;

            context.Report($"'{property.Text}' asks for a value from the query string, but nothing "
                           + "routes to this component: it is rendered by another one, which passes "
                           + "its parameters directly. The property is never filled.",
                property.Range.StartLine);
        }
    }
}

public sealed class BlazorLambdaInMarkupLoopRule : BlazorRuleBase
{
    public override string Key => "QG-CS-SML-0339";
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "15min";
    public override string Name => "A handler written as a lambda inside a markup loop is rebuilt on every render";

    public override void Execute(IRuleContext context)
    {
        if (context.Language.LanguageKey != "raz")
            return;

        var lines = context.File.Content.Split('\n');
        var loopIndent = -1;
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var trimmed = line.TrimStart();
            var indent = line.Length - trimmed.Length;

            if (loopIndent >= 0 && trimmed.Length > 0 && indent <= loopIndent && trimmed[0] == '}')
                loopIndent = -1;
            if (trimmed.StartsWith("@foreach", StringComparison.Ordinal)
                || trimmed.StartsWith("@for ", StringComparison.Ordinal)
                || trimmed.StartsWith("@for(", StringComparison.Ordinal)
                || trimmed.StartsWith("@while", StringComparison.Ordinal))
            {
                loopIndent = indent;
                continue;
            }
            if (loopIndent < 0)
                continue;
            // '@onclick="() => Remove(item)"' builds one delegate per item on every render, and the
            // framework cannot tell that the handler is the same as the one it had before
            if (!line.Contains("=>", StringComparison.Ordinal))
                continue;
            if (!line.Contains("@on", StringComparison.Ordinal)
                && !line.Contains("@bind", StringComparison.Ordinal))
                continue;

            context.Report("This handler is a lambda inside a loop, so the markup builds a new "
                           + "delegate for every item on every render and the framework redraws rows "
                           + "that did not change. Call a method with the item as its argument.",
                i + 1);
        }
    }
}

public sealed class BlazorParameterVisibilityRule : BlazorRuleBase
{
    public override string Key => "QG-CS-BUG-0193";
    public override string Name => "A component parameter must be public";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var property in context.Root.OfKind(NodeKind.PropertyDeclaration))
        {
            // Only a plain parameter has to be public. A cascading one is resolved through the
            // component's own metadata, and component libraries declare theirs private on purpose —
            // reporting those was every finding this rule made on a real application.
            if (!HasAttribute(property, "Parameter") || HasAttribute(property, "CascadingParameter"))
                continue;
            var modifiers = property.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (modifiers.Contains("public"))
                continue;

            context.Report($"'{property.Text}' is declared as a component parameter and is not public, "
                           + "so the framework cannot set it: whoever renders the component passes a "
                           + "value that goes nowhere, and the component uses its default instead.",
                property.Range.StartLine);
        }
    }
}

public sealed class BlazorParameterOnFieldRule : BlazorRuleBase
{
    public override string Key => "QG-CS-BUG-0194";
    public override string Name => "A component parameter has to be a property";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var field in context.Root.OfKind(NodeKind.FieldDeclaration))
        {
            if (!HasAttribute(field, "Parameter") && !HasAttribute(field, "CascadingParameter"))
                continue;
            // a field with an initialiser and no accessors is the shape the framework cannot assign
            if (field.OfKind(NodeKind.Accessor).Any())
                continue;

            context.Report($"'{field.Text}' carries the parameter attribute on a field. The framework "
                           + "assigns parameters through properties only, so this one is never set and "
                           + "the attribute reads as a promise the code does not keep.",
                field.Range.StartLine);
        }
    }
}

public sealed class BlazorAsyncVoidHandlerRule : BlazorRuleBase
{
    public override string Key => "QG-CS-BUG-0195";
    public override string Name => "An asynchronous component method should return a task";

    public override void Execute(IRuleContext context)
    {
        if (context.Language.LanguageKey != "raz" || !context.Tree.HasDedicatedParser)
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var modifiers = method.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (!modifiers.Contains("async"))
                continue;
            var returns = method.FirstChild(NodeKind.TypeReference)?.Text ?? string.Empty;
            if (returns != "void")
                continue;

            context.Report($"'{method.Text}' is asynchronous and returns nothing, so the component "
                           + "cannot wait for it and cannot see it fail: an exception inside it is "
                           + "raised on a thread with no handler and takes the circuit down. Return a "
                           + "task and let the caller await it.", method.Range.StartLine);
        }
    }
}

public sealed class BlazorSubscriptionWithoutDisposeRule : BlazorRuleBase
{
    public override string Key => "QG-CS-BUG-0196";
    public override string RemediationEffort => "15min";
    public override string Name => "A component that subscribes to an event has to unsubscribe";

    public override void Execute(IRuleContext context)
    {
        if (context.Language.LanguageKey != "raz" || !context.Tree.HasDedicatedParser)
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            var subscriptions = type.OfKind(NodeKind.Assignment)
                .Where(a => a.Text == "+=" && a.ChildAt(0)?.Kind == NodeKind.MemberSelect)
                .ToList();
            if (subscriptions.Count == 0)
                continue;
            // Unsubscribing is what Dispose is for here, and '-=' anywhere in the component is the
            // shape that does it. Either one present means the author has thought about the lifetime.
            var releases = type.OfKind(NodeKind.Assignment).Any(a => a.Text == "-=");
            var disposes = type.OfKind(NodeKind.FunctionDeclaration)
                .Any(m => m.Text is "Dispose" or "DisposeAsync");
            if (releases || disposes)
                continue;

            context.Report("This component subscribes to an event and never lets go of it. The "
                           + "publisher keeps a reference to a component the user has navigated away "
                           + "from, so it stays alive and keeps handling events for a screen that is "
                           + "no longer there. Unsubscribe in Dispose.",
                subscriptions[0].Range.StartLine);
        }
    }
}
