using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Web controllers and the routes that reach them. Everything here is decided by attributes the
/// framework reads at start-up, so a mistake compiles cleanly and shows up as a route that answers
/// 404, a parameter that stays empty, or a page that renders without the data it was written for.
/// </summary>
public static class AspNetRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new AspNetApiControllerBaseTypeRule(),
        new AspNetAbsoluteActionRouteRule(),
        new AspNetMissingControllerRouteRule(),
        new AspNetBackslashInRouteRule(),
        new BlazorRouteParameterTypeRule()
    ];
}

public abstract class AspNetRuleBase : RuleBase
{
    public override string[] Languages => ["cs", "raz"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasAttribute(SyntaxNode member, params string[] names)
        => member.ChildrenOf(NodeKind.Attribute)
            .Any(a => names.Any(n => a.Text.Contains(n, StringComparison.OrdinalIgnoreCase)));

    /// <summary>Types that answer web requests, by the convention the framework itself uses.</summary>
    protected static bool IsController(SyntaxNode type, IRuleContext context)
        => type.Text.EndsWith("Controller", StringComparison.Ordinal)
           || HasAttribute(type, "ApiController")
           || BaseNames(type, context).Any(b => b is "Controller" or "ControllerBase");

    protected static IEnumerable<string> BaseNames(SyntaxNode type, IRuleContext context)
    {
        var info = context.Project.FindTypes(type.Text).FirstOrDefault(t => t.Node == type);
        return info?.BaseNames ?? [];
    }

    /// <summary>Methods a controller exposes: public, not a constructor, not a local helper.</summary>
    protected static IEnumerable<SyntaxNode> Actions(SyntaxNode type)
        => type.OfKind(NodeKind.FunctionDeclaration)
            .Where(m => m.Ancestor(NodeKind.ClassDeclaration) == type
                        && m.ChildrenOf(NodeKind.Modifier).Any(x => x.Text == "public"));

    /// <summary>The literal a routing attribute carries, without its quotes.</summary>
    protected static IEnumerable<string> RouteTemplates(SyntaxNode member)
    {
        foreach (var attribute in member.ChildrenOf(NodeKind.Attribute))
        {
            if (!attribute.Text.Contains("Route", StringComparison.OrdinalIgnoreCase)
                && !attribute.Text.StartsWith("Http", StringComparison.Ordinal))
                continue;
            foreach (var literal in attribute.OfKind(NodeKind.StringLiteral))
                yield return literal.Text;
        }
    }
}

public sealed class AspNetApiControllerBaseTypeRule : AspNetRuleBase
{
    /// <summary>
    /// What only the view-aware base class offers. A controller that renders nothing has no use for
    /// it, but one that calls any of these does — deriving from the lighter base would stop compiling,
    /// and reporting it would be asking for a change that cannot be made.
    /// </summary>
    private static readonly string[] ViewMembers =
    [
        "View", "PartialView", "ViewBag", "ViewData", "ViewResult", "ViewComponent", "TempData",
        "Json", "OnActionExecuted", "OnActionExecuting", "OnActionExecutionAsync"
    ];

    public override string Key => "QG-CS-SML-0345";
    public override string Name => "An API controller should derive from the base without views";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!HasAttribute(type, "ApiController"))
                continue;
            if (!BaseNames(type, context).Contains("Controller"))
                continue;
            if (type.OfKind(NodeKind.Identifier).Any(i => ViewMembers.Contains(i.Text, StringComparer.Ordinal)))
                continue;

            context.Report($"'{type.Text}' answers with data and inherits the machinery for rendering "
                           + "views, which it never uses: view lookup, temp data, the action filters "
                           + "that go with them. Derive from the base without views and the type "
                           + "carries only what it needs.", type.Range.StartLine);
        }
    }
}

public sealed class AspNetAbsoluteActionRouteRule : AspNetRuleBase
{
    public override string Key => "QG-CS-SML-0341";
    public override string Name => "Action routes should be relative to the route of their controller";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!IsController(type, context))
                continue;

            var templates = Actions(type).SelectMany(RouteTemplates).ToList();
            if (templates.Count == 0)
                continue;
            // One relative path is enough to make the controller's route meaningful, and then the
            // absolute ones are a deliberate exception rather than a pattern. The rule speaks only
            // when every action writes its own full path.
            if (!templates.All(t => t.StartsWith('/') || t.StartsWith("~/", StringComparison.Ordinal)))
                continue;

            context.Report($"Every action of '{type.Text}' writes its own absolute path, so the route "
                           + "of the controller says nothing and moving the group means editing each "
                           + "one. Put the common prefix on the controller and make the actions "
                           + "relative to it.", type.Range.StartLine);
        }
    }
}

public sealed class AspNetMissingControllerRouteRule : AspNetRuleBase
{
    public override string Key => "QG-CS-SML-0343";
    public override string Name => "A controller whose actions carry a route needs one of its own";

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!IsController(type, context) || HasAttribute(type, "Route"))
                continue;

            var withTemplate = Actions(type)
                .Where(a => RouteTemplates(a).Any(t => t.Length > 0
                                                       && !t.StartsWith('/')
                                                       && !t.StartsWith("~/", StringComparison.Ordinal)))
                .ToList();
            if (withTemplate.Count == 0)
                continue;

            context.Report($"The actions of '{type.Text}' declare paths that are relative to a route "
                           + "the controller does not have, so what they answer on depends on the "
                           + "conventional route the application happens to configure. Say it on the "
                           + "controller.", type.Range.StartLine);
        }
    }
}

public sealed class AspNetBackslashInRouteRule : AspNetRuleBase
{
    public override string Key => "QG-CS-BUG-0099";
    public override string Name => "A route template should be written with forward slashes";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var member in context.Root.OfKind(NodeKind.ClassDeclaration, NodeKind.FunctionDeclaration))
        {
            foreach (var template in RouteTemplates(member))
            {
                if (!template.Contains('\\'))
                    continue;

                context.Report($"The path '{template}' separates its segments with a backslash. Routing "
                               + "splits on the forward slash only, so this is one long segment and the "
                               + "address nobody can reach is the one the code says it serves.",
                    member.Range.StartLine);
                break;
            }
        }
    }
}

public sealed class BlazorRouteParameterTypeRule : AspNetRuleBase
{
    /// <summary>The constraint a route puts on a segment, and the C# types that satisfy it.</summary>
    private static readonly Dictionary<string, string[]> Constraints = new(StringComparer.OrdinalIgnoreCase)
    {
        ["int"] = ["int", "Int32", "long", "Int64"],
        ["long"] = ["long", "Int64"],
        ["bool"] = ["bool", "Boolean"],
        ["datetime"] = ["DateTime", "DateOnly"],
        ["decimal"] = ["decimal", "Decimal"],
        ["double"] = ["double", "Double"],
        ["float"] = ["float", "Single"],
        ["guid"] = ["Guid"],
    };

    public override string Key => "QG-CS-BUG-0098";
    public override string Name => "A component parameter should have the type its route constrains it to";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (context.Language.LanguageKey != "raz" || !context.Tree.HasDedicatedParser)
            return;

        // '@page "/orders/{id:int}"' is markup, so the directive is read from the text; the parameter
        // it constrains is a property of the same component, declared in the '@code' block.
        var declared = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in context.File.Content.Split('\n'))
        {
            var trimmed = line.TrimStart();
            if (!trimmed.StartsWith("@page", StringComparison.Ordinal))
                continue;
            var open = trimmed.IndexOf('{');
            while (open >= 0)
            {
                var close = trimmed.IndexOf('}', open);
                if (close < 0)
                    break;
                var segment = trimmed[(open + 1)..close];
                var colon = segment.IndexOf(':');
                if (colon > 0)
                    declared[segment[..colon].Trim('*', '?')] = segment[(colon + 1)..].Split(':')[0];
                open = trimmed.IndexOf('{', close);
            }
        }
        if (declared.Count == 0)
            return;

        foreach (var property in context.Root.OfKind(NodeKind.PropertyDeclaration))
        {
            if (!declared.TryGetValue(property.Text, out var constraint)
                || !Constraints.TryGetValue(constraint, out var accepted))
                continue;
            var type = (property.FirstChild(NodeKind.TypeReference)?.Text ?? string.Empty).TrimEnd('?');
            if (type.Length == 0 || accepted.Contains(type, StringComparer.Ordinal))
                continue;

            context.Report($"The route constrains '{property.Text}' to {constraint} and the property is "
                           + $"declared as '{type}'. The two cannot both be right: the address that "
                           + "matches the route fails to bind, and the component is rendered with the "
                           + "parameter left empty.", property.Range.StartLine);
        }
    }
}
