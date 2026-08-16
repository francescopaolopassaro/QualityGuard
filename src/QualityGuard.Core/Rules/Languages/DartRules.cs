using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Dart and Flutter. The framework has a small set of mistakes that everybody makes once: rebuilding
/// from inside a build, keeping a controller alive after the widget is gone, touching a context that
/// belongs to a screen the user has already left. They are all visible in the tree, and none of them
/// fails at compile time.
/// </summary>
public static class DartRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new DartPrintInProductionRule(),
        new DartSetStateInBuildRule(),
        new DartMutableStatelessWidgetRule(),
        new DartUndisposedControllerRule(),
        new DartAsyncWithoutAwaitRule(),
        new DartRedundantNewRule(),
        new DartContextAfterAwaitRule()
    ];
}

public abstract class DartRuleBase : RuleBase
{
    protected static readonly string[] DisposableTypes =
    [
        "AnimationController", "TextEditingController", "ScrollController", "PageController",
        "TabController", "StreamSubscription", "StreamController", "FocusNode", "Timer",
        "VideoPlayerController", "WebViewController", "OverlayEntry", "Ticker"
    ];

    public override string[] Languages => ["dart"];
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "10min";

    protected static bool HasPreciseTree(IRuleContext context) => context.Tree.HasDedicatedParser;

    protected static bool IsWidget(SyntaxNode type)
        => type.Tokens.Any(t => t.Text is "StatelessWidget" or "StatefulWidget" or "State"
               or "InheritedWidget" or "RenderObjectWidget");

    protected static SyntaxNode? BuildMethod(SyntaxNode type)
        => type.OfKind(NodeKind.FunctionDeclaration).FirstOrDefault(f => f.Text == "build");
}

public sealed class DartPrintInProductionRule : DartRuleBase
{
    public override string Key => "QG-DART-SML-0001";
    public override string Name => "Diagnostics should not be printed to the console";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context) || context.File.Path.Contains("test", StringComparison.OrdinalIgnoreCase))
            return;

        foreach (var call in SyntaxQuery.InvocationsNamed(context.Root, "print"))
        {
            if (SyntaxQuery.Receiver(call).Length > 0)
                continue;

            context.Report(call, "print writes to the console of the device and stays in the release "
                                 + "build, where nobody reads it and where it can leak whatever it "
                                 + "formats. Use debugPrint while developing, and a logger for anything "
                                 + "that has to survive.");
        }
    }
}

public sealed class DartSetStateInBuildRule : DartRuleBase
{
    public override string Key => "QG-DART-BUG-0001";
    public override string Name => "A widget should not schedule a rebuild while it is building";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (BuildMethod(type) is not { } build)
                continue;

            foreach (var call in SyntaxQuery.InvocationsNamed(build, "setState"))
            {
                // inside a callback the call happens later, when the build is long finished
                if (call.Ancestor(NodeKind.Lambda) != null)
                    continue;

                context.Report(call, "setState during build asks the framework to rebuild the widget it "
                                     + "is currently building, which either throws or loops. Change the "
                                     + "state where the event happens — in a callback, in initState, or "
                                     + "in didChangeDependencies.");
            }
        }
    }
}

public sealed class DartMutableStatelessWidgetRule : DartRuleBase
{
    public override string Key => "QG-DART-BUG-0002";
    public override string Name => "A stateless widget should hold only final fields";
    public override IssueKind Kind => IssueKind.Bug;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!type.Tokens.Any(t => t.Text == "StatelessWidget"))
                continue;

            foreach (var field in type.OfKind(NodeKind.FieldDeclaration))
            {
                if (field.Ancestor(NodeKind.ClassDeclaration) != type)
                    continue;
                var modifiers = field.Tokens.Select(t => t.Text).ToList();
                if (modifiers.Contains("final") || modifiers.Contains("const") || modifiers.Contains("static"))
                    continue;

                context.Report(field, $"'{field.Text}' can be changed, but the framework may reuse or "
                                      + "rebuild this widget at any moment, so the new value is not what "
                                      + "gets rendered. Make the field final, and move anything that "
                                      + "really changes into a State.");
            }
        }
    }
}

public sealed class DartUndisposedControllerRule : DartRuleBase
{
    public override string Key => "QG-DART-BUG-0003";
    public override string Name => "A controller held by a state should be disposed";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "15min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var type in context.Root.OfKind(NodeKind.ClassDeclaration))
        {
            if (!IsWidget(type))
                continue;
            var dispose = type.OfKind(NodeKind.FunctionDeclaration).FirstOrDefault(f => f.Text == "dispose");
            var released = dispose == null
                ? []
                : SyntaxQuery.InvocationsNamed(dispose, "dispose", "cancel", "close")
                    .Select(SyntaxQuery.Receiver)
                    .ToHashSet(StringComparer.Ordinal);

            foreach (var field in type.OfKind(NodeKind.FieldDeclaration))
            {
                if (field.Ancestor(NodeKind.ClassDeclaration) != type || field.Text.Length == 0)
                    continue;
                var declared = field.Tokens.FirstOrDefault(t =>
                    DisposableTypes.Any(d => t.Text.StartsWith(d, StringComparison.Ordinal)));
                if (declared == null || released.Contains(field.Text))
                    continue;

                context.Report(field, $"'{field.Text}' is a {declared.Text} that nothing releases: it "
                                      + "keeps listening, keeps a reference to this state, and keeps the "
                                      + "widget tree alive after the screen is gone. Release it in "
                                      + "dispose().");
            }
        }
    }
}

public sealed class DartAsyncWithoutAwaitRule : DartRuleBase
{
    public override string Key => "QG-DART-SML-0002";
    public override string Name => "An async function should await something";
    public override Severity Severity => Severity.Minor;

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        var lines = context.File.Content.Split((char)10);

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            // the marker sits on the signature line, after the parameter list
            var signature = function.Line - 1 < lines.Length ? lines[function.Line - 1] : string.Empty;
            if (!signature.Contains(" async", StringComparison.Ordinal))
                continue;
            var body = SyntaxQuery.Body(function);
            if (body == null || body.Tokens.Any(t => t.Text is "await" or "yield"))
                continue;

            context.Report(function, $"'{function.Text}' is declared async but never waits for anything, "
                                     + "so it returns a future that is already complete while the callers "
                                     + "pay for the wrapping. Drop async, or await the work it should be "
                                     + "waiting for.");
        }
    }
}

public sealed class DartRedundantNewRule : DartRuleBase
{
    public override string Key => "QG-DART-CNV-0001";
    public override string Name => "The new keyword is not needed";
    public override Severity Severity => Severity.Minor;
    public override string RemediationEffort => "2min";

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens)
        {
            if (token.Kind != Tokenization.TokenKind.Keyword || token.Text != "new")
                continue;

            context.Report("Dart dropped the new keyword: it adds a word to every construction and "
                           + "distracts from the const that would let the framework reuse the widget. "
                           + "Remove it.", token.Line);
        }
    }
}

public sealed class DartContextAfterAwaitRule : DartRuleBase
{
    public override string Key => "QG-DART-BUG-0004";
    public override string Name => "A build context should not be used after an await";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        if (!HasPreciseTree(context))
            return;

        foreach (var function in SyntaxQuery.Functions(context.Root))
        {
            var body = SyntaxQuery.Body(function);
            if (body == null)
                continue;
            var awaitLine = body.Tokens.FirstOrDefault(t => t.Text == "await")?.Line;
            if (awaitLine == null)
                continue;

            foreach (var use in body.OfKind(NodeKind.Identifier))
            {
                if (use.Text != "context" || use.Line <= awaitLine)
                    continue;
                // a guarded use is the accepted way of doing this
                if (body.Tokens.Any(t => t.Text == "mounted" && t.Line < use.Line && t.Line > awaitLine))
                    break;

                context.Report(use, "The widget may have been removed while this function was waiting, "
                                    + "and using its context afterwards throws or navigates a screen "
                                    + $"that no longer exists (the await is on line {awaitLine}). Check "
                                    + "'mounted' after the await before touching the context.");
                break;
            }
        }
    }
}
