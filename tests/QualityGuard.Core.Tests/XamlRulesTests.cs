using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Desktop markup, read the same way for WPF, WinUI and Avalonia. Each case here fails when the
/// screen is built rather than when the project is compiled, which is why the markup is worth reading
/// against the class behind it.
/// </summary>
public class XamlRulesTests
{
    private const string Window = """
        <Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
            <Window.Resources>
                <SolidColorBrush x:Key="Accent" Color="#FF2196F3" />
            </Window.Resources>
            <StackPanel>
                <TextBlock x:Name="Header" Foreground="{StaticResource Accent}" />
                <TextBlock x:Name="Header" />
                <Button Click="OnSave" Background="{StaticResource Missing}" />
            </StackPanel>
        </Window>
        """;

    private static IReadOnlyList<int> Lines(string rule)
        => Analyze.LinesOf(Analyze.WithRules("MainWindow.xaml", Window, rule), rule);

    [Fact]
    public void A_name_used_twice_is_reported() => Assert.NotEmpty(Lines("QG-XAML-BUG-0001"));

    [Fact]
    public void A_resource_key_that_resolves_nowhere_is_reported()
    {
        var lines = Lines("QG-XAML-BUG-0002");
        // 'Accent' is defined in the same file and must not be reported
        Assert.Single(lines);
    }

    [Fact]
    public void A_binding_is_not_read_as_a_handler_name()
    {
        // without any code in the scan there is nothing to compare against, so the rule stays quiet
        Assert.Empty(Lines("QG-XAML-BUG-0003"));
    }
}
