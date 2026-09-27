using QualityGuard.Core.Analysis;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Three findings on a small hand-written project (an accessibility toolbar: one script, one stylesheet, one
/// demo page) that were wrong, and that sent an AI agent chasing problems that were not there:
/// its main script was never analysed, hex colours were reported as misspelt units, and a form's onsubmit
/// was reported as unreachable by keyboard under a nameless tag.
/// </summary>
public class FlowAbleRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "qg-flowable-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_root, true); } catch (IOException) { }
    }

    private string Write(string relative, string content)
    {
        var path = Path.Combine(_root, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    private IReadOnlyList<string> Scanned()
        => SourceScanner.Scan(new ScanOptions { Paths = [_root] }).Files
            .Select(f => Path.GetRelativePath(_root, f).Replace('\\', '/'))
            .ToList();

    [Fact]
    public void HeaderThatMentionsALibrary_DoesNotMakeTheFileALibrary()
    {
        Write("src/flowable.js", """
            /*!
             * FlowAble — standalone accessibility toolbar
             * Zero dependencies (no jQuery/Bootstrap/server data). Safe to extract as-is.
             */
            (function () { 'use strict'; var a = 1; })();
            """);
        Write("src/widgets.css", """
            /* Three buttons, a prototype of the toolbar layout. */
            .toolbar { display: flex; }
            """);

        var files = Scanned();

        Assert.Contains("src/flowable.js", files);
        Assert.Contains("src/widgets.css", files);
    }

    [Theory]
    [InlineData("/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */")]
    [InlineData("/*!\n * Bootstrap v5.3.2 (https://getbootstrap.com/)\n * Copyright 2011-2023 The Bootstrap Authors\n */")]
    [InlineData("/*! @license DOMPurify 3.0.6 | lodash 4.17.21 */")]
    [InlineData("/**\n * @license\n * Lodash <https://lodash.com/>\n */")]
    public void RealLibraryBanner_IsStillExcluded(string banner)
    {
        Write("wwwroot/lib-copy.js", banner + "\n(function(){var a=1;})();\n");

        Assert.DoesNotContain("wwwroot/lib-copy.js", Scanned());
    }

    [Fact]
    public void HexColours_AreNotUnits()
    {
        const string sheet = """
            :root {
              --muted: #9ca3af;
              --kb-bg: #333a4d;
              --link: #93c5fd;
              --short: #12ab;
            }
            .a { padding: 6px 16px 10px; font-size: 10px; color: #9ca3af; }
            """;
        var analysis = Analyze.WithRules("site.css", sheet, "QG-CSS-SML-0083");

        Assert.Empty(Analyze.LinesOf(analysis, "QG-CSS-SML-0083"));
    }

    [Fact]
    public void MisspeltUnit_IsStillReported()
    {
        var analysis = Analyze.WithRules("site.css", ".a { width: 10pz; }\n", "QG-CSS-SML-0083");

        Assert.Equal([1], Analyze.LinesOf(analysis, "QG-CSS-SML-0083"));
    }

    [Fact]
    public void FormSubmitHandler_IsNotAKeyboardTrap()
    {
        const string page = """
            <!doctype html>
            <html lang="en"><body>
              <form class="demo-form" onsubmit="return false;">
                <input id="n" type="text"><button type="submit">Send</button>
              </form>
            </body></html>
            """;
        var analysis = Analyze.WithRules("page.html", page, "QG-HTML-SML-0062");

        Assert.Empty(Analyze.LinesOf(analysis, "QG-HTML-SML-0062"));
    }

    [Fact]
    public void ClickHandlerOnDiv_IsReported_WithItsTagName()
    {
        const string page = """
            <!doctype html>
            <html lang="en"><body>
              <div class="card" onclick="open()">Open</div>
            </body></html>
            """;
        var analysis = Analyze.WithRules("page.html", page, "QG-HTML-SML-0062");

        var issue = Assert.Single(analysis.Issues, i => i.RuleKey == "QG-HTML-SML-0062");
        Assert.StartsWith("<div onclick>", issue.Message);
    }
}
