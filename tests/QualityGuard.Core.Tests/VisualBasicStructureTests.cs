using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// VB.NET block structure. Every case here was found on a real VB codebase, where the file collapsed
/// into a single nesting chain: one twelve-line function scored 75 on cognitive complexity because
/// nothing after it ever closed. The end-keyword parser was written for Ruby, and VB closes its
/// blocks in four different ways.
/// </summary>
public class VisualBasicStructureTests
{
    private static SyntaxTree Parse(string code)
        => SyntaxTree.Build(new SourceTokenizer(code, BuiltInLanguages.Basic).Tokenize(),
            BuiltInLanguages.Basic);

    private static IReadOnlyList<string> Functions(SyntaxTree tree)
        => tree.Root.OfKind(NodeKind.FunctionDeclaration).Select(f => f.Text).ToList();

    /// <summary>The functions declared directly in the class body, in order.</summary>
    private static IReadOnlyList<string> TopLevelFunctions(SyntaxTree tree)
    {
        var type = tree.Root.OfKind(NodeKind.ClassDeclaration).FirstOrDefault();
        var body = type?.FirstChild(NodeKind.Block);
        return body?.ChildrenOf(NodeKind.FunctionDeclaration).Select(f => f.Text).ToList() ?? [];
    }

    [Fact]
    public void End_If_closes_the_branch_instead_of_opening_another()
    {
        var code = """
            Public Class A
                Function First() As String
                    If Ready Then
                        Return "a"
                    Else
                        Return "b"
                    End If
                End Function

                Function Second() As Integer
                    Return 1
                End Function
            End Class
            """;
        Assert.Equal(["First", "Second"], TopLevelFunctions(Parse(code)));
    }

    [Fact]
    public void Next_closes_a_for_loop()
    {
        var code = """
            Public Class A
                Function First() As Integer
                    For Each item In Items
                        Total += item
                    Next
                    Return Total
                End Function

                Function Second() As Integer
                    Return 1
                End Function
            End Class
            """;
        Assert.Equal(["First", "Second"], TopLevelFunctions(Parse(code)));
    }

    [Fact]
    public void A_second_catch_ends_the_first_one()
    {
        var code = """
            Public Class A
                Function First() As Integer
                    Try
                        Work()
                    Catch exs As SoapException
                        Throw New DatoNonValidoException(exs.Message)
                    Catch ex As Exception
                        Throw ex
                    End Try
                    Return 1
                End Function

                Function Second() As Integer
                    Return 1
                End Function
            End Class
            """;
        Assert.Equal(["First", "Second"], TopLevelFunctions(Parse(code)));
    }

    [Fact]
    public void A_one_line_if_opens_no_block()
    {
        var code = """
            Public Class A
                Function First() As Integer
                    If Items Is Nothing Then Items = New List(Of String)
                    Return 1
                End Function

                Function Second() As Integer
                    Return 1
                End Function
            End Class
            """;
        Assert.Equal(["First", "Second"], TopLevelFunctions(Parse(code)));
    }

    [Fact]
    public void With_and_using_blocks_are_closed_by_their_own_end()
    {
        var code = """
            Public Class A
                Function First() As Integer
                    Using reader As New StreamReader(path)
                        Read(reader)
                    End Using
                    With Target
                        .Name = "x"
                    End With
                    Return 1
                End Function

                Function Second() As Integer
                    Return 1
                End Function
            End Class
            """;
        Assert.Equal(["First", "Second"], TopLevelFunctions(Parse(code)));
    }

    [Fact]
    public void A_conditional_compilation_directive_is_not_a_branch()
    {
        var code = """
            Public Class A
                Function First() As String
            #If DEBUG Then
                    Return "test"
            #Else
                    Return "live"
            #End If
                End Function

                Function Second() As Integer
                    Return 1
                End Function
            End Class
            """;
        Assert.Equal(["First", "Second"], TopLevelFunctions(Parse(code)));
    }

    [Fact]
    public void A_short_function_keeps_a_low_complexity()
    {
        var code = """
            Public Class A
                Function GetUrl() As String
                    Dim IsTest As Boolean = True
            #If DEBUG Then
                    If IsTest Then
                        Return UrlTest
                    Else
                        Return UrlLive
                    End If
            #Else
                    Return UrlLive
            #End If
                End Function
            End Class
            """;
        var tree = Parse(code);
        var function_ = tree.Root.OfKind(NodeKind.FunctionDeclaration).Single();
        // one branch, so the score is a small number rather than the 75 the broken nesting produced
        Assert.InRange(Core.Analysis.MetricCalculator.CognitiveComplexity(function_, 0), 0, 5);
    }

    [Fact]
    public void Ruby_still_closes_with_a_bare_end()
    {
        var tree = SyntaxTree.Build(
            new SourceTokenizer("class A\n  def first\n    1\n  end\n\n  def second\n    2\n  end\nend\n",
                BuiltInLanguages.Ruby).Tokenize(),
            BuiltInLanguages.Ruby);

        Assert.Equal(["first", "second"], Functions(tree));
    }

    [Fact]
    public void Redundant_boolean_literal_via_Not_is_reported()
    {
        var code = """
            Public Class A
                Sub F(a As Boolean)
                    Dim z = Not True
                End Sub
            End Class
            """;
        var lines = Analyze.LinesOf(Analyze.WithRules("A.vb", code, "QG-CS-SML-1082"), "QG-CS-SML-1082");
        Assert.Contains(3, lines);
    }

    [Fact]
    public void A_declaration_initializer_is_not_a_boolean_comparison()
    {
        var code = """
            Public Class A
                Sub F()
                    Dim condition = False
                    Dim exp = True
                End Sub
            End Class
            """;
        Assert.Empty(Analyze.LinesOf(Analyze.WithRules("A.vb", code, "QG-CS-SML-1082"), "QG-CS-SML-1082"));
    }
}
