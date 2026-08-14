using QualityGuard.Core.Syntax;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>Grammar coverage for the JavaScript and TypeScript dialects.</summary>
public class JsTsParserTests
{
    private static SyntaxNode Js(string code) => Analyze.File("sample.js", code).Tree.Root;

    private static SyntaxNode Ts(string code) => Analyze.File("sample.ts", code).Tree.Root;

    [Fact]
    public void Modules_classes_and_members_are_recognised()
    {
        var root = Js("""
            import { helper } from "./helper.js";

            export class Service {
                #cache = new Map();

                static create() {
                    return new Service();
                }

                async load(id) {
                    const value = await helper(id);
                    return value;
                }

                get size() {
                    return this.#cache.size;
                }
            }
            """);

        Assert.Single(root.OfKind(NodeKind.ImportDeclaration));
        var type = Assert.Single(root.OfKind(NodeKind.ClassDeclaration));
        Assert.Equal("Service", type.Text);
        Assert.Equal(2, type.OfKind(NodeKind.FunctionDeclaration).Count());
        Assert.Single(type.OfKind(NodeKind.Accessor));
        Assert.Empty(root.OfKind(NodeKind.Unknown));
    }

    [Fact]
    public void Statements_end_at_the_line_break()
    {
        var root = Js("""
            function go(items) {
              let total = 0
              for (let i = 0; i < items.length; i++) {
                total += items[i]
              }
              return total
            }
            """);

        var function = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        Assert.Single(function.OfKind(NodeKind.Loop));
        Assert.Single(function.OfKind(NodeKind.Jump));
        Assert.Empty(root.OfKind(NodeKind.Unknown));
    }

    [Fact]
    public void A_multi_line_parenthesised_return_stays_one_statement()
    {
        var root = Js("""
            function check(value) {
              if (
                value !== null &&
                value !== undefined
              ) {
                return (
                  typeof value === "string" &&
                  value.trim() !== ""
                );
              }
              return false;
            }
            """);

        var branch = Assert.Single(root.OfKind(NodeKind.If));
        Assert.Single(branch.ChildrenOf(NodeKind.Block));
        Assert.Equal(2, root.OfKind(NodeKind.Jump).Count());
        Assert.Empty(root.OfKind(NodeKind.Unknown));
    }

    [Fact]
    public void Arrow_functions_and_destructuring_are_parsed()
    {
        var root = Js("""
            const build = (items) => items.map((item) => item.name);
            const { first, second } = options;
            """);

        Assert.Equal(2, root.OfKind(NodeKind.Lambda).Count());
        var destructured = root.OfKind(NodeKind.VariableDeclaration).Last();
        Assert.Contains(destructured.DescendantsAndSelf(), n => n.Text == "second");
    }

    [Fact]
    public void Typescript_annotations_do_not_become_parameters()
    {
        var root = Ts("""
            export function findAncestor(
              node: TSESTree.Node,
              predicate: (node: TSESTree.Node) => boolean,
              scope: Scope.Reference,
            ): TSESTree.Node | undefined {
              return chain(node).find(predicate, scope);
            }
            """);

        var function = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        var parameters = SyntaxQuery.Parameters(function).Select(p => p.Text).ToArray();
        Assert.Equal(["node", "predicate", "scope"], parameters);
        Assert.Empty(root.OfKind(NodeKind.Unknown));
    }

    [Fact]
    public void Typescript_casts_and_object_return_types_are_handled()
    {
        var root = Ts("""
            export function pick(context: Context): { value: string; ok: boolean } | null {
              const settings = context.settings as Record<string, unknown>;
              return settings ? { value: "x", ok: true } : null;
            }
            """);

        var function = Assert.Single(root.OfKind(NodeKind.FunctionDeclaration));
        Assert.Empty(SyntaxQuery.Parameters(function).Where(p => p.Text is "value" or "ok"));
        Assert.Single(function.OfKind(NodeKind.Jump));
        Assert.Empty(root.OfKind(NodeKind.Unknown));
    }

    [Fact]
    public void Index_expressions_keep_their_key()
    {
        var root = Js("""
            function read(map, node) {
              return map[node.type];
            }
            """);

        var index = Assert.Single(root.OfKind(NodeKind.Index));
        Assert.Contains(index.DescendantsAndSelf(), n => n.Kind == NodeKind.Identifier && n.Text == "node");
    }
}
