using QualityGuard.Core.Analysis;
using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The configuration reader and the infrastructure rules built on it. What is being pinned here is
/// the structure: a setting only counts when it sits inside the resource it belongs to.
/// </summary>
public class InfrastructureRulesTests
{
    private static IReadOnlyList<int> Lines(string file, string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_manifest_is_read_as_a_tree_with_one_node_per_list_item()
    {
        var manifest = """
            apiVersion: v1
            kind: Pod
            spec:
              containers:
                - name: first
                  image: app:1.2
                  securityContext:
                    privileged: true
                - name: second
                  image: sidecar:3.1
            """;

        var root = ConfigTree.Parse(manifest, "k8");
        var containers = root.At("spec", "containers");

        Assert.NotNull(containers);
        Assert.Equal(2, containers!.Children.Count);
        // each item keeps its own settings instead of scattering them across its siblings
        Assert.Equal("first", containers.Children[0].ValueAt("name"));
        Assert.Equal("app:1.2", containers.Children[0].ValueAt("image"));
        Assert.True(containers.Children[0].At("securityContext", "privileged")!.IsTrue);
        Assert.Null(containers.Children[1].At("securityContext", "privileged"));
    }

    [Fact]
    public void A_terraform_block_keeps_its_labels()
    {
        var template = """
            resource "aws_ebs_volume" "data" {
              size = 40
              tags = {
                Name = "data"
              }
            }
            """;

        var root = ConfigTree.Parse(template, "tf");
        var resource = Assert.Single(root.Children);

        Assert.Equal("resource", resource.Key);
        Assert.Equal(["aws_ebs_volume", "data"], resource.Labels);
        Assert.Equal("40", resource.ValueAt("size"));
        Assert.Equal("data", resource.At("tags")!.ValueAt("Name"));
    }

    [Fact]
    public void A_volume_without_encryption_is_reported_and_an_encrypted_one_is_not()
    {
        var open = """
            resource "aws_ebs_volume" "data" {
              size = 40
            }
            """;
        Assert.NotEmpty(Lines("main.tf", open, "QG-TF-SEC-0063"));

        var encrypted = """
            resource "aws_ebs_volume" "data" {
              size = 40
              encrypted = true
            }
            """;
        Assert.Empty(Lines("main.tf", encrypted, "QG-TF-SEC-0063"));
    }

    [Fact]
    public void An_open_ingress_range_is_reported()
    {
        var template = """
            resource "aws_security_group" "web" {
              ingress {
                from_port = 22
                to_port = 22
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
            """;
        Assert.NotEmpty(Lines("main.tf", template, "QG-TF-SEC-0064"));
    }

    [Fact]
    public void A_narrow_range_is_left_alone()
    {
        var template = """
            resource "aws_security_group" "web" {
              ingress {
                from_port = 22
                to_port = 22
                cidr_blocks = ["10.0.1.0/24"]
              }
            }
            """;
        Assert.Empty(Lines("main.tf", template, "QG-TF-SEC-0064"));
    }

    [Theory]
    [InlineData("TLS_1_0", true)]
    [InlineData("TLSv1.1", true)]
    [InlineData("TLSv1.2", false)]
    [InlineData("TLS_1_2", false)]
    public void Only_an_outdated_protocol_version_is_reported(string version, bool reported)
    {
        var template = $$"""
            resource "aws_api_gateway_domain_name" "api" {
              domain_name = "api.example.com"
              security_policy = "{{version}}"
            }
            """;
        Assert.Equal(reported, Lines("main.tf", template, "QG-TF-SEC-0065").Count > 0);
    }

    [Fact]
    public void A_privileged_container_is_reported_and_its_compliant_neighbour_is_not()
    {
        var manifest = """
            apiVersion: v1
            kind: Pod
            spec:
              containers:
                - name: bad
                  image: app:1.0
                  securityContext:
                    privileged: true
                - name: good
                  image: app:1.0
                  securityContext:
                    privileged: false
            """;
        Assert.Equal([8], Lines("pod.yaml", manifest, "QG-K8-SEC-0001"));
    }

    [Fact]
    public void Sharing_a_host_namespace_is_reported()
    {
        var manifest = """
            apiVersion: v1
            kind: Pod
            spec:
              hostNetwork: true
              containers:
                - name: app
                  image: app:1.0
            """;
        Assert.NotEmpty(Lines("pod.yaml", manifest, "QG-K8-SEC-0006"));
    }

    [Fact]
    public void An_unpinned_image_is_reported_and_a_pinned_one_is_not()
    {
        var manifest = """
            apiVersion: v1
            kind: Pod
            spec:
              containers:
                - name: floating
                  image: app:latest
                - name: pinned
                  image: app:1.4.2
            """;
        Assert.Equal([6], Lines("pod.yaml", manifest, "QG-K8-SML-0001"));
    }

    [Fact]
    public void A_role_granting_a_wildcard_is_reported()
    {
        var manifest = """
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata:
              name: example
            rules:
              - apiGroups: [ "" ]
                resources: [ "*" ]
                verbs: [ "get" ]
            """;
        Assert.NotEmpty(Lines("role.yaml", manifest, "QG-K8-SEC-0023"));
    }

    [Fact]
    public void A_role_that_names_its_resources_is_left_alone()
    {
        var manifest = """
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata:
              name: example
            rules:
              - apiGroups: [ "" ]
                resources: [ "pods", "configmaps" ]
                verbs: [ "get", "list" ]
            """;
        Assert.Empty(Lines("role.yaml", manifest, "QG-K8-SEC-0023"));
    }
}
