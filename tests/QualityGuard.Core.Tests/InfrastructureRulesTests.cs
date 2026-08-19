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
    [Fact]
    public void A_key_declared_without_rotation_is_reported()
    {
        var template = """
            resource "google_kms_crypto_key" "db" {
              name     = "db"
              key_ring = google_kms_key_ring.db.id
            }
            """;
        Assert.NotEmpty(Lines("kms.tf", template, "QG-TF-SEC-0073"));
    }

    [Fact]
    public void The_grants_around_a_key_are_not_keys()
    {
        // 'crypto_key' as a substring matched the iam member and the key ring, neither of which
        // holds key material, and that was most of the reports on real modules
        var template = """
            resource "google_kms_crypto_key_iam_member" "member" {
              crypto_key_id = module.kms.keys["db"]
              role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
            }

            resource "google_kms_key_ring" "ring" {
              name     = "ring"
              location = "europe-west1"
            }
            """;
        Assert.Empty(Lines("kms.tf", template, "QG-TF-SEC-0073"));
    }

    [Fact]
    public void An_asymmetric_key_is_not_asked_to_rotate()
    {
        var template = """
            resource "google_kms_crypto_key" "attestor" {
              name    = "attestor-key"
              purpose = "ASYMMETRIC_SIGN"
            }
            """;
        Assert.Empty(Lines("kms.tf", template, "QG-TF-SEC-0073"));
    }

    [Fact]
    public void A_password_written_into_the_file_is_reported()
    {
        var template = """
            resource "google_service_account_key" "k" {
              client_secret = "s3cr3t-value"
            }
            """;
        Assert.NotEmpty(Lines("main.tf", template, "QG-TF-SEC-0009"));
    }

    [Fact]
    public void A_key_that_names_a_secret_instead_of_holding_one_is_left_alone()
    {
        var template = """
            resource "google_gke_hub_feature_membership" "acm" {
              secret_type      = "none"
              token_id         = "projects/p/secrets/token"
              password         = var.database_password
              api_key          = data.google_secret_manager_secret_version.key.secret_data
            }

            output "client_token" {
              description = "The bearer token for auth."
              sensitive   = true
            }
            """;
        Assert.Empty(Lines("main.tf", template, "QG-TF-SEC-0009"));
    }

    [Fact]
    public void Two_different_string_comparisons_are_not_the_same_expression()
    {
        // the generic reader drops the quotes, so 'x == null || x == "null"' read as one test twice
        var template = """
            locals {
              workload_identity_enabled = !(var.identity_namespace == null || var.identity_namespace == "null")
            }
            """;
        Assert.Empty(Lines("main.tf", template, "QG-TF-BUG-0028"));
    }

    [Fact]
    public void Prose_in_a_manifest_is_not_an_expression()
    {
        var manifest = """
            apiVersion: blueprints.cloud.google.com/v1alpha1
            kind: BlueprintMetadata
            spec:
              interfaces:
                variables:
                  - name: security_posture_mode
                    description: Valid values are `ENABLED` and `LIMITED`.
            """;
        Assert.Empty(Lines("metadata.yaml", manifest, "QG-K8-BUG-0028"));
    }
    [Fact]
    public void A_container_granted_a_host_level_capability_is_reported()
    {
        var manifest = """
            apiVersion: v1
            kind: Pod
            spec:
              containers:
                - name: inline
                  image: app:1
                  securityContext:
                    capabilities:
                      add: ["SYS_ADMIN"]
                - name: listed
                  image: app:1
                  securityContext:
                    capabilities:
                      add:
                        - NET_ADMIN
            """;
        Assert.Equal(2, Lines("pod.yaml", manifest, "QG-K8-SEC-0007").Count);
    }

    [Fact]
    public void A_policy_that_forbids_a_capability_is_not_a_container_that_asks_for_it()
    {
        var manifest = """
            apiVersion: constraints.gatekeeper.sh/v1beta1
            kind: K8sPSPCapabilities
            metadata:
              name: capabilities
            spec:
              parameters:
                allowedCapabilities: []
                requiredDropCapabilities:
                  - ALL
                forbiddenCapabilities:
                  - SYS_ADMIN
                  - NET_ADMIN
            """;
        Assert.Empty(Lines("policy.yaml", manifest, "QG-K8-SEC-0007"));
    }

    [Fact]
    public void A_container_that_drops_everything_and_adds_one_capability_is_left_alone()
    {
        var manifest = """
            apiVersion: v1
            kind: Pod
            spec:
              containers:
                - name: web
                  image: app:1
                  securityContext:
                    capabilities:
                      drop: ["ALL"]
                      add: ["NET_BIND_SERVICE"]
            """;
        Assert.Empty(Lines("pod.yaml", manifest, "QG-K8-SEC-0007"));
    }
    [Fact]
    public void A_bucket_permission_that_grants_everyone_is_reported()
    {
        var template = """
            resource "aws_s3_bucket_acl" "logs" {
              bucket = "logs"
              acl    = "public-read"
            }

            resource "aws_s3_bucket_acl" "private" {
              bucket = "private"
              acl    = "private"
            }
            """;
        Assert.Single(Lines("storage.tf", template, "QG-TF-SEC-0077"));
    }

    [Fact]
    public void A_public_access_block_switched_off_is_reported()
    {
        var template = """
            resource "aws_s3_bucket_public_access_block" "logs" {
              bucket            = "logs"
              block_public_acls = false
            }
            """;
        Assert.NotEmpty(Lines("storage.tf", template, "QG-TF-SEC-0078"));
    }

    [Fact]
    public void Versioning_that_is_suspended_is_reported_and_enabled_is_not()
    {
        var suspended = """
            resource "aws_s3_bucket_versioning" "logs" {
              versioning_configuration {
                status = "Suspended"
              }
            }
            """;
        var enabled = """
            resource "aws_s3_bucket_versioning" "logs" {
              versioning_configuration {
                status = "Enabled"
              }
            }
            """;
        Assert.NotEmpty(Lines("storage.tf", suspended, "QG-TF-SEC-0079"));
        Assert.Empty(Lines("storage.tf", enabled, "QG-TF-SEC-0079"));
    }

    [Fact]
    public void A_retention_shorter_than_a_week_is_reported()
    {
        var template = """
            resource "aws_db_instance" "main" {
              backup_retention_period = 1
            }

            resource "aws_db_instance" "other" {
              backup_retention_period = 30
            }
            """;
        Assert.Single(Lines("db.tf", template, "QG-TF-SEC-0080"));
    }

    [Fact]
    public void A_preflight_route_needs_no_authorization()
    {
        var template = """
            resource "aws_api_gateway_method" "open" {
              http_method   = "GET"
              authorization = "NONE"
            }

            resource "aws_api_gateway_method" "preflight" {
              http_method   = "OPTIONS"
              authorization = "NONE"
            }
            """;
        Assert.Single(Lines("api.tf", template, "QG-TF-SEC-0082"));
    }
}
