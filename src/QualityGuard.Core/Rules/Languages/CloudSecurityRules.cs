using System.Text.RegularExpressions;
using QualityGuard.Core.Analysis;
using QualityGuard.Core.Models;

namespace QualityGuard.Core.Rules.Languages;

/// <summary>
/// Access, retention and identity settings of managed cloud resources, read from the declaration
/// that creates them. A permission written here is granted for the lifetime of the resource and is
/// never reviewed again: nothing fails, no request is refused, and the only signal that the grant is
/// too wide is the text of the file itself.
/// </summary>
public static class CloudSecurityRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new GcpHighPrivilegedRoleRule(),
        new GcpPublicAccessRule(),
        new GcpExcessivePermissionsRule(),
        new GcpAppEngineTlsRule(),
        new GcpPrivilegeEscalationRule(),
        new GcpLegacyAccessControlRule(),
        new GcpLoadBalancerCipherRule(),
        new GcpBucketVersioningRule(),
        new GcpLogRetentionRule(),
        new GcpAuditLogExemptionRule(),
        new GcpUniformBucketAccessRule(),
        new AzureManagedIdentityRule(),
        new AzureAdminAccountRule(),
        new AzureHighPrivilegeRoleRule(),
        new AzureRoleBasedAccessRule(),
        new AzureOwnerCapableRoleRule(),
        new AzureKeyVaultPurgeProtectionRule()
    ];
}

public abstract class TerraformSecurityRule : ConfigRuleBase
{
    public override string[] Languages => ["tf"];
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override Severity Severity => Severity.Critical;
    public override string RemediationEffort => "15min";

    /// <summary>
    /// Resources of exactly these types. Matching the type by substring is what a first attempt
    /// does, and it reports the grants declared around a resource as though they were the resource.
    /// </summary>
    protected static IEnumerable<ConfigNode> OfType(IRuleContext context, params string[] types)
        => Typed(context, t => types.Any(x => string.Equals(x, t, StringComparison.OrdinalIgnoreCase)));

    protected static IEnumerable<ConfigNode> Typed(IRuleContext context, Func<string, bool> matches)
    {
        foreach (var block in context.Config.Children)
        {
            if (!string.Equals(block.Key, "resource", StringComparison.OrdinalIgnoreCase)
                || block.Labels.Count == 0)
                continue;
            if (matches(block.Labels[0]))
                yield return block;
        }
    }

    protected static string TypeOf(ConfigNode resource)
        => resource.Labels.Count > 0 ? resource.Labels[0] : string.Empty;

    /// <summary>
    /// Whether a value comes from elsewhere in the configuration instead of being written here. A
    /// reference cannot be judged, and reporting it asks for a change at the wrong line.
    /// </summary>
    protected static bool IsReference(string value)
        => value.StartsWith("var.", StringComparison.Ordinal)
           || value.StartsWith("local.", StringComparison.Ordinal)
           || value.StartsWith("data.", StringComparison.Ordinal)
           || value.Contains("${", StringComparison.Ordinal);
}

// --------------------------------------------------------------------------------- Google Cloud

public sealed class GcpHighPrivilegedRoleRule : TerraformSecurityRule
{
    /// <summary>
    /// The tail of a role name that carries write access over everything the service owns. The
    /// trailing version group matters: the provider publishes roles such as
    /// <c>roles/iam.serviceAccountAdmin.v1</c>, and a pattern that stops at the word misses them.
    /// </summary>
    private static readonly Regex FullAccessRole =
        new(@"^.*(?:admin|developer|manager|owner|superuser)(?:\.?v\d+)?$", RegexOptions.Compiled);

    private static readonly string[] OwnerRoleResources =
    [
        "google_bigquery_dataset_access", "google_storage_bucket_access_control",
        "google_storage_default_object_access_control", "google_storage_object_access_control"
    ];

    private static readonly string[] AccessListResources =
    [
        "google_storage_bucket_acl", "google_storage_default_object_acl", "google_storage_object_acl"
    ];

    public override string Key => "QG-TF-SEC-0047";
    public override string Name => "An identity should not be granted a full-access role";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Typed(context, IsGrant))
        {
            var role = resource.Child("role");
            if (role == null || IsReference(role.Value) || !FullAccessRole.IsMatch(role.Value))
                continue;

            context.Report($"'{role.Value}' gives this member every operation the service offers, "
                           + "including the ones that change who else has access. One compromised "
                           + "credential is then enough to take the resource over and to remove the "
                           + "trace of it. Grant the narrowest predefined role that covers the task.",
                role.Line);
        }

        foreach (var resource in OfType(context, OwnerRoleResources))
        {
            var role = resource.Child("role");
            if (role != null && string.Equals(role.Value, "OWNER", StringComparison.Ordinal))
                context.Report("Granting OWNER hands over the object together with the right to "
                               + "re-grant it, so the access can no longer be withdrawn from here. "
                               + "Grant READER or WRITER instead.", role.Line);
        }

        foreach (var resource in OfType(context, AccessListResources))
        {
            foreach (var (text, line) in Items(resource.Child("role_entity")))
            {
                if (text.StartsWith("OWNER:", StringComparison.Ordinal))
                    context.Report("This entry grants OWNER, which includes the right to change the "
                                   + "access list itself. Grant READER or WRITER instead.", line);
            }
        }

        foreach (var resource in OfType(context, "google_cloud_identity_group"))
        {
            foreach (var membership in resource.ChildrenNamed("roles"))
            {
                var name = membership.Child("name");
                if (name != null && name.Value is "MANAGER" or "OWNER")
                    context.Report($"Membership with '{name.Value}' lets the member change the group, "
                                   + "and the group is what every access rule downstream is written "
                                   + "against. Give plain MEMBER to everyone who only needs the "
                                   + "access the group carries.", name.Line);
            }
        }
    }

    /// <summary>
    /// A resource that exists only to attach a role. Listing the provider's grantable types by hand
    /// dates immediately — every release adds services — while the shape of the name does not, and
    /// the role attribute read afterwards is what keeps the match honest.
    /// </summary>
    private static bool IsGrant(string type)
        => type.StartsWith("google_", StringComparison.Ordinal)
           && (type.EndsWith("_iam_binding", StringComparison.Ordinal)
               || type.EndsWith("_iam_member", StringComparison.Ordinal));
}

public sealed class GcpPublicAccessRule : TerraformSecurityRule
{
    public override string Key => "QG-TF-SEC-0051";
    public override string Name => "A resource should not be granted to every user of the internet";
    public override Severity Severity => Severity.Blocker;

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in Typed(context, t => IsGoogle(t, "_iam_binding")))
        {
            foreach (var (text, line) in Items(resource.Child("members")))
            {
                if (IsEveryone(text))
                    Report(context, text, line);
            }
        }

        foreach (var resource in Typed(context, t => IsGoogle(t, "_iam_member")))
        {
            var member = resource.Child("member");
            if (member != null && IsEveryone(member.Value))
                Report(context, member.Value, member.Line);
        }

        foreach (var resource in OfType(context, "google_storage_default_object_access_control",
                     "google_storage_object_access_control"))
        {
            var entity = resource.Child("entity");
            if (entity != null && IsEveryone(entity.Value))
                Report(context, entity.Value, entity.Line);
        }

        foreach (var resource in OfType(context, "google_bigquery_dataset_access"))
        {
            var group = resource.Child("special_group");
            if (group != null && IsEveryone(group.Value))
                Report(context, group.Value, group.Line);
        }
    }

    private static bool IsGoogle(string type, string suffix)
        => type.StartsWith("google_", StringComparison.Ordinal)
           && type.EndsWith(suffix, StringComparison.Ordinal);

    private static bool IsEveryone(string value)
        => value.Contains("allUsers", StringComparison.Ordinal)
           || value.Contains("allAuthenticatedUsers", StringComparison.Ordinal);

    private static void Report(IRuleContext context, string member, int line)
        => context.Report($"'{member}' is not a group inside the organisation: it is everyone with a "
                          + "network route to the provider, including every account created a minute "
                          + "ago. Nothing further asks who the caller is, and the access log cannot "
                          + "attribute what happens. Name the accounts or the group that needs it.",
            line);
}

public sealed class GcpExcessivePermissionsRule : TerraformSecurityRule
{
    /// <summary>
    /// A permission is sensitive when the verb at the end of it changes something. The check reads
    /// the last segment because the service prefix says nothing: <c>run.services.get</c> and
    /// <c>run.services.delete</c> differ only there.
    /// </summary>
    private static readonly string[] ChangingVerbs =
    [
        "abort", "access", "add", "allocate", "analyze", "apply", "approve", "associate", "attach",
        "begin", "bind", "call", "cancel", "clear", "close", "compute", "connect", "create", "delete",
        "deploy", "destroy", "detach", "disable", "drop", "enable", "evict", "exec", "import",
        "install", "invoke", "listvulnerabilities", "manage", "migrate", "move", "mutate", "patch",
        "pause", "proxy", "publish", "purchase", "purge", "put", "reject", "remove", "reopen",
        "replace", "rerun", "reset", "resize", "restart", "restore", "resume", "rollback", "rotate",
        "run", "sample", "scan", "send", "set", "sign", "sourcecodeget", "sourcecodeset", "start",
        "stop", "suspend", "undelete", "undeploy", "update", "upload", "use", "validate", "write"
    ];

    private static readonly string[] ChangingWords = ["login", "create", "delete", "set"];

    private const int Tolerated = 5;

    public override string Key => "QG-TF-SEC-0053";
    public override string Name => "A custom role should not accumulate write permissions";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "google_project_iam_custom_role",
                     "google_organization_iam_custom_role"))
        {
            var permissions = resource.Child("permissions");
            if (permissions == null)
                continue;

            var count = Items(permissions).Count(item => Changes(item.Text));
            if (count <= Tolerated)
                continue;

            context.Report($"This role carries {count} permissions that change or destroy something. "
                           + "A role built that wide is handed out once and then reused for tasks "
                           + "that need a fraction of it, so a single compromised account can deploy, "
                           + "delete and cover its traces. Split it into roles that each cover one "
                           + "task, and prefer the read-only form where reading is enough.",
                permissions.Line);
        }
    }

    private static bool Changes(string permission)
    {
        var suffix = permission[(permission.LastIndexOf('.') + 1)..].ToLowerInvariant();
        if (suffix.Contains("readonly", StringComparison.Ordinal))
            return false;
        return ChangingVerbs.Any(verb => suffix.StartsWith(verb, StringComparison.Ordinal))
               || ChangingWords.Any(word => suffix.Contains(word, StringComparison.Ordinal));
    }
}

public sealed class GcpPrivilegeEscalationRule : TerraformSecurityRule
{
    /// <summary>
    /// Permissions whose whole purpose is to act as somebody else, or to start something that runs
    /// as somebody else. They are what turns a limited account into an unlimited one, so they matter
    /// however few of them a role carries — unlike the write permissions counted by QG-TF-SEC-0053.
    /// </summary>
    private static readonly HashSet<string> EscalationPermissions = new(StringComparer.OrdinalIgnoreCase)
    {
        "cloudbuild.builds.create", "cloudfunctions.functions.create", "cloudfunctions.functions.update",
        "cloudscheduler.jobs.create", "composer.environments.create", "compute.instances.create",
        "dataflow.jobs.create", "dataproc.clusters.create", "deploymentmanager.deployments.create",
        "iam.roles.update", "iam.serviceAccountKeys.create", "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken",
        "iam.serviceAccounts.implicitDelegation", "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt", "orgpolicy.policy.set", "run.services.create",
        "serviceusage.apiKeys.create", "serviceusage.apiKeys.list", "storage.hmacKeys.create"
    };

    public override string Key => "QG-TF-SEC-0055";
    public override string Name => "A custom role should not grant a permission that escalates privileges";
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "google_project_iam_custom_role",
                     "google_organization_iam_custom_role"))
        {
            foreach (var (text, line) in Items(resource.Child("permissions")))
            {
                var escalates = EscalationPermissions.Contains(text)
                                || text.EndsWith(".setIamPolicy", StringComparison.OrdinalIgnoreCase);
                if (!escalates)
                    continue;

                context.Report($"'{text}' lets the holder act as another identity or grant itself "
                               + "more, so the ceiling of this role is not what it lists but whatever "
                               + "the most privileged account it can reach is allowed to do. Remove "
                               + "it, and give the workload its own account with the rights it needs.",
                    line);
            }
        }
    }
}

public sealed class GcpAppEngineTlsRule : TerraformSecurityRule
{
    public override string Key => "QG-TF-SEC-0054";
    public override string Name => "An application handler should require an encrypted connection";
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "google_app_engine_standard_app_version",
                     "google_app_engine_flexible_app_version"))
        {
            foreach (var handler in resource.ChildrenNamed("handlers"))
            {
                var level = handler.Child("security_level");
                if (level == null)
                {
                    context.Report("This handler does not say which transport it accepts, and the "
                                   + "default accepts plain HTTP. A request that arrives that way "
                                   + "carries its session cookie and its payload across the network "
                                   + "readable. Set security_level to SECURE_ALWAYS.", handler.Line);
                    continue;
                }

                if (level.Value is "SECURE_OPTIONAL" or "SECURE_NEVER" or "SECURE_DEFAULT")
                    context.Report($"'{level.Value}' lets the client decide whether the connection is "
                                   + "encrypted, and a client that asks for plain HTTP is served. "
                                   + "Everything it sends, credentials included, crosses the network "
                                   + "readable. Set security_level to SECURE_ALWAYS.", level.Line);
            }
        }
    }
}

public sealed class GcpLegacyAccessControlRule : TerraformSecurityRule
{
    public override string Key => "QG-TF-SEC-0056";
    public override string Name => "A cluster should not enable legacy attribute-based access control";
    public override string RemediationEffort => "1h";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "google_container_cluster"))
        {
            var legacy = resource.Child("enable_legacy_abac");
            if (legacy is { IsTrue: true })
                context.Report("Legacy attribute-based access control is switched on, so the cluster "
                               + "also grants access from a policy file that sits outside the role "
                               + "definitions everything else is audited against. Permissions that "
                               + "look revoked stay in force. Leave it off and express the access as "
                               + "roles and bindings.", legacy.Line);
        }
    }
}

public sealed class GcpLoadBalancerCipherRule : TerraformSecurityRule
{
    public override string Key => "QG-TF-SEC-0057";
    public override string Name => "A load balancer should not accept obsolete cipher suites";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "google_compute_ssl_policy"))
        {
            var profile = resource.Child("profile");
            if (profile == null)
            {
                context.Report("No profile is named, so the policy keeps the widest one the provider "
                               + "offers: it negotiates with clients that only support algorithms "
                               + "already broken, and somebody in the middle of the connection can "
                               + "steer the handshake onto them. Set profile to RESTRICTED.",
                    resource.Line);
                continue;
            }

            if (profile.Value is "COMPATIBLE" or "MODERN")
                context.Report($"The '{profile.Value}' profile still offers cipher suites that no "
                               + "longer protect what they carry, and the weakest client decides "
                               + "which one is used. Set profile to RESTRICTED, then fix the clients "
                               + "that fail to connect — the failure names them.", profile.Line);
        }
    }
}

public sealed class GcpBucketVersioningRule : TerraformSecurityRule
{
    public override string Key => "QG-TF-SEC-0058";
    public override string Name => "An object store should keep previous versions of its objects";
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "google_storage_bucket"))
        {
            // a retention policy already prevents an object from being replaced or removed early, so
            // asking for versioning on top of it names a problem this bucket does not have
            if (resource.Child("retention_policy") != null)
                continue;

            var versioning = resource.Child("versioning");
            if (versioning == null)
            {
                context.Report("Versioning is not declared, so it is off: an object overwritten or "
                               + "deleted — by a faulty deployment, or by whoever obtains a write "
                               + "credential — leaves nothing to restore from. Add a versioning block "
                               + "with enabled set to true.", resource.Line);
                continue;
            }

            var enabled = versioning.Child("enabled");
            if (enabled is { IsFalse: true })
                context.Report("Versioning is switched off, so the last write to an object is the "
                               + "only copy that exists. A deletion is then final, whether it was a "
                               + "mistake or somebody removing evidence. Set enabled to true.",
                    enabled.Line);
        }
    }
}

public sealed class GcpLogRetentionRule : TerraformSecurityRule
{
    private const int MinimumDays = 14;

    public override string Key => "QG-TF-SEC-0059";
    public override string Name => "Logs should be kept long enough to investigate an incident";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "20min";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "google_logging_project_bucket_config",
                     "google_logging_billing_account_bucket_config",
                     "google_logging_organization_bucket_config",
                     "google_logging_folder_bucket_config"))
        {
            var retention = resource.Child("retention_days");
            if (retention == null || !int.TryParse(retention.Value, out var days) || days >= MinimumDays)
                continue;

            context.Report($"Logs are discarded after {days} days. An intrusion is typically noticed "
                           + "weeks after it happened, and by then the records that would say what "
                           + "was reached are gone — the investigation has nothing to work from. Keep "
                           + $"at least {MinimumDays} days.", retention.Line);
        }
    }
}

public sealed class GcpAuditLogExemptionRule : TerraformSecurityRule
{
    public override string Key => "QG-TF-SEC-0060";
    public override string Name => "Audit logging should not exempt individual members";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "google_project_iam_audit_config"))
        {
            foreach (var config in resource.ChildrenNamed("audit_log_config"))
            {
                var exempted = config.Child("exempted_members");
                if (exempted == null)
                    continue;

                var members = Items(exempted).ToList();
                // a list filled from elsewhere cannot be judged here, and the file that defines it is
                // where the decision would have to be changed anyway
                if (members.Count == 0 || members.Any(member => IsReference(member.Text)))
                    continue;

                context.Report("These members act on the project without leaving an audit record, so "
                               + "the log no longer answers the question it exists for: who did this. "
                               + "An account excluded here is also the most attractive one to take "
                               + "over. Audit every member and filter the noise when reading instead.",
                    exempted.Line);
            }
        }
    }
}

public sealed class GcpUniformBucketAccessRule : TerraformSecurityRule
{
    public override string Key => "QG-TF-SEC-0062";
    public override string Name => "An object store should enforce a single access model";
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "google_storage_bucket"))
        {
            // the setting had another name before the provider renamed it, and a bucket that still
            // uses the old one is already uniform: reporting it asks for a change that is done
            var legacy = resource.Child("bucket_policy_only");
            if (legacy is { IsTrue: true })
                continue;

            var uniform = resource.Child("uniform_bucket_level_access");
            if (uniform == null)
            {
                context.Report("Uniform access is not enforced, so per-object access lists keep "
                               + "working alongside the project's own permissions. An object can then "
                               + "be readable to someone the bucket policy denies, and nothing in "
                               + "that policy shows it. Set uniform_bucket_level_access to true.",
                    resource.Line);
                continue;
            }

            if (uniform.IsFalse)
                context.Report("Per-object access lists override the bucket policy, so the "
                               + "permissions that were reviewed are not the permissions that apply. "
                               + "Set uniform_bucket_level_access to true and express the access once.",
                    uniform.Line);
        }
    }
}

// ---------------------------------------------------------------------------------------- Azure

public sealed class AzureManagedIdentityRule : TerraformSecurityRule
{
    /// <summary>
    /// The resources that run code, and therefore call something else on their own behalf. The
    /// provider accepts an identity block on far more types than these — a storage account, a
    /// database server, a registry — but those are what gets called rather than what calls, and they
    /// need an identity only for the narrower case of holding their own encryption key. Reporting
    /// them turned twenty-nine ordinary storage accounts into findings on one sample repository and
    /// buried the machines that really do keep a password in a script.
    /// </summary>
    private static readonly string[] IdentityCapableResources =
    [
        "azurerm_api_management", "azurerm_app_service", "azurerm_app_service_slot",
        "azurerm_batch_pool", "azurerm_container_group", "azurerm_data_factory",
        "azurerm_function_app", "azurerm_function_app_slot", "azurerm_kubernetes_cluster",
        "azurerm_linux_function_app", "azurerm_linux_function_app_slot",
        "azurerm_linux_virtual_machine", "azurerm_linux_virtual_machine_scale_set",
        "azurerm_linux_web_app", "azurerm_linux_web_app_slot", "azurerm_logic_app_standard",
        "azurerm_machine_learning_compute_cluster", "azurerm_machine_learning_compute_instance",
        "azurerm_machine_learning_inference_cluster", "azurerm_machine_learning_synapse_spark",
        "azurerm_management_group_policy_assignment", "azurerm_policy_assignment",
        "azurerm_resource_group_policy_assignment", "azurerm_resource_policy_assignment",
        "azurerm_spring_cloud_app", "azurerm_stream_analytics_job",
        "azurerm_subscription_policy_assignment", "azurerm_virtual_machine",
        "azurerm_virtual_machine_scale_set", "azurerm_windows_function_app",
        "azurerm_windows_function_app_slot", "azurerm_windows_virtual_machine",
        "azurerm_windows_virtual_machine_scale_set", "azurerm_windows_web_app",
        "azurerm_windows_web_app_slot"
    ];

    public override string Key => "QG-TF-SEC-0038";
    public override string Name => "A service should authenticate with a platform-managed identity";
    public override Severity Severity => Severity.Major;
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, IdentityCapableResources))
        {
            if (resource.Child("identity") != null)
                continue;

            context.Report($"'{TypeOf(resource)}' is created without a managed identity, so whatever "
                           + "it calls has to be reached with a secret somebody stored and nobody "
                           + "rotates — in a variable, a settings file, or the pipeline. Declare an "
                           + "identity block and grant that identity the access instead.",
                resource.Line);
        }
    }
}

public sealed class AzureAdminAccountRule : TerraformSecurityRule
{
    public override string Key => "QG-TF-SEC-0039";
    public override string Name => "A resource should not enable its own administrative account";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "azurerm_container_registry"))
        {
            var admin = resource.Child("admin_enabled");
            if (admin is { IsTrue: true })
                context.Report("The built-in administrator account is enabled. It is a single shared "
                               + "credential with full control, it belongs to no person, and every "
                               + "action taken with it is attributed to the registry rather than to "
                               + "whoever used it. Disable it and grant the roles individually.",
                    admin.Line);
        }

        foreach (var resource in OfType(context, "azurerm_batch_pool"))
        {
            var level = resource.At("start_task", "user_identity", "auto_user", "elevation_level");
            if (level != null && string.Equals(level.Value, "Admin", StringComparison.Ordinal))
                context.Report("The start task runs as an administrator, so anything it executes — "
                               + "including a command built from data it fetched — has full control "
                               + "of the node. Run it as a non-elevated user.", level.Line);
        }
    }
}

public sealed class AzureHighPrivilegeRoleRule : TerraformSecurityRule
{
    private static readonly HashSet<string> FullControlRoles =
        new(StringComparer.Ordinal) { "Owner", "Contributor", "User Access Administrator" };

    public override string Key => "QG-TF-SEC-0041";
    public override string Name => "An assignment should not hand out a full-control built-in role";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "azurerm_role_assignment"))
        {
            var role = resource.Child("role_definition_name");
            if (role == null || !FullControlRoles.Contains(role.Value))
                continue;

            context.Report($"'{role.Value}' covers every resource in the scope it is given, and two "
                           + "of the three can also hand that access to somebody else. The assignment "
                           + "is made once and outlives the reason for it. Assign the built-in role "
                           + "that matches the task, scoped to the resource that needs it.",
                role.Line);
        }
    }
}

public sealed class AzureRoleBasedAccessRule : TerraformSecurityRule
{
    public override string Key => "QG-TF-SEC-0043";
    public override string Name => "Role-based access control should not be switched off";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "azurerm_kubernetes_cluster"))
        {
            var flag = resource.Child("role_based_access_control_enabled");
            if (flag is { IsFalse: true })
                Report(context, flag.Line);

            var nested = resource.Child("role_based_access_control")?.Child("enabled");
            if (nested is { IsFalse: true })
                Report(context, nested.Line);
        }

        foreach (var resource in OfType(context, "azurerm_key_vault"))
        {
            // the provider renamed the argument; a vault that still sets the old one has made the
            // decision there, and reading both would report the same vault twice
            var legacy = resource.Child("enable_rbac_authorization");
            if (legacy != null)
            {
                if (legacy.IsFalse)
                    Report(context, legacy.Line);
                continue;
            }

            var flag = resource.Child("rbac_authorization_enabled");
            if (flag is { IsFalse: true })
                Report(context, flag.Line);
        }
    }

    private static void Report(IRuleContext context, int line)
        => context.Report("Role-based access control is disabled, so access falls back to a policy "
                          + "list kept on the resource itself: it is invisible to the reviews and the "
                          + "reports that read role assignments, and an entry left in it is never "
                          + "noticed. Enable it and express the access as roles.", line);
}

public sealed class AzureOwnerCapableRoleRule : TerraformSecurityRule
{
    private static readonly Regex PlainSubscriptionScope =
        new(@"^/subscriptions/[^/]+/?$", RegexOptions.Compiled);

    private static readonly Regex PlainManagementGroupScope =
        new(@"^/providers/microsoft\.management/.+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex ReferencedSubscriptionScope =
        new(@"azurerm_subscription\.[^.]*(primary|current)[^.]*\.id", RegexOptions.Compiled);

    private static readonly Regex ReferencedManagementGroupScope =
        new(@"azurerm_management_group\.[^.]*(parent|root)[^.]*\.id", RegexOptions.Compiled);

    public override string Key => "QG-TF-SEC-0044";
    public override string Name => "A custom role should not amount to ownership of the subscription";
    public override string RemediationEffort => "30min";

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "azurerm_role_definition"))
        {
            var actions = resource.Child("permissions")?.Child("actions");
            if (!Items(actions).Any(action => action.Text == "*"))
                continue;

            // a wildcard scoped to one resource group is a deliberate, contained choice; the two
            // together — every action, over the whole subscription — are what reproduce ownership
            if (!Items(resource.Child("assignable_scopes")).Any(scope => IsWide(scope.Text)))
                continue;

            context.Report("This role allows every action over the whole subscription, which is the "
                           + "built-in owner role written out by hand — including the right to grant "
                           + "it to somebody else. Narrow the actions to the ones the role is for, or "
                           + "the assignable scope to the resource group it applies to.",
                resource.Line);
        }
    }

    private static bool IsWide(string scope)
        => PlainSubscriptionScope.IsMatch(scope)
           || PlainManagementGroupScope.IsMatch(scope)
           || ReferencedSubscriptionScope.IsMatch(scope)
           || ReferencedManagementGroupScope.IsMatch(scope);
}

public sealed class AzureKeyVaultPurgeProtectionRule : TerraformSecurityRule
{
    public override string Key => "QG-TF-SEC-0061";
    public override string Name => "A key vault should be protected against permanent deletion";
    public override Severity Severity => Severity.Major;

    public override void Execute(IRuleContext context)
    {
        foreach (var resource in OfType(context, "azurerm_key_vault"))
        {
            var protection = resource.Child("purge_protection_enabled");
            if (protection == null)
            {
                context.Report("Purge protection is not declared, so it is off: a deleted key can be "
                               + "purged immediately and everything encrypted with it becomes "
                               + "unreadable for good. Set purge_protection_enabled to true.",
                    resource.Line);
                continue;
            }

            if (protection.IsFalse)
                context.Report("Purge protection is switched off, so whoever can delete a key can "
                               + "also destroy it before the retention window ends — deliberately, or "
                               + "by running the wrong pipeline. The data it protects is not "
                               + "recoverable afterwards. Set purge_protection_enabled to true.",
                    protection.Line);
        }
    }
}
