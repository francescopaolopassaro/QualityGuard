using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The JavaScript and TypeScript rules chosen by measuring against an annotated reference corpus.
/// Each is pinned with the defect it must find and the shape it must leave alone.
/// </summary>
public class JsTsMeasuredRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "sample.js")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void An_assertion_that_is_never_called_is_reported()
    {
        var read = """
            describe('t', function () {
              it('checks', function () {
                expect(value).to.throw;
              });
            });
            """;
        Assert.NotEmpty(Lines(read, "QG-JS-BUG-0143"));

        var called = """
            describe('t', function () {
              it('checks', function () {
                expect(value).to.throw();
              });
            });
            """;
        Assert.Empty(Lines(called, "QG-JS-BUG-0143"));
    }

    [Fact]
    public void An_assertion_left_on_a_connector_is_reported()
    {
        var unfinished = """
            it('checks', function () {
              expect(value).to.not.be;
            });
            """;
        Assert.NotEmpty(Lines(unfinished, "QG-JS-BUG-0143"));
    }

    [Fact]
    public void A_property_that_asserts_by_itself_is_left_alone()
    {
        // 'true' and 'ok' assert as a plain read: calling them would be the mistake
        var valid = """
            it('checks', function () {
              expect(value).to.be.true;
              expect(other).to.be.ok;
            });
            """;
        Assert.Empty(Lines(valid, "QG-JS-BUG-0143"));
    }

    [Fact]
    public void An_assertion_comparing_a_value_with_itself_is_reported()
    {
        var same = """
            it('checks', function () {
              assert.equal(obj, obj);
            });
            """;
        Assert.NotEmpty(Lines(same, "QG-JS-BUG-0144"));

        var spaced = """
            it('checks', function () {
              assert.equal(1 + 1, 1+1);
            });
            """;
        Assert.NotEmpty(Lines(spaced, "QG-JS-BUG-0144"));

        var distinct = """
            it('checks', function () {
              assert.equal(actual, 3);
            });
            """;
        Assert.Empty(Lines(distinct, "QG-JS-BUG-0144"));
    }

    [Fact]
    public void A_cleartext_url_is_reported()
    {
        var plain = """
            const endpoint = 'http://api.internal.corp/orders';
            """;
        Assert.NotEmpty(Lines(plain, "QG-JS-SEC-0080"));

        var secure = """
            const endpoint = 'https://api.internal.corp/orders';
            const local = 'http://localhost:8080/health';
            """;
        Assert.Empty(Lines(secure, "QG-JS-SEC-0080"));
    }

    [Fact]
    public void Transit_encryption_switched_off_is_reported()
    {
        var off = """
            new CfnReplicationGroup(this, 'group', {
              transitEncryptionEnabled: false
            });
            """;
        Assert.NotEmpty(Lines(off, "QG-JS-SEC-0080"));
    }

    [Fact]
    public void An_obsolete_tls_version_is_reported()
    {
        var weak = """
            const agent = new https.Agent({ secureProtocol: 'TLSv1_method' });
            """;
        Assert.NotEmpty(Lines(weak, "QG-JS-SEC-0081"));

        var current = """
            const agent = new https.Agent({ minVersion: 'TLSv1.2' });
            """;
        Assert.Empty(Lines(current, "QG-JS-SEC-0081"));
    }

    [Fact]
    public void A_resource_declared_without_encryption_is_reported()
    {
        var missing = """
            new CfnDBCluster(this, 'db', {});
            """;
        Assert.NotEmpty(Lines(missing, "QG-JS-SEC-0082"));

        var encrypted = """
            new CfnDBCluster(this, 'db', { storageEncrypted: true });
            """;
        Assert.Empty(Lines(encrypted, "QG-JS-SEC-0082"));
    }

    [Fact]
    public void Options_the_rule_cannot_see_are_left_alone()
    {
        // the property may well be set inside 'props': reporting it would be a guess
        var indirect = """
            new CfnDBCluster(this, 'db', props);
            """;
        Assert.Empty(Lines(indirect, "QG-JS-SEC-0082"));
    }

    [Fact]
    public void A_constant_holding_false_is_followed()
    {
        var code = """
            const unencrypted = false;
            new CfnVolume(this, 'vol', { encrypted: unencrypted });
            """;
        Assert.NotEmpty(Lines(code, "QG-JS-SEC-0082"));
    }

    [Fact]
    public void A_publicly_reachable_resource_is_reported()
    {
        var open = """
            new CfnDBInstance(this, 'db', { publiclyAccessible: true });
            """;
        Assert.NotEmpty(Lines(open, "QG-JS-SEC-0083"));

        var range = """
            group.addIngressRule(Peer.ipv4('0.0.0.0/0'), Port.tcp(22));
            """;
        Assert.NotEmpty(Lines(range, "QG-JS-SEC-0083"));
    }

    [Fact]
    public void A_policy_that_grants_everything_is_reported()
    {
        var star = """
            new PolicyStatement({
              actions: ['*'],
              resources: ['arn:aws:s3:::bucket/*']
            });
            """;
        Assert.NotEmpty(Lines(star, "QG-JS-SEC-0084"));

        var named = """
            new PolicyStatement({
              actions: ['s3:GetObject'],
              resources: ['arn:aws:s3:::bucket/*']
            });
            """;
        Assert.Empty(Lines(named, "QG-JS-SEC-0084"));
    }

    [Fact]
    public void A_relative_executable_path_is_reported()
    {
        var relative = """
            child_process.exec('./run.sh');
            """;
        Assert.NotEmpty(Lines(relative, "QG-JS-SEC-0085"));

        var onPath = """
            child_process.exec('ls');
            """;
        Assert.Empty(Lines(onPath, "QG-JS-SEC-0085"));
    }
    [Fact]
    public void A_setup_hook_written_after_a_test_is_reported()
    {
        var late = """
            describe('service', () => {
              it('lists users', () => {});
              beforeEach(() => {});
            });
            """;
        Assert.NotEmpty(Lines(late, "QG-JS-SML-0372"));

        var ordered = """
            describe('service', () => {
              beforeEach(() => {});
              it('lists users', () => {});
              afterEach(() => {});
            });
            """;
        Assert.Empty(Lines(ordered, "QG-JS-SML-0372"));
    }

    [Fact]
    public void A_teardown_hook_between_tests_is_reported()
    {
        var between = """
            describe('service', () => {
              it('a', () => {});
              afterEach(() => {});
              it('b', () => {});
            });
            """;
        Assert.NotEmpty(Lines(between, "QG-JS-SML-0372"));
    }

    [Fact]
    public void A_memoised_function_of_several_arguments_is_reported()
    {
        var unkeyed = """
            const format = memoize((amount, locale) => amount.toLocaleString(locale));
            """;
        Assert.NotEmpty(Lines(unkeyed, "QG-JS-BUG-0145"));

        var keyed = """
            const format = memoize(
              (amount, locale) => amount.toLocaleString(locale),
              (amount, locale) => amount + locale);
            """;
        Assert.Empty(Lines(keyed, "QG-JS-BUG-0145"));

        var single = """
            const square = memoize((n) => n * n);
            """;
        Assert.Empty(Lines(single, "QG-JS-BUG-0145"));
    }

    [Fact]
    public void A_negated_matcher_with_an_argument_is_reported()
    {
        var uncertain = """
            it('checks', function () {
              expect(load).to.not.throw(ReferenceError);
            });
            """;
        Assert.NotEmpty(Lines(uncertain, "QG-JS-BUG-0146"));

        var certain = """
            it('checks', function () {
              expect(load).to.throw(TypeError);
            });
            """;
        Assert.Empty(Lines(certain, "QG-JS-BUG-0146"));
    }

    [Fact]
    public void The_subject_of_an_assertion_counts_as_an_argument()
    {
        var duplicated = """
            it('checks', function () {
              expect(obj).a(obj, other);
            });
            """;
        Assert.NotEmpty(Lines(duplicated, "QG-JS-BUG-0144"));
    }

    [Fact]
    public void Two_equal_literals_are_left_alone()
    {
        // asserting that 42 equals 42 is a deliberate constant check, not a mistake
        var literals = """
            it('checks', function () {
              assert.equal(42, 42);
              assert.deepStrictEqual({ a: 1 }, { a: '1' });
            });
            """;
        Assert.Empty(Lines(literals, "QG-JS-BUG-0144"));
    }

}
