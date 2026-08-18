using System.Text.RegularExpressions;

namespace QualityGuard.Core.Rules;

/// <summary>
/// Decides whether a string literal is an address that would really travel unencrypted.
///
/// Matching "http://" and reporting it produced hundreds of findings on any HTTP client library,
/// because most of those literals are not addresses at all: they are XML namespaces, which are
/// names and never fetched; documentation hosts reserved so that examples cannot reach anything;
/// and the loopback and metadata addresses, which never leave the machine. Each of those is a
/// separate list, and a literal has to survive all of them before it counts.
/// </summary>
public static partial class CleartextProtocols
{
    /// <summary>Every scheme that carries its content in the open, and what to use instead.</summary>
    private static readonly (string Scheme, string Instead)[] Insecure =
    [
        ("http", "https"), ("ftp", "sftp, scp or ftps"), ("ws", "wss"), ("telnet", "ssh"),
        ("gopher", "https"), ("tftp", "sftp"), ("smtp", "smtps"), ("ldap", "ldaps"),
        ("imap", "imaps"), ("pop3", "pop3s"), ("amqp", "amqps"), ("mqtt", "mqtts"),
        ("sip", "sips"), ("rtmp", "rtmps"), ("irc", "ircs"), ("nntp", "nntps"),
        ("stomp", "stomps"),
    ];

    /// <summary>
    /// Hosts that never leave the machine or the cluster: loopback in its several spellings, the
    /// link-local range, the metadata endpoints of the major clouds, and in-cluster service names.
    /// </summary>
    [GeneratedRegex(@"^(?:localhost|127(?:\.\d+){1,3}|\[(?:0*:){7}:?0*1\]|\[::1\]|169\.254\.\d+\.\d+"
                    + @"|\[fd00:ec2::254\]|168\.63\.129\.16|100\.100\.100\.200"
                    + @"|metadata\.google\.internal|metadata\.internal|host\.docker\.internal"
                    + @"|gateway\.docker\.internal)(?::|$)|\.svc\.cluster\.local(?::|$)",
        RegexOptions.IgnoreCase)]
    private static partial Regex SafeHost();

    /// <summary>
    /// Authorities that appear in namespace declarations. A namespace URI is an identifier: nothing
    /// is ever fetched from it, so the scheme in front of it says nothing about the traffic.
    /// </summary>
    [GeneratedRegex(@"^(?:www\.w3\.org|schemas\.android\.com|schemas\.microsoft\.com"
                    + @"|schemas\.xmlsoap\.org|www\.sap\.com|www\.opengis\.net|hl7\.org"
                    + @"|unitsofmeasure\.org|purl\.org|docs\.oasis-open\.org|xmlns\.com"
                    + @"|json-ld\.org|schema\.org|www\.springframework\.org|maven\.apache\.org"
                    + @"|dublincore\.org|ogp\.me|xml\.apache\.org|schemas\.openxmlformats\.org"
                    + @"|rdfs\.org|schemas\.google\.com|a9\.com|ns\.adobe\.com|ltsc\.ieee\.org"
                    + @"|docbook\.org|graphml\.graphdrawing\.org|json-schema\.org)(?::|$)",
        RegexOptions.IgnoreCase)]
    private static partial Regex NamespaceAuthority();

    /// <summary>Domains reserved for examples, which by definition resolve to nothing.</summary>
    [GeneratedRegex(@"(?:(?:^|\.)example\.(?:com|net|org)|\.(?:example|test|localhost))(?::|$)",
        RegexOptions.IgnoreCase)]
    private static partial Regex DocumentationHost();

    /// <summary>The authority of a literal that will not parse as a URL — a template, usually.</summary>
    [GeneratedRegex(@"^([a-z0-9]+)://(?:[^@\s/?#]+@)?([^\s/?#]+)", RegexOptions.IgnoreCase)]
    private static partial Regex Authority();

    /// <summary>
    /// Whether the literal names something that would really be reached in the clear, and if so
    /// which scheme it uses and what should replace it.
    /// </summary>
    public static bool IsExposedAddress(string literal, out string scheme, out string instead)
    {
        scheme = string.Empty;
        instead = string.Empty;
        if (string.IsNullOrEmpty(literal))
            return false;

        var match = Authority().Match(literal.Trim());
        if (!match.Success)
            return false;

        var found = match.Groups[1].Value.ToLowerInvariant();
        var pair = Array.Find(Insecure, p => p.Scheme == found);
        if (pair.Scheme is null)
            return false;

        var host = match.Groups[2].Value;
        if (SafeHost().IsMatch(host) || NamespaceAuthority().IsMatch(host)
            || DocumentationHost().IsMatch(host))
            return false;

        // a placeholder is not a host: the address is assembled somewhere else and this half of it
        // proves nothing about where the traffic ends up
        if (host.Contains('%') || host.Contains('{') || host.Contains('$') || host.Contains('<'))
            return false;

        scheme = found;
        instead = pair.Instead;
        return true;
    }

    /// <summary>The sentence to report, naming the scheme found and the one to use.</summary>
    public static string Advice(string scheme, string instead)
        => $"'{scheme}://' carries everything it sends in the open, so anyone on the path between "
           + $"the two ends can read it and change the answer before it arrives. Use {instead}.";
}
