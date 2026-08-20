namespace QualityGuard.Mcp;

public enum McpTransport
{
    Stdio,
    Http
}

/// <summary>
/// How the server listens. The transport is chosen with --transport (or the QG_MCP_* environment
/// variables), so one binary serves both an IDE/local client over stdio and a remote deployment over
/// Streamable HTTP.
/// </summary>
public sealed class McpServerConfig
{
    public static McpServerConfig FromArgs(string[] args)
    {
        var config = new McpServerConfig();
        config.HelpRequested = args.Any(a => a is "--help" or "-h");
        config.Transport = Flag(args, "--transport") switch
        {
            "http" or "Http" => McpTransport.Http,
            _ => McpTransport.Stdio
        };
        config.Host = First(args, "--host", Env("QG_MCP_HOST"), "localhost")!;
        config.Port = int.TryParse(First(args, "--port", Env("QG_MCP_PORT"), null), out var port)
            ? port
            : 3001;
        config.Endpoint = First(args, "--endpoint", Env("QG_MCP_ENDPOINT"), "/mcp")!;
        return config;
    }

    public static string Usage => """
        QualityGuard.Mcp -- Model Context Protocol server for QualityGuard

        Usage:
          QualityGuard.Mcp [--transport stdio|http] [--host <host>] [--port <port>] [--endpoint <path>]

        Options:
          --transport  stdio (default, for local clients) or http (remote / Streamable HTTP).
          --host       bind address for the HTTP transport (default localhost).
          --port       TCP port for the HTTP transport (default 3001).
          --endpoint   HTTP route of the MCP endpoint (default /mcp).

        Environment variables: QG_MCP_TRANSPORT, QG_MCP_HOST, QG_MCP_PORT, QG_MCP_ENDPOINT.
        """;

    public McpTransport Transport { get; private set; } = McpTransport.Stdio;
    public bool HelpRequested { get; private set; }
    public string Host { get; private set; } = "localhost";
    public int Port { get; private set; } = 3001;
    public string Endpoint { get; private set; } = "/mcp";

    private static string Flag(string[] args, string name)
    {
        for (var i = 0; i + 1 < args.Length; i++)
        {
            if (args[i] == name)
                return args[i + 1];
        }
        return string.Empty;
    }

    private static string? First(string[] args, string name, string? fallback, string? defaultValue)
    {
        var value = Flag(args, name);
        if (!string.IsNullOrWhiteSpace(value))
            return value;
        if (!string.IsNullOrWhiteSpace(fallback))
            return fallback;
        return defaultValue;
    }

    private static string? Env(string name) => Environment.GetEnvironmentVariable(name);
}