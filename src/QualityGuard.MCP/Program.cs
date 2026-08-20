using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Extensions.Tasks;
using ModelContextProtocol.Server;
using QualityGuard.Mcp;

var config = McpServerConfig.FromArgs(args);

if (config.HelpRequested)
{
    Console.WriteLine(McpServerConfig.Usage);
    return 0;
}

switch (config.Transport)
{
    case McpTransport.Stdio:
        await RunStdioAsync();
        break;
    case McpTransport.Http:
        await RunHttpAsync(config);
        break;
    default:
        throw new InvalidOperationException($"Unknown transport: {config.Transport}");
}
return 0;

async Task RunStdioAsync()
{
    var builder = Host.CreateApplicationBuilder();
    // MCP speaks JSON-RPC on stdout; every log line must go to stderr or it corrupts the protocol.
    builder.Logging.ClearProviders();
    builder.Logging.SetMinimumLevel(LogLevel.Warning);
    builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
    builder.Services.AddMcpServer()
        .WithStdioServerTransport()
        .WithToolsFromAssembly()
        .WithTasks(new InMemoryMcpTaskStore());
    await builder.Build().RunAsync();
}

async Task RunHttpAsync(McpServerConfig config)
{
    var builder = WebApplication.CreateBuilder();
    builder.Logging.ClearProviders();
    builder.Logging.SetMinimumLevel(LogLevel.Warning);
    builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
    builder.Services.AddMcpServer()
        .WithHttpTransport(options =>
        {
            options.Stateless = true;
        })
        .WithToolsFromAssembly()
        .WithTasks(new InMemoryMcpTaskStore());
    var app = builder.Build();
    var pattern = string.IsNullOrWhiteSpace(config.Endpoint)
        ? string.Empty
        : config.Endpoint.StartsWith('/')
            ? config.Endpoint
            : "/" + config.Endpoint;
    app.MapMcp(pattern);
    await app.RunAsync($"http://{config.Host}:{config.Port}");
}