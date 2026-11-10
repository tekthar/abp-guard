namespace AbpGuard;

/// <summary>A tool a personal access token may be limited to: its name, and whether it only reads.</summary>
public sealed record GuardTool(string Name, bool ReadOnly);

/// <summary>
/// What a personal access token may be limited to besides its access: the host's tools (its tool
/// catalog, MCP's and plugins'). A token limited to some tools names only these, and a read-only one only tools that read.
/// The default has no tools, so a token can't be limited to any.
/// </summary>
public interface ITokenRestrictions
{
    Task<IReadOnlyList<GuardTool>> ToolsAsync(CancellationToken cancellationToken);
}

/// <summary>The default: no tools.</summary>
public sealed class NoTokenRestrictions : ITokenRestrictions
{
    public Task<IReadOnlyList<GuardTool>> ToolsAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<GuardTool>>([]);
}
