using Microsoft.Extensions.Configuration;

namespace AbpGuard.Data;

/// <summary>
/// Which database Guard keeps its tables in: ConnectionStrings:Guard, else ConnectionStrings:Default, so a
/// host that keeps everything in one database sets nothing new.
/// </summary>
public static class GuardConnection
{
    public const string Name = "Guard";

    public static string? Of(IConfiguration configuration) =>
        configuration.GetConnectionString(Name) is { Length: > 0 } own ? own : configuration.GetConnectionString("Default");
}
