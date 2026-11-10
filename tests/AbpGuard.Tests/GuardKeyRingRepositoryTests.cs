using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AbpGuard.Tests;

/// <summary>AddGuardKeyRing: the ring in Guard's database, which the start-up check counts as kept.</summary>
public class GuardKeyRingRepositoryTests
{
    [Fact]
    public void The_ring_goes_to_Guards_database_and_passes_the_start_up_check()
    {
        ServiceCollection services = new();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Default"] = "Host=localhost;Database=host" }).Build());
        services.AddDataProtection().AddGuardKeyRing();

        KeyManagementOptions options = services.BuildServiceProvider().GetRequiredService<IOptions<KeyManagementOptions>>().Value;

        Assert.IsType<GuardKeyRingRepository>(options.XmlRepository);
        Assert.Null(GuardKeyRing.Problem(options));
    }
}
