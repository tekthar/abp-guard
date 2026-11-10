using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using AbpGuard.Domain;

namespace AbpGuard.Services;

/// <summary>
/// Removes security events older than the site keeps them (two years by default), once an hour. The only
/// thing that ever deletes an event. Browsers' sessions that ended over a month ago go too.
/// </summary>
public class SecurityAuditRetention(IServiceScopeFactory scopes, ILogger<SecurityAuditRetention> logger) : BackgroundService
{
    private const int Batch = 5000;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using PeriodicTimer timer = new(TimeSpan.FromHours(1));
        do
        {
            try
            {
                await PruneAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Pruning the security audit failed; it runs again in an hour.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task PruneAsync(CancellationToken cancellationToken)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        GuardDb guardDb = scope.ServiceProvider.GetRequiredService<GuardDb>();
        int days = await guardDb.RunAsync(db => db.SecuritySettings.AsNoTracking().Where(s => s.Id == SecuritySettings.SingletonId)
            .Select(s => (int?)s.RetentionDays).FirstOrDefaultAsync(cancellationToken), cancellationToken: cancellationToken) ?? SecuritySettings.DefaultRetentionDays;
        DateTime before = DateTime.UtcNow.AddDays(-Math.Clamp(days, SecuritySettings.MinRetentionDays, SecuritySettings.MaxRetentionDays));
        while (await guardDb.RunAsync(db => db.SecurityEvents.Where(e => e.Time < before).OrderBy(e => e.Time).Take(Batch)
                   .ExecuteDeleteAsync(cancellationToken), requiresNew: true, cancellationToken: cancellationToken) == Batch)
        {
        }

        await scope.ServiceProvider.GetRequiredService<WebSessions>().PruneAsync(cancellationToken);
    }
}
