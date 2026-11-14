using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using AbpGuard.Acting;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services.TwoFactor;

/// <summary>
/// Where a person stands under the site admins' rule: whether it applies to them (a site admin while the rule is on), by
/// when they must have a strong factor (null once they have one), and whether that's past.
/// </summary>
public sealed record StrongFactorDue(bool Applies, DateTime? RequiredBy, bool Overdue)
{
    public static StrongFactorDue None { get; } = new(false, null, false);
}

/// <summary>
/// The rule that every site admin has a strong factor (<see cref="GuardAdminsOptions"/>). A site admin is whoever's roles
/// can manage everything (<see cref="AbilityFactory.HoldsAdminRightsAsync"/>, the Admin policy's rights, whatever a
/// request's token limits). The grace is counted per person from when Guard first sees them as one without a strong
/// factor (a sign-in, or their session read), kept on the account (<c>StrongFactorDueAt</c>), cleared when they have one,
/// and restarted when an admin resets their factors. Each step is in the security log. With second factors switched off
/// (the emergency switch) the rule holds no one.
/// </summary>
public sealed class AdminsStrongFactor(GuardDb guardDb, IOptions<GuardOptions> options, IConfiguration configuration, AbilityFactory abilities, SecurityLog audit)
    : ITransientDependency
{
    /// <summary>Whether the server's operator set the rule (Guard:Admins:RequireStrongFactor).</summary>
    public bool Required => options.Value.Admins.RequireStrongFactor;

    /// <summary>Whether the rule holds now: set, and second factors not switched off.</summary>
    public bool On => Required && !SecondFactors.IsDisabled(configuration, options.Value);

    /// <summary>How long a site admin has to set one up.</summary>
    public TimeSpan Grace => TimeSpan.FromHours(Math.Clamp(options.Value.Admins.GraceHours, 0, 24 * 366));

    /// <summary>Whether the rule holds the person to keeping a strong factor: a site admin (not a service account), while it's on.</summary>
    public async Task<bool> HoldsAsync(Guid accountId, CancellationToken cancellationToken) =>
        On && !await guardDb.RunAsync(db => db.Accounts.AnyAsync(a => a.Id == accountId && a.IsService, cancellationToken), cancellationToken: cancellationToken)
        && await abilities.HoldsAdminRightsAsync(accountId, cancellationToken);

    /// <summary>
    /// Brings the person's date up to date and says where they stand: the grace starts the first time Guard sees a site
    /// admin without a strong factor, and the date goes once they have one, or aren't held by the rule.
    /// </summary>
    public async Task<StrongFactorDue> CheckAsync(Guid accountId, string? ip, CancellationToken cancellationToken)
    {
        var row = await guardDb.RunAsync(db => db.Accounts.AsNoTracking().Where(a => a.Id == accountId).Select(a => new { a.Username, a.StrongFactorDueAt })
            .FirstOrDefaultAsync(cancellationToken), cancellationToken: cancellationToken);
        if (row is null)
        {
            return StrongFactorDue.None;
        }

        bool applies = await HoldsAsync(accountId, cancellationToken);
        if (!applies || await guardDb.RunAsync(db => SecondFactors.HasFactorAsync(db, accountId, cancellationToken), cancellationToken: cancellationToken))
        {
            if (row.StrongFactorDueAt is not null)
            {
                await ClearAsync(accountId, row.Username, met: applies, ip, cancellationToken);
            }

            return new StrongFactorDue(applies, null, false);
        }

        DateTime due = row.StrongFactorDueAt ?? await StartAsync(accountId, row.Username, ip, cancellationToken);
        return new StrongFactorDue(true, due, DateTime.UtcNow >= due);
    }

    /// <summary>A strong factor was set up: the person's date goes, and the log says the rule is met.</summary>
    public async Task MetAsync(Guid accountId, CancellationToken cancellationToken)
    {
        string? username = await guardDb.RunAsync(db => db.Accounts.AsNoTracking().Where(a => a.Id == accountId && a.StrongFactorDueAt != null).Select(a => a.Username)
            .FirstOrDefaultAsync(cancellationToken), cancellationToken: cancellationToken);
        if (username is not null)
        {
            await ClearAsync(accountId, username, met: true, null, cancellationToken);
        }
    }

    /// <summary>An admin reset the person's factors: a site admin's grace starts again from now.</summary>
    public async Task RestartAsync(Guid accountId, CancellationToken cancellationToken)
    {
        if (!await HoldsAsync(accountId, cancellationToken))
        {
            await guardDb.RunAsync(db => db.Accounts.Where(a => a.Id == accountId).ExecuteUpdateAsync(s => s.SetProperty(a => a.StrongFactorDueAt, (DateTime?)null),
                cancellationToken), requiresNew: true, cancellationToken);
            return;
        }

        DateTime due = DateTime.UtcNow + Grace;
        string? username = await guardDb.RunAsync(async db =>
        {
            await db.Accounts.Where(a => a.Id == accountId).ExecuteUpdateAsync(s => s.SetProperty(a => a.StrongFactorDueAt, due), cancellationToken);
            return await db.Accounts.AsNoTracking().Where(a => a.Id == accountId).Select(a => a.Username).FirstOrDefaultAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.StrongFactorGrace, new AuditTarget("Account", accountId, username), new { requiredBy = due, restarted = true },
            cancellationToken);
    }

    /// <summary>A sign-in past the grace was sent to set up a strong factor before going on.</summary>
    public Task SentToEnrolAsync(Guid accountId, string username, string? ip, CancellationToken cancellationToken) =>
        audit.WriteAsync(SecurityAuditTypes.StrongFactorEnrol, username, accountId, "site admins' rule", ip, cancellationToken);

    /// <summary>Starts the person's grace, once: of two requests at once, only the first sets it and is logged.</summary>
    private async Task<DateTime> StartAsync(Guid accountId, string username, string? ip, CancellationToken cancellationToken)
    {
        DateTime due = DateTime.UtcNow + Grace;
        (int set, DateTime? kept) = await guardDb.RunAsync(async db =>
        {
            int set = await db.Accounts.Where(a => a.Id == accountId && a.StrongFactorDueAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(a => a.StrongFactorDueAt, due), cancellationToken);
            return (set, await db.Accounts.AsNoTracking().Where(a => a.Id == accountId).Select(a => a.StrongFactorDueAt).FirstOrDefaultAsync(cancellationToken));
        }, requiresNew: true, cancellationToken);
        if (set > 0)
        {
            await audit.WriteAsync(SecurityAuditTypes.StrongFactorGrace, username, accountId, $"required by {due:O}", ip, cancellationToken);
        }

        return kept ?? due;
    }

    private async Task ClearAsync(Guid accountId, string username, bool met, string? ip, CancellationToken cancellationToken)
    {
        int cleared = await guardDb.RunAsync(db => db.Accounts.Where(a => a.Id == accountId && a.StrongFactorDueAt != null)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.StrongFactorDueAt, (DateTime?)null), cancellationToken), requiresNew: true, cancellationToken);
        if (cleared > 0 && met)
        {
            await audit.WriteAsync(SecurityAuditTypes.StrongFactorSetUp, username, accountId, "site admins' rule met", ip, cancellationToken);
        }
    }
}
