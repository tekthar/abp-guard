using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// Creates the internal directory, the first admin, the admins and users groups (admins and users by default,
/// GuardOptions.Seed and AdminsGroupName in a host), and the sign-up settings.
/// </summary>
public class GuardSeeder(GuardDb guardDb, AccountProjector projector, IConfiguration configuration, IHostEnvironment environment,
    Microsoft.Extensions.Options.IOptions<GuardOptions> options, ILogger<GuardSeeder> logger)
    : ITransientDependency
{
    private const int MinAdminPassword = 10;

    public Task SeedAsync(CancellationToken cancellationToken = default)
    {
        if (configuration.GetValue("Guard:TwoFactor:Disabled", false))
        {
            logger.LogWarning("Guard:TwoFactor:Disabled is set: nobody is asked for a second factor. It's the emergency switch for a site whose admins "
                + "lost theirs; remove it once they're back in.");
        }

        return SeedTablesAsync(cancellationToken);
    }

    private Task SeedTablesAsync(CancellationToken cancellationToken) => guardDb.RunAsync(async db =>
    {
        GuardSeedOptions seed = options.Value.Seed;
        if (!await db.Directories.AnyAsync(d => d.Id == GuardConstants.InternalDirectoryId, cancellationToken))
        {
            db.Directories.Add(new UserDirectory(GuardConstants.InternalDirectoryId, seed.InternalDirectoryName, GuardConstants.InternalType, order: 0));
        }

        string adminPassword = configuration["Guard:Seed:AdminPassword"]
            ?? throw new InvalidOperationException("Guard:Seed:AdminPassword is not configured.");
        if (!await db.DirectoryUsers.AnyAsync(u => u.DirectoryId == GuardConstants.InternalDirectoryId && u.NormalizedUsername == "admin", cancellationToken))
        {
            // The rule every other password keeps; checked when the admin is made, so a site already running still starts.
            if (adminPassword.Length < MinAdminPassword)
            {
                throw new InvalidOperationException($"Guard:Seed:AdminPassword needs at least {MinAdminPassword} characters, as every password does.");
            }

            DirectoryUser admin = new(Guid.NewGuid(), GuardConstants.InternalDirectoryId, "internal:admin", "admin")
            {
                DisplayName = seed.AdminDisplayName,
                Email = seed.AdminEmail,
            };
            admin.PasswordHash = AuthService.HashPassword(admin, adminPassword);
            db.DirectoryUsers.Add(admin);
        }

        await EnsureGroupAsync(db, GuardConstants.AdminsGroupId, options.Value.AdminsGroupName, seed.AdminsGroupDescription, cancellationToken);
        await EnsureGroupAsync(db, GuardConstants.UsersGroupId, seed.UsersGroupName, seed.UsersGroupDescription, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        await DirectoryGroups.EnsureAsync(db, cancellationToken, options.Value.Texts.Product());
        if (!await db.SignUpSettings.AnyAsync(s => s.Id == SignUpSettings.SiteId, cancellationToken))
        {
            // Closed, or open into the internal directory when the host says so (Guard:SignUp:Open). Once: an admin's
            // later choice stays.
            db.SignUpSettings.Add(SelfService.Initial(options.Value.SignUp));
        }

        await db.SaveChangesAsync(cancellationToken);

        await projector.RebuildAsync(db, cancellationToken: cancellationToken);
        await db.SaveChangesAsync(cancellationToken);

        await EnsureRolesAsync(db, cancellationToken);

        Account adminAccount = await db.Accounts.FirstAsync(a => a.NormalizedUsername == "admin", cancellationToken);
        if (!await db.Memberships.AnyAsync(m => m.GroupId == GuardConstants.AdminsGroupId && m.MemberType == MemberType.Account && m.MemberId == adminAccount.Id, cancellationToken))
        {
            db.Memberships.Add(new GroupMembership(Guid.NewGuid(), GuardConstants.AdminsGroupId, MemberType.Account, adminAccount.Id, MembershipSource.Manual));
            await db.SaveChangesAsync(cancellationToken);
        }

        // admins must use a second factor on a production site, and is offered one in Development so dev servers and
        // test scripts sign in as before. Once, so an admin's later choice stays.
        SecuritySettings settings = await Controllers.SecuritySettingsController.LoadAsync(db, cancellationToken);
        if (!settings.AdminsTwoFactorSeeded)
        {
            Group admins = await db.Groups.FirstAsync(g => g.Id == GuardConstants.AdminsGroupId, cancellationToken);
            admins.TwoFactor = environment.IsDevelopment() ? TwoFactorModes.Optional : TwoFactorModes.Required;
            settings.AdminsTwoFactorSeeded = true;
            await db.SaveChangesAsync(cancellationToken);
        }
    }, requiresNew: true, cancellationToken);

    /// <summary>
    /// System roles. Administrator is granted to the admins group, so admin rights follow group membership,
    /// nested groups included. Directory helpdesk is an example of a scoped role: its grant's scope says which
    /// directories it covers.
    /// </summary>
    private static async Task EnsureRolesAsync(GuardDbContext db, CancellationToken cancellationToken)
    {
        (Guid Id, string Key, string Name, string Description, string[] Rules)[] roles =
        [
            (GuardRoles.AdministratorId, "administrator", "Administrator", "Can do everything.",
            [
                """{ "action": "manage", "subject": "all" }""",
            ]),
            (GuardRoles.DirectoryHelpdeskId, "directory-helpdesk", "Directory helpdesk",
                "Sees and can lock or unlock accounts in the directories named in the grant's scope (directoryIds).",
            [
                """{ "action": "read", "subject": "Account", "conditions": { "directoryId": { "$in": "${grant.directoryIds}" } } }""",
                """{ "action": ["lock", "unlock"], "subject": "Account", "conditions": { "directoryId": { "$in": "${grant.directoryIds}" } } }""",
                """{ "action": ["lock", "unlock"], "subject": "Account", "inverted": true, "conditions": { "id": "${user.id}" }, "reason": "You can't lock or unlock your own account." }""",
                """{ "action": "read", "subject": "Group", "conditions": { "directoryId": { "$in": "${grant.directoryIds}" } } }""",
            ]),
        ];

        foreach ((Guid id, string key, string name, string description, string[] rules) in roles)
        {
            if (await db.Roles.AnyAsync(r => r.Id == id, cancellationToken))
            {
                continue;
            }

            db.Roles.Add(new Role(id, key, name, isSystem: true) { Description = description });
            for (int i = 0; i < rules.Length; i++)
            {
                db.RoleRules.Add(new RoleRule(Guid.NewGuid(), id, i, rules[i]));
            }
        }

        if (!await db.RoleGrants.AnyAsync(g => g.RoleId == GuardRoles.AdministratorId && g.PrincipalId == GuardConstants.AdminsGroupId, cancellationToken))
        {
            db.RoleGrants.Add(new RoleGrant(Guid.NewGuid(), GuardRoles.AdministratorId, PrincipalType.Group, GuardConstants.AdminsGroupId, "{}"));
        }

        await db.SaveChangesAsync(cancellationToken);
    }

    private static async Task EnsureGroupAsync(GuardDbContext db, Guid id, string name, string description, CancellationToken cancellationToken)
    {
        if (!await db.Groups.AnyAsync(g => g.Id == id, cancellationToken))
        {
            db.Groups.Add(new Group(id, GuardConstants.InternalDirectoryId, name, isLocal: true) { Description = description });
        }
    }
}

/// <summary>Runs each directory's sync on its interval.</summary>
public class DirectorySyncScheduler(IServiceScopeFactory scopes, IGuardLocks locks, ILogger<DirectorySyncScheduler> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
        using PeriodicTimer timer = new(TimeSpan.FromSeconds(30));
        do
        {
            try
            {
                // One server schedules at a time (M10 step 2), so a directory that's due is synced once, not by each.
                await using IAsyncDisposable? held = await locks.TryTakeAsync("directory-sync-schedule", stoppingToken);
                if (held is null)
                {
                    continue;
                }

                await using AsyncServiceScope scope = scopes.CreateAsyncScope();
                GuardDb guardDb = scope.ServiceProvider.GetRequiredService<GuardDb>();
                DateTime now = DateTime.UtcNow;
                List<UserDirectory> due = await guardDb.RunAsync(db => db.Directories.AsNoTracking()
                    .Where(d => d.IsActive && d.Type != GuardConstants.InternalType && d.SyncIntervalMinutes != null)
                    .ToListAsync(stoppingToken), requiresNew: true, stoppingToken);

                foreach (UserDirectory directory in due.Where(d => d.LastSyncAt is null || d.LastSyncAt.Value.AddMinutes(d.SyncIntervalMinutes!.Value) <= now))
                {
                    await scope.ServiceProvider.GetRequiredService<DirectorySyncService>().SyncAsync(directory.Id, stoppingToken);
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Scheduled directory sync failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
