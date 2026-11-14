using System.Text.Json.Serialization;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Data;
using AbpGuard.Directories;
using AbpGuard.Domain;
using AbpGuard.Services;
using AbpGuard.Acting;
using Volo.Abp;
using Volo.Abp.Domain.Entities;

namespace AbpGuard.Controllers;

[Route("api/guard")]
[GuardFeature(nameof(GuardFeatures.Directories))]
[Authorize(Policy = GuardPolicies.Admin)]
public class DirectoriesController(
    GuardDb guardDb,
    ConnectorCatalog connectors,
    DirectorySecrets secrets,
    DirectorySyncService sync,
    AccountProjector projector,
    AuthService auth,
    SecurityLog audit,
    Microsoft.Extensions.Options.IOptions<GuardOptions> options) : GuardControllerBase
{
    public sealed record DirectoryTypeDto(string Type, string DisplayName, List<string> Capabilities, List<DirectorySettingDefinition> Settings, string? PluginKey);

    public sealed record DirectoryInput(string Name, string Type, [property: JsonRequired] bool IsActive, [property: JsonRequired] bool AuthenticationEnabled, int? SyncIntervalMinutes, Dictionary<string, string>? Settings,
        Dictionary<string, string>? Names = null);

    public sealed record ReorderInput(List<Guid> DirectoryIds);

    public sealed record TestLoginInput(string Username, string Password);

    public sealed record TestLoginStep(string Step, bool Succeeded, string Message);

    [HttpGet("directory-types")]
    public async Task<List<DirectoryTypeDto>> Types() =>
        (await connectors.DescribeAllAsync())
            .Select(c => new DirectoryTypeDto(c.Type, c.DisplayName, Enum.GetValues<DirectoryCapabilities>().Where(f => f != DirectoryCapabilities.None && c.Capabilities.HasFlag(f)).Select(f => f.ToString()).ToList(), c.Settings, c.PluginKey))
            .ToList();

    [HttpGet("directories")]
    public async Task<List<DirectoryDto>> List(CancellationToken cancellationToken)
    {
        List<ConnectorDescription> available = await connectors.DescribeAllAsync();
        return await guardDb.RunAsync(async db =>
        {
            List<UserDirectory> directories = await db.Directories.AsNoTracking().OrderBy(d => d.Order).ToListAsync(cancellationToken);
            return await ToDtosAsync(db, directories, available, cancellationToken);
        }, cancellationToken: cancellationToken);
    }

    [HttpPost("directories")]
    [StepUp]
    public async Task<DirectoryDto> Create([FromBody] DirectoryInput input, CancellationToken cancellationToken)
    {
        List<ConnectorDescription> available = await connectors.DescribeAllAsync();
        // An internal directory keeps its accounts in Guard (a "Customers" directory for sign-ups); others need a connector.
        ConnectorDescription? connector = input.Type == GuardConstants.InternalType ? null : available.FirstOrDefault(c => c.Type == input.Type)
            ?? throw new UserFriendlyException($"No connector for directory type '{input.Type}'. Is its plugin enabled?");
        await CheckSettingsAsync(input.Type, input.Settings);

        (DirectoryDto dto, List<object> events) = await guardDb.RunAsync(async db =>
        {
            int order = (await db.Directories.MaxAsync(d => (int?)d.Order, cancellationToken) ?? 0) + 1;
            UserDirectory directory = new(Guid.NewGuid(), RequireName(input.Name), input.Type, order) { Names = GuardNamesByLanguage.Clean(input.Names, 200) };
            List<string> secretsSet = Apply(directory, input, connector, isNew: true);
            db.Directories.Add(directory);
            audit.Add(db, SecurityAuditTypes.DirectoryCreated, Target(directory), new
            {
                type = directory.Type,
                order = directory.Order,
                isActive = directory.IsActive,
                authenticationEnabled = directory.AuthenticationEnabled,
                settings = Settings(directory),
                secrets = secretsSet,
            });
            await db.SaveChangesAsync(cancellationToken);
            await DirectoryGroups.EnsureAsync(db, cancellationToken, options.Value.Texts.Product());
            await db.SaveChangesAsync(cancellationToken);
            List<object> events = await projector.RebuildAsync(db, cancellationToken: cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            return ((await ToDtosAsync(db, [directory], available, cancellationToken))[0], events);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        await PublishAsync(events);
        return dto;
    }

    [HttpPut("directories/{id:guid}")]
    [StepUp]
    public async Task<DirectoryDto> Update(Guid id, [FromBody] DirectoryInput input, CancellationToken cancellationToken)
    {
        List<ConnectorDescription> available = await connectors.DescribeAllAsync();
        if (input.Type != GuardConstants.InternalType)
        {
            await CheckSettingsAsync(input.Type, input.Settings);
        }

        (DirectoryDto dto, List<object> events) = await guardDb.RunAsync(async db =>
        {
            UserDirectory directory = await db.Directories.FirstOrDefaultAsync(d => d.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(UserDirectory), id);
            if (directory.IsInternal && !input.IsActive)
            {
                throw new UserFriendlyException("The internal directory can't be deactivated: the first admin lives there.");
            }

            ConnectorDescription? connector = available.FirstOrDefault(c => c.Type == directory.Type);
            if (!directory.IsInternal && connector is null)
            {
                throw new UserFriendlyException($"The '{directory.Type}' connector is not available, so its settings can't be validated. Enable its plugin first.");
            }

            var before = new { directory.Name, directory.IsActive, directory.AuthenticationEnabled, directory.SyncIntervalMinutes, Settings = Settings(directory) };
            directory.Name = RequireName(input.Name);
            if (input.Names is not null)
            {
                directory.Names = GuardNamesByLanguage.Clean(input.Names, 200);
            }

            List<string> secretsReplaced = Apply(directory, input, connector, isNew: false);
            // Whoever can point a directory at another host, or change its bind password, sees every later sign-in's password.
            Dictionary<string, string> after = Settings(directory);
            audit.Add(db, SecurityAuditTypes.DirectoryUpdated, Target(directory), new
            {
                name = before.Name == directory.Name ? null : new { before = before.Name, after = directory.Name },
                isActive = before.IsActive == directory.IsActive ? (bool?)null : directory.IsActive,
                authenticationEnabled = before.AuthenticationEnabled == directory.AuthenticationEnabled ? (bool?)null : directory.AuthenticationEnabled,
                syncIntervalMinutes = before.SyncIntervalMinutes == directory.SyncIntervalMinutes ? null : new { before = before.SyncIntervalMinutes, after = directory.SyncIntervalMinutes },
                settings = before.Settings.Keys.Union(after.Keys)
                    .Where(k => before.Settings.GetValueOrDefault(k) != after.GetValueOrDefault(k))
                    .ToDictionary(k => k, k => new { before = before.Settings.GetValueOrDefault(k), after = after.GetValueOrDefault(k) }),
                secrets = secretsReplaced,
            });
            await db.SaveChangesAsync(cancellationToken);
            await DirectoryGroups.EnsureAsync(db, cancellationToken, options.Value.Texts.Product());
            await db.SaveChangesAsync(cancellationToken);
            List<object> events = await projector.RebuildAsync(db, cancellationToken: cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            return ((await ToDtosAsync(db, [directory], available, cancellationToken))[0], events);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        await PublishAsync(events);
        return dto;
    }

    [HttpPost("directories/reorder")]
    [StepUp]
    public async Task<List<DirectoryDto>> Reorder([FromBody] ReorderInput input, CancellationToken cancellationToken)
    {
        List<ConnectorDescription> available = await connectors.DescribeAllAsync();
        (List<DirectoryDto> dtos, List<object> events) = await guardDb.RunAsync(async db =>
        {
            List<UserDirectory> directories = await db.Directories.ToListAsync(cancellationToken);
            if (input.DirectoryIds.Count != directories.Count || !directories.All(d => input.DirectoryIds.Contains(d.Id)))
            {
                throw new UserFriendlyException("Reorder needs every directory exactly once.");
            }

            List<string> before = directories.OrderBy(d => d.Order).Select(d => d.Name).ToList();
            for (int i = 0; i < input.DirectoryIds.Count; i++)
            {
                directories.First(d => d.Id == input.DirectoryIds[i]).Order = i;
            }

            // The order decides which directory owns a username, and so whose password signs it in.
            audit.Add(db, SecurityAuditTypes.DirectoriesReordered, null, new { before, after = directories.OrderBy(d => d.Order).Select(d => d.Name).ToList() });
            await db.SaveChangesAsync(cancellationToken);
            List<object> events = await projector.RebuildAsync(db, cancellationToken: cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            return (await ToDtosAsync(db, directories.OrderBy(d => d.Order).ToList(), available, cancellationToken), events);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        await PublishAsync(events);
        return dtos;
    }

    [HttpDelete("directories/{id:guid}")]
    [StepUp]
    public async Task<NoContentResult> Delete(Guid id, CancellationToken cancellationToken)
    {
        if (id == GuardConstants.InternalDirectoryId)
        {
            throw new UserFriendlyException("The internal directory can't be deleted.");
        }

        List<object> events = await guardDb.RunAsync(async db =>
        {
            UserDirectory directory = await db.Directories.FirstOrDefaultAsync(d => d.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(UserDirectory), id);
            Account me = await db.Accounts.FirstAsync(a => a.Id == CurrentAccountId, cancellationToken);
            if (me.DirectoryId == id)
            {
                throw new UserFriendlyException("You can't delete the directory your own account comes from.");
            }

            if (await db.SignUpSettings.AnyAsync(s => s.DirectoryId == id, cancellationToken))
            {
                throw new UserFriendlyException($"Sign-up creates accounts in {directory.Name}. Choose another directory for sign-ups first.");
            }

            List<Guid> groupIds = await db.Groups.Where(g => g.DirectoryId == id).Select(g => g.Id).ToListAsync(cancellationToken);
            List<Guid> userIds = await db.DirectoryUsers.Where(u => u.DirectoryId == id).Select(u => u.Id).ToListAsync(cancellationToken);
            await db.Memberships.Where(m => groupIds.Contains(m.GroupId)
                || (m.MemberType == MemberType.Group && groupIds.Contains(m.MemberId))
                || (m.MemberType == MemberType.DirectoryUser && userIds.Contains(m.MemberId))).ExecuteDeleteAsync(cancellationToken);
            await db.Groups.Where(g => g.DirectoryId == id).ExecuteDeleteAsync(cancellationToken);
            await db.DirectoryUsers.Where(u => u.DirectoryId == id).ExecuteDeleteAsync(cancellationToken);
            await db.SyncRuns.Where(r => r.DirectoryId == id).ExecuteDeleteAsync(cancellationToken);
            db.Directories.Remove(directory);
            audit.Add(db, SecurityAuditTypes.DirectoryDeleted, Target(directory), new { type = directory.Type, users = userIds.Count, groups = groupIds.Count });
            await db.SaveChangesAsync(cancellationToken);
            List<object> events = await projector.RebuildAsync(db, cancellationToken: cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            return events;
        }, requiresNew: true, cancellationToken, isTransactional: true);

        await PublishAsync(events);
        return NoContent();
    }

    [HttpPost("directories/{id:guid}/sync")]
    public async Task<SyncRunDto> Sync(Guid id, CancellationToken cancellationToken) =>
        SyncRunDto.From(await sync.SyncAsync(id, cancellationToken));

    [HttpGet("directories/{id:guid}/sync-runs")]
    public Task<List<SyncRunDto>> SyncRuns(Guid id, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db => (await db.SyncRuns.AsNoTracking()
                .Where(r => r.DirectoryId == id)
                .OrderByDescending(r => r.StartedAt)
                .Take(20)
                .ToListAsync(cancellationToken))
            .Select(SyncRunDto.From)
            .ToList(), cancellationToken: cancellationToken);

    [HttpPost("directories/{id:guid}/test")]
    [Reads]
    public async Task<ConnectionTestResult> Test(Guid id, CancellationToken cancellationToken)
    {
        UserDirectory directory = await LoadAsync(id, cancellationToken);
        if (directory.IsInternal)
        {
            return new ConnectionTestResult(true, $"The internal directory is stored in {options.Value.Texts.Product()}'s database and is always available.");
        }

        return await connectors.WithConnectorAsync(directory.Type, async (connector, _) => connector is null
            ? new ConnectionTestResult(false, $"The '{directory.Type}' connector is not available. Is its plugin enabled?")
            : await connector.TestAsync(connectors.BuildContext(directory), cancellationToken));
    }

    /// <summary>A step-by-step check of one sign-in against one directory, including whether it would win on precedence.</summary>
    [HttpPost("directories/{id:guid}/test-login")]
    public async Task<object> TestLogin(Guid id, [FromBody] TestLoginInput input, CancellationToken cancellationToken)
    {
        UserDirectory directory = await LoadAsync(id, cancellationToken);
        string normalized = GuardConstants.Normalize(input.Username ?? string.Empty);
        List<TestLoginStep> steps = [];

        ConnectionTestResult connection = await Test(id, cancellationToken);
        steps.Add(new TestLoginStep("Connection", connection.Succeeded, connection.Message));
        if (!connection.Succeeded)
        {
            return new { steps };
        }

        (DirectoryUser? record, UserDirectory? owner) = await guardDb.RunAsync(async db =>
        {
            DirectoryUser? record = await db.DirectoryUsers.AsNoTracking().FirstOrDefaultAsync(u => u.DirectoryId == id && u.NormalizedUsername == normalized, cancellationToken);
            UserDirectory? owner = await db.DirectoryUsers.AsNoTracking()
                .Where(u => u.NormalizedUsername == normalized)
                .Join(db.Directories.Where(d => d.IsActive), u => u.DirectoryId, d => d.Id, (u, d) => d)
                .OrderBy(d => d.Order)
                .FirstOrDefaultAsync(cancellationToken);
            return (record, owner);
        }, cancellationToken: cancellationToken);

        if (record is null)
        {
            steps.Add(new TestLoginStep("FindUser", false, $"'{input.Username}' is not in {directory.Name} (as of the last sync)."));
            return new { steps };
        }

        steps.Add(new TestLoginStep("FindUser", true, $"Found {record.Username} ({record.DisplayName}), external id {record.ExternalId}."));

        (bool authenticated, string? error) = await auth.AuthenticateAsync(directory, record, input.Password ?? string.Empty);
        steps.Add(new TestLoginStep("Authenticate", authenticated, authenticated ? "Password accepted by the directory." : $"Rejected: {error}."));

        bool wins = owner?.Id == directory.Id;
        steps.Add(new TestLoginStep("Precedence", wins, wins
            ? $"{directory.Name} owns '{record.Username}': it is the first active directory with that username."
            : $"'{record.Username}' is owned by {owner?.Name ?? "no active directory"}, which comes earlier in the order. Signing in uses that directory, not this one."));

        return new { steps };
    }

    private async Task<UserDirectory> LoadAsync(Guid id, CancellationToken cancellationToken) =>
        await guardDb.RunAsync(db => db.Directories.AsNoTracking().FirstOrDefaultAsync(d => d.Id == id, cancellationToken), cancellationToken: cancellationToken)
        ?? throw new EntityNotFoundException(typeof(UserDirectory), id);

    /// <summary>Refuses settings the directory's connector finds wrong (a name attribute without a language, say), each problem said.</summary>
    private async Task CheckSettingsAsync(string type, Dictionary<string, string>? settings)
    {
        IReadOnlyList<string> problems = await connectors.WithConnectorAsync(type, (c, _) =>
            Task.FromResult(c is IDirectorySettingsValidator v ? v.ProblemsIn(settings ?? new()) : (IReadOnlyList<string>)[]));
        if (problems.Count > 0)
        {
            throw new UserFriendlyException(string.Join(" ", problems));
        }
    }

    /// <summary>Applies the input to the directory; returns the names of the secrets it set or replaced (never their values).</summary>
    private List<string> Apply(UserDirectory directory, DirectoryInput input, ConnectorDescription? connector, bool isNew)
    {
        directory.IsActive = input.IsActive;
        directory.AuthenticationEnabled = input.AuthenticationEnabled;
        directory.SyncIntervalMinutes = input.SyncIntervalMinutes is > 0 ? input.SyncIntervalMinutes : null;
        if (connector is null)
        {
            return [];
        }

        Dictionary<string, string> incoming = input.Settings ?? new();
        Dictionary<string, string> stored = secrets.Unprotect(directory.ProtectedSecrets);
        Dictionary<string, string> plain = new();
        Dictionary<string, string> secret = new();
        foreach (DirectorySettingDefinition definition in connector.Settings)
        {
            incoming.TryGetValue(definition.Name, out string? value);
            if (definition.Secret)
            {
                // Blank or the mask means "keep the stored secret".
                if (string.IsNullOrEmpty(value) || value == DirectorySecrets.Mask)
                {
                    value = stored.GetValueOrDefault(definition.Name);
                }

                if (!string.IsNullOrEmpty(value))
                {
                    secret[definition.Name] = value;
                }
            }
            else if (!string.IsNullOrEmpty(value) || definition.DefaultValue is not null)
            {
                plain[definition.Name] = string.IsNullOrEmpty(value) ? definition.DefaultValue! : value.Trim();
            }

            if (definition.Required && string.IsNullOrEmpty(definition.Secret ? secret.GetValueOrDefault(definition.Name) : plain.GetValueOrDefault(definition.Name)))
            {
                throw new UserFriendlyException($"'{definition.Label}' is required.");
            }
        }

        directory.SettingsJson = JsonSerializer.Serialize(plain);
        directory.ProtectedSecrets = secrets.Protect(secret);
        return secret.Keys.Union(stored.Keys).Where(k => secret.GetValueOrDefault(k) != stored.GetValueOrDefault(k)).Order().ToList();
    }

    private static AuditTarget Target(UserDirectory directory) => new("Directory", directory.Id, directory.Name);

    private static Dictionary<string, string> Settings(UserDirectory directory) =>
        JsonSerializer.Deserialize<Dictionary<string, string>>(directory.SettingsJson) ?? new();

    private static string RequireName(string name) =>
        string.IsNullOrWhiteSpace(name) || name.Trim().Length > 200
            ? throw new UserFriendlyException("Directory names are 1–200 characters.")
            : name.Trim();

    private async Task<List<DirectoryDto>> ToDtosAsync(GuardDbContext db, List<UserDirectory> directories, List<ConnectorDescription> available, CancellationToken cancellationToken)
    {
        List<Guid> ids = directories.Select(d => d.Id).ToList();
        Dictionary<Guid, int> userCounts = await db.DirectoryUsers.Where(u => ids.Contains(u.DirectoryId) && u.IsActive)
            .GroupBy(u => u.DirectoryId).ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken);
        Dictionary<Guid, int> groupCounts = await db.Groups.Where(g => ids.Contains(g.DirectoryId))
            .GroupBy(g => g.DirectoryId).ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken);

        // What each directory's connector warns of in its settings: plain-text connections, certificate checks off.
        Dictionary<Guid, IReadOnlyList<string>> warnings = [];
        foreach (UserDirectory d in directories.Where(d => !d.IsInternal))
        {
            Dictionary<string, string> plain = JsonSerializer.Deserialize<Dictionary<string, string>>(d.SettingsJson) ?? new();
            warnings[d.Id] = await connectors.WithConnectorAsync(d.Type, (c, _) =>
                Task.FromResult(c is IDirectoryConnectorWarnings w ? w.WarningsFor(plain) : (IReadOnlyList<string>)[]));
        }

        return directories.Select(d =>
        {
            ConnectorDescription? connector = available.FirstOrDefault(c => c.Type == d.Type);
            Dictionary<string, string> settings = JsonSerializer.Deserialize<Dictionary<string, string>>(d.SettingsJson) ?? new();
            bool secretsReadable = secrets.TryUnprotect(d.ProtectedSecrets, out Dictionary<string, string> stored);
            foreach (string secretName in stored.Keys)
            {
                settings[secretName] = DirectorySecrets.Mask;
            }

            return new DirectoryDto(
                d.Id, d.Name, d.Type, d.IsInternal ? "Internal" : connector?.DisplayName ?? d.Type, d.Order, d.IsActive, d.AuthenticationEnabled,
                settings, d.SyncIntervalMinutes, d.LastSyncAt, d.LastSyncSucceeded, d.LastSyncMessage,
                userCounts.GetValueOrDefault(d.Id), groupCounts.GetValueOrDefault(d.Id),
                d.IsInternal || connector is not null, connector?.PluginKey, secretsReadable, warnings.GetValueOrDefault(d.Id) ?? []) { Names = d.Names };
        }).ToList();
    }
}
