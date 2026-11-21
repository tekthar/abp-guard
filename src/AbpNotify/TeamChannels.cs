using System.Text.Json.Serialization;
using AbpConnections;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Domain.Entities;

namespace AbpNotify;

/// <summary>A team's channel as the store has it: where it's kept (the site, or a scope), its channel and connection, and where it posts.</summary>
public sealed record ChannelTargetView(Guid Id, Guid? ScopeId, string Name, string Channel, Guid ConnectionId, string Connection, string Where);

public sealed record ChannelTargetInput(string Name, [property: JsonRequired] Guid ConnectionId, string? Where);

/// <summary>A Slack or Teams connection a team's channel may go through: the site's, or the scope's own.</summary>
public sealed record ChannelConnectionDto(Guid Id, string Name, string Type, bool Site);

/// <summary>The channels there are, for admins: each one's kinds, whether it reaches people, and whether it's set up.</summary>
public sealed record ChannelDto(string Key, string? Name, IReadOnlyList<string> Kinds, bool Personal, bool Ready);

/// <summary>Teams' channels to post to: kept at site scope or a scope's, and posting once per event.</summary>
public sealed class ChannelTargetStore(IServiceScopeFactory scopes, IServiceProvider services, INotifyChannels channels) : ITransientDependency
{
    /// <summary>The connection kinds a team's channel can go through, and the channel each is.</summary>
    public static readonly IReadOnlyDictionary<string, string> ChannelOf = new Dictionary<string, string>
    {
        [SlackConnectionKind.Key] = SlackConnectionKind.Key, [TeamsConnectionKind.Key] = TeamsConnectionKind.Key,
    };

    public async Task<List<ChannelDto>> ChannelsAsync(CancellationToken ct)
    {
        List<ChannelDto> found = [];
        await using INotifyChannelsLease lease = await channels.LeaseAsync(ct);
        foreach (NotifyChannelEntry entry in lease.Items)
        {
            found.Add(new ChannelDto(entry.Key, (entry.Channel as IPersonalNotifyChannel)?.Name, entry.Channel.Kinds, entry.Channel is IPersonalNotifyChannel,
                await entry.Channel.ReadyAsync(ct)));
        }

        return found;
    }

    /// <summary>The site's targets (no scope), or a scope's own and the site's.</summary>
    public async Task<List<ChannelTargetView>> ListAsync(Guid? scopeId, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        List<ChannelTarget> targets = await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().ChannelTargets.AsNoTracking()
            .Where(t => t.ScopeId == null || t.ScopeId == scopeId).OrderBy(t => t.Name).ToListAsync(ct);
        List<Guid> ids = [.. targets.Select(t => t.ConnectionId).Distinct()];
        Dictionary<Guid, string> names = await scope.ServiceProvider.GetRequiredService<IConnectionsDbContext>().Connections.AsNoTracking()
            .Where(c => ids.Contains(c.Id)).ToDictionaryAsync(c => c.Id, c => c.Name, ct);
        return [.. targets.Select(t => new ChannelTargetView(t.Id, t.ScopeId, t.Name, t.Channel, t.ConnectionId, names.GetValueOrDefault(t.ConnectionId) ?? "", t.Where))];
    }

    /// <summary>The Slack and Teams connections a scope's team channels may go through: the site's, and the scope's own.</summary>
    public async Task<List<ChannelConnectionDto>> ConnectionsAsync(Guid? scopeId, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        List<string> types = [.. ChannelOf.Keys];
        return await scope.ServiceProvider.GetRequiredService<IConnectionsDbContext>().Connections.AsNoTracking()
            .Where(c => types.Contains(c.Type) && (c.ScopeId == null || c.ScopeId == scopeId)).OrderBy(c => c.Name)
            .Select(c => new ChannelConnectionDto(c.Id, c.Name, c.Type, c.ScopeId == null)).ToListAsync(ct);
    }

    /// <summary>A target at site scope (no scope) or a scope's: through a Slack or Teams connection of that scope or the site's.</summary>
    public async Task<ChannelTargetView> CreateAsync(Guid? scopeId, ChannelTargetInput input, Guid actorId, CancellationToken ct)
    {
        string name = (input.Name ?? "").Trim();
        if (name.Length is 0 or > 100)
        {
            throw new UserFriendlyException("A channel's name is 1 to 100 characters.");
        }

        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        Connection connection = await scope.ServiceProvider.GetRequiredService<IConnectionsDbContext>().Connections.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == input.ConnectionId, ct) ?? throw new UserFriendlyException("There's no such connection.");
        if (!ChannelOf.TryGetValue(connection.Type, out string? channel))
        {
            throw new UserFriendlyException($"{connection.Name} isn't a Slack or Teams connection.");
        }

        if (connection.ScopeId is { } owner && owner != scopeId)
        {
            throw new UserFriendlyException($"{connection.Name} belongs to another project.");
        }

        string where = (input.Where ?? "").Trim();
        if (channel == SlackConnectionKind.Key && where.Length is 0 or > 100)
        {
            throw new UserFriendlyException("Name the Slack channel to post to (its id, or #name).");
        }

        INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
        ChannelTarget target = new(Guid.NewGuid(), scopeId, name, channel, connection.Id, channel == SlackConnectionKind.Key ? where.TrimStart('#') : "", actorId);
        db.ChannelTargets.Add(target);
        await db.SaveChangesAsync(ct);
        return new ChannelTargetView(target.Id, target.ScopeId, target.Name, target.Channel, target.ConnectionId, connection.Name, target.Where);
    }

    /// <summary>Removes a target of this scope (the site's, or the scope's own).</summary>
    public async Task DeleteAsync(Guid? scopeId, Guid id, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        if (await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().ChannelTargets.Where(t => t.Id == id && t.ScopeId == scopeId).ExecuteDeleteAsync(ct) == 0)
        {
            throw new EntityNotFoundException(typeof(ChannelTarget), id);
        }
    }

    /// <summary>
    /// Posts a message to a team's channel once for an event: the post is claimed first, so an event heard twice posts
    /// once. False when it was posted already, or the target is gone.
    /// </summary>
    public async Task<bool> PostOnceAsync(Guid eventId, Guid targetId, string template, IReadOnlyDictionary<string, object?> model, Guid? scopeId, Guid? subjectId,
        string? subjectKey, string source, CancellationToken ct)
    {
        ChannelTarget? target;
        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
            target = await db.ChannelTargets.AsNoTracking().FirstOrDefaultAsync(t => t.Id == targetId, ct);
            DateTime now = DateTime.UtcNow;
            NotifyTable posts = NotifyTable.Of<ChannelPost>(db);
            if (target is null || await db.Database.ExecuteSqlRawAsync($$"""
                    INSERT INTO {{posts.Name}} ({{posts.Columns(nameof(ChannelPost.EventId), nameof(ChannelPost.TargetId), nameof(ChannelPost.PostedAt))}})
                    VALUES ({0}, {1}, {2})
                    ON CONFLICT ({{posts.Columns(nameof(ChannelPost.EventId), nameof(ChannelPost.TargetId))}}) DO NOTHING
                    """, [eventId, targetId, now], ct) != 1)
            {
                return false;
            }
        }

        await services.GetRequiredService<INotifyMessenger>().SendAsync(new NotifyMessage(template, [NotifyRecipient.Address(ChatAddress.Of(target.ConnectionId, target.Where), target.Name)],
            model, target.Channel, scopeId, subjectId, subjectKey, Source: source, Later: true), ct);
        return true;
    }

    /// <summary>What uses a connection, so it isn't removed under them: the team channels that post through it.</summary>
    public async Task<IReadOnlyList<string>> UsesAsync(Guid connectionId, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        List<string> names = await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().ChannelTargets.AsNoTracking()
            .Where(t => t.ConnectionId == connectionId).Select(t => t.Name).ToListAsync(ct);
        return [.. names.Select(n => $"the team channel {n}")];
    }
}
