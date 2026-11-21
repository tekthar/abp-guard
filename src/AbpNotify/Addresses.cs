using System.Security.Cryptography;
using System.Text;
using AbpGuard;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace AbpNotify;

/// <summary>A channel that reaches people one by one, as its person sees it: whether it's set up, and their address on it.</summary>
public sealed record MyChannelDto(string Channel, string Name, bool PeopleTypeAddress, string? AddressHint, bool Ready, string? Address, bool Verified, bool Pending);

public sealed record ChannelAddressInput(string Address);

public sealed record ChannelCodeInput(string Code);

/// <summary>
/// People's addresses on channels: verified ones for channels to use; a typed one waits for the code the channel sent
/// to it. A code is six digits, good for ten minutes and five tries.
/// </summary>
[ExposeServices(typeof(INotifyAddresses), typeof(INotifyReach), typeof(ChannelAddressBook))]
public sealed class ChannelAddressBook(IServiceScopeFactory scopes, IServiceProvider services, INotifyChannels channels, IOptions<NotifyOptions> options)
    : INotifyAddresses, INotifyReach, ITransientDependency
{
    public const string CodeTemplate = "channel.code";
    private static readonly TimeSpan CodeLife = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ResendWait = TimeSpan.FromMinutes(1);
    private const int MaxPendingPerAddress = 3;
    private const int MaxTries = 5;

    public async Task<string?> AddressAsync(Guid accountId, string channel, CancellationToken cancellationToken = default)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().ChannelAddresses.AsNoTracking()
            .Where(a => a.AccountId == accountId && a.Channel == channel && a.VerifiedAt != null).Select(a => a.Address).FirstOrDefaultAsync(cancellationToken);
    }

    public async Task RememberAsync(Guid accountId, string channel, string address, CancellationToken cancellationToken = default)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        DateTime now = DateTime.UtcNow;
        INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
        NotifyTable t = NotifyTable.Of<ChannelAddress>(db);
        (string addressColumn, string verified, string updated) = (t[nameof(ChannelAddress.Address)], t[nameof(ChannelAddress.VerifiedAt)], t[nameof(ChannelAddress.UpdatedAt)]);
        await db.Database.ExecuteSqlRawAsync($$"""
            INSERT INTO {{t.Name}} ({{t.Columns(nameof(ChannelAddress.AccountId), nameof(ChannelAddress.Channel), nameof(ChannelAddress.Address),
                nameof(ChannelAddress.VerifiedAt), nameof(ChannelAddress.CodeTries), nameof(ChannelAddress.UpdatedAt))}})
            VALUES ({0}, {1}, {2}, {3}, 0, {4})
            ON CONFLICT ({{t.Columns(nameof(ChannelAddress.AccountId), nameof(ChannelAddress.Channel))}}) DO UPDATE SET {{addressColumn}} = EXCLUDED.{{addressColumn}},
                {{verified}} = EXCLUDED.{{verified}}, {{t[nameof(ChannelAddress.CodeHash)]}} = NULL, {{t[nameof(ChannelAddress.CodeExpiresAt)]}} = NULL,
                {{t[nameof(ChannelAddress.CodeTries)]}} = 0, {{updated}} = EXCLUDED.{{updated}}
            """, [accountId, channel, address, now, now], cancellationToken);
    }

    /// <summary>Whether the person has a verified address on a channel that reaches people one by one and is set up.</summary>
    public async Task<bool> ReachesAsync(Guid accountId, string channel, CancellationToken cancellationToken) =>
        (await MineAsync(accountId, cancellationToken)).Any(x => x.Channel == channel && x.Ready && x.Verified);

    /// <summary>The channels that reach people one by one, and the person's address on each.</summary>
    public async Task<List<MyChannelDto>> MineAsync(Guid me, CancellationToken cancellationToken)
    {
        Dictionary<string, ChannelAddress> mine;
        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            mine = await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().ChannelAddresses.AsNoTracking().Where(a => a.AccountId == me)
                .ToDictionaryAsync(a => a.Channel, cancellationToken);
        }

        List<MyChannelDto> found = [];
        await using INotifyChannelsLease lease = await channels.LeaseAsync(cancellationToken);
        foreach (NotifyChannelEntry entry in lease.Items)
        {
            if (entry.Channel is not IPersonalNotifyChannel personal)
            {
                continue;
            }

            ChannelAddress? address = mine.GetValueOrDefault(entry.Key);
            found.Add(new MyChannelDto(entry.Key, personal.Name, personal.PeopleTypeAddress, personal.AddressHint, await entry.Channel.ReadyAsync(cancellationToken),
                address?.Address, address?.VerifiedAt is not null, address is { VerifiedAt: null, CodeHash: not null }));
        }

        return found;
    }

    /// <summary>Sends a code to a typed address; it's used once the code comes back.</summary>
    public async Task<List<MyChannelDto>> StartAsync(Guid me, string channelKey, string typed, CancellationToken cancellationToken)
    {
        string address;
        await using (INotifyChannelsLease lease = await channels.LeaseAsync(cancellationToken))
        {
            INotifyChannel channel = lease.Items.Where(i => i.Key == channelKey).Select(i => i.Channel).FirstOrDefault()
                ?? throw new UserFriendlyException($"There's no channel \"{channelKey}\".");
            if (channel is not IPersonalNotifyChannel { PeopleTypeAddress: true } personal)
            {
                throw new UserFriendlyException($"Addresses on {channelKey} aren't typed; it finds yours.");
            }

            if (!await channel.ReadyAsync(cancellationToken))
            {
                throw new UserFriendlyException($"{personal.Name} isn't set up on this site yet.");
            }

            address = personal.Normalize(typed ?? "") ?? throw new UserFriendlyException($"\"{typed}\" isn't an address {personal.Name} can reach ({personal.AddressHint}).");
        }

        string code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        DateTime now = DateTime.UtcNow;
        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
            ChannelAddress? row = await db.ChannelAddresses.FirstOrDefaultAsync(a => a.AccountId == me && a.Channel == channelKey, cancellationToken);
            // A code costs a message and reaches someone's phone: one a minute for a person, a few people at once for a
            // number, and asking again for the same address keeps the tries the last code used.
            if (row is { CodeHash: not null } && row.UpdatedAt > now - ResendWait)
            {
                throw new UserFriendlyException("A code was sent a moment ago; wait a minute before asking for another.", GuardErrorCodes.TooManyRequests);
            }

            int others = await db.ChannelAddresses.CountAsync(a => a.Channel == channelKey && a.Address == address && a.AccountId != me
                && a.CodeHash != null && a.UpdatedAt > now.AddHours(-1), cancellationToken);
            if (others >= MaxPendingPerAddress)
            {
                throw new UserFriendlyException($"Codes were sent to {address} for others lately; try again in an hour.", GuardErrorCodes.TooManyRequests);
            }

            int tries = row is { CodeHash: not null } && row.Address == address && row.CodeExpiresAt > now ? row.CodeTries : 0;
            if (row is null)
            {
                db.ChannelAddresses.Add(row = new ChannelAddress { AccountId = me, Channel = channelKey });
            }

            (row.Address, row.VerifiedAt, row.CodeHash, row.CodeExpiresAt, row.CodeTries, row.UpdatedAt) = (address, null, Hash(me, code), now + CodeLife, tries, now);
            await db.SaveChangesAsync(cancellationToken);
        }

        NotifySent sent = await services.GetRequiredService<INotifyMessenger>().SendAsync(new NotifyMessage(CodeTemplate, [NotifyRecipient.Address(address)],
            new Dictionary<string, object?> { ["code"] = code }, channelKey, Source: "channel-code") { Secret = true }, cancellationToken);
        if (sent.Sent == 0)
        {
            throw new UserFriendlyException($"The code couldn't be sent to {address}; check it and try again.");
        }

        return await MineAsync(me, cancellationToken);
    }

    /// <summary>Looks the person up on a channel that finds addresses itself (Slack, by their email), and keeps what it finds.</summary>
    public async Task<List<MyChannelDto>> FindAsync(Guid me, string channelKey, CancellationToken cancellationToken)
    {
        await using (INotifyChannelsLease lease = await channels.LeaseAsync(cancellationToken))
        {
            INotifyChannel channel = lease.Items.Where(i => i.Key == channelKey).Select(i => i.Channel).FirstOrDefault()
                ?? throw new UserFriendlyException($"There's no channel \"{channelKey}\".");
            if (channel is not IPersonalNotifyChannel { PeopleTypeAddress: false } personal)
            {
                throw new UserFriendlyException($"Type your address on {channelKey}; it doesn't find people.");
            }

            NotifyPerson person = await services.GetRequiredService<INotifyPeople>().PeopleAsync([me], cancellationToken) is [var found, ..]
                ? found
                : throw new UserFriendlyException("Your account isn't active.");
            if (await channel.AddressAsync(person, cancellationToken) is null)
            {
                throw new UserFriendlyException(channelKey == PushChannel.ChannelKey
                    ? $"No phone of yours is registered: sign in to the {options.Value.ApplicationName} app on your phone, and it registers itself."
                    : $"{personal.Name} doesn't know you by {person.Email ?? "your email"}.");
            }
        }

        return await MineAsync(me, cancellationToken);
    }

    /// <summary>Verifies a typed address with the code sent to it.</summary>
    public async Task<List<MyChannelDto>> VerifyAsync(Guid me, string channelKey, string code, CancellationToken cancellationToken)
    {
        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
            ChannelAddress row = await db.ChannelAddresses.FirstOrDefaultAsync(a => a.AccountId == me && a.Channel == channelKey && a.CodeHash != null, cancellationToken)
                ?? throw new UserFriendlyException("No code is waiting for this channel; ask for one first.");
            if (row.CodeExpiresAt < DateTime.UtcNow || row.CodeTries >= MaxTries)
            {
                throw new UserFriendlyException("That code has run out; ask for a new one.");
            }

            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(row.CodeHash!), Encoding.ASCII.GetBytes(Hash(me, (code ?? "").Trim()))))
            {
                row.CodeTries++;
                await db.SaveChangesAsync(cancellationToken);
                throw new UserFriendlyException("That isn't the code we sent.");
            }

            (row.VerifiedAt, row.CodeHash, row.CodeExpiresAt, row.CodeTries, row.UpdatedAt) = (DateTime.UtcNow, null, null, 0, DateTime.UtcNow);
            await db.SaveChangesAsync(cancellationToken);
        }

        return await MineAsync(me, cancellationToken);
    }

    public async Task<List<MyChannelDto>> RemoveAsync(Guid me, string channelKey, CancellationToken cancellationToken)
    {
        if (channelKey == PushChannel.ChannelKey)
        {
            // The push channel's address is the person's phones: removing it forgets them.
            await services.GetRequiredService<DeviceBook>().UnregisterAllAsync(me, cancellationToken);
            return await MineAsync(me, cancellationToken);
        }

        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().ChannelAddresses.Where(a => a.AccountId == me && a.Channel == channelKey)
                .ExecuteDeleteAsync(cancellationToken);
        }

        return await MineAsync(me, cancellationToken);
    }

    private static string Hash(Guid account, string code) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{account:N}:{code}")));
}
