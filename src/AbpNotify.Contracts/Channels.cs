namespace AbpNotify;

// The channel contract, one for whoever adds a channel, in the application or a plugin: a channel finds a person's
// address and delivers a message the application rendered. It needs nothing but .NET, so a plugin takes only this.

/// <summary>What a template is for: a mail (with a subject), or a short message for a chat channel or a phone.</summary>
public static class NotifyTemplateKinds
{
    public const string Email = "email";
    public const string Message = "message";
}

/// <summary>
/// One rendered message for one recipient, ready for a channel: its log id, where it goes, what it says, a Message-ID
/// that replies can refer to, where answers go, and the thread it's part of.
/// </summary>
public sealed record NotifyDelivery(Guid Id, string Address, string? Name, string? Subject, string Markdown, string Text, string Html, string Language,
    string MessageId, string? ReplyTo = null, string? Thread = null);

/// <summary>
/// A way to reach people: it says whether it can deliver now, finds a person's address (null when it can't reach
/// them), and delivers a rendered message, throwing when it can't so the message is tried again.
/// </summary>
public interface INotifyChannel
{
    /// <summary>A short key: <c>email</c> for mail; a plugin's is <c>{plugin}:{key}</c> where the application offers it.</summary>
    string Key { get; }

    /// <summary>The template kinds it carries (<see cref="NotifyTemplateKinds"/>).</summary>
    IReadOnlyList<string> Kinds { get; }

    Task<bool> ReadyAsync(CancellationToken cancellationToken);

    /// <summary>Whether an address is one this channel can deliver to.</summary>
    bool IsAddress(string address);

    Task<string?> AddressAsync(NotifyPerson person, CancellationToken cancellationToken);

    Task DeliverAsync(NotifyDelivery delivery, CancellationToken cancellationToken);
}

/// <summary>
/// A channel that reaches people one by one, as opposed to one that posts to a team's channel. People find it among
/// their own channels: one whose addresses they type (a phone number) is verified with a code it sends first.
/// </summary>
public interface IPersonalNotifyChannel
{
    /// <summary>Its name for people ("SMS", "Slack").</summary>
    string Name { get; }

    /// <summary>Whether people type their address (and verify it); else the channel finds it (Slack, by their email).</summary>
    bool PeopleTypeAddress { get; }

    /// <summary>What an address looks like, for the field people type it in ("+966500000000").</summary>
    string? AddressHint { get; }

    /// <summary>The address as the channel keeps it ("+966 50 000 0000" → "+966500000000"); null when it isn't one.</summary>
    string? Normalize(string address);
}

/// <summary>
/// People's verified addresses on channels other than mail. A channel that finds an address itself (Slack, by email)
/// remembers it here so it doesn't look again.
/// </summary>
public interface INotifyAddresses
{
    /// <summary>The person's verified address on a channel; null when they have none.</summary>
    Task<string?> AddressAsync(Guid accountId, string channel, CancellationToken cancellationToken = default);

    /// <summary>Keeps an address a channel found for a person, as verified.</summary>
    Task RememberAsync(Guid accountId, string channel, string address, CancellationToken cancellationToken = default);
}

/// <summary>A channel as the application offers it: its key, and who added it when a plugin did.</summary>
public sealed record NotifyChannelEntry(string Key, INotifyChannel Channel, string? Owner);

/// <summary>The channels offered now, held while they're used (a plugin's can't unload under it).</summary>
public interface INotifyChannelsLease : IAsyncDisposable
{
    IReadOnlyList<NotifyChannelEntry> Items { get; }
}

/// <summary>Where the channels come from: the application's own (mail among them), and what its plugins add.</summary>
public interface INotifyChannels
{
    Task<INotifyChannelsLease> LeaseAsync(CancellationToken cancellationToken);
}
