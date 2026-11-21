namespace AbpNotify;

/// <summary>Who a message goes to: a person (an account), or an address on the message's channel.</summary>
public sealed record NotifyRecipient(string Kind, string Value, string? Name = null)
{
    public const string PersonKind = "person";
    public const string AddressKind = "address";

    public static NotifyRecipient Person(Guid accountId) => new(PersonKind, accountId.ToString());

    public static NotifyRecipient Address(string address, string? name = null) => new(AddressKind, address, name);
}

/// <summary>
/// A message for the application to render and send: a template and its model, to recipients on a channel (the mail
/// channel when null), with what it's about and what sent it for the application's log. Later leaves delivery to the
/// background; a secret (a code) is sent now and once, and its text isn't kept.
/// </summary>
public sealed record NotifyMessage(string Template, IReadOnlyList<NotifyRecipient> To, IReadOnlyDictionary<string, object?> Model, string? Channel = null,
    Guid? ScopeId = null, Guid? SubjectId = null, string? SubjectKey = null, string? Source = null, bool Later = false)
{
    public bool Secret { get; init; }
}

/// <summary>What a send did: sent now, waiting to be tried again, or failed; and how many people the channel couldn't reach.</summary>
public sealed record NotifySent(int Sent, int Retrying, int Failed, int Unreachable, IReadOnlyList<Guid> Messages);

/// <summary>
/// The application's messages: it renders a template for each recipient, keeps the message, delivers it and tries
/// again when delivery fails. Throws when the template or the channel doesn't exist.
/// </summary>
public interface INotifyMessenger
{
    Task<NotifySent> SendAsync(NotifyMessage message, CancellationToken cancellationToken);

    /// <summary>Whether the application has a template by this key.</summary>
    bool HasTemplate(string key);
}

/// <summary>A person as the notices see them: their name, email, language and time zone (null: the site's).</summary>
public sealed record NotifyPerson(Guid Id, string Name, string? Email, string? Language, string? TimeZone);
