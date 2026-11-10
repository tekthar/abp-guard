namespace AbpGuard;

/// <summary>
/// A way that reaches a person: <c>email</c> to the address their mail goes to, or a channel (sms, whatsapp…)
/// to their verified address on it. <paramref name="Name"/> is the channel's name as people see it.
/// </summary>
public sealed record GuardChannel(string Method, string Name, string Address);

/// <summary>A way the site can send people a code: <c>email</c> or a channel, its name, and whether it's set up to send now.</summary>
public sealed record GuardMethod(string Method, string Name, bool Ready);

/// <summary>
/// A message Guard sends: one of its kinds (<see cref="GuardMessageKinds"/>) to an account (by its id) or an
/// address, with the values its template uses. <paramref name="Channel"/> is null for email. A secret one is delivered
/// once as rendered, its text and subject kept nowhere, and never retried; every kind that carries a link or a code
/// (<see cref="GuardMessageKinds.CarriesSecret"/>) is one, whatever the sender says, so no host can forget it.
/// </summary>
public sealed record GuardMessage(
    string Kind,
    Guid? AccountId,
    string? Address,
    string? Name,
    IReadOnlyDictionary<string, object?> Model,
    string? Language,
    string Source,
    string? Channel = null,
    bool Secret = false)
{
    public bool Secret { get; init; } = Secret || GuardMessageKinds.CarriesSecret(Kind);
}

/// <summary>How a message went: how many were sent, and how many recipients nothing reached.</summary>
public sealed record GuardSendResult(int Sent, int Unreachable);

/// <summary>
/// How Guard reaches people: the mails self-service sends, an added address's confirmation, and a second
/// step's code. The default writes each message, rendered from Guard's own texts, to a pickup folder (Development);
/// a host sends them its own way.
/// </summary>
public interface IGuardMessenger
{
    /// <summary>
    /// The ways that reach the person now, in no particular order: email when mail can go out and they have an address,
    /// and each channel where they have a verified address. Guard applies the site's allowed methods itself.
    /// </summary>
    Task<IReadOnlyList<GuardChannel>> ReachAsync(Guid accountId, string? emailAddress, CancellationToken cancellationToken);

    /// <summary>
    /// The ways the site has of sending a person a code, email first, then each channel that reaches people one by one
    /// and carries a short message: what an admin may allow for a second step (SecuritySettings.SecondFactorMethods).
    /// </summary>
    Task<IReadOnlyList<GuardMethod>> MethodsAsync(CancellationToken cancellationToken);

    Task<GuardSendResult> SendAsync(GuardMessage message, CancellationToken cancellationToken);
}
