namespace AbpGuard;

/// <summary>
/// What shows a sign-up comes from a person: the answer the visitor sent with the form, checked here. The
/// default asks nothing and lets every sign-up through (the self-service limits still apply); a host may ask its own
///.
/// </summary>
public interface ISignUpChallenges
{
    /// <summary>Whether the answer is right; the address is the visitor's, for providers that check it.</summary>
    Task<bool> VerifyAsync(string? answer, string? address, CancellationToken cancellationToken);
}

/// <summary>The default: no challenge.</summary>
public sealed class NoSignUpChallenges : ISignUpChallenges
{
    public Task<bool> VerifyAsync(string? answer, string? address, CancellationToken cancellationToken) => Task.FromResult(true);
}
