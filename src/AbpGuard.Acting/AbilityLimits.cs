using Casl;

namespace AbpGuard.Acting;

/// <summary>
/// Narrows the request's own ability: a token's scopes, an impersonation's fixed denies. Applied by guard to
/// the request's subject only, so no path to that person's ability skips it. Any module may add one.
/// </summary>
public interface IAbilityLimit
{
    Ability Apply(Ability ability, ActingContext acting);
}
