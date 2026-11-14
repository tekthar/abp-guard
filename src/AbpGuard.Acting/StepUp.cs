using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Volo.Abp;
using AbpGuard;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Acting;

/// <summary>How recently a person must have proved who they are to do something sensitive. Guard keeps it.</summary>
public interface IStepUpPolicy
{
    Task<TimeSpan> WindowAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// A step-up's levels: <c>password</c> (the password again, with a code of the person's second factor when they have one)
/// and <c>strong</c> (a passkey alone, or the password and an authenticator app's code).
/// </summary>
public static class StepUpLevels
{
    public const string Password = "password";
    public const string Strong = "strong";
}

/// <summary>
/// The categories Guard's own step-up marks name, and the ones strong by default. A host names its own marks' categories
/// and lists the strong ones in the same setting (<c>Guard:StepUp:Strong</c>).
/// </summary>
public static class StepUpCategories
{
    /// <summary>Installing and trusting plugins (a host's).</summary>
    public const string Plugins = "plugins";

    /// <summary>Roles, grants and groups: who may do what. A merge moves grants, so it's here too.</summary>
    public const string Roles = "roles";

    /// <summary>The security settings, the retention periods, the security feed, sign-up, second-factor methods and an admin's reset of someone's factors.</summary>
    public const string Security = "security";

    /// <summary>Directories and their connectors' secrets.</summary>
    public const string Directories = "directories";

    /// <summary>OAuth apps.</summary>
    public const string Apps = "apps";

    /// <summary>Service accounts and their keys.</summary>
    public const string ServiceAccounts = "service-accounts";

    /// <summary>A personal access token made by a site admin: a lasting key past every later step-up.</summary>
    public const string AdminTokens = "admin-tokens";

    /// <summary>A full export of everyone's data, and exports of AI calls (a host's).</summary>
    public const string Exports = "exports";

    /// <summary>Backups' downloads and restores (a host's).</summary>
    public const string Backups = "backups";

    /// <summary>Rule scripts and automation scripts (a host's).</summary>
    public const string Scripts = "scripts";

    /// <summary>Connections' and webhooks' secrets (a host's).</summary>
    public const string Secrets = "secrets";

    /// <summary>A second site's takeover (a host's).</summary>
    public const string Sites = "sites";

    /// <summary>Accounts an admin makes, locks and corrects (password level by default).</summary>
    public const string Accounts = "accounts";

    /// <summary>A person's own second factors (password level by default; see <see cref="StepUpGuard.EnsureAtAsync"/>).</summary>
    public const string Factors = "factors";

    /// <summary>A person's own personal access tokens (password level by default).</summary>
    public const string Tokens = "tokens";

    /// <summary>Privacy requests and their handling: exports of a person's data, erasures, consent, the record of processing (password level by default).</summary>
    public const string Privacy = "privacy";

    /// <summary>A person's own name and addresses (password level by default).</summary>
    public const string Profile = "profile";

    /// <summary>The categories strong unless the server's operator says otherwise (<c>Guard:StepUp:Strong</c>).</summary>
    public static readonly IReadOnlyList<string> DefaultStrong =
        [Plugins, Roles, Security, Directories, Apps, ServiceAccounts, AdminTokens, Exports, Backups, Scripts, Secrets, Sites];
}

/// <summary>
/// The categories a site asks a strong step-up for, as <c>Guard:StepUp:Strong</c> says: a comma-separated list, <c>*</c>
/// for every category (a mark that names none too), or <c>none</c> for no category (every step-up at the password level,
/// as before 0.7.0). Unset or empty, <see cref="StepUpCategories.DefaultStrong"/>.
/// </summary>
public sealed record StepUpStrongCategories(bool All, IReadOnlySet<string> Categories)
{
    public static StepUpStrongCategories Default { get; } = new(false, new HashSet<string>(StepUpCategories.DefaultStrong, StringComparer.OrdinalIgnoreCase));

    public static StepUpStrongCategories Parse(string? setting) => Parse(setting is null ? [] : [setting]);

    /// <summary>The setting's values: one comma-separated value, or each of a list's entries (which may hold commas too).</summary>
    public static StepUpStrongCategories Parse(IEnumerable<string?> values)
    {
        List<string> named = [.. values.SelectMany(v => (v ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))];
        if (named.Count == 0)
        {
            return Default;
        }

        if (named.Contains("*", StringComparer.Ordinal))
        {
            return new(true, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        }

        return new(false, new HashSet<string>(named.Where(n => !n.Equals("none", StringComparison.OrdinalIgnoreCase)), StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>Whether a mark of the category asks for a strong step-up; one that names none is strong only under <c>*</c>.</summary>
    public bool Includes(string? category) => All || (category is { Length: > 0 } && Categories.Contains(category));

    /// <summary>The setting as security settings show it: <c>["*"]</c>, or the categories in order.</summary>
    public List<string> Shown() => All ? ["*"] : [.. Categories.Order(StringComparer.Ordinal)];
}

/// <summary>The ways a person may step up, best first (<c>passkey</c>, <c>app</c>, <c>password</c>, <c>email</c>…), and whether any is strong.</summary>
public sealed record StepUpMethods(IReadOnlyList<string> Methods, bool HasStrong);

/// <summary>What a step-up asks of a person: which categories are strong, and the ways the person has. Guard keeps it.</summary>
public interface IStepUpLevels
{
    /// <summary>Whether a mark of the category asks for a strong step-up (a mark that names none: <c>null</c>).</summary>
    bool IsStrong(string? category);

    /// <summary>The person's ways to step up at the level (<see cref="StepUpLevels"/>), best first.</summary>
    Task<StepUpMethods> MethodsAsync(Guid accountId, string level, CancellationToken cancellationToken = default);
}

/// <summary>Without Guard's levels, every step-up is at the password level, as before 0.7.0.</summary>
[Dependency(TryRegister = true)]
[ExposeServices(typeof(IStepUpLevels))]
public sealed class PasswordStepUpLevels : IStepUpLevels, ITransientDependency
{
    public bool IsStrong(string? category) => false;

    public Task<StepUpMethods> MethodsAsync(Guid accountId, string level, CancellationToken cancellationToken = default) =>
        Task.FromResult(new StepUpMethods([StepUpLevels.Password], false));
}

/// <summary>
/// A token never steps up, so a step-up mark refuses it; a host may let a personal access token through a category it
/// names, for automation (a publisher's CI uploading versions with a token scoped to that). By default none passes.
/// </summary>
public interface IStepUpTokenPolicy
{
    /// <summary>Whether the request's token may do what a mark of the category guards (<c>null</c>: a mark that names none).</summary>
    Task<bool> AllowsAsync(string? category, ActingContext acting, CancellationToken cancellationToken = default);
}

/// <summary>Guard's default: no token passes a step-up mark.</summary>
[Dependency(TryRegister = true)]
[ExposeServices(typeof(IStepUpTokenPolicy))]
public sealed class NoStepUpTokens : IStepUpTokenPolicy, ITransientDependency
{
    public Task<bool> AllowsAsync(string? category, ActingContext acting, CancellationToken cancellationToken = default) => Task.FromResult(false);
}

/// <summary>
/// Step-up: before a sensitive action the person proves again, recently, that they are who the session says. Each mark
/// names a category (<see cref="StepUpCategories"/>), whose level is the operator's (<see cref="IStepUpLevels"/>): a
/// <c>password</c> one passes on the token's <c>auth_time</c> within the window, a <c>strong</c> one on its
/// <c>strong_auth_time</c>. Refuses with 403 <c>step_up_required</c> (data: <c>level</c>, <c>category</c>, <c>methods</c>,
/// <c>maxAgeSeconds</c>), or 403 <c>strong_factor_required</c> (<c>category</c>) when a strong one is asked of someone with
/// no strong factor yet. Marking an action is <see cref="StepUpAttribute"/>, or <see cref="EnsureAsync(string, CancellationToken)"/>
/// when only some inputs make it sensitive (replacing a stored password).
/// </summary>
public class StepUpGuard(ActingContext acting, IStepUpPolicy policy, IStepUpLevels? levels = null, IStepUpTokenPolicy? tokens = null) : ITransientDependency
{
    private readonly IStepUpLevels _levels = levels ?? new PasswordStepUpLevels();
    private readonly IStepUpTokenPolicy _tokens = tokens ?? new NoStepUpTokens();

    /// <summary>A mark that names no category: the password level (strong only when the operator makes every category strong).</summary>
    public Task EnsureAsync(CancellationToken cancellationToken = default) => CheckAsync(null, null, false, cancellationToken);

    /// <summary>A mark of the category, at the level the operator gives it.</summary>
    public Task EnsureAsync(string category, CancellationToken cancellationToken = default) => CheckAsync(category, null, false, cancellationToken);

    /// <summary>
    /// A mark of the category at a level the caller decides, not the setting: Guard's rules for a person's own second
    /// factors (a strong step-up to add one once they have a strong factor, where a sign-in with a recovery code counts
    /// too, so someone who lost their device can set up a new one).
    /// </summary>
    public Task EnsureAtAsync(string category, string level, bool recoverySignInCounts = false, CancellationToken cancellationToken = default) =>
        CheckAsync(category, level, recoverySignInCounts, cancellationToken);

    private async Task CheckAsync(string? category, string? level, bool recoverySignInCounts, CancellationToken cancellationToken)
    {
        // A personal access token can't step up: a stolen one must never change who may do what. A host may let one through
        // a category it names.
        if (acting.TokenId is not null)
        {
            if (await _tokens.AllowsAsync(category, acting, cancellationToken))
            {
                return;
            }

            throw new UserFriendlyException("A personal access token can't do this: it changes who may do what or reveals a secret. Sign in to do it.",
                GuardErrorCodes.Forbidden);
        }

        TimeSpan window = await policy.WindowAsync(cancellationToken);
        bool strong = (level ?? (_levels.IsStrong(category) ? StepUpLevels.Strong : StepUpLevels.Password)) == StepUpLevels.Strong;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        bool Recent(DateTimeOffset? proved) => proved is { } at && now - at <= window;
        if (strong ? Recent(acting.StrongAuthTime) || (recoverySignInCounts && Recent(acting.RecoveryAuthTime)) : Recent(acting.AuthTime))
        {
            return;
        }

        StepUpMethods methods = acting.SubjectId is { } subject
            ? await _levels.MethodsAsync(subject, strong ? StepUpLevels.Strong : StepUpLevels.Password, cancellationToken)
            : new StepUpMethods([StepUpLevels.Password], false);
        if (strong && !methods.HasStrong)
        {
            throw new UserFriendlyException("This needs a passkey or an authenticator app: set one up first.", GuardErrorCodes.StrongFactorRequired)
                .WithData("category", category!);
        }

        throw new UserFriendlyException(strong ? "Confirm it's you with your passkey, or your password and authenticator app." : "Confirm your password to do this.",
                GuardErrorCodes.StepUpRequired)
            .WithData("level", strong ? StepUpLevels.Strong : StepUpLevels.Password)
            .WithData("category", category!)
            .WithData("methods", methods.Methods.ToArray())
            .WithData("maxAgeSeconds", (int)window.TotalSeconds);
    }
}

/// <summary>
/// Marks a sensitive action: it needs a sign-in or a step-up within the site's window, at the level of its category
/// (<see cref="StepUpCategories"/>; <c>Guard:StepUp:Strong</c> says which are strong). A mark that names none is at the
/// password level.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class StepUpAttribute : TypeFilterAttribute
{
    public StepUpAttribute() : this("")
    {
    }

    public StepUpAttribute(string category) : base(typeof(StepUpFilter))
    {
        Category = category is { Length: > 0 } ? category : null;
        Arguments = [category ?? ""];
    }

    /// <summary>The mark's category; null when it names none.</summary>
    public string? Category { get; }
}

public sealed class StepUpFilter(StepUpGuard guard, string category) : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        await (category is { Length: > 0 } ? guard.EnsureAsync(category, context.HttpContext.RequestAborted) : guard.EnsureAsync(context.HttpContext.RequestAborted));
        await next();
    }
}
