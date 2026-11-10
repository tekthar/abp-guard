namespace AbpGuard;

/// <summary>
/// The names Guard writes into tokens, cookies, headers, stored rows and protected data, in one place, from
/// the configuration's "Guard:Names" section or a host's code. Each is an identifier something already holds: a browser's
/// session, a token in an app or a script, a refresh token in the database, a secret protected with a purpose. Changing
/// one on a running site breaks what holds the old one, so a site keeps the names it started with.
/// </summary>
public sealed class GuardNames
{
    public const string Section = "Guard:Names";

    /// <summary>The claim with the impersonation session a token belongs to.</summary>
    public string SessionClaim { get; set; } = "guard_session";

    /// <summary>The claim with the mode an actor acts in.</summary>
    public string ModeClaim { get; set; } = "guard_mode";

    /// <summary>The personal access token a request came with (its id), set only by the token's own sign-in.</summary>
    public string TokenClaim { get; set; } = "guard_token";

    /// <summary>A personal access token's (or an app's) access: <c>read</c> or <c>write</c>.</summary>
    public string TokenAccessClaim { get; set; } = "guard_token_access";

    /// <summary>A resource (a host's project, say) a personal access token is limited to; one claim each, none for all.</summary>
    public string TokenProjectClaim { get; set; } = "guard_token_project";

    /// <summary>A tool a personal access token is limited to; one claim each, none for every tool.</summary>
    public string TokenToolClaim { get; set; } = "guard_token_tool";

    /// <summary>The header a browser's page sends back with the anti-forgery value on every request that changes something.</summary>
    public string CsrfHeader { get; set; } = "X-Guard-Csrf";

    /// <summary>What the anti-forgery value is derived with, beside the session's secret.</summary>
    public string CsrfSalt { get; set; } = "guard-csrf:";

    /// <summary>How a new personal access token starts, and one the sign-in recognises.</summary>
    public string PersonalTokenPrefix { get; set; } = "guard_pat_";

    /// <summary>
    /// How tokens issued before under another prefix start: recognised for as long as they live, never issued. A site
    /// that changes <see cref="PersonalTokenPrefix"/> keeps the old one here (tokens live for months).
    /// </summary>
    public List<string> AcceptedTokenPrefixes { get; set; } = [];

    /// <summary>Whether a bearer token is a personal access token: it starts with the prefix new ones get, or an accepted one.</summary>
    public bool IsPersonalToken(string token) =>
        token.StartsWith(PersonalTokenPrefix, StringComparison.Ordinal)
        || AcceptedTokenPrefixes.Any(p => p.Length > 0 && token.StartsWith(p, StringComparison.Ordinal));

    /// <summary>How a new OAuth app's client id starts (only made with it: an app is found by its whole id).</summary>
    public string AppIdPrefix { get; set; } = "guard_app_";

    /// <summary>How a new OAuth app's client secret starts (only made with it: a secret is checked whole).</summary>
    public string AppSecretPrefix { get; set; } = "guard_cs_";

    /// <summary>The property an OAuth app keeps its kind in (made by an admin, or registered by an agent).</summary>
    public string AppKindProperty { get; set; } = "guard_kind";

    /// <summary>The property an app's authorization keeps the access a person allowed in.</summary>
    public string AppAccessProperty { get; set; } = "guard_access";

    /// <summary>The scope an app asks for to only read.</summary>
    public string ReadScope { get; set; } = "api.read";

    /// <summary>The grant type of the second step at the token endpoint.</summary>
    public string SecondFactorGrantType { get; set; } = "urn:abpguard:grant-type:second-factor";

    /// <summary>
    /// What the Data Protection purposes start with: the authenticator apps' secrets, directories' passwords and mailed
    /// links are protected with "{prefix}.SecondFactor.v1" and the like, and only read back with the same.
    /// </summary>
    public string ProtectionPrefix { get; set; } = "AbpGuard";

    /// <summary>What an imported directory's id is derived with, beside its source's name.</summary>
    public string ImportedDirectorySalt { get; set; } = "guard-imported-directory:";

    /// <summary>A Data Protection purpose under <see cref="ProtectionPrefix"/>.</summary>
    public string Purpose(string name) => $"{ProtectionPrefix}.{name}";
}
