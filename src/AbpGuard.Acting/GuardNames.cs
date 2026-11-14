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

    /// <summary>
    /// The header the security log's feed signs each batch in (<c>t={unix seconds},v1={hex HMAC-SHA256 of "t.body"}</c>):
    /// the name its receiver checks.
    /// </summary>
    public string FeedSignatureHeader { get; set; } = "X-Guard-Signature";

    /// <summary>
    /// Headers the feed signs each batch in as well, with the same value: the names a host used before it renamed
    /// <see cref="FeedSignatureHeader"/>, so a receiver set up under one of them keeps working while it moves.
    /// </summary>
    public List<string> FormerFeedSignatureHeaders { get; set; } = [];

    /// <summary>A Data Protection purpose under <see cref="ProtectionPrefix"/>.</summary>
    public string Purpose(string name) => $"{ProtectionPrefix}.{name}";

    /// <summary>
    /// The claim and scope names a site gave tokens before it renamed them, if it did: a token made under them is read as
    /// if made under today's (<see cref="Current"/>), so it keeps its limits until it expires, and a refresh issues today's.
    /// </summary>
    public FormerTokenNames? Former { get; set; }

    private static readonly System.Text.RegularExpressions.Regex LimitClaim = new("^[a-z0-9]+_(session|mode|token(_access|_project|_tool)?)$", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1));
    private static readonly HashSet<string> OtherTokenClaims = ["id_token", "access_token", "refresh_token"];

    /// <summary>
    /// A token's principal under today's names: claims carried under a <see cref="Former"/> name are renamed, and so are
    /// former scopes in claims of <paramref name="scopeClaimType"/>. Null when it carries a session, mode, token or limit
    /// claim under a name that is neither today's nor a former one: such a token is refused, never read as unlimited, and an
    /// impersonation never as the person it stands for.
    /// </summary>
    public System.Security.Claims.ClaimsPrincipal? Current(System.Security.Claims.ClaimsPrincipal principal, string scopeClaimType)
    {
        string[] today = [SessionClaim, ModeClaim, TokenClaim, TokenAccessClaim, TokenProjectClaim, TokenToolClaim];
        Dictionary<string, string> renamed = Former is null ? [] : new Dictionary<string, string?>
        {
            [Former.SessionClaim ?? ""] = SessionClaim,
            [Former.ModeClaim ?? ""] = ModeClaim,
            [Former.TokenClaim ?? ""] = TokenClaim,
            [Former.TokenAccessClaim ?? ""] = TokenAccessClaim,
            [Former.TokenProjectClaim ?? ""] = TokenProjectClaim,
            [Former.TokenToolClaim ?? ""] = TokenToolClaim,
        }.Where(p => p.Key.Length > 0 && p.Key != p.Value).ToDictionary(p => p.Key, p => p.Value!);
        IReadOnlyDictionary<string, string> scopes = Former?.Scopes ?? [];
        bool changed = false;
        System.Security.Claims.ClaimsPrincipal current = new();
        foreach (System.Security.Claims.ClaimsIdentity identity in principal.Identities)
        {
            System.Security.Claims.ClaimsIdentity copy = new(identity.AuthenticationType, identity.NameClaimType, identity.RoleClaimType);
            copy.Actor = identity.Actor;
            copy.Label = identity.Label;
            copy.BootstrapContext = identity.BootstrapContext;
            foreach (System.Security.Claims.Claim claim in identity.Claims)
            {
                string type = renamed.GetValueOrDefault(claim.Type, claim.Type);
                string value = claim.Type == scopeClaimType ? scopes.GetValueOrDefault(claim.Value, claim.Value) : claim.Value;
                if (LimitClaim.IsMatch(type) && !today.Contains(type) && !OtherTokenClaims.Contains(type))
                {
                    return null;
                }

                changed |= type != claim.Type || value != claim.Value;
                System.Security.Claims.Claim renamedClaim = new(type, value, claim.ValueType, claim.Issuer, claim.OriginalIssuer);
                foreach ((string key, string property) in claim.Properties)
                {
                    renamedClaim.Properties[key] = property;
                }

                copy.AddClaim(renamedClaim);
            }

            current.AddIdentity(copy);
        }

        return changed ? current : principal;
    }
}

/// <summary>The claim and scope names a site's tokens carried before a rename (<see cref="GuardNames.Former"/>).</summary>
public sealed class FormerTokenNames
{
    public string? SessionClaim { get; set; }
    public string? ModeClaim { get; set; }
    public string? TokenClaim { get; set; }
    public string? TokenAccessClaim { get; set; }
    public string? TokenProjectClaim { get; set; }
    public string? TokenToolClaim { get; set; }

    /// <summary>Each former scope and today's (<c>old.api</c> and <c>api</c>, say).</summary>
    public Dictionary<string, string> Scopes { get; set; } = [];
}
