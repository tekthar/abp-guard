namespace AbpGuard;

/// <summary>
/// Guard's settings, from the configuration's "Guard" section; the keys Guard already read (Guard:Oidc:*,
/// Guard:TwoFactor:*, Guard:SignIn:*, Guard:Seed:*) keep working as they are. A host may fill what it knows in code.
/// </summary>
public sealed class GuardOptions
{
    public const string Section = "Guard";

    /// <summary>
    /// The site's address as people reach it (https://example.com): the links in mail, the authenticator app's issuer, the
    /// origin a browser's sign-in must come from.
    /// </summary>
    public string? PublicUrl { get; set; }

    /// <summary>
    /// The name the site's admins group is made with, once, at the first start (its id is fixed, GuardConstants.AdminsGroupId,
    /// and admin rights follow the id, never the name).
    /// </summary>
    public string AdminsGroupName { get; set; } = "admins";

    /// <summary>
    /// The scope of the host's own API in the tokens Guard issues (api by default): what the web's and the
    /// phone's tokens carry and apps are granted. A host's clients and its MCP metadata name the same.
    /// </summary>
    public string ApiScope { get; set; } = Controllers.GuardOidc.ApiScope;

    /// <summary>The browser's cookies Guard sets and reads.</summary>
    public GuardCookieOptions Cookies { get; set; } = new();

    /// <summary>The host's pages Guard links to or sends people to.</summary>
    public GuardPageOptions Pages { get; set; } = new();

    /// <summary>The host's own OpenID Connect clients, as Guard treats them apart.</summary>
    public GuardClientOptions Clients { get; set; } = new();

    /// <summary>What the host uses of Guard; each off removes that feature's endpoints (all on by default).</summary>
    public GuardFeatures Features { get; set; } = new();

    /// <summary>The site's defaults when a host doesn't say (<see cref="IGuardSiteDefaults"/>).</summary>
    public GuardSiteOptions Site { get; set; } = new();

    /// <summary>The default messenger's pickup folder (<see cref="IGuardMessenger"/>).</summary>
    public GuardMessengerOptions Messenger { get; set; } = new();

    /// <summary>What alerts site admins of a possible breach, and how much makes a burst.</summary>
    public Services.SecurityAlertOptions SecurityAlerts { get; set; } = new();

    /// <summary>The product's name in Guard's messages, and a host's own templates for them.</summary>
    public GuardTextOptions Texts { get; set; } = new();

    /// <summary>Whether sign-up starts open (Guard:SignUp:Open); closed by default.</summary>
    public GuardSignUpOptions SignUp { get; set; } = new();

    /// <summary>The names the first start seeds with (Guard:Seed:*): the admin, the internal directory, the two groups.</summary>
    public GuardSeedOptions Seed { get; set; } = new();

    /// <summary>Two-factor sign-in (Guard:TwoFactor:*): the authenticator app's issuer, and what the second step lists.</summary>
    public GuardTwoFactorOptions TwoFactor { get; set; } = new();

    /// <summary>Passkeys (Guard:Passkeys:*): the relying party, the site's address the browser checks.</summary>
    public GuardPasskeyOptions Passkeys { get; set; } = new();

    /// <summary>Step-up (Guard:StepUp:*): which categories ask for a strong proof.</summary>
    public GuardStepUpOptions StepUp { get; set; } = new();

    /// <summary>Site admins (Guard:Admins:*): whether each must have a strong factor, and how long they have to set one up.</summary>
    public GuardAdminsOptions Admins { get; set; } = new();
}

/// <summary>
/// The rule that every site admin (whoever's roles can manage everything) has a strong factor: a passkey or an
/// authenticator app. Configuration only (environment Guard__Admins__RequireStrongFactor); no page changes it.
/// </summary>
public sealed class GuardAdminsOptions
{
    /// <summary>The environment variable that turns the rule on, as security settings name where it comes from.</summary>
    public const string RequireStrongFactorVariable = "Guard__Admins__RequireStrongFactor";

    /// <summary>Whether every site admin must have a strong factor; off by default.</summary>
    public bool RequireStrongFactor { get; set; }

    /// <summary>
    /// How long a site admin has to set one up, counted from when Guard first sees them as one without a strong factor;
    /// after it, signing in asks them to set one up before going on. 48 by default; 0 asks at once.
    /// </summary>
    public int GraceHours { get; set; } = 48;
}

/// <summary>
/// Which step-up categories ask for a strong proof (a passkey, or an authenticator app's code):
/// Guard:StepUp:Strong (environment Guard__StepUp__Strong), the server operator's, never a page's; and whether the app's
/// code alone is that proof (Guard:StepUp:AppCodeAlone).
/// </summary>
public sealed class GuardStepUpOptions
{
    /// <summary>The variable that sets <see cref="AppCodeAlone"/>.</summary>
    public const string AppCodeAloneVariable = "Guard__StepUp__AppCodeAlone";

    /// <summary>
    /// Whether an authenticator app's code alone steps up, at either level (the session already proved the password; the
    /// code proves the device). True by default; false asks the password with the code, as 0.7.0 did. A sent or recovery
    /// code never steps up alone.
    /// </summary>
    public bool AppCodeAlone { get; set; } = true;

    /// <summary>
    /// A comma-separated list of categories, <c>*</c> for every one, or <c>none</c> for none (every step-up at the password
    /// level, as before 0.7.0). Null or empty: <see cref="Acting.StepUpCategories.DefaultStrong"/>.
    /// </summary>
    public string? Strong { get; set; }
}

/// <summary>
/// The relying party passkeys belong to: the site's address. A passkey works only where its relying party's id is the
/// site's domain (or a parent of it) and the page's origin is listed: a site moved to a new address keeps its passkeys
/// only while the old origin stays in <see cref="Origins"/>.
/// </summary>
public sealed class GuardPasskeyOptions
{
    /// <summary>The relying party's id, a domain (example.com). Null: the host of <see cref="GuardOptions.PublicUrl"/>.</summary>
    public string? RpId { get; set; }

    /// <summary>
    /// The origins a passkey's ceremony may come from (https://example.com), each also given comma-separated. Empty: the
    /// origin of <see cref="GuardOptions.PublicUrl"/>.
    /// </summary>
    public List<string> Origins { get; set; } = [];

    /// <summary>The site's name the device shows. Null: the product's English name (Texts.ProductName).</summary>
    public string? RpName { get; set; }
}

/// <summary>
/// Two-factor sign-in's settings a host gives. Guard:TwoFactor:Disabled, the emergency switch, stays a
/// setting of its own.
/// </summary>
public sealed class GuardTwoFactorOptions
{
    /// <summary>
    /// The name authenticator apps show for the site, and the sent codes name. Null: the product's English name
    /// (Texts.ProductName) and the site's host, "Example (example.com)", say. One name in every language, as an app's
    /// entry stays as it was set up.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// Whether the second step lists "recovery" among the methods when the person has recovery codes left. Off by
    /// default, so the methods are the person's factors and the codes the site sends.
    /// </summary>
    public bool ListsRecovery { get; set; }
}

/// <summary>
/// Sign-up when the site is first set up: open, into the internal directory, or closed until an admin opens
/// it. It's the default only: once an admin chooses on the sign-up settings, their choice stays.
/// </summary>
public sealed class GuardSignUpOptions
{
    public bool Open { get; set; }
}

/// <summary>
/// What the first start makes, by name (neutral names by default). Made once: renaming them later is an admin's, and
/// changing these settings after doesn't. The admin's password is Guard:Seed:AdminPassword, read only at that start.
/// </summary>
public sealed class GuardSeedOptions
{
    public string AdminDisplayName { get; set; } = "Administrator";

    public string AdminEmail { get; set; } = "admin@example.com";

    public string InternalDirectoryName { get; set; } = "Internal";

    public string AdminsGroupDescription { get; set; } = "Administrators. Members, direct or nested, can administer the site.";

    public string UsersGroupName { get; set; } = "users";

    public string UsersGroupDescription { get; set; } = "Everyone who may sign in.";
}

/// <summary>
/// The names of a browser session's cookies: its secret (only the server reads it), the anti-forgery value the
/// page sends back as X-Guard-Csrf, the phone's embedded mode, and the page's language. A host beside another on the same
/// domain gives its own, so the two don't read each other's.
/// </summary>
public sealed class GuardCookieOptions
{
    public string Session { get; set; } = "guard_session";

    public string Csrf { get; set; } = "guard_csrf";

    public string Embedded { get; set; } = "guard_embedded";

    public string Language { get; set; } = "NEXT_LOCALE";
}

/// <summary>
/// The host's pages, as paths on its public address: where mailed links and the OAuth consent go. A path may hold
/// <c>{lang}</c> (/{lang}/reset-password): a mailed link has the recipient's language there, else the site's first.
/// </summary>
public sealed class GuardPageOptions
{
    /// <summary>The page's address on the site, its {lang} the language given (else en).</summary>
    public static string Link(string site, string path, string? language) =>
        site + path.Replace("{lang}", Uri.EscapeDataString(language is { Length: > 0 } ? language : "en"), StringComparison.Ordinal);

    public string SignUpVerify { get; set; } = "/signup/verify";

    public string PasswordReset { get; set; } = "/reset-password";

    public string AddressVerify { get; set; } = "/emails/verify";

    public string Consent { get; set; } = "/oauth/consent";

    /// <summary>The security log's page for site admins, which a security alert links to.</summary>
    public string SecurityLog { get; set; } = "/admin/security";
}

/// <summary>
/// The host's own clients (OpenID Connect client ids): its web server, which may refresh with a password to step up, and
/// its phone app, whose sign-ins the person's list shows as their phone. Apps people allow are never these.
/// </summary>
public sealed class GuardClientOptions
{
    public string Web { get; set; } = Controllers.GuardOidc.WebClientId;

    public string Mobile { get; set; } = Controllers.GuardOidc.MobileClientId;
}

/// <summary>A site's time zone (an IANA name), the day its weeks start on, and the languages people may choose.</summary>
public sealed class GuardSiteOptions
{
    public string TimeZone { get; set; } = "UTC";

    public DayOfWeek FirstDayOfWeek { get; set; } = DayOfWeek.Monday;

    public List<string> Languages { get; set; } = ["en"];
}

/// <summary>
/// Where the default messenger writes each message it sends, one file each, rendered from Guard's own texts. Null
/// writes nowhere: a message is then not sent, and says so.
/// </summary>
public sealed class GuardMessengerOptions
{
    public string? PickupFolder { get; set; }
}
