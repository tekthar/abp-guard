# AbpGuard

Accounts, sign-in and authorization for ABP applications on .NET 10 and PostgreSQL, as a package any product can use
instead of writing its own security. Nothing in it assumes one product: every name it writes is a setting.

> **Preview.** 0.x versions may change their API in any minor version (SemVer). Pin an exact version.

> **Not a Volosoft project.** [ABP Framework](https://abp.io) is made and owned by [Volosoft](https://volosoft.com).
> AbpGuard is an independent enhancement that works on ABP: this repository and its packages don't belong to
> Volosoft, and aren't affiliated with or endorsed by them.

## What it does

- **Directories and accounts:** user directories in order of precedence (an internal one with passwords, and a
  connector interface for others such as LDAP), service accounts, account merges, preferences and added email addresses.
- **Groups:** nested groups, organizations and email-domain groups, imports.
- **Sign-in:** web sessions with CSRF protection, rate limits, an OpenIddict server (password, refresh and code grants)
  with its token endpoint, OAuth apps with consent, dynamic client registration, and personal access tokens.
- **Step-up by category:** sensitive actions ask for the password again within a window, and the dangerous categories
  (roles, security settings, directories, apps…, the server operator's to choose) for a strong proof: a passkey, or an
  authenticator app's code (alone by default, or with the password). A personal access token never passes, unless the
  host's policy names its category.
- **Two-factor sign-in:** passkeys (WebAuthn), authenticator apps (TOTP), recovery codes and codes sent by email or a
  host's own channels, with Off, Optional, Required or Strong per group, and a rule the server's operator may turn on that
  every site admin has a passkey or an authenticator app.
- **Self-service:** sign-up with a confirmed email, and password reset.
- **Authorization with [CASL .NET](https://www.nuget.org/packages/Casl.Net):** roles hold rules in CASL's format; grants
  give a role to an account or a group with a scope; the same rules filter queries in SQL and go to the browser.
- **Personal data:** a map of every store a site's modules and plugins keep, the record of processing, a person's
  data exported, names and addresses corrected, erasure with legal holds, retention periods swept daily, and a privacy
  notice with consent.
- **The security log**, kept for a set number of days, downloaded as CSV or fed to a receiver as it's written, with
  alerts to site admins of what may be a breach.
- **Connections to outside systems** (`AbpConnections`, since 0.8.0): settings and secrets kept encrypted, OAuth sign-in
  with PKCE once for everyone or by each person with their own account, tokens refreshed one at a time on any server, and
  an outbound guard that refuses private addresses. It works without the rest of Guard.

Guard keeps its tables in the `guard` schema of the host's database, or in a database of its own.

## Packages

On [nuget.org](https://www.nuget.org/packages?q=AbpGuard):

| Package | What it holds |
|---|---|
| `AbpGuard.Contracts` | The public contracts: lookups, the directory connector interface, account and group events. No ABP, EF Core or OpenIddict. |
| `AbpGuard.Acting` | The acting context (whose rights a request uses and who acts), step-up, read-only requests, error codes, the names Guard writes. |
| `AbpGuard` | The ABP module: domain, services, the EF Core contexts and their migrations, the seams. |
| `AbpGuard.HttpApi` | The API (since 0.5.0): sign-in and sessions, OpenIddict's `/connect/*`, and `api/guard/*`; `AbpGuardHttpApiModule` brings `AbpGuardModule`. |
| `AbpConnections` | Connections to outside systems (since 0.8.0): the tables' model for the host's own context, `ConnectionManager`, the kinds' interfaces, and the outbound guard. |
| `AbpConnections.HttpApi` | Connections over HTTP under `api/connections` (since 0.8.0); `AbpConnectionsHttpApiModule` brings `AbpConnectionsModule`. |

Coming from ABP's module template? [Where ABP's layers are in this repository](docs/abp-layers.md).

## Use it in a host

`samples/AbpGuard.SampleHost` is a complete host with Guard's defaults only. In short:

```csharp
builder.Host.UseAutofac();
// Guard protects secrets with the Data Protection key ring: keep it in Guard's database so every server reads the same keys.
builder.Services.AddDataProtection().SetApplicationName("my-product").AddGuardKeyRing();
await builder.AddApplicationAsync<MyHostModule>();   // [DependsOn(typeof(AbpGuardHttpApiModule))]

WebApplication app = builder.Build();
await GuardDatabase.MigrateAsync(app.Services);
await GuardDatabase.SeedAsync(app.Services);
await app.InitializeApplicationAsync();
await app.RunAsync();
```

Configure it in the `Guard` section (`GuardOptions`):

- **Connection:** `ConnectionStrings:Guard` names Guard's database, falling back to `ConnectionStrings:Default`.
- **Addresses:** `PublicUrl` is where people reach the host. `Pages` holds the paths of the pages Guard's mails link to.
  A path may contain `{lang}`, such as `/{lang}/reset-password`. A mailed link puts the recipient's language there, or
  the site's first language when the recipient has none.
- **Names:** `Cookies` holds the cookie names (`guard_session`, `guard_csrf`, `guard_embedded`), `Clients` the OAuth
  clients (`web`, `mobile`), `ApiScope` the scope of your own API (`api`), and `AdminsGroupName` and `Seed` the groups
  the first start makes (`admins`, `users`).
- **Stored and wire names:** `Guard:Names` (`GuardNames`) holds what Guard writes into tokens, headers, stored rows and
  protected data: the claims (`guard_token` and the like), the anti-forgery header (`X-Guard-Csrf`), the token prefix
  (`guard_pat_`), the app id and secret prefixes, the read scope (`api.read`), the second step's grant type
  (`urn:abpguard:grant-type:second-factor`), the Data Protection purposes' prefix (`AbpGuard`) and the header the
  security log's feed is signed in (`X-Guard-Signature`). `Former` reads tokens made under claim and scope names a site
  used before. Choose them before your first release: changing one later breaks whatever already holds the old one.
  Refusals carry the error codes `Guard:Forbidden` and `Guard:TooManyRequests`.
- **Features:** `Features` switches whole features off, and their endpoints go with them. These are `Directories`,
  `PersonalTokens`, `OAuthApps`, `ClientRegistration`, `Merges`, `Handoff`, `SignUp`, `TwoFactor`, `DataExport`,
  `Erasure`, `Retention`, `PrivacyNotice`, `SecurityAlerts` and `SecurityFeed`.
- **Mail:** `Messenger:PickupFolder` gives the default messenger a folder to write mail to. For real delivery, replace
  `IGuardMessenger`.
- **Texts:** `Texts` holds your product's name in Guard's messages (`Texts:ProductName:en`, and other languages), or
  templates of your own. Give it: without one, the mails name "AbpGuard".
- **First start:** `SignUp:Open` opens sign-up into the internal directory; it is closed by default, and an admin's
  later choice stays. `Seed` names what the first start makes: the admin's display name and email, the internal
  directory, and the admins and users groups with their descriptions. The admin signs in as `admin` (its username, not
  its email). Its password is `Seed:AdminPassword`,
  at least 10 characters: keep it in a secret store or an environment variable, not in `appsettings.json`. The sample
  host keeps its own in `appsettings.Development.json`, so it starts only in Development until you give one.
- **Two-factor:** `TwoFactor:Issuer` is the name authenticator apps show. By default it is your product's English name
  and the site's host. Set `TwoFactor:ListsRecovery` to list "recovery" among the second step's methods when the person
  has recovery codes left.
- **Passkeys:** they belong to the site's address, `PublicUrl` by default; `Passkeys:RpId` (a domain), `Passkeys:Origins`
  (the pages' origins, a list or comma-separated) and `Passkeys:RpName` set it otherwise. Outside Development, a site
  with neither can't add or use a passkey, and says what to set. Keep an old address in `Origins` after a move, or its
  passkeys stop working.
- **Step-up levels:** `StepUp:Strong` lists the categories that need a strong proof, comma-separated, `*` for all or
  `none`; by default `plugins, roles, security, accounts, directories, apps, service-accounts, admin-tokens, exports,
  backups, scripts, secrets, sites`. Your own marks name their categories, `[StepUp("publishing")]`, and may be listed too. It's
  the server operator's (environment `Guard__StepUp__Strong`): no page changes it.
- **The app's code alone:** `StepUp:AppCodeAlone` (on by default; environment `Guard__StepUp__AppCodeAlone`) lets an
  authenticator app's code alone step up, at either level: the session already proved the password, the code proves the
  device. Too many wrong codes then end the session, as wrong passwords do. Set it to `false` to ask the password with the
  code. A sent or recovery code never steps up alone.
- **Site admins:** `Admins:RequireStrongFactor` (off by default; environment `Guard__Admins__RequireStrongFactor`) makes
  every site admin have a passkey or an authenticator app, within `Admins:GraceHours` (48) of when Guard first sees them
  without one; after it, signing in asks them to set one up first.
- **Data folder:** `DataRoot` is where Guard looks once for sign-in key files kept on disk, and keeps them when there's
  no database for them. A host can give its own setting instead (`GuardStartupOptions`, through ABP's PreConfigure).

Guard needs ABP's clock in UTC. It sets `AbpClockOptions.Kind` to UTC itself and refuses to start if a host sets
another kind.

`IServiceAccounts` lets your own code make service accounts, and give them tokens, list and revoke them. Your code
decides who may ask. Guard refuses tokens for an agent's account and audits each change as the admin pages do.

`AddGuardKeyRing(certificate)` keeps the Data Protection key ring in Guard's database encrypted by a certificate. Every
server needs the same certificate with its private key.

A host can replace each of Guard's seams with its own service: `IGuardMessenger`, `IGuardLocks`, `IGuardRateLimits`,
`IGuardEventSink`, `IGuardBroadcast`, `IGuardSiteDefaults`, `ISignUpChallenges`, `ITokenRestrictions`,
`ISecurityFeedSender` and `IStepUpTokenPolicy` (which personal access tokens may pass a step-up mark, by its category; none
by default). Otherwise Guard uses its defaults. ABP registers a class under an interface only when the class's name
ends with the interface's (`MarketplaceStepUpTokenPolicy` for `IStepUpTokenPolicy`); one named otherwise needs
`[ExposeServices(typeof(IStepUpTokenPolicy))]` with `[Dependency(ReplaceServices = true)]`, or
`services.Replace(ServiceDescriptor.Transient<IStepUpTokenPolicy, MyPolicy>())`, or Guard's default stays in its place.

**Behind a proxy or load balancer**, tell ASP.NET Core which proxies to trust, before Guard's middleware, so Guard sees
each person's own address and scheme. Sign-in limits count wrong passwords per IP address; without this, every request
comes from the proxy's address and shares one count:

```csharp
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownProxies.Add(IPAddress.Parse("10.0.0.10"));   // your proxy's address; or KnownNetworks for a range
});
app.UseForwardedHeaders();
```

**A host that ran the earlier packages** keeps its sessions, tokens and protected data by setting the names it shipped
with: see [docs/upgrading.md](docs/upgrading.md).

## Connections

`AbpConnections` keeps what an application needs to reach outside systems for its people: a drive, a mailbox, a
repository host, an MCP server. A connection has a kind (`IConnectionKind`: its settings, how it signs in with OAuth, and
a test call), its settings, and its secrets, which are encrypted and never shown again. It needs only ABP, EF Core and
Data Protection, not the rest of Guard.

```csharp
[DependsOn(typeof(AbpConnectionsHttpApiModule))]   // or AbpConnectionsModule, for the services without the API
public class MyHostModule : AbpModule
{
    public override void ConfigureServices(ServiceConfigurationContext context)
    {
        context.Services.AddAbpDbContext<MyDbContext>(o => o.ReplaceDbContext<IConnectionsDbContext>());
        context.Services.AddSingleton<IConnectionKind, MyDriveKind>();
        Configure<ConnectionsOptions>(o => o.WherePeopleSignIn = "Profile > Connected accounts");
    }
}

public class MyDbContext(DbContextOptions<MyDbContext> options) : AbpDbContext<MyDbContext>(options), IConnectionsDbContext
{
    public DbSet<Connection> Connections => Set<Connection>();
    public DbSet<ConnectionAccount> ConnectionAccounts => Set<ConnectionAccount>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ConfigureConnections("my_schema");   // the tables connections and connection_accounts, in your migrations
    }
}
```

- **Scopes:** a connection belongs to the site (no scope) or to one scope of yours, such as a project. `ScopeId` is
  the column `ScopeId` unless `ConfigureConnections` names another.
- **Secrets and tokens** are protected with Data Protection under `ConnectionsOptions.SecretsPurpose`
  (`AbpConnections.Secrets.v1`). Every server needs the same key ring (`AddGuardKeyRing`, or your own). Never change the
  purpose once a secret is saved: every saved secret is lost with it.
- **Signing in** is OAuth's authorization code with PKCE. `POST api/connections/{id}/authorize` gives the provider's
  address. The provider sends the browser back to your page ending in `CallbackPath` (`/connections/callback`), which
  posts the code and state to `POST api/connections/complete`. Only the person who started a sign-in can finish it,
  within `SignInTime` (10 minutes).
- **Each person their own account:** a connection made with `EachPerson` has every person sign in themselves, under
  `api/connections/mine`. `ConnectionManager.ForPersonAsync` gives that person's token, or throws
  `PersonNotSignedInException` saying where to sign in (`WherePeopleSignIn`).
- **Using one:** `GetForUseAsync` gives the settings, the secrets and an access token, refreshed first when it's about to
  expire. A refresh runs one at a time for each connection on every server (`IConnectionLocks`, ABP's distributed lock
  by default: give ABP a distributed lock provider when you run more than one server). If the provider refuses a refresh,
  the connection must sign in again. If the provider doesn't answer, the tokens stay.
- **Kinds that come and go**, such as a plugin's, come from your own `IConnectionKinds`. It leases them while they're used
  and keys each one (`plugin:type`, say). By default, every `IConnectionKind` registered is offered under its `Type`.
- **What uses a connection** (`IConnectionUses`): it can't be removed while anything does, and the refusal names the
  users.
- **Who may manage** a scope's connections is `IConnectionRights`. By default, site admins (`GuardPolicies.Admin`, which
  `AbpGuardModule` defines) manage the site's, and a scope's need your own rights. Without `AbpGuardModule`, no one
  manages them until you register your own, and the API refuses with a 403 that says so.
- **The step-up** (the `secrets` category, strong by default) guards whatever could hand a secret or a sign-in to someone
  else: setting a secret, changing any setting of a connection that holds a secret or a sign-in (a new address would
  receive them on the next test or refresh; `ChangeNeedsStepUpAsync` tells), signing one in for everyone, and removing
  one. Signing in with one's own account needs none.
- **A new provider ends the sign-in:** when a change moves where a connection signs in (the provider's addresses, the
  client, the resource), its tokens and every person's own end with it, and it signs in again. Other settings keep them.
- **The audit:** `ISecurityAudit` hears every change, by name and never with a secret. With `AbpGuardModule` it goes to
  Guard's security log, and without it nowhere, unless you register your own.
- **The outbound guard:** the `Connections` HTTP client refuses private and loopback addresses, unless
  `Network:AllowedPrivateHosts` lists the host. When `Network:AllowedHosts` lists any hosts, it reaches only those
  (`*.example.com` matches subdomains). Give your own clients the same rules with `.RefusePrivateAddresses()`. The
  refusal names `OutboundGuard.Caller` ("this server" by default).

## Build and test

You need the .NET 10 SDK. The integration tests also need PostgreSQL: `localhost:5432` with user and password
`postgres` (the official image's defaults), or the server `GUARD_TEST_POSTGRES` names.

```bash
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:17
dotnet build AbpGuard.slnx -c Release
dotnet test AbpGuard.slnx -c Release
dotnet pack AbpGuard.slnx -c Release -o artifacts
```

## Releasing

The version is `VersionPrefix` and `VersionSuffix` in `Directory.Build.props`, and `CHANGELOG.md` needs an entry for
it. Pushing the tag `v<version>`, such as `v0.2.0`, runs the checks. GitHub Actions then pushes the packages
to nuget.org and makes a GitHub release.

Publishing uses nuget.org's Trusted Publishing, so no API key is stored anywhere: nuget.org gives the release job a key
that lasts an hour. It needs a Trusted Publishing policy on nuget.org for this repository, the workflow file `ci.yml`
and the environment `release`, and the repository variable `NUGET_USER` set to the nuget.org account that owns the
packages.

## Contributing

Issues and pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md) for
vulnerabilities. CI runs on GitHub Actions for every pull request.

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE).
