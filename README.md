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
- **Step-up:** sensitive actions ask for the password again within a window; a personal access token never passes.
- **Two-factor sign-in:** authenticator apps (TOTP), recovery codes and codes sent by email or a host's own channels,
  with Off, Optional or Required per group.
- **Self-service:** sign-up with a confirmed email, and password reset.
- **Authorization with [CASL .NET](https://www.nuget.org/packages/Casl.Net):** roles hold rules in CASL's format; grants
  give a role to an account or a group with a scope; the same rules filter queries in SQL and go to the browser.
- **Personal data:** a map of every store a site's modules and plugins keep, the record of processing, a person's
  data exported, names and addresses corrected, erasure with legal holds, retention periods swept daily, and a privacy
  notice with consent.
- **The security log**, kept for a set number of days, downloaded as CSV or fed to a receiver as it's written, with
  alerts to site admins of what may be a breach.

Guard keeps its tables in the `guard` schema of the host's database, or in a database of its own.

## Packages

On [nuget.org](https://www.nuget.org/packages?q=AbpGuard):

| Package | What it holds |
|---|---|
| `AbpGuard.Contracts` | The public contracts: lookups, the directory connector interface, account and group events. No ABP, EF Core or OpenIddict. |
| `AbpGuard.Acting` | The acting context (whose rights a request uses and who acts), step-up, read-only requests, error codes, the names Guard writes. |
| `AbpGuard` | The ABP module: domain, services, controllers, the EF Core contexts and their migrations. |

## Use it in a host

`samples/AbpGuard.SampleHost` is a complete host with Guard's defaults only. In short:

```csharp
builder.Host.UseAutofac();
// Guard protects secrets with the Data Protection key ring: keep it in Guard's database so every server reads the same keys.
builder.Services.AddDataProtection().SetApplicationName("my-product").AddGuardKeyRing();
await builder.AddApplicationAsync<MyHostModule>();   // [DependsOn(typeof(AbpGuardModule))]

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
- **Data folder:** `DataRoot` is where Guard looks once for sign-in key files kept on disk, and keeps them when there's
  no database for them. A host can give its own setting instead (`GuardStartupOptions`, through ABP's PreConfigure).

Guard needs ABP's clock in UTC. It sets `AbpClockOptions.Kind` to UTC itself and refuses to start if a host sets
another kind.

`IServiceAccounts` lets your own code make service accounts, and give them tokens, list and revoke them. Your code
decides who may ask. Guard refuses tokens for an agent's account and audits each change as the admin pages do.

`AddGuardKeyRing(certificate)` keeps the Data Protection key ring in Guard's database encrypted by a certificate. Every
server needs the same certificate with its private key.

A host can replace each of Guard's seams with its own service: `IGuardMessenger`, `IGuardLocks`, `IGuardRateLimits`,
`IGuardEventSink`, `IGuardBroadcast`, `IGuardSiteDefaults`, `ISignUpChallenges`, `ITokenRestrictions` and
`ISecurityFeedSender`. Otherwise Guard uses its defaults.

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
