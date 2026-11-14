# For ABP developers: where ABP's layers are

AbpGuard is an ABP module that does what ABP's Identity, Account, PermissionManagement and OpenIddict modules do
together, but it isn't split into ABP's standard module layers. This page maps one onto the other.

| ABP's layer (`abp new -t module`) | In AbpGuard |
|---|---|
| `*.Domain.Shared` (constants, error codes) | `AbpGuard.Acting`: `GuardErrorCodes`, `GuardStatusCodes`, `GuardNames`, `GuardPolicies`; `AbpGuard.Contracts` for the rest |
| `*.Domain` (entities, domain services) | `AbpGuard`: `Domain/` (accounts, groups, directories, roles and grants, sessions, tokens, the security log), `Services/` |
| `*.Application.Contracts` (DTOs, interfaces) | `AbpGuard.Contracts`: lookups other modules use (`IAccountLookup`, `IGroupLookup`…), events (`*Eto`), personal data, merges, directories |
| `*.Application` (application services) | `AbpGuard`: `Services/` (account, group, directory, privacy and security services) |
| `*.EntityFrameworkCore` | `AbpGuard`: `Data/GuardDbContext` with its own migrations in the package, schema `guard`, run at start by `GuardDatabase.MigrateAsync` |
| `*.HttpApi` | Inside `AbpGuard`: `Controllers/`, under `api/guard/*`, plus OpenIddict's endpoints (`/connect/*`) |
| `*.HttpApi.Client` | Not yet |
| `*.Web` / `*.Blazor` | `@abpjs/guard` (planned), released with the packages |
| Request-time helpers | `AbpGuard.Acting`: `ActingContext` (who is acting, and as what), `[StepUp]` (the password again), read-only requests |

## What works the ABP way

- **Modules:** `AbpGuardModule` and `AbpGuardActingModule`, with `[DependsOn]` on ABP's own modules and OpenIddict.
- **The database:** a context of its own (`GuardDbContext`, an `AbpDbContext`) with migrations shipped in the package,
  like a module whose tables live apart from the host's; it uses ABP's event outbox (`IHasEventOutbox`).
- **Events:** distributed events with `*Eto` records (`AccountCreatedEto`, `AccountErasedEto`…) through ABP's event bus.
- **Options:** `GuardOptions` and its parts, from the `Guard` section of configuration.
- **Replacing a part:** the seams in `Seams/` (messenger, message templates, rate limits, locks, event sink, the
  security feed, site defaults) are services you replace in `ConfigureServices`.
- **Errors:** `GuardErrorCodes`, mapped to HTTP statuses for the API.

## Where it differs, and why

- **Authorization is CASL, not ABP's permission definitions:** roles hold rules in CASL's format (`manage` on
  `Record` where the project is the grant's), so a grant can be scoped to a project, a directory or a schema, which
  ABP's permissions (per user or role, site-wide) can't say. `GuardPolicies` gives ASP.NET Core policies over them.
- **Controllers inside the main package:** there's no `AbpGuard.HttpApi` yet, so a host that adds the module gets the
  API at `api/guard/*`. Moving them into `AbpGuard.HttpApi`, as AbpAi and AbpAgent did, is planned for a later minor
  version.
- **Services, not application services:** plain services with no `I*AppService` interfaces and no auto API controllers.
- **Texts:** messages and mail texts are English by default and set per site through `GuardTextOptions` and the
  message templates seam, not through ABP's localization resources.
- **One main package:** domain, services, EF Core and controllers are in `AbpGuard`. A split into ABP's layers is a
  decision for before 1.0.
