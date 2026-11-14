# Changelog

All notable changes to AbpGuard (Toda.Guard until 0.1.0) are written here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the packages follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html): before 1.0, a minor version may
change the API.

## [Unreleased]

## [0.7.1] - 2026-11-14

An authenticator app's code alone is a strong step-up, as the operator may choose. No migration.

### Added

- **`Guard:StepUp:AppCodeAlone`** (environment `Guard__StepUp__AppCodeAlone`), on by default: the app's code alone
  steps up at either level, a strong one (the session already proved the password; the code proves the device). Set to
  `false`, a step-up with the app asks the password too, as in 0.7.0. A sent or recovery code never steps up alone.
  - `POST session/step-up` takes `{ method: 'app', code }` with no password, and marks `authTime` and `strongAuthTime`,
    as a passkey does. The token endpoint's step-up takes `step_up_method=app` and `step_up_code` with no
    `step_up_password`.
  - Too many wrong codes alone (the sign-in's limit, ten in 15 minutes) end the session, as too many wrong passwords do:
    401 `session_ended`, and the refresh token is revoked. A step-up by someone whose account is no longer active ends it too.
  - `step_up_required`'s data says `appCodeAlone: true|false`, so a dialog shows the code alone or the password and the
    code. The strong message reads "Confirm it's you with your passkey or your authenticator app." when it's on.
  - The security settings show `stepUpAppCodeAlone`, read-only.
  - `StepUpMethods` has `AppCodeAlone`; its two-argument constructor stays, with it false.

## [0.7.0] - 2026-11-14

Passkeys, a strong step-up for the dangerous categories, and a rule that every site admin has a strong factor. Two
migrations, run at start as the others are: `Passkeys` (the tables `guard.passkeys` and `guard.passkey_challenges`,
the columns `sessions.StrongAuthTime`, `sessions.RecoveryAuthTime` and `session_handoffs.StrongAuthTime`) and
`AdminsStrongFactor` (`accounts.StrongFactorDueAt`).

### Added

- **Passkeys** (WebAuthn, with Fido2NetLib 4.3.2, MIT), a second factor beside the authenticator app: discoverable
  (`residentKey: 'required'`) and with user verification, as many as a person likes, each with its name, provider (from
  the AAGUIDs of the common password managers, platforms and security keys, kept in the package; null when unknown) and
  whether it's synced (`backedUp`). The options and answers are the browser's JSON
  (`PublicKeyCredentialCreationOptionsJSON`, `PublicKeyCredentialRequestOptionsJSON`, the credential's `toJSON()`):
  - `POST api/guard/me/passkeys/options`, `POST api/guard/me/passkeys` `{ name, credential }` (the factor, with
    `recoveryCodes` when it's the person's first), `PUT api/guard/me/passkeys/{id}` `{ name }`; removing is
    `DELETE api/guard/me/second-factors/{id}`.
  - A step-up with a passkey alone: `POST api/guard/session/step-up/options`, then `POST api/guard/session/step-up`
    `{ method: 'passkey', credential }`.
  - A sign-in's second step: `POST api/guard/session/second-step/options` `{ ticket }`, then
    `POST api/guard/session/second-factor` `{ ticket, method: 'passkey', credential }` (or the token endpoint's second
    step with the `credential` parameter).
  - Setting one up at sign-in: `POST api/guard/second-factor/enrol/passkey/options` `{ ticket }` and
    `POST api/guard/second-factor/enrol/passkey` `{ ticket, name, credential }`, beside the app.
  - Every challenge is good once, for five minutes, for the purpose and the web session (an app's sign-in, or the
    sign-in's ticket) that asked; options are 20 per session or ticket in five minutes. A refused answer (origin,
    relying party, challenge, user verification, signature, a signature count that went back) is `passkey_rejected`,
    and counts with wrong codes; the same device's passkey again is `passkey_exists`; asking a person with none to
    prove with one is `no_passkey`.
  - The relying party: `Guard:Passkeys:RpId`, `Guard:Passkeys:Origins` (a list, or comma-separated) and
    `Guard:Passkeys:RpName`, by default the host and origin of `Guard:PublicUrl` and the product's name.
- **Strong proofs:** beside `auth_time`, a session (a column) and a token (a claim) carry `strong_auth_time`: a sign-in
  whose second step was a passkey or the app, a step-up with a passkey, or the password and the app's code (the answer
  carries `authTime` and `strongAuthTime`). A sign-in with a recovery code carries `recovery_auth_time`, which counts as
  strong for setting up a new factor alone. `ActingContext.StrongAuthTime` and `RecoveryAuthTime` read them; the phone's
  handoff carries the strong one to its web view.
- **Step-up by category:** `[StepUp("roles")]`, `StepUpGuard.EnsureAsync("roles")`, and `StepUpGuard.EnsureAtAsync` for a
  level the code decides. A category is `strong` when `Guard:StepUp:Strong` (environment `Guard__StepUp__Strong`) lists
  it: a comma-separated list, `*` for every one, or `none`; by default `plugins, roles, security, accounts, directories,
  apps, service-accounts, admin-tokens, exports, backups, scripts, secrets, sites` (`StepUpCategories.DefaultStrong`). A strong
  one passes on `strong_auth_time` within the site's window, never on the password alone or with a sent or recovery code.
  `403 step_up_required`'s data gains `level`, `category` and `methods` (the person's ways, best first: `passkey`, `app`,
  `password`, `email`…); `403 strong_factor_required` (`data: { category }`) answers someone with no strong factor yet.
  `IStepUpLevels` decides (Guard's `GuardStepUpLevels`); with `Guard:TwoFactor:Disabled` no category is strong.
- **`IStepUpTokenPolicy`**: a host may let a personal access token through a category it names (by default none passes),
  for automation such as a publisher's CI.
- **The site admins' rule:** `Guard:Admins:RequireStrongFactor` (environment `Guard__Admins__RequireStrongFactor`, off by
  default) makes every site admin (whoever's roles can manage everything) have a passkey or the app, within
  `Guard:Admins:GraceHours` (48) of when Guard first sees them without one (a sign-in, or their session read). Past it,
  signing in asks them to set one up first; while it holds, their last strong factor can't be removed
  (`last_strong_factor`); an admin's reset of their factors starts their grace again. The security log has
  `account.strong-factor.grace`, `auth.strong-factor.enrol` and `account.strong-factor.set-up`.
- **Who must:** `GET api/guard/me` gains `strongFactor: { has, methods, requiredBy, overdue }`;
  `GET api/guard/me/second-factors` (and an admin's `GET api/guard/accounts/{id}/second-factors`) list passkeys beside the
  app, each with `strong`, and the person's `strong`, `requiredBy` and `overdue`. `GET api/guard/security/settings` gains
  `stepUpStrong` and `adminsStrongFactor: { required, graceHours, source: 'environment', variable }`, read-only.
- **An admin removes one of a person's factors** for a lost device: `DELETE api/guard/accounts/{id}/second-factors/{factorId}`
  (category `security`), as the reset is.
- **Notices:** every factor added or removed, by the person or an admin, or reset, is told to the person by mail where
  mail reaches them (`guard.second-factor-added`, `guard.second-factor-removed`, English and Arabic, which hosts may reword).
- **Personal data:** passkeys and their challenges are in the data map (`guard.sign-in-secrets`), a person's export
  (`passkeys`: name, provider, created, last used) and erasure.

### Changed

- **Guard's own marks name categories:** `accounts`, `roles` (roles, grants, groups and their members, merges, anonymous
  grants), `security` (security settings, retention, the security feed, sign-up, second-factor methods, a group's
  two-factor mode, an admin's reset or removal of someone's factors), `directories`, `apps`, `service-accounts`,
  `privacy` (exports of a person's data, erasures, holds, consent, the record of processing), `profile` (a person's own
  name and addresses), `factors`, `tokens`, and `admin-tokens` for a token a site admin makes. With the defaults, roles,
  groups, security settings, an admin's changes to someone's account (their password, addresses, name), directories,
  apps, service accounts and an admin's own tokens need a strong step-up.
- **A person's factors:** adding one needs a strong step-up once they have a strong factor (a password-level one for their
  first; a sign-in with a recovery code counts for adding alone); removing their last strong one needs a strong step-up.
  A group's `strong` mode takes a passkey as well as the app, and a sign-in's methods list `passkey` first.
- Removing the last factor while a group requires one is refused with the code `last_strong_factor`.
- `StepUpAttribute` takes a category (`Category`); `StepUpFilter` is made with one. `SecondFactorDto`,
  `MySecondFactorsDto`, `SecondStepPassed`, `SessionStepUpDto`, `SecuritySettingsDto` and `WebSessionInfo` gain members;
  `SecondFactors.PassAsync` takes a passkey's `credential`, `StepUpAsync` says whether a step-up was strong,
  `WebSessions.MarkSteppedUpAsync(id, strong)` marks a strong one, and `SecondFactors`' constructor takes `Passkeys`,
  `IGuardSiteDefaults` and `AdminsStrongFactor`.
- The token endpoint's tokens carry `strong_auth_time` after a second step with the app or a passkey, or a refresh's
  step-up with the app's code, and `recovery_auth_time` after a recovery code; a refresh keeps both.

### Upgrading

- Reference 0.7.0 of every AbpGuard package. The two migrations run at start (`GuardDatabase.MigrateAsync`).
- **Give passkeys the site's address:** `Guard:PublicUrl`, or `Guard:Passkeys:RpId` and `Guard:Passkeys:Origins`. Outside
  Development, without one, adding or using a passkey fails with an error that says what to set, and the start logs it.
  A site moved to a new address keeps its passkeys only while the old origin stays in `Guard:Passkeys:Origins`.
- **Decide the strong categories before the upgrade reaches people:** with the defaults, an admin with no passkey or
  authenticator app can't change roles, groups, security settings, directories, apps or service accounts until they set
  one up (`strong_factor_required`); their first factor needs only a password-level step-up. Set
  `Guard__StepUp__Strong=none` to keep every step-up at the password level while your admins set theirs up, or list your
  own categories.
- **Name your own marks' categories:** `[StepUp("plugins")]`, `EnsureAsync("backups")`, and list any of your own you want
  strong in `Guard:StepUp:Strong`. A mark without one still compiles and stays at the password level (strong only under
  `*`). A host that needs a token through a mark registers an `IStepUpTokenPolicy`.
- **Your step-up prompt** reads `error.data.level` and `methods`: at `strong`, offer a passkey
  (`session/step-up/options`, then `{ method: 'passkey', credential }`) or the password with the app's code; on
  `strong_factor_required`, offer to set one up. Recovery and sent codes never pass a strong category.
- **The site admins' rule** is off until you turn it on: `Guard__Admins__RequireStrongFactor=true` and, if 48 hours isn't
  right, `Guard__Admins__GraceHours`.
- Code that makes `SecondFactors` or a `StepUpFilter` itself (a test double, say) follows the new constructors above.
- Not yet in the package: a step-up with a passkey on the token endpoint (the phone's), and signing in with a passkey
  alone.

## [0.6.0] - 2026-11-14

Accounts and groups in pages, as ABP's lists page. No new tables or columns; every other route is as it was.

### Added

- `GET api/guard/accounts/page` and `GET api/guard/groups/page`: ABP's `PagedAndSortedResultRequestDto` in
  (`SkipCount`, `MaxResultCount` 25 unless given and at most ABP's 1,000, `Sorting` as `field` or `field desc`,
  several by commas) and `PagedResultDto` out (`totalCount`, `items`). Accounts take the list's search as `Filter` and
  its `Status`, and sort by username, displayName, email, status, createdAt or lastLoginAt; groups take `Filter`,
  `DirectoryId` and `Kind`, and sort by name, kind or directory (its name). Ties go by id, so a page holds still while
  names change; a sort the list doesn't take is a 400 validation error. `AccountPageInput`, `GroupPageInput` and
  `GuardPaging` in AbpGuard.HttpApi.

### Changed

- `GET api/guard/accounts` and `GET api/guard/groups` are as they were (every match by name, at most 500): what
  pickers search.

## [0.5.0] - 2026-11-14

Guard's API is a package of its own, AbpGuard.HttpApi, as an ABP module's controllers are (`*.HttpApi`). No new tables or
columns, and the routes, shapes and behaviour are the same.

### Changed

- **The controllers moved to `AbpGuard.HttpApi`** (module `AbpGuardHttpApiModule`, which depends on `AbpGuardModule`):
  sign-in and sessions, OpenIddict's `/connect/*` handling, and everything under `api/guard/*`. Their types keep the
  namespace `AbpGuard.Controllers`, so code that names a DTO or a controller only needs the new package. `AbpGuard` alone
  is now the services, the tables and the seams, for a worker or a host that serves no API of Guard's.
- `GuardEvents` and `GuardOidc` stay in `AbpGuard` (same namespace), as its services use them; the security settings'
  loader is `GuardSecuritySettings.LoadAsync`, and `SecuritySettingsController.LoadAsync` still calls it.

### Upgrading

- Reference `AbpGuard.HttpApi` 0.5.0 (it brings `AbpGuard`), and put `typeof(AbpGuardHttpApiModule)` in your module's
  `[DependsOn]` in place of, or beside, `typeof(AbpGuardModule)`. Without it, the host has no sign-in, `/connect/*` or
  `api/guard/*` endpoints of Guard's.
- Remove `ConventionalControllers.Create(typeof(AbpGuardModule).Assembly)` if your module has it: that assembly
  holds no controllers now, and `AbpGuardHttpApiModule` adds its own to MVC.
- Keep every AbpGuard package at the same version (`AbpGuard`, `AbpGuard.Contracts`, `AbpGuard.Acting`,
  `AbpGuard.HttpApi`).

## [0.4.0] - 2026-11-14

The security log's feed can sign under a host's former header names too. No new tables or columns.

### Added

- **`GuardNames.FormerFeedSignatureHeaders`** (`Guard:Names:FormerFeedSignatureHeaders`, empty by default): each
  batch's signature goes under these headers as well as `FeedSignatureHeader`, with the same value, so a host can
  rename the header and a receiver set up under the old name keeps working while it moves. `SecurityFeed.Sign` takes
  them as `alsoUnder`; a name given twice, in any case, or empty is left out.

## [0.3.1] - 2026-11-13

Casl.Net 0.2.0 and its security fixes. No new tables or columns.

### Security

- **Casl.Net 0.2.0** (was 0.1.0): a null placeholder variable now fails an ability's build instead of matching every
  unassigned row, `ToMongoQuery` keeps deny-overrides, `PermittedFields` leaves out fields a deny pattern names, `$regex`
  decides the same in memory and on PostgreSQL, and a regex's time is bounded. `AbilityFactory` already builds each
  grant on its own: one whose rules no longer build is logged and left out, and one carrying a deny rule denies
  everything until it's fixed, so a broken grant can't widen access. A host that references Casl.Net itself should take
  0.2.0 too.

### Changed

- The README says the seeded admin signs in as `admin`, not with its email.

## [0.3.0] - 2026-11-11

What the host Guard came from built after 0.1.0, brought into the package: privacy (correction, erasure, retention,
the privacy notice and consent, breaches), names by language, renamed claims and plugins. Same tables in the `guard`
schema; eight new migrations, run at start as the others are.

### Added

- **Correction:** a person corrects their display name and chooses which confirmed address is their primary (the one
  before is told); admins do the same for internal accounts. `AccountChangedEto` carries the change.
- **Erasure:** a person asks to be erased, an admin erases an account or someone outside the site by an address, or
  declines; every module's and plugin's `IPersonalDataEraser` runs first, Guard's own last, and an erasure that meets a
  failing store waits to be resumed. Legal holds stop it. An erased account becomes "Former person {n}"
  (`AccountErasedEto`); those names are kept for erased accounts.
- **Retention:** stores declare rules (`IPersonalDataSweeper`), admins set and confirm their periods, and a daily sweep
  removes what's past them. A new site starts confirmed with the defaults; an upgraded one sweeps nothing until an admin
  confirms.
- **Privacy notice and consent:** versions in each language, accepted on sign-up, by people signed in and through a
  host's own forms (`IPrivacyNoticeAcceptance`); consent withdrawn where it's the legal basis.
- **Breaches:** alerts to site admins (`Guard:SecurityAlerts`), the security log as CSV, and a signed feed of it to a
  receiver outside the server's network.
- **Apps may register themselves** only once an admin allows it on a new site; an upgraded site keeps it on.
- **Names by language** for people, service accounts, directories (from a connector's settings), groups and roles;
  service accounts' pictures; directory connectors' warnings and settings checks.
- **Renamed claims and plugins:** `Guard:Names:Former` reads tokens made under a site's former claim and scope names;
  `PersonalDataKeys` moves what Guard keeps by a plugin's key when a host renames its plugins.
- Names a host may set: `Guard:Names:FeedSignatureHeader` (`X-Guard-Signature` by default) and
  `Guard:Pages:SecurityLog` (`/admin/security`).

### Changed

- Declining an erasure, adding a legal hold and marking a consent withdrawal handled ask for a step-up, as an admin's
  other changes do.
- `PersonalDataDeclaration.SchemaOf` names a plugin's schema from its app ID: `acme.notes` is `plg_acme__notes` ("."
  written "__", "-" written "_"). A one-word key from before app IDs keeps its old name. Code or tests that build
  `plg_{publisher}_{app}` themselves read no tables until they follow it.
- `IServiceAccounts` has `RenameAsync` and `SetPictureAsync`. A host's own implementation, or a test double, needs them
  before it builds.
- A new site refuses apps registering themselves until an admin allows it; an upgraded site keeps them allowed.

## [0.2.0] - 2026-11-10

Toda.Guard is now AbpGuard, a product of its own. Same code, tables and migrations, under new package ids and
namespaces, with neutral defaults for every name it writes. A host that ran Toda.Guard keeps its sessions, tokens and
protected data by setting the names it shipped with: see `docs/upgrading.md`.

The repository moved to [tekthar/abp-guard](https://github.com/tekthar/abp-guard), with its history.

### Changed

- **Packages and namespaces:** `Toda.Guard.Contracts`, `Toda.Guard.Acting` and `Toda.Guard` are `AbpGuard.Contracts`,
  `AbpGuard.Acting` and `AbpGuard`; namespaces follow. `TodaGuardModule` is `AbpGuardModule`, the admin policy is
  `GuardAdmin`, and the authentication schemes are `GuardBearer`, `GuardSession` and `GuardToken`.
- **Neutral defaults for the names Guard writes** (each still set by `Guard:Names`, `Guard:Cookies` and the rest):
  cookies `guard_session`, `guard_csrf`, `guard_embedded`; claims and app properties `guard_*`; the anti-forgery header
  `X-Guard-Csrf`; token prefixes `guard_pat_`, `guard_app_`, `guard_cs_`; scopes `api` and `api.read`; clients `web` and
  `mobile`; the second step's grant type `urn:abpguard:grant-type:second-factor`; the Data Protection purposes' prefix
  `AbpGuard`; groups `admins` and `users`. **Breaking** for a host that relied on the defaults: set the old names.
- **Error codes:** `Guard:Forbidden` and `Guard:TooManyRequests`. **Breaking** for clients that check the code.
- **Texts:** Guard's own texts mark the product's name, which comes from `Guard:Texts:ProductName`, else "AbpGuard".
  The seed's default names and the samples name no product.
- The personal-data declaration's JSON schema id is `urn:abpguard:personal-data@1`.
- Comments no longer cite design records by number.

### Added

- `scripts/check-names.sh`, run by CI on the sources and on the packages: the old product's name comes back nowhere.

## [0.1.0] - 2026-10-31

The fixes from a security review of 0.1.0-preview.1, which they all affect: update, and stop using the preview.

### Security

- Setting up an authenticator app with a sign-in ticket is refused when the ticket's second step is a code the site
  sends (email or a channel). Before, a password alone could put in an app of one's own there and pass the step without
  the code.
- A password reset ends what the old password signed in: browser sessions, the phone app's and scripts' sign-ins, and
  personal access tokens (apps a person allowed stay, as when they sign out everywhere). It is in the security log
  as `auth.password.reset`.
- A sign-up's confirmation link works only for the password that sign-up set: signing up again for the same address
  before confirming makes the links mailed before stop working.
- Sign-in, step-up and second-step limits take a try before the password or code is checked, and sending codes takes
  from its limits before a code is made, so requests sent at once can't go past a limit. A wrong password for a merged
  account counts toward the limit as any other.
- A security event keeps at most 256 characters of the username it was given.
- A recovery code, an emailed code, an authenticator's step and a sign-in ticket each pass once, however many requests
  use them together.
- The default messenger writes each header on one line: a name, address or subject with a line break no longer starts
  a header of its own.
- An access token is checked against its entry and its sign-in on every request: revoking it, revoking the app's
  permission, signing out everywhere, a lock or a merge stops it at once, not when its 15 minutes run out.
- With `Features:PersonalTokens` off, no personal access token signs in, those issued before included.
- A merge right short of an admin's lists, reads and resumes only the merges of accounts it may merge; resuming takes a
  step-up.
- CI pins each action by commit SHA, and Dependabot keeps the pins current.
- A sign-in refused before a password was checked (no such username, an account that can't sign in) takes as long as a
  wrong password, so its speed doesn't tell which usernames exist.
- Sign-in limits count a username's wrong passwords per IP address (5 in 15 minutes), with a cap of 50 from anywhere:
  guesses from elsewhere no longer lock a person out. A right step-up while the name is blocked answers
  `too_many_attempts` (429) and keeps the session; only the session's own wrong password at the limit ends it.
- Creating an account, a service account or a group, locking an account, removing an address and saving privacy
  settings ask for a step-up, as an admin's other changes do; a test keeps every new admin change to that.
- `Guard:Seed:AdminPassword` needs at least 10 characters when the admin is made. The sample host keeps its password in
  `appsettings.Development.json`, so a copy started in Production needs one of its own.
- Sign-in, handoff and consent redirects go through ASP.NET's `LocalRedirect` as well as Guard's own check: only a path
  of this site, whatever a request or a misconfigured `Pages:Consent` says.
- A data export is in the security log before its first byte goes out, and `privacy.export.ended` says after whether it
  finished (with what it held) or was cut off: a download stopped part way is logged too.
- An app is granted `offline_access`, and so a refresh token, only when it asked for it.
- With `Features:OAuthApps` off, the code flow and the authorization endpoint go too, discovery names neither them nor
  the registration endpoint, and apps' tokens issued before stop (their refresh is refused). With `ClientRegistration`
  off, discovery no longer names the registration endpoint.

### Changed

- A data export's own entry in the security log (`privacy.export.self`, `.account`, `.address`) now holds
  `{ state: "started", files }`; what it held is in the `privacy.export.ended` entry that follows it.
- One OpenIddict version for all its packages (7.7.1), and no explicit `Microsoft.Extensions.Identity.Core` (it comes
  with ASP.NET Core).

- Adding, removing or choosing an account's addresses (`POST /api/guard/accounts/{id}/emails`,
  `DELETE …/emails/{emailId}`, `PUT …/mail-to`) needs the Admin policy; an `update` right on accounts no longer
  reaches them. A person adds their own at `/api/guard/me/emails`, through a mailed link. **Breaking** for a host whose
  roles relied on `update`.
- Merging an account with a right short of an admin's is refused when the merger would be the survivor, or the account
  merged away holds grants or memberships added in Guard.
- Locking, unlocking or resetting the second factors of an account with an administrator's rights needs an
  administrator, whatever the actor's role says (the seeded Directory helpdesk's included).
- Allowing an app at `/connect/authorize` takes the browser's session: any bearer token is refused, the phone's and
  scripts' from the token endpoint too.
- Display names with a line break or another control character are refused at sign-up, and when an admin creates an
  account or a service account.

## [0.1.0-preview.1] - 2026-10-29

Extracted from Toda at 19563f7d, with its history for these paths. The first version as packages on nuget.org:
`Toda.Guard.Contracts`, `Toda.Guard.Acting` and `Toda.Guard`.

### Added

- Directories, accounts (people, service accounts and agents), groups, sign-in with web sessions and OpenIddict,
  OAuth apps, personal access tokens, step-up, two-factor sign-in, self-service sign-up and password reset,
  authorization with CASL .NET, and the security log.
- `GuardOptions` for everything a host sets: addresses and pages (with `{lang}`), cookies, clients, the API scope,
  features, the messenger's folder, the texts and product name, sign-up's default, the seeded names and two-factor.
- `GuardNames` (`Guard:Names`): the names Guard writes into tokens, headers, stored rows and protected data.
- `IServiceAccounts`: service accounts, and their tokens, made from a host's own code.
- Seams with defaults a host may replace: `IGuardMessenger`, `IGuardLocks`, `IGuardRateLimits`, `IGuardEventSink`,
  `IGuardBroadcast`, `IGuardSiteDefaults`, `ISignUpChallenges` and `ITokenRestrictions`.
- `AddGuardKeyRing`, with an optional certificate to encrypt the key ring at rest.
- `samples/Toda.Guard.SampleHost`, a host with the defaults only, and integration tests against PostgreSQL.
