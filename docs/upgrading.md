# Moving from Toda.Guard to AbpGuard

AbpGuard 0.2.0 is Toda.Guard renamed: the same code, tables and migrations under new package ids and namespaces, with
neutral defaults for every name it writes. A host that ran Toda.Guard 0.1.x keeps its sessions, tokens and protected
data by setting the names it shipped with. Those names belong in the host's own configuration or code: AbpGuard
carries none of them.

This file is the one place in the repository that lists the old names, so a host can copy them. It isn't packed.

## 1. Packages and code

| Before | After |
|---|---|
| `Toda.Guard.Contracts` | `AbpGuard.Contracts` |
| `Toda.Guard.Acting` | `AbpGuard.Acting` |
| `Toda.Guard` | `AbpGuard` |
| namespace `Toda.Guard` (and below) | `AbpGuard` (and below) |
| `TodaGuardModule`, `TodaGuardActingModule` | `AbpGuardModule`, `AbpGuardActingModule` |
| policy `TodaAdmin` (`GuardPolicies.Admin`) | `GuardAdmin` |
| schemes `TodaBearer`, `TodaSession`, `TodaToken` | `GuardBearer`, `GuardSession`, `GuardToken` |

Code that uses the constants (`GuardPolicies.Admin`, `WebSessionHandler.SchemeName`, `PersonalTokenHandler.SchemeName`,
`AbpGuardModule.GuardBearer`) needs only a rebuild. Policy and scheme names never leave the server.

## 2. The names to keep

Set these before the first start on AbpGuard, in `appsettings.json` or in code before Guard reads its settings:

```json
{
  "Guard": {
    "Cookies": { "Session": "toda_session", "Csrf": "toda_csrf", "Embedded": "toda_embedded" },
    "Clients": { "Web": "toda-web", "Mobile": "toda-mobile" },
    "ApiScope": "toda.api",
    "AdminsGroupName": "toda-admins",
    "Seed": { "UsersGroupName": "toda-users" },
    "Texts": { "ProductName": { "en": "Toda", "ar": "تودا" } },
    "Names": {
      "SessionClaim": "toda_session",
      "ModeClaim": "toda_mode",
      "TokenClaim": "toda_token",
      "TokenAccessClaim": "toda_token_access",
      "TokenProjectClaim": "toda_token_project",
      "TokenToolClaim": "toda_token_tool",
      "CsrfHeader": "X-Toda-Csrf",
      "CsrfSalt": "toda-csrf:",
      "PersonalTokenPrefix": "toda_pat_",
      "AppIdPrefix": "toda_app_",
      "AppSecretPrefix": "toda_cs_",
      "AppKindProperty": "toda_kind",
      "AppAccessProperty": "toda_access",
      "ReadScope": "toda.read",
      "SecondFactorGrantType": "urn:toda:grant-type:second-factor",
      "ProtectionPrefix": "Toda.Guard",
      "ImportedDirectorySalt": "toda-imported-directory:",
      "FeedSignatureHeader": "X-Toda-Signature"
    }
  }
}
```

What each keeps working:

- **Cookies, `SessionClaim`, `CsrfHeader`, `CsrfSalt`:** browsers stay signed in, and pages keep sending the
  anti-forgery header they send today.
- **`PersonalTokenPrefix`:** personal access tokens already issued keep signing in. To give new tokens a new prefix,
  set it and list the old one in `AcceptedTokenPrefixes`, for as long as old tokens live.
- **`Token*Claim`, `ModeClaim`, `App*`, `ReadScope`, `ApiScope`, `Clients`:** refresh tokens, app permissions and
  clients registered in the database keep matching.
- **`SecondFactorGrantType`:** apps that send the second step to the token endpoint keep working.
- **`ProtectionPrefix`:** authenticator apps' secrets, directories' passwords and links already mailed stay readable.
  Keep `SetApplicationName(...)` on the Data Protection builder as it was too.
- **`ImportedDirectorySalt`:** imported directories keep the ids they were given.
- **`FeedSignatureHeader`:** a receiver of the security log's feed set up under the old name keeps finding the
  signature where it looks for it (from 0.3.0, for a host whose own Guard had the feed before).
- **`AdminsGroupName`, `Seed`, `Texts:ProductName`:** names Guard shows and the product named in its mails. The groups
  themselves are found by id, so a site already seeded keeps its rights either way.

## 3. What changes regardless

- **Error codes:** refusals carry `Guard:Forbidden` and `Guard:TooManyRequests` instead of the old `Toda:` codes.
  Clients that check the code check the new one. The status codes are unchanged.
- **The JSON schema of a plugin's personal-data declaration** has the id `urn:abpguard:personal-data@1`. The
  extension point a manifest names is still `guard.personal-data@1`.

## 4. The database

Nothing to do. The tables stay in the `guard` schema, the migrations keep their ids, and the rename adds no migration:
`dotnet ef migrations script` gives the same SQL before and after it.
