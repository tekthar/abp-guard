using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using AbpGuard.Controllers;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using AbpGuard.Data;
using AbpGuard.Domain;
using AbpGuard.Directories;
using AbpGuard.Services;
using Volo.Abp.EntityFrameworkCore;
using Volo.Abp.EntityFrameworkCore.DistributedEvents;
using Volo.Abp.EventBus.Distributed;
using Volo.Abp.Modularity;

namespace AbpGuard;

[DependsOn(typeof(AbpGuardActingModule), typeof(Volo.Abp.AspNetCore.Mvc.AbpAspNetCoreMvcModule),
    typeof(Volo.Abp.EntityFrameworkCore.PostgreSql.AbpEntityFrameworkCorePostgreSqlModule))]
public class AbpGuardModule : AbpModule
{
    /// <summary>The default authentication scheme: it sends each bearer token to the handler for its kind, and a browser's cookie to its session's.</summary>
    public const string GuardBearer = "GuardBearer";

    public const string Version = "0.3.0";

    /// <summary>
    /// The scheme for a request: a personal access token, any other bearer token (OpenIddict's), or with no
    /// bearer token a browser's session cookie. A bearer token always wins, so a phone or tool never acts on a cookie.
    /// </summary>
    public static string SchemeFor(Microsoft.AspNetCore.Http.HttpRequest request) =>
        PersonalTokenHandler.Carries(request) ? PersonalTokenHandler.SchemeName
        : request.Headers.Authorization.Count == 0 && WebSessionHandler.Carries(request) ? WebSessionHandler.SchemeName
        : OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

    /// <summary>What Guard's outbox carries: every concrete GuardEvent, the contracts' *Eto records.</summary>
    public static bool Carries(Type type) => typeof(GuardEvent).IsAssignableFrom(type) && !type.IsAbstract;

    public override void ConfigureServices(ServiceConfigurationContext context)
    {
        IConfiguration configuration = context.Services.GetConfiguration();

        context.Services.AddAbpDbContext<GuardDbContext>();
        // ABP's clock in UTC: the outbox stamps its rows with it, and Postgres takes only UTC in timestamptz.
        // A host that sets another kind is told at start (OnApplicationInitialization).
        Configure<Volo.Abp.Timing.AbpClockOptions>(options => options.Kind = DateTimeKind.Utc);
        // Where Guard's events go: ABP's distributed bus and Guard's outbox, unless the host says otherwise.
        context.Services.TryAddTransient<IGuardEventSink, DistributedGuardEventSink>();
        // Locks every server shares: Postgres advisory locks on Guard's database, unless the host gives its own.
        context.Services.TryAddSingleton<IGuardLocks, PostgresGuardLocks>();
        // What Guard's limits count with: guard.rate_limits, unless the host gives its own.
        context.Services.TryAddSingleton<IGuardRateLimits, PostgresGuardRateLimits>();
        // Guard's settings, and the site's defaults from them unless the host has its own.
        context.Services.Configure<GuardOptions>(configuration.GetSection(GuardOptions.Section));
        context.Services.TryAddTransient<IGuardSiteDefaults, OptionsGuardSiteDefaults>();
        // What the host uses of Guard: a feature switched off loses its endpoints.
        context.Services.AddOptions<Microsoft.AspNetCore.Mvc.MvcOptions>()
            .Configure<Microsoft.Extensions.Options.IOptions<GuardOptions>>((mvc, guard) => mvc.Conventions.Add(new GuardFeatureConvention(guard.Value.Features)));
        // No tools for tokens to be limited to, and no challenge on sign-up, unless the host has them.
        context.Services.TryAddTransient<ITokenRestrictions, NoTokenRestrictions>();
        context.Services.TryAddTransient<ISignUpChallenges, NoSignUpChallenges>();
        // How Guard reaches people: its own texts to a pickup folder, unless the host sends them its way.
        context.Services.TryAddTransient<IGuardMessenger, PickupGuardMessenger>();
        Configure<AbpDbContextOptions>(options =>
            options.Configure<GuardDbContext>(c => c.UseNpgsql(npgsql =>
                npgsql.MigrationsHistoryTable("__EFMigrationsHistory", GuardDbContext.Schema))));
        Configure<AbpDistributedEventBusOptions>(options => options.Outboxes.Configure(GuardDbContext.Schema, outbox =>
        {
            outbox.UseDbContext<GuardDbContext>();
            // The outbox sender's lock is named after this: the module's own, or Projects' sender and this one wait on each other.
            outbox.DatabaseName = GuardDbContext.Schema;
            outbox.Selector = Carries;
        }));

        // Sign-in: OpenIddict issues short-lived access tokens and rotating refresh tokens to the
        // first-party Next.js server; APIs validate them locally.
        // Their keys: certificates, a folder mounted from a secret store, or Postgres (made once, shared by every node).
        // Where the key files of before are looked for: Guard:DataRoot.
        string dataRoot = Path.GetFullPath(DataRoot(configuration) ?? context.Services.ExecutePreConfiguredActions<GuardStartupOptions>().DataRoot
            ?? Path.Combine(context.Services.GetHostingEnvironment().ContentRootPath, "App_Data"));
        (SecurityKey signingKey, SecurityKey encryptionKey) = OidcKeys.Resolve(configuration, dataRoot);

        context.Services.AddDbContext<OidcDbContext>(options =>
        {
            options.UseNpgsql(GuardConnection.Of(configuration),
                npgsql => npgsql.MigrationsHistoryTable(OidcDbContext.HistoryTable, GuardDbContext.Schema));
            options.UseOpenIddict<Guid>();
        });

        // The host's API scope (GuardOptions.ApiScope, api by default), the read scope and the second step's grant
        // (GuardNames), as the host configured them.
        context.Services.AddOptions<OpenIddict.Server.OpenIddictServerOptions>()
            .Configure<Microsoft.Extensions.Options.IOptions<GuardOptions>, Microsoft.Extensions.Options.IOptions<GuardNames>>((server, guard, names) =>
            {
                server.Scopes.Add(guard.Value.ApiScope);
                server.Scopes.Add(names.Value.ReadScope);
                server.GrantTypes.Add(names.Value.SecondFactorGrantType);
            })
            // Apps switched off (Features:OAuthApps): no authorization endpoint and no code flow, so nothing is left of
            // them to reach. After OpenIddict's own configuration, which allows the flow.
            .PostConfigure<Microsoft.Extensions.Options.IOptions<GuardOptions>>((server, guard) =>
            {
                if (!guard.Value.Features.OAuthApps)
                {
                    server.AuthorizationEndpointUris.Clear();
                    server.GrantTypes.Remove(OpenIddictConstants.GrantTypes.AuthorizationCode);
                    server.ResponseTypes.Remove(OpenIddictConstants.ResponseTypes.Code);
                }
            });
        context.Services.AddOpenIddict()
            .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<OidcDbContext>().ReplaceDefaultEntities<Guid>())
            .AddServer(options =>
            {
                options.SetTokenEndpointUris("connect/token")
                    .SetRevocationEndpointUris("connect/revoke")
                    // Apps and agents: the authorization code flow, always with PKCE, behind a consent page.
                    .SetAuthorizationEndpointUris("connect/authorize");
                options.AllowPasswordFlow().AllowRefreshTokenFlow().AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
                options.RegisterScopes(OpenIddictConstants.Scopes.OfflineAccess);
                // Revoking the phone app's (or a script's) refresh token ends its whole sign-in.
                options.AddEventHandler(EndSignInOnRevocation.Descriptor);
                // MCP clients register themselves (RFC 7591) at the endpoint the discovery document names.
                options.AddEventHandler<OpenIddict.Server.OpenIddictServerEvents.HandleConfigurationRequestContext>(handler => handler.UseInlineHandler(context =>
                {
                    if (context.Issuer is { } issuer)
                    {
                        // Only what's on: apps (Features:OAuthApps), and their registering themselves (ClientRegistration).
                        GuardFeatures features = context.Transaction.GetHttpRequest()!.HttpContext.RequestServices
                            .GetRequiredService<Microsoft.Extensions.Options.IOptions<GuardOptions>>().Value.Features;
                        if (features.OAuthApps && features.ClientRegistration)
                        {
                            context.Metadata["registration_endpoint"] = new Uri(issuer, "connect/register").AbsoluteUri;
                        }

                        // Behind the web app, the endpoints are where the issuer is (the site's public address), not
                        // where this request came in.
                        context.AuthorizationEndpoint = features.OAuthApps ? new Uri(issuer, "connect/authorize") : null;
                        context.TokenEndpoint = new Uri(issuer, "connect/token");
                        context.RevocationEndpoint = new Uri(issuer, "connect/revoke");
                        context.JsonWebKeySetEndpoint = new Uri(issuer, ".well-known/jwks");
                    }

                    return default;
                    // After OpenIddict sets the issuer, before it fills in the endpoints still empty. Not the issuer's own
                    // order: with two handlers on one order, which runs first changes as handlers are added.
                }).SetOrder(OpenIddict.Server.OpenIddictServerHandlers.Discovery.AttachIssuer.Descriptor.Order + 500));
                // PKCE with S256 only: "plain" would hand the verifier over in the clear (MCP requires S256).
                options.Configure(server => server.CodeChallengeMethods.Remove(OpenIddictConstants.CodeChallengeMethods.Plain));
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15))
                    .SetRefreshTokenLifetime(TimeSpan.FromDays(14))
                    .SetRefreshTokenReuseLeeway(TimeSpan.FromSeconds(30));
                options.AddSigningKey(signingKey).AddEncryptionKey(encryptionKey);
                if (configuration["Guard:Oidc:Issuer"] is { Length: > 0 } issuer)
                {
                    options.SetIssuer(new Uri(issuer));
                }

                OpenIddictServerAspNetCoreBuilder aspNetCore = options.UseAspNetCore().EnableTokenEndpointPassthrough().EnableAuthorizationEndpointPassthrough();
                if (configuration.GetValue("Guard:Oidc:AllowHttp", false))
                {
                    aspNetCore.DisableTransportSecurityRequirement();
                }
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
                // Each request checks the token's own entry and its sign-in's: revoking either, signing out everywhere,
                // a lock or a merge stops an access token at once, not when its 15 minutes run out.
                options.EnableTokenEntryValidation();
                options.EnableAuthorizationEntryValidation();
                // Apps switched off: their access tokens, issued before, stop too (their refresh is refused at the token endpoint).
                options.AddEventHandler<OpenIddict.Validation.OpenIddictValidationEvents.ProcessAuthenticationContext>(handler => handler.UseInlineHandler(context =>
                {
                    IServiceProvider services = context.Transaction.GetHttpRequest()!.HttpContext.RequestServices;
                    if (!services.GetRequiredService<Microsoft.Extensions.Options.IOptions<GuardOptions>>().Value.Features.OAuthApps
                        && context.AccessTokenPrincipal?.HasClaim(services.GetRequiredService<Microsoft.Extensions.Options.IOptions<GuardNames>>().Value.TokenClaim) == true)
                    {
                        context.Reject(OpenIddictConstants.Errors.InvalidToken, "Apps are switched off on this site.");
                    }

                    return default;
                }).SetOrder(OpenIddict.Validation.OpenIddictValidationHandlers.ValidateAccessToken.Descriptor.Order + 1_000));
                // A token made under the names a site used before reads as made under today's (GuardNames.Former).
                options.AddEventHandler(TokenNamesOfToday.Descriptor);
            });

        // A bearer token is either an access token from the token endpoint (OpenIddict) or a personal access token. A
        // request without one is a browser's, signed in by its session cookie.
        context.Services.AddMemoryCache();
        // A session ended or stepped up on another server is forgotten here at once (docs/ha.md step 2).
        context.Services.AddSingleton<IGuardBroadcastHandler, Services.WebSessionChanged>();
        // Telling the other servers: no one to tell on a site of one server, unless the host has several.
        context.Services.TryAddSingleton<IGuardBroadcast, SingleServerGuardBroadcast>();
        // Directory connectors and merge participants: the host's own from DI, unless the host has plugins.
        context.Services.TryAddSingleton<IGuardExtensions, ServiceGuardExtensions>();
        context.Services.AddAuthentication(GuardBearer)
            .AddPolicyScheme(GuardBearer, null, options => options.ForwardDefaultSelector = http => SchemeFor(http.Request))
            .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, PersonalTokenHandler>(PersonalTokenHandler.SchemeName, null)
            .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, WebSessionHandler>(WebSessionHandler.SchemeName, null);

        // Anti-forgery for the session cookie is the handler's own check (the X-Guard-Csrf header); ABP's, for its own
        // cookie schemes, doesn't apply.
        Configure<Volo.Abp.AspNetCore.Mvc.AntiForgery.AbpAntiForgeryOptions>(options => options.AutoValidate = false);

        context.Services.AddAuthorizationBuilder()
            .AddPolicy(GuardPolicies.Admin, policy => policy.RequireAuthenticatedUser().AddRequirements(new GuardAdminRequirement()));
        context.Services.AddTransient<IAuthorizationHandler, GuardAdminHandler>();

        context.Services.AddHostedService<DirectorySyncScheduler>();
        context.Services.AddHostedService<SecurityAuditRetention>();
        context.Services.AddHostedService<Services.Privacy.PersonalDataRetentionWorker>();
        context.Services.TryAddSingleton<ISecurityFeedSender>(_ => new HttpSecurityFeedSender());
        context.Services.AddHostedService<Services.SecurityFeedWorker>();
        context.Services.AddHostedService<Services.SecurityAlertsWorker>();
    }

    /// <summary>Guard's data folder from its settings, Guard:DataRoot, or null (then the host's, <see cref="GuardStartupOptions"/>).</summary>
    public static string? DataRoot(IConfiguration configuration) => configuration["Guard:DataRoot"] is { Length: > 0 } root ? root : null;

    /// <summary>Why Guard can't run with ABP's clock as the host set it, or null: it needs UTC.</summary>
    public static string? ClockProblem(Volo.Abp.Timing.AbpClockOptions clock) => clock.Kind == DateTimeKind.Utc ? null
        : $"Guard can't start: ABP's clock is {clock.Kind}, and Guard needs it in UTC (its outbox stamps rows with it, and Postgres "
          + "keeps only UTC times). Leave AbpClockOptions.Kind as Guard sets it, DateTimeKind.Utc.";

    public override void OnApplicationInitialization(Volo.Abp.ApplicationInitializationContext context)
    {
        if (ClockProblem(context.ServiceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<Volo.Abp.Timing.AbpClockOptions>>().Value) is { } clock)
        {
            throw new InvalidOperationException(clock);
        }

        // What Guard protects lives and dies with the key ring: a site that doesn't keep it doesn't start;
        // a developer's machine is told.
        if (GuardKeyRing.Problem(context.ServiceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<Microsoft.AspNetCore.DataProtection.KeyManagement.KeyManagementOptions>>().Value) is { } keyRing)
        {
            if (!context.ServiceProvider.GetRequiredService<IHostEnvironment>().IsDevelopment())
            {
                throw new InvalidOperationException($"Guard can't start: {keyRing}. Keep the key ring where every server and restart reads it, such as Postgres (AddGuardKeyRing).");
            }

            context.ServiceProvider.GetRequiredService<ILogger<AbpGuardModule>>().LogWarning(
                "Guard: {Problem}; what Guard protected (authenticator secrets, mailed links, directory passwords) is lost with it", keyRing);
        }

        // A test site shows accounts' passwords on its sign-in page: said once at start, so a site people use doesn't by mistake.
        if (context.ServiceProvider.GetRequiredService<TestAccounts>().List() is { Count: > 0 } shown)
        {
            context.ServiceProvider.GetRequiredService<ILogger<AbpGuardModule>>().LogWarning(
                "The sign-in page shows {Count} test accounts with their passwords ({Section}): only for a test site", shown.Count, TestAccounts.Section);
        }
    }
}

public sealed class GuardAdminRequirement : IAuthorizationRequirement;

/// <summary>
/// What a host gives Guard before it starts (ABP's PreConfigure): the data folder when Guard:DataRoot isn't set, such as
/// a setting of the host's own that its deployments already have.
/// </summary>
public sealed class GuardStartupOptions
{
    public string? DataRoot { get; set; }
}

/// <summary>
/// Admin = may "manage" "all". Out of the box that comes from the Administrator role, granted to the
/// internal admins group (by id, never by name), so it follows group membership including nesting. The ability
/// is the request's, through the acting context, so a token's limits apply here too.
/// </summary>
public sealed class GuardAdminHandler(AbilityFactory abilities, AbpGuard.Acting.ActingContext acting) : AuthorizationHandler<GuardAdminRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, GuardAdminRequirement requirement)
    {
        if (acting.SubjectId is Guid accountId && (await abilities.ForAccountAsync(accountId)).Can("manage", "all"))
        {
            context.Succeed(requirement);
        }
    }
}
