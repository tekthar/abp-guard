using Microsoft.Extensions.DependencyInjection;
using Volo.Abp.AspNetCore.ExceptionHandling;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Modularity;

namespace AbpGuard;

/// <summary>
/// The error codes Guard answers with: a refusal, a step-up needed (with its <c>level</c>, <c>category</c>,
/// <c>methods</c> and <c>maxAgeSeconds</c> in the error's data), a strong factor needed, and too many tries. Clients tell them apart by status and by <c>step_up_required</c>; the others' names are
/// Guard's own.
/// </summary>
public static class GuardErrorCodes
{
    /// <summary>The person may not do this (a rule refused it). 403.</summary>
    public const string Forbidden = "Guard:Forbidden";

    /// <summary>
    /// A sensitive action needs the person to have proved who they are recently. 403, not 401, which would end
    /// the session; the error's data says how recent (<c>maxAgeSeconds</c>).
    /// </summary>
    public const string StepUpRequired = "step_up_required";

    /// <summary>
    /// A strong step-up is asked of someone with no strong factor yet (a passkey or an authenticator app). 403; the data
    /// names the <c>category</c>, and the prompt offers to set one up.
    /// </summary>
    public const string StrongFactorRequired = "strong_factor_required";

    /// <summary>Too many requests from one place in a while (sign-up, password reset). 429.</summary>
    public const string TooManyRequests = "Guard:TooManyRequests";

    /// <summary>The action doesn't fit the thing as it is now (merged, erased). 409; the codes below say which, where a screen tells them apart.</summary>
    public const string Conflict = "Guard:Conflict";

    /// <summary>Deleting an account something still holds (records, places, roles): deactivate it instead. 409.</summary>
    public const string AccountInUse = "account_in_use";

    /// <summary>Deleting an account a directory keeps: it would come back on the next sync. 409.</summary>
    public const string AccountSynced = "account_synced";

    /// <summary>Deleting an account that has signed in: it has a history. 409.</summary>
    public const string AccountSignedIn = "account_signed_in";

    /// <summary>A person's action asked of a service account (an agent's): it's managed where it was made. 409.</summary>
    public const string ServiceAccount = "service_account";

    /// <summary>A link to mail to an account with no address to mail it to. 409.</summary>
    public const string NoEmail = "no_email";

    /// <summary>A password for an account whose directory keeps its own. 409.</summary>
    public const string NotInternal = "not_internal";

    /// <summary>A role change that would reach past the places anonymous visitors have it in. 409.</summary>
    public const string RoleGivenToAnonymous = "role_given_to_anonymous";

    /// <summary>The codes answered 409.</summary>
    public static readonly string[] Conflicts = [Conflict, AccountInUse, AccountSynced, AccountSignedIn, ServiceAccount, NoEmail, NotInternal, RoleGivenToAnonymous];
}

/// <summary>The acting context's module: its services, and Guard's error codes answered with their own statuses.</summary>
[DependsOn(typeof(AbpAspNetCoreMvcModule))]
public class AbpGuardActingModule : AbpModule
{
    public override void ConfigureServices(ServiceConfigurationContext context)
    {
        Configure<AbpExceptionHttpStatusCodeOptions>(options =>
        {
            options.Map(GuardErrorCodes.Forbidden, System.Net.HttpStatusCode.Forbidden);
            options.Map(GuardErrorCodes.StepUpRequired, System.Net.HttpStatusCode.Forbidden);
            options.Map(GuardErrorCodes.StrongFactorRequired, System.Net.HttpStatusCode.Forbidden);
            options.Map(GuardErrorCodes.TooManyRequests, System.Net.HttpStatusCode.TooManyRequests);
            foreach (string conflict in GuardErrorCodes.Conflicts)
            {
                options.Map(conflict, System.Net.HttpStatusCode.Conflict);
            }
        });
        // The names Guard writes into tokens, cookies and stored data (Guard:Names), as a host gives them.
        context.Services.Configure<GuardNames>(context.Services.GetConfiguration().GetSection(GuardNames.Section));
    }

    /// <summary>After every module has registered its services: Guard's status finder, unless the host has its own.</summary>
    public override void PostConfigureServices(ServiceConfigurationContext context) =>
        GuardHttpExceptionStatusCodeFinder.UseUnlessTheHostHasItsOwn(context.Services);
}
