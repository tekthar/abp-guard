using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Volo.Abp;
using Volo.Abp.AspNetCore.ExceptionHandling;
using Volo.Abp.DependencyInjection;
using Volo.Abp.ExceptionHandling;

namespace AbpGuard;

/// <summary>
/// The statuses Guard's errors answer with, for a host that hasn't chosen its own: a refusal or a step-up
/// needed is 403, too many tries 429, and a business rule that says no to the input (a taken username, a short password,
/// a bad link) 400, where ABP's default would answer 403 and make it look like a permission problem; a code the host
/// mapped itself keeps the host's status. A host with its own finder that does the same keeps it.
/// </summary>
[DisableConventionalRegistration]
public class GuardHttpExceptionStatusCodeFinder(IOptions<AbpExceptionHttpStatusCodeOptions> options) : DefaultHttpExceptionStatusCodeFinder(options)
{
    private readonly AbpExceptionHttpStatusCodeOptions _mappings = options.Value;

    public override HttpStatusCode GetStatusCode(HttpContext httpContext, Exception exception)
    {
        if (exception is IHasErrorCode { Code: { } code })
        {
            switch (code)
            {
                case GuardErrorCodes.Forbidden:
                case GuardErrorCodes.StepUpRequired:
                    return HttpStatusCode.Forbidden;
                case GuardErrorCodes.TooManyRequests:
                    return HttpStatusCode.TooManyRequests;
            }
        }

        // A refused input is 400, where ABP's default would answer 403: for Guard's own codes and codes no one mapped. A
        // code the host mapped itself (AbpExceptionHttpStatusCodeOptions) keeps the host's status, 403 included.
        if (exception is UserFriendlyException or BusinessException && exception is not Volo.Abp.Authorization.AbpAuthorizationException)
        {
            HttpStatusCode mapped = base.GetStatusCode(httpContext, exception);
            return mapped == HttpStatusCode.Forbidden && !HostMapped(exception) ? HttpStatusCode.BadRequest : mapped;
        }

        return base.GetStatusCode(httpContext, exception);
    }

    /// <summary>Whether the exception's code is one the host mapped to a status itself.</summary>
    private bool HostMapped(Exception exception) =>
        exception is IHasErrorCode { Code: { Length: > 0 } code } && _mappings.ErrorCodeToHttpStatusCodeMappings.ContainsKey(code);

    /// <summary>Uses Guard's finder when the host still has ABP's default one; a host's own finder stays.</summary>
    public static void UseUnlessTheHostHasItsOwn(IServiceCollection services)
    {
        ServiceDescriptor? current = services.LastOrDefault(d => d.ServiceType == typeof(IHttpExceptionStatusCodeFinder));
        if (current is null || current.ImplementationType == typeof(DefaultHttpExceptionStatusCodeFinder))
        {
            services.Replace(ServiceDescriptor.Transient<IHttpExceptionStatusCodeFinder, GuardHttpExceptionStatusCodeFinder>());
        }
    }
}
