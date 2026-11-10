using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Volo.Abp.AspNetCore.ExceptionHandling;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.ExceptionHandling;
using Volo.Abp.Http;

namespace AbpGuard.Controllers;

/// <summary>
/// Guard's refusals answer with their JSON error and status (400, 403, 429) whatever the client accepts. ABP
/// turns an exception into JSON only for an action with an object result or a client that asks for JSON; a download's
/// fetch (Accept: */*) or an action answering with NoContent or a file got a server error page instead. This does what
/// ABP would have done, the same body and status, exactly where ABP leaves the exception unhandled, so nothing ABP
/// answers changes. An action that answers its errors itself (the phone's handoff redirects to sign-in) is left alone.
/// </summary>
public sealed class GuardErrorsAttribute() : TypeFilterAttribute(typeof(GuardErrorsFilter));

/// <summary>Marks an action whose refusals aren't JSON (a redirect a browser follows): <see cref="GuardErrorsAttribute"/> leaves it alone.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class AnswersItsOwnErrorsAttribute : Attribute;

public sealed class GuardErrorsFilter(
    IExceptionToErrorInfoConverter converter,
    IHttpExceptionStatusCodeFinder statusCodes,
    IOptions<AbpExceptionHandlingOptions> handling,
    ILogger<GuardErrorsFilter> logger) : IAsyncExceptionFilter
{
    public async Task OnExceptionAsync(ExceptionContext context)
    {
        if (context.ExceptionHandled || AbpAnswersIt(context)
            || context.ActionDescriptor.EndpointMetadata.OfType<AnswersItsOwnErrorsAttribute>().Any())
        {
            return;
        }

        logger.LogException(context.Exception);
        RemoteServiceErrorInfo error = converter.Convert(context.Exception, options =>
        {
            options.SendExceptionsDetailsToClients = handling.Value.SendExceptionsDetailsToClients;
            options.SendStackTraceToClients = handling.Value.SendStackTraceToClients;
            options.SendExceptionDataToClientTypes = handling.Value.SendExceptionDataToClientTypes;
        });
        context.HttpContext.Response.Headers[AbpHttpConsts.AbpErrorFormat] = "true";
        context.Result = new ObjectResult(new RemoteServiceErrorResponse(error))
        {
            StatusCode = (int)statusCodes.GetStatusCode(context.HttpContext, context.Exception),
            ContentTypes = { "application/json" },
        };
        context.ExceptionHandled = true;
        await Task.CompletedTask;
    }

    /// <summary>Where ABP's own exception filter answers with JSON already: an object result, or a client that takes JSON.</summary>
    private static bool AbpAnswersIt(ExceptionContext context) =>
        (context.ActionDescriptor.IsControllerAction() && context.ActionDescriptor.HasObjectResult())
        || context.HttpContext.Request.CanAccept(MimeTypes.Application.Json)
        || context.HttpContext.Request.IsAjax();
}
