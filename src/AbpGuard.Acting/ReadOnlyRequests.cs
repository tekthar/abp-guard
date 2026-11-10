using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AbpGuard.Acting;

/// <summary>
/// Marks an endpoint that changes nothing although it isn't a GET: a query, an export, a preview, a plan. A request
/// that may only read (a read-only token now, an impersonation later) may call it.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class ReadsAttribute : Attribute;

/// <summary>
/// Keeps a request that may only read to reading: GET, HEAD and OPTIONS, and endpoints marked
/// <see cref="ReadsAttribute"/>. Anything else is refused before it runs, plugin endpoints included, so an endpoint
/// nobody marked fails safe.
/// </summary>
public sealed class ReadOnlyRequests(RequestDelegate next)
{
    public const string ErrorCode = "read_only";

    public async Task InvokeAsync(HttpContext http)
    {
        if (!HttpMethods.IsGet(http.Request.Method) && !HttpMethods.IsHead(http.Request.Method) && !HttpMethods.IsOptions(http.Request.Method)
            && http.GetEndpoint()?.Metadata.GetMetadata<ReadsAttribute>() is null
            && http.RequestServices.GetRequiredService<ActingContext>().ReadOnly)
        {
            http.Response.StatusCode = StatusCodes.Status403Forbidden;
            await http.Response.WriteAsJsonAsync(new { error = new { code = ErrorCode, message = "This token can only read." } }, http.RequestAborted);
            return;
        }

        await next(http);
    }
}
