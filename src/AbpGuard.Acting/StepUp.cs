using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Volo.Abp;
using AbpGuard;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Acting;

/// <summary>How recently a person must have proved who they are to do something sensitive. Guard keeps it.</summary>
public interface IStepUpPolicy
{
    Task<TimeSpan> WindowAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Step-up: before a sensitive action the person proves again, recently, that they are who the session
/// says. Refuses with 403 <c>step_up_required</c> unless the token says they signed in or stepped up within the
/// window. The list of sensitive actions is kept in; marking an action is <see cref="StepUpAttribute"/>, or
/// <see cref="EnsureAsync"/> when only some inputs make it sensitive (replacing a stored password).
/// </summary>
public class StepUpGuard(ActingContext acting, IStepUpPolicy policy) : ITransientDependency
{
    public async Task EnsureAsync(CancellationToken cancellationToken = default)
    {
        // A personal access token can't step up: a stolen one must never change who may do what.
        if (acting.TokenId is not null)
        {
            throw new UserFriendlyException("A personal access token can't do this: it changes who may do what or reveals a secret. Sign in to do it.",
                GuardErrorCodes.Forbidden);
        }

        TimeSpan window = await policy.WindowAsync(cancellationToken);
        if (acting.AuthTime is { } proved && DateTimeOffset.UtcNow - proved <= window)
        {
            return;
        }

        throw new UserFriendlyException("Confirm your password to do this.", GuardErrorCodes.StepUpRequired)
            .WithData("maxAgeSeconds", (int)window.TotalSeconds);
    }
}

/// <summary>Marks a sensitive action: it needs a sign-in or a step-up within the site's window.</summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class StepUpAttribute() : TypeFilterAttribute(typeof(StepUpFilter));

public sealed class StepUpFilter(StepUpGuard guard) : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        await guard.EnsureAsync(context.HttpContext.RequestAborted);
        await next();
    }
}
