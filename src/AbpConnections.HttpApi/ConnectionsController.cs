using AbpGuard.Acting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Volo.Abp;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Authorization;
using Volo.Abp.Domain.Entities;
using Volo.Abp.Uow;

namespace AbpConnections;

/// <summary>Where to send the browser to sign a connection in.</summary>
public sealed record ConnectionAuthorizeInput(string RedirectUri);

public sealed record ConnectionAuthorizeAnswer(string Url);

/// <summary>What the provider sent back to the application's sign-in page.</summary>
public sealed record ConnectionCompleteInput(string Code, string State);

/// <summary>
/// Connections over HTTP. A scope's (<c>?scopeId=</c>, the site's without one) are managed by whoever
/// <see cref="IConnectionRights"/> allows; setting a secret, and removing a connection, take a step-up
/// (<see cref="StepUpCategories.Secrets"/>). Each person's own sign-ins are under <c>mine</c>.
/// </summary>
[Route("api/connections")]
[Authorize]
[UnitOfWork(IsDisabled = true)] // the manager keeps its own units of work
[ApiExplorerSettings(IgnoreApi = false)]
public class ConnectionsController(ConnectionManager manager, IConnectionRights rights, ActingContext acting, StepUpGuard stepUp) : AbpControllerBase
{
    private Guid Me => acting.SubjectId ?? throw new AbpAuthorizationException("Not signed in.");

    [HttpGet("types")]
    public async Task<List<ConnectionKindView>> Types([FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        return await manager.KindsAsync(cancellationToken);
    }

    [HttpGet]
    public async Task<List<ConnectionView>> List([FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        return await manager.ListAsync(scopeId, cancellationToken);
    }

    [HttpGet("{id:guid}")]
    public async Task<ConnectionView> Get(Guid id, [FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        return await manager.GetAsync(id, scopeId, cancellationToken);
    }

    [HttpPost]
    public async Task<ConnectionView> Create([FromBody] ConnectionChange change, [FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        if (ConnectionManager.SetsSecrets(change))
        {
            await stepUp.EnsureAsync(StepUpCategories.Secrets, cancellationToken);
        }

        return await manager.CreateAsync(change, scopeId, Me, cancellationToken);
    }

    [HttpPut("{id:guid}")]
    public async Task<ConnectionView> Update(Guid id, [FromBody] ConnectionChange change, [FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        if (ConnectionManager.SetsSecrets(change))
        {
            await stepUp.EnsureAsync(StepUpCategories.Secrets, cancellationToken);
        }

        return await manager.UpdateAsync(id, change, scopeId, cancellationToken);
    }

    [HttpDelete("{id:guid}")]
    [StepUp(StepUpCategories.Secrets)]
    public async Task Delete(Guid id, [FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        await manager.DeleteAsync(id, scopeId, cancellationToken);
    }

    [HttpPost("{id:guid}/test")]
    public async Task<ConnectionView> Test(Guid id, [FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        return await manager.TestAsync(id, scopeId, cancellationToken, Me);
    }

    /// <summary>Where to send the browser to sign a connection in for everyone.</summary>
    [HttpPost("{id:guid}/authorize")]
    public async Task<ConnectionAuthorizeAnswer> Authorize(Guid id, [FromBody] ConnectionAuthorizeInput input, [FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        return new(await manager.AuthorizeAsync(id, scopeId, input.RedirectUri, Me, cancellationToken));
    }

    /// <summary>The provider's answer, from the application's sign-in page: only the person who started it finishes it.</summary>
    [HttpPost("complete")]
    public Task<ConnectionView> Complete([FromBody] ConnectionCompleteInput input, CancellationToken cancellationToken) =>
        manager.CompleteAsync(input.Code, input.State, Me, cancellationToken);

    [HttpPost("{id:guid}/sign-out")]
    public async Task<ConnectionView> SignOut(Guid id, [FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        return await manager.SignOutAsync(id, scopeId, cancellationToken);
    }

    // ---- each person's own sign-ins ----

    /// <summary>The connections each person signs in to that the caller may use, and whether they have.</summary>
    [HttpGet("mine")]
    public async Task<List<PersonalConnectionView>> Mine(CancellationToken cancellationToken) =>
        await manager.PersonalListAsync(Me, await rights.ScopesOfAsync(Me, cancellationToken), cancellationToken);

    /// <summary>Where to send the browser to sign in with the caller's own account.</summary>
    [HttpPost("{id:guid}/mine/authorize")]
    public async Task<ConnectionAuthorizeAnswer> AuthorizeMine(Guid id, [FromBody] ConnectionAuthorizeInput input, CancellationToken cancellationToken)
    {
        ConnectionView connection = await MineAsync(id, cancellationToken);
        return new(await manager.AuthorizeAsync(id, connection.ScopeId, input.RedirectUri, Me, cancellationToken, personal: true));
    }

    /// <summary>Forgets the caller's own sign-in.</summary>
    [HttpDelete("{id:guid}/mine")]
    public async Task SignOutMine(Guid id, CancellationToken cancellationToken)
    {
        await MineAsync(id, cancellationToken);
        await manager.SignOutPersonAsync(id, Me, cancellationToken);
    }

    /// <summary>A connection each person signs in to, in the site or one of the caller's scopes; 404 otherwise.</summary>
    private async Task<ConnectionView> MineAsync(Guid id, CancellationToken cancellationToken)
    {
        ConnectionView? connection = await manager.FindAsync(id, cancellationToken);
        if (connection is not { EachPerson: true }
            || connection.ScopeId is { } scope && !(await rights.ScopesOfAsync(Me, cancellationToken)).Contains(scope))
        {
            throw new EntityNotFoundException(typeof(Connection), id);
        }

        return connection;
    }
}
