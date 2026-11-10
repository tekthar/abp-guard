using AbpGuard.Data;
using Volo.Abp.DependencyInjection;
using Volo.Abp.EntityFrameworkCore;
using Volo.Abp.Uow;

namespace AbpGuard.Services;

/// <summary>
/// Runs work against GuardDbContext in a unit of work: the current one, or a new one when <c>requiresNew</c> says so
/// (the same as the platform's ModuleDb, which Guard no longer references). A host's way of making several
/// modules' work one transaction (a host's, for edits that span modules) doesn't reach
/// Guard: Guard is only read on that path today, but a Guard write a scheduled change caused would commit on its own and
/// survive a preview's rollback.
/// </summary>
public class GuardDb(IUnitOfWorkManager unitOfWorkManager, IDbContextProvider<GuardDbContext> provider) : ITransientDependency
{
    // The token stays before isTransactional (CA1068 would have it last): hundreds of callers pass requiresNew and the
    // token by position.
#pragma warning disable CA1068
    public async Task<T> RunAsync<T>(Func<GuardDbContext, Task<T>> work, bool requiresNew = false, CancellationToken cancellationToken = default, bool isTransactional = false)
    {
        using IUnitOfWork uow = unitOfWorkManager.Begin(requiresNew: requiresNew, isTransactional: isTransactional);
        GuardDbContext db = await provider.GetDbContextAsync();
        T result = await work(db);
        await uow.CompleteAsync(cancellationToken);
        return result;
    }

    public Task RunAsync(Func<GuardDbContext, Task> work, bool requiresNew = false, CancellationToken cancellationToken = default, bool isTransactional = false) =>
        RunAsync<bool>(async db => { await work(db); return true; }, requiresNew, cancellationToken, isTransactional);
#pragma warning restore CA1068
}
