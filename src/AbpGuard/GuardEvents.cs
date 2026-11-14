namespace AbpGuard.Controllers;

/// <summary>Guard's events to the host's sink (<see cref="IGuardEventSink"/>), by their type: what the services and the API publish.</summary>
public static class GuardEvents
{
    public static Task PublishAsync(IGuardEventSink publisher, object e, CancellationToken cancellationToken = default) => e switch
    {
        AccountCreatedEto x => publisher.PublishAsync(x, cancellationToken),
        AccountUpdatedEto x => publisher.PublishAsync(x, cancellationToken),
        AccountDeactivatedEto x => publisher.PublishAsync(x, cancellationToken),
        AccountReactivatedEto x => publisher.PublishAsync(x, cancellationToken),
        AccountChangedEto x => publisher.PublishAsync(x, cancellationToken),
        AccountErasedEto x => publisher.PublishAsync(x, cancellationToken),
        AccountMergedEto x => publisher.PublishAsync(x, cancellationToken),
        GroupCreatedEto x => publisher.PublishAsync(x, cancellationToken),
        MembershipChangedEto x => publisher.PublishAsync(x, cancellationToken),
        DirectorySyncCompletedEto x => publisher.PublishAsync(x, cancellationToken),
        _ => Task.CompletedTask,
    };
}
