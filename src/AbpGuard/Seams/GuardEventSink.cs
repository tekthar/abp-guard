using Volo.Abp.EventBus.Distributed;

namespace AbpGuard;

/// <summary>
/// Where Guard's events go: published in the unit of work that makes the change, so they commit with it.
/// The default hands them to ABP's distributed event bus, into Guard's own outbox; a host may send them its own way
///. Always called with the event's own type.
/// </summary>
public interface IGuardEventSink
{
    Task PublishAsync<TEvent>(TEvent eventData, CancellationToken cancellationToken = default) where TEvent : GuardEvent;
}

/// <summary>The default sink: ABP's distributed event bus, through Guard's outbox once the unit of work completes.</summary>
public sealed class DistributedGuardEventSink(IDistributedEventBus bus) : IGuardEventSink
{
    public Task PublishAsync<TEvent>(TEvent eventData, CancellationToken cancellationToken = default) where TEvent : GuardEvent =>
        bus.PublishAsync(eventData, onUnitOfWorkComplete: true, useOutbox: true);
}
