using AbpGuard.Acting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Authorization;
using Volo.Abp.Uow;

namespace AbpNotify;

/// <summary>
/// The signed-in person's notices: their inbox (newest first, read or not, whether told now or kept for their digest)
/// and their choices of how they hear of each event.
/// </summary>
[Route("api/notify/me")]
[Authorize]
[UnitOfWork(IsDisabled = true)] // the store keeps its own units of work
[ApiExplorerSettings(IgnoreApi = false)]
public class NotifyInboxController(NoticeStore notices, ActingContext acting) : AbpControllerBase
{
    /// <summary>The inbox, 50 at a time: <c>before</c> the last one shown for the next page; <c>unread</c> for those not read.</summary>
    [HttpGet("notices")]
    public Task<InboxView> Inbox([FromQuery] bool unread, [FromQuery] DateTime? before, CancellationToken cancellationToken) =>
        notices.InboxAsync(Me, unread, before?.ToUniversalTime(), cancellationToken);

    /// <summary>How many the person hasn't read.</summary>
    [HttpGet("notices/unread")]
    public Task<int> Unread(CancellationToken cancellationToken) => notices.UnreadAsync(Me, cancellationToken);

    /// <summary>Marks these read, or all of them; answers how many are left unread.</summary>
    [HttpPost("notices/read")]
    public Task<int> Read([FromBody] InboxReadInput input, CancellationToken cancellationToken) => notices.MarkReadAsync(Me, input, cancellationToken);

    [HttpPost("notices/{id:guid}/unread")]
    public Task<int> MarkUnread(Guid id, CancellationToken cancellationToken) => notices.MarkUnreadAsync(Me, id, cancellationToken);

    [HttpGet("settings")]
    public Task<NotificationSettingsDto> Settings(CancellationToken cancellationToken) => notices.SettingsDtoAsync(Me, cancellationToken);

    [HttpPut("settings")]
    public Task<NotificationSettingsDto> SaveSettings([FromBody] NotificationSettingsInput input, CancellationToken cancellationToken) =>
        notices.SaveSettingsAsync(Me, input, cancellationToken);

    private Guid Me => acting.SubjectId ?? throw new AbpAuthorizationException("Not signed in.");
}

/// <summary>The signed-in person's addresses on the channels that reach people, a typed one verified with a code.</summary>
[Route("api/notify/me/channels")]
[Authorize]
[UnitOfWork(IsDisabled = true)]
[ApiExplorerSettings(IgnoreApi = false)]
public class NotifyMyChannelsController(ChannelAddressBook book, ActingContext acting) : AbpControllerBase
{
    [HttpGet]
    public Task<List<MyChannelDto>> List(CancellationToken cancellationToken) => book.MineAsync(Me, cancellationToken);

    /// <summary>Sends a code to the address typed; it's used once <c>verify</c> gets the code back.</summary>
    [HttpPut("{channel}")]
    public Task<List<MyChannelDto>> Start(string channel, [FromBody] ChannelAddressInput input, CancellationToken cancellationToken) =>
        book.StartAsync(Me, channel, input.Address, cancellationToken);

    /// <summary>Finds the person on a channel that looks people up itself (Slack, by their email).</summary>
    [HttpPost("{channel}/find")]
    public Task<List<MyChannelDto>> Find(string channel, CancellationToken cancellationToken) => book.FindAsync(Me, channel, cancellationToken);

    [HttpPost("{channel}/verify")]
    public Task<List<MyChannelDto>> Verify(string channel, [FromBody] ChannelCodeInput input, CancellationToken cancellationToken) =>
        book.VerifyAsync(Me, channel, input.Code, cancellationToken);

    [HttpDelete("{channel}")]
    public Task<List<MyChannelDto>> Remove(string channel, CancellationToken cancellationToken) => book.RemoveAsync(Me, channel, cancellationToken);

    private Guid Me => acting.SubjectId ?? throw new AbpAuthorizationException("Not signed in.");
}

/// <summary>
/// The signed-in person's phones: the application's app registers its push token on every start and when it changes,
/// and forgets it on sign-out; a person lists theirs and removes one.
/// </summary>
[Route("api/notify/me/devices")]
[Authorize]
[UnitOfWork(IsDisabled = true)]
[ApiExplorerSettings(IgnoreApi = false)]
public class NotifyDevicesController(DeviceBook devices, ActingContext acting) : AbpControllerBase
{
    [HttpGet]
    public Task<List<DeviceDto>> List(CancellationToken cancellationToken) => devices.MineAsync(Me, cancellationToken);

    /// <summary>Registers the phone, or says it's still there; the same token again changes nothing but when it was seen.</summary>
    [HttpPut]
    public Task<DeviceDto> Register([FromBody] DeviceInput input, CancellationToken cancellationToken) => devices.RegisterAsync(Me, input, cancellationToken);

    [HttpDelete("{id:guid}")]
    public async Task<NoContentResult> Remove(Guid id, CancellationToken cancellationToken)
    {
        await devices.UnregisterAsync(Me, id, cancellationToken);
        return NoContent();
    }

    /// <summary>Forgets the phone with this token (the app signing out).</summary>
    [HttpDelete]
    public async Task<NoContentResult> RemoveByToken([FromQuery] string? token, CancellationToken cancellationToken)
    {
        await devices.UnregisterAsync(Me, token, cancellationToken);
        return NoContent();
    }

    private Guid Me => acting.SubjectId ?? throw new AbpAuthorizationException("Not signed in.");
}

/// <summary>
/// How notices are sent, for whoever <see cref="INotifyRights"/> allows: the site's sending settings, the channels there
/// are, and teams' channels to post to, the site's (no <c>scopeId</c>) or a scope's.
/// </summary>
[Route("api/notify")]
[Authorize]
[UnitOfWork(IsDisabled = true)]
[ApiExplorerSettings(IgnoreApi = false)]
public class NotifyAdminController(NoticeStore notices, ChannelTargetStore targets, INotifyRights rights, ActingContext acting) : AbpControllerBase
{
    /// <summary>How long to gather what follows a message, and how many a person gets an hour before the rest wait for their digest.</summary>
    [HttpGet("settings")]
    public async Task<NoticeSiteSettingsDto> Site(CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(null, cancellationToken);
        return await notices.SiteAsync(cancellationToken);
    }

    [HttpPut("settings")]
    public async Task<NoticeSiteSettingsDto> SaveSite([FromBody] NoticeSiteSettingsDto input, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(null, cancellationToken);
        return await notices.SaveSiteAsync(input, cancellationToken);
    }

    [HttpGet("channels")]
    public async Task<List<ChannelDto>> Channels(CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(null, cancellationToken);
        return await targets.ChannelsAsync(cancellationToken);
    }

    /// <summary>The site's teams' channels, or a scope's own and the site's.</summary>
    [HttpGet("targets")]
    public async Task<List<ChannelTargetView>> Targets([FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        return await targets.ListAsync(scopeId, cancellationToken);
    }

    /// <summary>The Slack and Teams connections a scope's teams' channels may go through: the site's, and the scope's own.</summary>
    [HttpGet("targets/connections")]
    public async Task<List<ChannelConnectionDto>> Connections([FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        return await targets.ConnectionsAsync(scopeId, cancellationToken);
    }

    [HttpPost("targets")]
    public async Task<ChannelTargetView> Create([FromBody] ChannelTargetInput input, [FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        return await targets.CreateAsync(scopeId, input, acting.SubjectId ?? throw new AbpAuthorizationException("Not signed in."), cancellationToken);
    }

    [HttpDelete("targets/{id:guid}")]
    public async Task<NoContentResult> Delete(Guid id, [FromQuery] Guid? scopeId, CancellationToken cancellationToken)
    {
        await rights.EnsureMayManageAsync(scopeId, cancellationToken);
        await targets.DeleteAsync(scopeId, id, cancellationToken);
        return NoContent();
    }
}
