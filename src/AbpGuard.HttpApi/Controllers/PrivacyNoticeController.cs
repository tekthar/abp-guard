using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AbpGuard.Acting;
using AbpGuard.Services;
using AbpGuard.Services.Privacy;

namespace AbpGuard.Controllers;

/// <summary>
/// The privacy notice and consent (PDPL): anyone reads the notice; a person signed in accepts a new
/// version and withdraws consent where it's the legal basis; a site admin publishes versions and marks withdrawals
/// handled. Each goes in the security log.
/// </summary>
[Route("api/guard")]
[GuardFeature(nameof(GuardFeatures.PrivacyNotice))]
public class PrivacyNoticeController(PrivacyNotices notices, SecurityLog audit) : GuardControllerBase
{
    /// <summary>The notice now, in the language asked for (else the request's, else English): 204 when none is published.</summary>
    [HttpGet("privacy-notice")]
    [AllowAnonymous]
    public async Task<ActionResult<PrivacyNoticeDto>> Notice([FromQuery] string? language, CancellationToken cancellationToken) =>
        await notices.CurrentAsync(language, cancellationToken) is { } notice ? notice : NoContent();

    [HttpGet("me/privacy")]
    [Authorize]
    public Task<MyPrivacyDto> Mine(CancellationToken cancellationToken) => notices.MineAsync(CurrentAccountId, cancellationToken);

    [HttpPost("me/privacy/accept")]
    [Authorize]
    public async Task<MyPrivacyDto> Accept([FromBody] NoticeAcceptInput input, CancellationToken cancellationToken)
    {
        await notices.AcceptAsync(CurrentAccountId, input.Version, ClientIp, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.NoticeAccepted, null, new { input.Version }, cancellationToken);
        return await notices.MineAsync(CurrentAccountId, cancellationToken);
    }

    /// <summary>Withdrawing consent can't be taken back by the person, so it asks for the password again.</summary>
    [HttpPost("me/privacy/withdraw")]
    [Authorize]
    [StepUp]
    public async Task<MyPrivacyDto> Withdraw([FromBody] ConsentWithdrawInput input, CancellationToken cancellationToken)
    {
        await notices.WithdrawAsync(CurrentAccountId, input.Store, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.ConsentWithdrawn, null, new { store = input.Store }, cancellationToken);
        return await notices.MineAsync(CurrentAccountId, cancellationToken);
    }

    [HttpGet("privacy/notices")]
    [Authorize(Policy = GuardPolicies.Admin)]
    public Task<List<PrivacyNoticeVersionDto>> Versions(CancellationToken cancellationToken) => notices.VersionsAsync(cancellationToken);

    /// <summary>Publishes a new version: everyone signed in on the web is asked to accept it, so it asks for the password again.</summary>
    [HttpPost("privacy/notices")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public async Task<PrivacyNoticeVersionDto> Publish([FromBody] PrivacyNoticeInput input, CancellationToken cancellationToken)
    {
        PrivacyNoticeVersionDto published = await notices.PublishAsync(input, CurrentAccountId, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.NoticePublished, null, new { published.Version, languages = published.Texts.Keys }, cancellationToken);
        return published;
    }

    [HttpGet("privacy/consent-withdrawals")]
    [Authorize(Policy = GuardPolicies.Admin)]
    public Task<List<ConsentWithdrawalDto>> Withdrawals(CancellationToken cancellationToken) => notices.WithdrawalsAsync(cancellationToken);

    /// <summary>A withdrawal marked handled leaves the admins' list of what's waiting, so it asks for the password again.</summary>
    [HttpPost("privacy/consent-withdrawals/{id:guid}/handled")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public async Task<ConsentWithdrawalDto> Handled(Guid id, [FromBody] ConsentHandledInput? input, CancellationToken cancellationToken)
    {
        ConsentWithdrawalDto handled = await notices.HandleAsync(id, CurrentAccountId, input?.Note, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.ConsentHandled, new AuditTarget("Account", handled.AccountId, null), new { store = handled.Store }, cancellationToken);
        return handled;
    }
}
