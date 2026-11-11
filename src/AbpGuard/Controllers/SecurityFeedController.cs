using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AbpGuard.Acting;
using AbpGuard.Services;

namespace AbpGuard.Controllers;

/// <summary>
/// Administration › Security, the security log's feed (PDPL): where it goes, its secret (made anew and
/// shown once), and a send now. Each change asks for the password again and goes in the log; the secret never does.
/// </summary>
[Route("api/guard/security/feed")]
[Authorize(Policy = GuardPolicies.Admin)]
[GuardFeature(nameof(GuardFeatures.SecurityFeed))]
public class SecurityFeedController(SecurityFeed feed, SecurityLog audit) : GuardControllerBase
{
    [HttpGet]
    public Task<SecurityFeedDto> Get(CancellationToken cancellationToken) => feed.GetAsync(cancellationToken);

    [HttpPut]
    [StepUp]
    public async Task<SecurityFeedDto> Save([FromBody] SecurityFeedInput input, CancellationToken cancellationToken)
    {
        SecurityFeedDto saved = await feed.SaveAsync(input, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.FeedChanged, null, new { saved.Url, saved.Enabled }, cancellationToken);
        return saved;
    }

    [HttpPost("secret")]
    [StepUp]
    public async Task<SecurityFeedSecretDto> NewSecret(CancellationToken cancellationToken)
    {
        SecurityFeedSecretDto secret = await feed.NewSecretAsync(cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.FeedChanged, null, new { secret = "made anew" }, cancellationToken);
        return secret;
    }

    /// <summary>Sends what's waiting now, as the worker would in the next minute; says how many events went.</summary>
    [HttpPost("send")]
    public async Task<object> Send(CancellationToken cancellationToken) =>
        new { sent = await feed.SendAsync(cancellationToken), feed = await feed.GetAsync(cancellationToken) };
}

/// <summary>Checks the security log for alerts now, as the worker does every five minutes; returns what it told.</summary>
[Route("api/guard/security/alerts")]
[Authorize(Policy = GuardPolicies.Admin)]
[GuardFeature(nameof(GuardFeatures.SecurityAlerts))]
public class SecurityAlertsController(SecurityAlerts alerts) : GuardControllerBase
{
    [HttpPost("check")]
    public Task<List<SecurityAlert>> Check(CancellationToken cancellationToken) => alerts.CheckAsync(cancellationToken);
}
