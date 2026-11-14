using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AbpGuard.Acting;
using AbpGuard.Services;
using AbpGuard.Services.Privacy;
using Volo.Abp;

namespace AbpGuard.Controllers;

/// <summary>
/// Administration › Privacy, retention (PDPL): each store's periods, set and confirmed by a site admin,
/// and a sweep now. Shortening a period or sweeping removes data, so both ask for the password again; both go in the
/// security log.
/// </summary>
[Route("api/guard/privacy/retention")]
[Authorize(Policy = GuardPolicies.Admin)]
[GuardFeature(nameof(GuardFeatures.Retention))]
public class RetentionController(PersonalDataRetention retention, SecurityLog audit) : GuardControllerBase
{
    [HttpGet]
    public Task<RetentionDto> Get(CancellationToken cancellationToken) => retention.GetAsync(cancellationToken);

    [HttpPut]
    [StepUp]
    public async Task<RetentionDto> Save([FromBody] RetentionInput input, CancellationToken cancellationToken)
    {
        RetentionDto saved = await retention.SaveAsync(input, CurrentAccountId, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.Retention, null, new { days = input.Days, confirmed = input.Confirm }, cancellationToken);
        return saved;
    }

    /// <summary>Sweeps now, waiting for another server's sweep to end; refused until the periods are confirmed.</summary>
    [HttpPost("sweep")]
    [StepUp]
    public async Task<Dictionary<string, int>> Sweep(CancellationToken cancellationToken) =>
        await retention.SweepAsync(wait: true, cancellationToken)
        ?? throw new UserFriendlyException("Confirm the retention periods first: until then nothing is swept.", "not_confirmed");
}
