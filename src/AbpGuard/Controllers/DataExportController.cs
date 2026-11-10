using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Data;
using AbpGuard.Services;
using AbpGuard.Services.Privacy;
using AbpGuard.Acting;
using Volo.Abp;
using Volo.Abp.Domain.Entities;

namespace AbpGuard.Controllers;

public sealed record DataExportInput(bool Files = true);

public sealed record OutsideDataExportInput(string? Email, string? Phone, bool Files = true);

/// <summary>
/// A person's data exported (PDPL): by the person themself from the You page, by a site admin for an
/// account, or for someone outside the site known by an address. Each asks for the password again, goes in the security log
/// with what it held (never the data), and answers with a zip written as it's made. The actions return nothing, as the
/// zip goes straight to the response, and refuse by throwing: ABP then answers a refusal, the step-up's too, as JSON
/// whatever the client accepts, which it doesn't for an action that returns a result of its own.
/// </summary>
[Route("api/guard")]
[GuardFeature(nameof(GuardFeatures.DataExport))]
public class DataExportController(PersonalDataExports exports, GuardDb guardDb, IGuardRateLimits limits, IGuardSiteDefaults site, SecurityLog audit)
    : GuardControllerBase
{
    /// <summary>A person's own exports a day: an export can be big, and each one goes through every store.</summary>
    public const int OwnPerDay = 3;

    [HttpPost("me/data-export")]
    [Authorize]
    [StepUp]
    public async Task Mine([FromBody] DataExportInput? input, CancellationToken cancellationToken)
    {
        Guid me = CurrentAccountId;
        var account = await guardDb.RunAsync(db => db.Accounts.AsNoTracking().Where(a => a.Id == me)
            .Select(a => new { a.DisplayName, a.Username, a.IsService }).FirstOrDefaultAsync(cancellationToken), cancellationToken: cancellationToken);
        if (account is null || account.IsService)
        {
            throw new UserFriendlyException("A service account has no data of its own to export.", "not_a_person");
        }

        if (!await limits.TryTakeAsync($"data-export|{me}", OwnPerDay, TimeSpan.FromDays(1), cancellationToken))
        {
            throw new UserFriendlyException($"You can export your data {OwnPerDay} times a day. Try again tomorrow.", GuardErrorCodes.TooManyRequests);
        }

        PersonalDataSubject subject = (await exports.SubjectOfAccountAsync(me, cancellationToken))!;
        await SendAsync(subject, $"{account.DisplayName} ({account.Username})", account.Username, PersonalDataRequesters.Person,
            SecurityAuditTypes.PrivacyExportSelf, new AuditTarget("account", me, account.Username), input?.Files ?? true, cancellationToken);
    }

    [HttpPost("accounts/{id:guid}/data-export")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public async Task Account(Guid id, [FromBody] DataExportInput? input, CancellationToken cancellationToken)
    {
        var account = await guardDb.RunAsync(db => db.Accounts.AsNoTracking().Where(a => a.Id == id)
            .Select(a => new { a.DisplayName, a.Username }).FirstOrDefaultAsync(cancellationToken), cancellationToken: cancellationToken);
        if (account is null || await exports.SubjectOfAccountAsync(id, cancellationToken) is not { } subject)
        {
            throw new EntityNotFoundException("There's no such account.");
        }

        await SendAsync(subject, $"{account.DisplayName} ({account.Username})", account.Username, PersonalDataRequesters.Admin,
            SecurityAuditTypes.PrivacyExportAccount, new AuditTarget("account", id, account.Username), input?.Files ?? true, cancellationToken);
    }

    [HttpPost("privacy/people/data-export")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public async Task Outside([FromBody] OutsideDataExportInput input, CancellationToken cancellationToken)
    {
        PersonalDataSubject subject = PersonalDataSubject.Outside(input.Email, input.Phone);
        if (subject.Emails.Count + subject.Phones.Count == 0)
        {
            throw new UserFriendlyException("Give the person's email address or phone number.", "no_address");
        }

        string address = subject.Emails.Concat(subject.Phones).First();
        await SendAsync(subject, address, address, PersonalDataRequesters.Admin, SecurityAuditTypes.PrivacyExportAddress,
            new AuditTarget("address", null, address), input.Files, cancellationToken);
    }

    private async Task SendAsync(PersonalDataSubject subject, string about, string fileName, string requestedBy, string auditType, AuditTarget target,
        bool files, CancellationToken cancellationToken)
    {
        // The zip library still writes its end synchronously, which Kestrel refuses by default; the rest goes out as it's made.
        HttpContext.Features.Get<IHttpBodyControlFeature>()?.AllowSynchronousIO = true;
        Response.ContentType = "application/zip";
        Response.Headers.ContentDisposition = $"attachment; filename=\"data-{Safe(fileName)}-{DateTime.UtcNow:yyyy-MM-dd}.zip\"";

        // In the log before the first byte goes out: a download cut off part way has still taken some of the person's data.
        await audit.WriteAsync(auditType, target, new { state = "started", files }, CancellationToken.None);
        DataExportSummary? summary = null;
        try
        {
            summary = await exports.WriteAsync(Response.Body, subject, about, requestedBy, site.RequestLanguage, files, cancellationToken);
        }
        finally
        {
            await audit.WriteAsync(SecurityAuditTypes.PrivacyExportEnded, target, summary is null
                ? new { export = auditType, state = "aborted" }
                : new
                {
                    export = auditType,
                    state = "finished",
                    stores = summary.Rows,
                    noLongerReadable = summary.NoLongerReadable,
                    files = summary.Files,
                    missing = summary.Missing.Select(m => m.Store),
                }, CancellationToken.None);
        }
    }

    private static string Safe(string name) => new([.. name.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '-')]);
}
