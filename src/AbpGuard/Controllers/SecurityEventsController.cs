using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Data;
using AbpGuard.Domain;
using AbpGuard.Services;
using Volo.Abp;

namespace AbpGuard.Controllers;

/// <summary>
/// One entry of the security audit: who (Username, AccountId), who acted for them when that was someone else
/// (ActingUsername, ActingMode), what to (Target*), and the rest as Detail, usually JSON. A grant's scope is described as
/// its module names it now (ScopeLabel, ScopeHref: a project's name and members page).
/// </summary>
public sealed record SecurityEventDto(
    Guid Id, DateTime Time, string Type, Guid? AccountId, string? Username, Guid? ActingAccountId, string? ActingUsername, string? ActingMode,
    Guid? SessionId, string? TargetType, Guid? TargetId, string? TargetName, string? Detail, string? Ip, string? ScopeLabel = null, string? ScopeHref = null);

public sealed record SecurityEventPageDto(long Total, List<SecurityEventDto> Items);

/// <summary>
/// The security audit, for site admins: sign-ins, exports, and every change to who may do what, newest first,
/// by kind, by the account it was done by, for or to, and by text. Nothing here edits or deletes an event; the retention
/// setting (<see cref="SecuritySettingsController"/>) decides how long they're kept.
/// </summary>
[Route("api/guard/security-events")]
[Authorize(Policy = GuardPolicies.Admin)]
public class SecurityEventsController(GuardDb guardDb, IEnumerable<IGrantScopeDescriber> describers) : GuardControllerBase
{
    /// <summary>
    /// Events newest first. <c>type</c> is one kind (<c>grant.added</c>) or every kind under a prefix ending in a dot
    /// (<c>grant.</c>); <c>account</c> finds what an account did, what was done to it and what was done acting for it.
    /// </summary>
    [HttpGet]
    public async Task<SecurityEventPageDto> List([FromQuery] string? type, [FromQuery] Guid? account, [FromQuery] string? q,
        [FromQuery] DateTime? from, [FromQuery] DateTime? to, [FromQuery] int skip = 0, [FromQuery] int take = 50, CancellationToken cancellationToken = default)
    {
        SecurityEventPageDto page = await guardDb.RunAsync(async db =>
        {
            IQueryable<SecurityEvent> events = db.SecurityEvents.AsNoTracking();
            if (!string.IsNullOrWhiteSpace(type))
            {
                string t = type.Trim();
                events = t.EndsWith('.') ? events.Where(e => e.Type.StartsWith(t)) : events.Where(e => e.Type == t);
            }

            if (account is { } id)
            {
                events = events.Where(e => e.AccountId == id || e.TargetId == id || e.ActingAccountId == id);
            }

            if (!string.IsNullOrWhiteSpace(q))
            {
                string like = SqlLike.Containing(q.Trim());
                events = events.Where(e => EF.Functions.ILike(e.Username ?? "", like) || EF.Functions.ILike(e.TargetName ?? "", like)
                    || EF.Functions.ILike(e.Detail ?? "", like) || EF.Functions.ILike(e.Ip ?? "", like));
            }

            if (from is { } f)
            {
                DateTime since = DateTime.SpecifyKind(f, DateTimeKind.Utc);
                events = events.Where(e => e.Time >= since);
            }

            if (to is { } u)
            {
                DateTime until = DateTime.SpecifyKind(u, DateTimeKind.Utc);
                events = events.Where(e => e.Time < until);
            }

            long total = await events.LongCountAsync(cancellationToken);
            List<SecurityEvent> rows = await events.OrderByDescending(e => e.Time).ThenByDescending(e => e.Id)
                .Skip(Math.Max(0, skip)).Take(Math.Clamp(take, 1, 200)).ToListAsync(cancellationToken);
            List<Guid> actors = rows.Select(r => r.ActingAccountId).OfType<Guid>().Distinct().ToList();
            Dictionary<Guid, string> names = actors.Count == 0
                ? []
                : await db.Accounts.AsNoTracking().Where(a => actors.Contains(a.Id)).ToDictionaryAsync(a => a.Id, a => a.Username, cancellationToken);
            return new SecurityEventPageDto(total, rows.Select(e => new SecurityEventDto(
                e.Id, e.Time, e.Type, e.AccountId, e.Username, e.ActingAccountId, e.ActingAccountId is { } a ? names.GetValueOrDefault(a) : null, e.ActingMode,
                e.SessionId, e.TargetType, e.TargetId, e.TargetName, e.Detail, e.Ip)).ToList());
        }, cancellationToken: cancellationToken);

        Dictionary<Guid, string> scopeKeys = page.Items.Where(e => e.Type.StartsWith("grant.", StringComparison.Ordinal))
            .Select(e => (e.Id, Key: ScopeKey(e.Detail))).Where(x => x.Key is not null).ToDictionary(x => x.Id, x => x.Key!);
        if (scopeKeys.Count == 0)
        {
            return page;
        }

        Dictionary<string, GrantScopeLabel> labels = [];
        foreach (IGrantScopeDescriber describer in describers)
        {
            foreach ((string key, GrantScopeLabel label) in await describer.DescribeAsync(scopeKeys.Values.Distinct().ToList(), cancellationToken))
            {
                labels[key] = label;
            }
        }

        return page with
        {
            Items = page.Items.Select(e => scopeKeys.TryGetValue(e.Id, out string? key) && labels.TryGetValue(key, out GrantScopeLabel? label)
                ? e with { ScopeLabel = label.Label, ScopeHref = label.Href }
                : e).ToList(),
        };
    }

    private static string? ScopeKey(string? detail)
    {
        if (detail is null || !detail.StartsWith('{'))
        {
            return null;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(detail);
            return doc.RootElement.TryGetProperty("scopeKey", out JsonElement key) && key.ValueKind == JsonValueKind.String ? key.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
