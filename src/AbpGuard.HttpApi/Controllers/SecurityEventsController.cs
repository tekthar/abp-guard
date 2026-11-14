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
public class SecurityEventsController(GuardDb guardDb, IEnumerable<IGrantScopeDescriber> describers, SecurityLog audit) : GuardControllerBase
{
    /// <summary>The most rows a download holds: a filter narrows a longer log.</summary>
    public const int MostDownloaded = 100_000;

    /// <summary>The events a filter keeps: a kind or a prefix, an account, text, a time span.</summary>
    private static IQueryable<SecurityEvent> Filter(IQueryable<SecurityEvent> events, string? type, Guid? account, string? q, DateTime? from, DateTime? to)
    {
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

        return events;
    }

    /// <summary>
    /// The events a filter keeps, as CSV for a spreadsheet or an investigation: oldest first, at most
    /// <see cref="MostDownloaded"/>. A cell a spreadsheet would run as a formula is written as text. The download is logged.
    /// </summary>
    [HttpGet("export")]
    public async Task<FileContentResult> Export([FromQuery] string? type, [FromQuery] Guid? account, [FromQuery] string? q,
        [FromQuery] DateTime? from, [FromQuery] DateTime? to, CancellationToken cancellationToken = default)
    {
        List<SecurityEvent> rows = await guardDb.RunAsync(db => Filter(db.SecurityEvents.AsNoTracking(), type, account, q, from, to)
            .OrderBy(e => e.Time).ThenBy(e => e.Id).Take(MostDownloaded).ToListAsync(cancellationToken), cancellationToken: cancellationToken);
        System.Text.StringBuilder csv = new("\uFEFFtime,type,username,account,acting_account,acting_mode,target_type,target_id,target_name,detail,ip\r\n");
        foreach (SecurityEvent e in rows)
        {
            csv.AppendJoin(',', new[]
            {
                e.Time.ToString("O", System.Globalization.CultureInfo.InvariantCulture), e.Type, e.Username, e.AccountId?.ToString(), e.ActingAccountId?.ToString(),
                e.ActingMode, e.TargetType, e.TargetId?.ToString(), e.TargetName, e.Detail, e.Ip,
            }.Select(CsvCell)).Append("\r\n");
        }

        await audit.WriteAsync(SecurityAuditTypes.LogExported, null, new { type, account, q, from, to, rows = rows.Count }, cancellationToken);
        return File(System.Text.Encoding.UTF8.GetBytes(csv.ToString()), "text/csv; charset=utf-8", $"security-log-{DateTime.UtcNow:yyyy-MM-dd}.csv");
    }

    /// <summary>A CSV cell: quoted when it must be, and a value a spreadsheet would run as a formula (=, +, -, @, a tab or a return first) kept as text.</summary>
    public static string CsvCell(string? value)
    {
        string v = value ?? "";
        if (v.Length > 0 && v[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
        {
            v = "'" + v;
        }

        return v.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? $"\"{v.Replace("\"", "\"\"", StringComparison.Ordinal)}\"" : v;
    }

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
            IQueryable<SecurityEvent> events = Filter(db.SecurityEvents.AsNoTracking(), type, account, q, from, to);
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
