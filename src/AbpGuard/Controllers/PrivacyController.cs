using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using AbpGuard.Data;
using AbpGuard.Domain;
using AbpGuard.Services;
using AbpGuard.Services.Privacy;
using AbpGuard.Acting;
using Volo.Abp;

namespace AbpGuard.Controllers;

public sealed record PrivacyStoreInput(string? LegalBasis, bool? Sensitive, string? Notes);

public sealed record PrivacySettingsInput(PrivacyContactDto? Controller, PrivacyContactDto? Officer, string? Country, Dictionary<string, PrivacyDestination>? Destinations);

/// <summary>
/// Administration › Privacy (PDPL): the site's data map, what admins record for it (each store's legal
/// basis, whether it may hold sensitive data and notes; the controller, the officer and who receives each destination's
/// data), and the record of processing. Recording grants nothing, so it needs no step-up; it goes in the security log,
/// as the record's downloads do.
/// </summary>
[Route("api/guard/privacy")]
[Authorize(Policy = GuardPolicies.Admin)]
public class PrivacyController(PersonalDataCatalog catalog, IPluginPersonalDataSource plugins, GuardDb guardDb, SecurityLog audit, IOptions<GuardOptions> options)
    : GuardControllerBase
{
    private const int NameLength = 200;
    private const int ContactLength = 500;
    private const int NotesLength = 4000;

    [HttpGet]
    public Task<PrivacyMapDto> Get(CancellationToken cancellationToken) => catalog.MapAsync(cancellationToken);

    /// <summary>Every plugin the site has and what it declares, for Administration › Plugins.</summary>
    [HttpGet("plugins")]
    public Task<IReadOnlyList<InstalledPlugin>> Plugins(CancellationToken cancellationToken) => plugins.ListAsync(cancellationToken);

    [HttpPut("stores/{key}")]
    [StepUp]
    public async Task<PrivacyRecordedDto> SaveStore(string key, [FromBody] PrivacyStoreInput input, CancellationToken cancellationToken)
    {
        PrivacyMapDto map = await catalog.MapAsync(cancellationToken);
        if (map.Stores.All(s => s.Key != key))
        {
            throw new UserFriendlyException($"There's no store '{key}' on this site.");
        }

        string? basis = string.IsNullOrWhiteSpace(input.LegalBasis) ? null : input.LegalBasis.Trim();
        if (basis is not null && !LegalBases.All.Contains(basis))
        {
            throw new UserFriendlyException($"A legal basis is one of {string.Join(", ", LegalBases.All)}.");
        }

        string? notes = string.IsNullOrWhiteSpace(input.Notes) ? null : input.Notes.Trim();
        if (notes?.Length > NotesLength)
        {
            throw new UserFriendlyException($"Notes take at most {NotesLength} characters.");
        }

        Guid me = CurrentAccountId;
        return await guardDb.RunAsync(async db =>
        {
            PrivacyStoreRecord? record = await db.PrivacyStores.FirstOrDefaultAsync(r => r.StoreKey == key, cancellationToken);
            if (record is null)
            {
                db.PrivacyStores.Add(record = new PrivacyStoreRecord(key));
            }

            audit.Add(db, SecurityAuditTypes.PrivacyStore, new AuditTarget("privacy-store", null, key), new
            {
                legalBasis = new { before = record.LegalBasis, after = basis },
                sensitive = new { before = record.Sensitive, after = input.Sensitive },
                notesChanged = record.Notes != notes,
            });
            (record.LegalBasis, record.Sensitive, record.Notes, record.UpdatedAt, record.UpdatedBy) = (basis, input.Sensitive, notes, DateTime.UtcNow, me);
            await db.SaveChangesAsync(cancellationToken);
            string name = await db.Accounts.Where(a => a.Id == me).Select(a => a.DisplayName).FirstOrDefaultAsync(cancellationToken) ?? "";
            return new PrivacyRecordedDto(key, basis, input.Sensitive, notes, record.UpdatedAt, new PrivacyPersonDto(me, name));
        }, cancellationToken: cancellationToken);
    }

    [HttpPut("settings")]
    [StepUp]
    public Task<PrivacySettingsDto> SaveSettings([FromBody] PrivacySettingsInput input, CancellationToken cancellationToken)
    {
        PrivacyContactDto controller = Contact(input.Controller, "controller");
        PrivacyContactDto officer = Contact(input.Officer, "data protection officer");
        string? country = Text(input.Country, NameLength, "The site's country");
        Dictionary<string, PrivacyDestination> destinations = [];
        foreach ((string key, PrivacyDestination where) in input.Destinations ?? [])
        {
            // The host's destinations, or a service a plugin calls (service:{name}, as its manifest names it).
            if (!PersonalDataDestinations.IsKnown(key))
            {
                throw new UserFriendlyException($"'{key}' isn't a destination; they're {string.Join(", ", PersonalDataDestinations.All)}, or service:{{name}}.");
            }

            destinations[key] = new PrivacyDestination(Text(where.Recipient, NameLength, "A recipient"), Text(where.Country, NameLength, "A country"), where.OutsideCountry);
        }

        Guid me = CurrentAccountId;
        return guardDb.RunAsync(async db =>
        {
            PrivacySettings? settings = await db.PrivacySettings.FirstOrDefaultAsync(cancellationToken);
            if (settings is null)
            {
                db.PrivacySettings.Add(settings = new PrivacySettings());
            }

            audit.Add(db, SecurityAuditTypes.PrivacySettings, null, new
            {
                controller = settings.ControllerName != controller.Name || settings.ControllerContact != controller.Contact,
                officer = settings.OfficerName != officer.Name || settings.OfficerContact != officer.Contact,
                country = new { before = settings.Country, after = country },
                destinations = destinations.Keys.Order(StringComparer.Ordinal),
            });
            (settings.ControllerName, settings.ControllerContact, settings.OfficerName, settings.OfficerContact) = (controller.Name, controller.Contact, officer.Name, officer.Contact);
            settings.Country = country;
            (settings.Destinations, settings.UpdatedAt, settings.UpdatedBy) = (destinations, DateTime.UtcNow, me);
            await db.SaveChangesAsync(cancellationToken);
            Dictionary<Guid, string> names = await db.Accounts.Where(a => a.Id == me).ToDictionaryAsync(a => a.Id, a => a.DisplayName, cancellationToken);
            return PersonalDataCatalog.Settings(settings, names);
        }, cancellationToken: cancellationToken);
    }

    /// <summary>The record of processing, as Markdown or CSV, in English or Arabic; each download goes in the security log.</summary>
    [HttpGet("record")]
    public async Task<IActionResult> Record([FromQuery] string format = ProcessingRecord.Markdown, [FromQuery] string language = "en",
        CancellationToken cancellationToken = default)
    {
        // A refusal is JSON with its status whatever the download's fetch accepts ([GuardErrors] on every Guard controller).
        if (format is not (ProcessingRecord.Markdown or ProcessingRecord.Csv))
        {
            throw new UserFriendlyException("The record comes as markdown or csv.", "bad_format");
        }

        if (!options.Value.Texts.Record.ContainsKey(language))
        {
            throw new UserFriendlyException($"The record comes in {string.Join(", ", options.Value.Texts.Record.Keys)}.", "bad_language");
        }

        ProcessingRecordTexts texts = options.Value.Texts.RecordIn(language);

        PrivacyMapDto map = await catalog.MapAsync(cancellationToken);
        DateTime now = DateTime.UtcNow;
        string body = format == ProcessingRecord.Csv ? ProcessingRecord.ToCsv(map, texts, language) : ProcessingRecord.ToMarkdown(map, texts, language, now);
        await audit.WriteAsync(SecurityAuditTypes.PrivacyRecordExported, null, new { format, language }, cancellationToken);
        string name = $"record-of-processing-{now:yyyy-MM-dd}-{language}.{(format == ProcessingRecord.Csv ? "csv" : "md")}";
        return File(Encoding.UTF8.GetBytes(body), format == ProcessingRecord.Csv ? "text/csv; charset=utf-8" : "text/markdown; charset=utf-8", name);
    }

    private static PrivacyContactDto Contact(PrivacyContactDto? input, string who) =>
        new(Text(input?.Name, NameLength, $"The {who}'s name"), Text(input?.Contact, ContactLength, $"The {who}'s contact"));

    private static string? Text(string? value, int length, string what)
    {
        string? text = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        return text?.Length > length ? throw new UserFriendlyException($"{what} takes at most {length} characters.") : text;
    }
}
