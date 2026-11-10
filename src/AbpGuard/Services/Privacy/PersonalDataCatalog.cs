using Microsoft.EntityFrameworkCore;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services.Privacy;

/// <summary>A store as a site has it: what its module or plugin declares, and what an admin recorded for it.</summary>
public sealed record PrivacyStoreDto(
    string Key,
    string Owner,
    string OwnerKind,
    LocalizedText Name,
    LocalizedText Purpose,
    IReadOnlyList<string> Tables,
    IReadOnlyList<string> Files,
    IReadOnlyList<PersonalDataField> Fields,
    string About,
    IReadOnlyList<string> Kinds,
    string Kept,
    IReadOnlyList<string> GoesTo,
    bool SuggestSensitive,
    PrivacyRecordedDto? Recorded)
{
    public const string Module = "module";
    public const string Plugin = "plugin";
}

/// <summary>What an admin recorded: the legal basis, whether it may hold sensitive data (null: not decided), and notes.</summary>
public sealed record PrivacyRecordedDto(string StoreKey, string? LegalBasis, bool? Sensitive, string? Notes, DateTime UpdatedAt, PrivacyPersonDto? UpdatedBy);

public sealed record PrivacyPersonDto(Guid Id, string Name);

public sealed record PrivacyContactDto(string? Name, string? Contact);

/// <summary>The site's controller and data protection officer, and who receives each destination's data.</summary>
public sealed record PrivacySettingsDto(PrivacyContactDto Controller, PrivacyContactDto Officer, string? Country,
    IReadOnlyDictionary<string, PrivacyDestination> Destinations, DateTime? UpdatedAt, PrivacyPersonDto? UpdatedBy);

/// <summary>
/// A site's data map: every store of its modules and plugins with what's recorded, every plugin with
/// its declaration, the site's settings, records for stores no longer declared, and the lists a site knows.
/// </summary>
public sealed record PrivacyMapDto(
    IReadOnlyList<PrivacyStoreDto> Stores,
    IReadOnlyList<InstalledPlugin> Plugins,
    PrivacySettingsDto Settings,
    IReadOnlyList<PrivacyRecordedDto> NoLongerDeclared,
    IReadOnlyList<string> Kinds,
    IReadOnlyList<string> Destinations,
    IReadOnlyList<string> LegalBases);

/// <summary>
/// Guard's data map: the stores its host's modules declare (<see cref="IPersonalDataDeclarations"/>)
/// and its host's plugins (<see cref="IPluginPersonalDataSource"/>), with what admins recorded for each.
/// </summary>
public sealed class PersonalDataCatalog(IEnumerable<IPersonalDataDeclarations> modules, IPluginPersonalDataSource plugins, GuardDb guardDb) : ITransientDependency
{
    public async Task<PrivacyMapDto> MapAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<InstalledPlugin> installed = await plugins.ListAsync(cancellationToken);
        List<(PersonalDataStore Store, string Kind)> declared =
        [
            .. modules.SelectMany(m => m.Stores).Select(s => (s, PrivacyStoreDto.Module)),
            .. installed.SelectMany(p => p.PersonalData.Stores).Select(s => (s, PrivacyStoreDto.Plugin)),
        ];

        return await guardDb.RunAsync(async db =>
        {
            Dictionary<string, PrivacyStoreRecord> records = await db.PrivacyStores.AsNoTracking().ToDictionaryAsync(r => r.StoreKey, cancellationToken);
            PrivacySettings? settings = await db.PrivacySettings.AsNoTracking().FirstOrDefaultAsync(cancellationToken);
            HashSet<Guid> people = [.. records.Values.Select(r => r.UpdatedBy).OfType<Guid>()];
            if (settings?.UpdatedBy is { } by)
            {
                people.Add(by);
            }

            Dictionary<Guid, string> names = await db.Accounts.AsNoTracking().Where(a => people.Contains(a.Id))
                .ToDictionaryAsync(a => a.Id, a => a.DisplayName, cancellationToken);
            PrivacyRecordedDto Recorded(PrivacyStoreRecord r) => new(r.StoreKey, r.LegalBasis, r.Sensitive, r.Notes, r.UpdatedAt, Person(r.UpdatedBy, names));

            List<PrivacyStoreDto> stores = [];
            foreach ((PersonalDataStore s, string kind) in declared.DistinctBy(d => d.Store.Key))
            {
                stores.Add(new PrivacyStoreDto(s.Key, s.Owner, kind, s.Name, s.Purpose, s.Tables, s.Files, s.Fields, s.About, s.Kinds, s.Kept, s.GoesTo,
                    s.Kinds.Contains(PersonalDataKinds.Content), records.TryGetValue(s.Key, out PrivacyStoreRecord? r) ? Recorded(r) : null));
            }

            HashSet<string> keys = [.. stores.Select(s => s.Key)];
            return new PrivacyMapDto(stores, installed, Settings(settings, names),
                [.. records.Values.Where(r => !keys.Contains(r.StoreKey)).OrderBy(r => r.StoreKey, StringComparer.Ordinal).Select(Recorded)],
                PersonalDataKinds.All, PersonalDataDestinations.All, LegalBases.All);
        }, cancellationToken: cancellationToken);
    }

    public static PrivacySettingsDto Settings(PrivacySettings? settings, IReadOnlyDictionary<Guid, string> names) =>
        new(new PrivacyContactDto(settings?.ControllerName, settings?.ControllerContact), new PrivacyContactDto(settings?.OfficerName, settings?.OfficerContact),
            settings?.Country, settings?.Destinations ?? [], settings?.UpdatedAt, Person(settings?.UpdatedBy, names));

    private static PrivacyPersonDto? Person(Guid? id, IReadOnlyDictionary<Guid, string> names) =>
        id is { } known ? new PrivacyPersonDto(known, names.GetValueOrDefault(known, "")) : null;
}

/// <summary>Guard on its own has no plugins: a host that has them registers its own source (one that reads its installed plugins, say).</summary>
[Dependency(TryRegister = true)]
[ExposeServices(typeof(IPluginPersonalDataSource))]
public sealed class NoPluginPersonalData : IPluginPersonalDataSource, ITransientDependency
{
    public Task<IReadOnlyList<InstalledPlugin>> ListAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<InstalledPlugin>>([]);
}
