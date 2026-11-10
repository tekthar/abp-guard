using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AbpGuard.Data;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services.Privacy;

/// <summary>A store an export holds nothing of, and why: no exporter, its export failed, its plugin was turned off.</summary>
public sealed record DataExportMissing(string Store, string Why);

/// <summary>What an export held: rows a store, those on items the person can no longer read, files, and what's missing.</summary>
public sealed record DataExportSummary(IReadOnlyDictionary<string, int> Rows, IReadOnlyDictionary<string, int> NoLongerReadable, int Files,
    IReadOnlyList<DataExportMissing> Missing);

/// <summary>
/// A person's data exported (PDPL): every store a site has, walked through the exporters its modules and
/// plugins give (<see cref="IPersonalDataExporter"/>), as a zip written to the response as it's made, so nothing of it is
/// kept on the site. It starts with a README (so a proxy never sees a silent connection), holds a folder a store and the
/// person's files, and ends with an index of what's in it and what isn't, and why. Host exporters come from DI; each
/// plugin's runs under its own lease, taken for it and released when it's done.
/// </summary>
public sealed class PersonalDataExports(PersonalDataCatalog catalog, IGuardExtensions extensions, IServiceProvider services, GuardDb guardDb,
    IOptions<GuardOptions> options, ILogger<PersonalDataExports> logger) : ITransientDependency
{
    /// <summary>An account's subject: its id, with its own address and the verified ones it added, so mail to them is found.</summary>
    public Task<PersonalDataSubject?> SubjectOfAccountAsync(Guid accountId, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            string? email = await db.Accounts.AsNoTracking().Where(a => a.Id == accountId).Select(a => a.Email ?? "").FirstOrDefaultAsync(cancellationToken);
            if (email is null)
            {
                return null;
            }

            List<string> added = await db.AccountEmails.AsNoTracking().Where(e => e.AccountId == accountId && e.VerifiedAt != null)
                .Select(e => e.Email).ToListAsync(cancellationToken);
            return (PersonalDataSubject?)new PersonalDataSubject(accountId,
                [.. added.Prepend(email).Where(e => e.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase)], []);
        }, cancellationToken: cancellationToken);

    /// <summary>
    /// Writes the zip to <paramref name="output"/>: for <paramref name="about"/> (a name, or an address), asked for by the
    /// person or an admin (<see cref="PersonalDataRequesters"/>), its texts in <paramref name="language"/>.
    /// </summary>
    public async Task<DataExportSummary> WriteAsync(Stream output, PersonalDataSubject subject, string about, string requestedBy, string language, bool files,
        CancellationToken cancellationToken) =>
        await WriteAsync(output, await catalog.MapAsync(cancellationToken), subject, about, requestedBy, language, files, cancellationToken);

    /// <summary>The same, from a map of the site's stores already read.</summary>
    internal async Task<DataExportSummary> WriteAsync(Stream output, PrivacyMapDto map, PersonalDataSubject subject, string about, string requestedBy,
        string language, bool files, CancellationToken cancellationToken)
    {
        PersonalDataExportTexts texts = options.Value.Texts.ExportIn(language);
        ProcessingRecordTexts record = options.Value.Texts.RecordIn(language);
        DateTime madeAt = DateTime.UtcNow;
        ZipWriter writer = new(subject, requestedBy, language, files);
        List<DataExportMissing> missing = [];
        HashSet<string> exported = [];

        await using (ZipArchive zip = await ZipArchive.CreateAsync(output, ZipArchiveMode.Create, leaveOpen: true, entryNameEncoding: null, cancellationToken))
        {
            writer.Zip = zip;
            await writer.TextAsync("README.md", Readme(map, texts, record, about, requestedBy, madeAt), cancellationToken);
            HashSet<string> modules = [.. map.Stores.Where(s => s.OwnerKind == PrivacyStoreDto.Module).Select(s => s.Key)];
            foreach (IPersonalDataExporter exporter in services.GetServices<IPersonalDataExporter>())
            {
                await RunAsync(exporter, plugin: null, modules);
            }

            List<string> plugins;
            await using (IGuardLease<IPersonalDataExporter> lease = extensions.Lease<IPersonalDataExporter>(services))
            {
                plugins = [.. lease.Items.Where(i => i.PluginKey is not null).Select(i => i.PluginKey!).Distinct(StringComparer.Ordinal)];
            }

            foreach (string plugin in plugins)
            {
                HashSet<string> declared = [.. map.Stores.Where(s => s.OwnerKind == PrivacyStoreDto.Plugin && s.Owner == plugin).Select(s => s.Key)];
                await using IGuardLease<IPersonalDataExporter> lease = extensions.Lease<IPersonalDataExporter>(services);
                List<IPersonalDataExporter> theirs = [.. lease.Items.Where(i => i.PluginKey == plugin).Select(i => i.Instance)];
                if (theirs.Count == 0)
                {
                    missing.AddRange(declared.Where(s => !exported.Contains(s)).Select(s => new DataExportMissing(s, texts.TurnedOff)));
                    exported.UnionWith(declared);
                    continue;
                }

                foreach (IPersonalDataExporter exporter in theirs)
                {
                    await RunAsync(exporter, plugin, declared);
                }
            }

            foreach (PrivacyStoreDto store in map.Stores.Where(s => !exported.Contains(s.Key)))
            {
                missing.Add(new DataExportMissing(store.Key, texts.NoExporter));
            }

            DataExportSummary summary = new(writer.Rows, writer.Hidden, writer.Files, missing);
            await writer.TextAsync("index.json", Index(map, subject, about, requestedBy, language, files, madeAt, summary), cancellationToken);
            return summary;
        }

        async Task RunAsync(IPersonalDataExporter exporter, string? plugin, HashSet<string> declared)
        {
            List<string> stores = [];
            foreach (string named in exporter.Stores)
            {
                string key = plugin is null ? named : $"{plugin}.{named}";
                if (!declared.Contains(key))
                {
                    missing.Add(new DataExportMissing(key, texts.NotDeclared));
                }
                else if (exported.Add(key))
                {
                    stores.Add(key);
                }
            }

            if (stores.Count == 0)
            {
                return;
            }

            writer.Begin(plugin, stores);
            try
            {
                await exporter.ExportAsync(writer, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "The personal data export of {Stores} failed", string.Join(", ", stores));
                writer.Failed();
                missing.AddRange(stores.Select(s => new DataExportMissing(s, texts.Failed)));
            }
            finally
            {
                writer.End();
            }
        }
    }

    private static string Readme(PrivacyMapDto map, PersonalDataExportTexts t, ProcessingRecordTexts record, string about, string requestedBy, DateTime madeAt)
    {
        string Text(LocalizedText text) => t.Language == "ar" ? text.Ar : text.En;
        StringBuilder md = new();
        md.Append("# ").Append(t.Title).Append("\n\n")
            .Append(string.Format(CultureInfo.InvariantCulture, t.Intro, about, madeAt.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture),
                requestedBy == PersonalDataRequesters.Admin ? t.ByAdmin : t.ByPerson))
            .Append("\n\n").Append(t.Layout).Append("\n\n");
        if (requestedBy == PersonalDataRequesters.Admin)
        {
            md.Append(t.Redact).Append("\n\n");
        }

        md.Append("## ").Append(t.Stores).Append('\n');
        foreach (PrivacyStoreDto s in map.Stores)
        {
            md.Append("\n### ").Append(Text(s.Name)).Append(" (`").Append(s.Key).Append("`)\n\n")
                .Append(Text(s.Purpose).ReplaceLineEndings(" ")).Append("\n\n")
                .Append(record.Kept).Append(": ").Append(ProcessingRecord.Kept(s.Kept, record)).Append('\n');
        }

        return md.ToString();
    }

    private static string Index(PrivacyMapDto map, PersonalDataSubject subject, string about, string requestedBy, string language, bool files, DateTime madeAt,
        DataExportSummary summary)
    {
        JsonObject index = new()
        {
            ["about"] = about,
            ["accountId"] = subject.AccountId?.ToString(),
            ["emails"] = new JsonArray([.. subject.Emails.Select(e => (JsonNode?)e)]),
            ["phones"] = new JsonArray([.. subject.Phones.Select(p => (JsonNode?)p)]),
            ["madeAt"] = madeAt,
            ["requestedBy"] = requestedBy,
            ["language"] = language,
            ["files"] = files,
            ["stores"] = new JsonArray([.. map.Stores.Where(s => summary.Rows.ContainsKey(s.Key)).Select(s => (JsonNode?)new JsonObject
            {
                ["key"] = s.Key,
                ["name"] = language == "ar" ? s.Name.Ar : s.Name.En,
                ["rows"] = summary.Rows[s.Key],
                ["noLongerReadable"] = summary.NoLongerReadable.GetValueOrDefault(s.Key),
            })]),
            ["filesWritten"] = summary.Files,
            ["missing"] = new JsonArray([.. summary.Missing.Select(m => (JsonNode?)new JsonObject { ["store"] = m.Store, ["why"] = m.Why })]),
        };
        return index.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    /// <summary>
    /// What exporters write to: a JSON file a call, and files, in one zip, one entry at a time. It holds a store to the
    /// stores its exporter may write (a plugin's by their short keys), and leaves out of a person's own export any row on
    /// an item they can no longer read, whatever the exporter wrote.
    /// </summary>
    private sealed class ZipWriter(PersonalDataSubject subject, string requestedBy, string language, bool files) : IPersonalDataExport
    {
        private readonly HashSet<string> _names = new(StringComparer.OrdinalIgnoreCase);
        private string? _plugin;
        private HashSet<string> _stores = [];

        public ZipArchive Zip { get; set; } = null!;
        public Dictionary<string, int> Rows { get; } = [];
        public Dictionary<string, int> Hidden { get; } = [];
        public int Files { get; private set; }

        public PersonalDataSubject Subject => subject;
        public string RequestedBy => requestedBy;
        public string Language => language;
        bool IPersonalDataExport.Files => files;

        /// <summary>An exporter starts: its stores are in the index from here, with what it writes to them.</summary>
        public void Begin(string? plugin, IEnumerable<string> stores)
        {
            (_plugin, _stores) = (plugin, [.. stores]);
            foreach (string store in _stores)
            {
                Rows.TryAdd(store, 0);
            }
        }

        /// <summary>An exporter failed: its stores are said missing instead, whatever it wrote before.</summary>
        public void Failed()
        {
            foreach (string store in _stores)
            {
                Rows.Remove(store);
                Hidden.Remove(store);
            }
        }

        public void End() => (_plugin, _stores) = (null, []);

        public async Task WriteAsync(string store, string name, IAsyncEnumerable<JsonObject> rows, CancellationToken cancellationToken = default)
        {
            string key = Store(store);
            ZipArchiveEntry entry = Zip.CreateEntry(Unique($"{key}/{Safe(name)}.json"), CompressionLevel.Fastest);
            await using Stream target = await entry.OpenAsync(cancellationToken);
            await using Utf8JsonWriter json = new(target, new JsonWriterOptions { Indented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            json.WriteStartArray();
            await foreach (JsonObject row in rows.WithCancellation(cancellationToken))
            {
                bool unreadable = row[PersonalDataExportKeys.NoLongerReadable]?.GetValueKind() == JsonValueKind.True;
                if (unreadable && requestedBy != PersonalDataRequesters.Admin)
                {
                    continue;
                }

                row.WriteTo(json);
                Rows[key]++;
                if (unreadable)
                {
                    Hidden[key] = Hidden.GetValueOrDefault(key) + 1;
                }

                if (json.BytesPending > 64 * 1024)
                {
                    await json.FlushAsync(cancellationToken);
                }
            }

            json.WriteEndArray();
            await json.FlushAsync(cancellationToken);
        }

        public async Task WriteFileAsync(string store, string name, Stream content, CancellationToken cancellationToken = default)
        {
            string key = Store(store);
            if (!files)
            {
                return;
            }

            ZipArchiveEntry entry = Zip.CreateEntry(Unique($"files/{key}/{Safe(name)}"), CompressionLevel.Fastest);
            await using Stream target = await entry.OpenAsync(cancellationToken);
            await content.CopyToAsync(target, cancellationToken);
            Files++;
        }

        public async Task TextAsync(string name, string text, CancellationToken cancellationToken)
        {
            ZipArchiveEntry entry = Zip.CreateEntry(name, CompressionLevel.Fastest);
            await using Stream target = await entry.OpenAsync(cancellationToken);
            await target.WriteAsync(Encoding.UTF8.GetBytes(text), cancellationToken);
        }

        private string Store(string store)
        {
            string key = _plugin is null || store.StartsWith(_plugin + ".", StringComparison.Ordinal) ? store : $"{_plugin}.{store}";
            return _stores.Contains(key) ? key : throw new InvalidOperationException($"This exporter doesn't export '{store}'.");
        }

        private string Unique(string path)
        {
            string unique = path;
            for (int n = 2; !_names.Add(unique); n++)
            {
                int dot = path.LastIndexOf('.');
                unique = dot > path.LastIndexOf('/') ? $"{path[..dot]} ({n}){path[dot..]}" : $"{path} ({n})";
            }

            return unique;
        }

        /// <summary>A file's own name, safe in a zip: no folders, nothing a file system refuses.</summary>
        private static string Safe(string name)
        {
            string safe = new([.. Path.GetFileName(name.Replace('\\', '/')).Select(c => c < 32 || "<>:\"|?*".Contains(c) ? '_' : c)]);
            return safe.Trim().Trim('.') is { Length: > 0 } trimmed ? trimmed[..Math.Min(trimmed.Length, 150)] : "file";
        }
    }
}

/// <summary>
/// A person's data export's own words in one language: its README, and why a store isn't in it. A host
/// rewords them or adds a language in <see cref="GuardTextOptions.Export"/> (Guard:Texts).
/// </summary>
public sealed record PersonalDataExportTexts(string Language, string Title, string Intro, string ByPerson, string ByAdmin, string Layout, string Redact, string Stores,
    string NoExporter, string NotDeclared, string Failed, string TurnedOff)
{
    public static readonly PersonalDataExportTexts English = new("en",
        "Personal data",
        "The data this site keeps about {0}, as it was on {1} (UTC), asked for by {2}.",
        "the person themself",
        "a site admin",
        "Each store of data that holds something about this person is a folder, with its rows as JSON; files are under `files/`. "
        + "`index.json` says how many rows each store holds, and which stores aren't here and why. Only what's about this person or by them "
        + "is here: not other people's comments, nor the fields of records they didn't write.",
        "Rows marked `\"noLongerReadable\": true` are on items the person can no longer open (a project they left). The controller may "
        + "redact them before handing this export over.",
        "What the site keeps",
        "Nothing exports this store for one person.",
        "Its module or plugin doesn't declare this store.",
        "Its export failed; the site's log says why.",
        "Its plugin was turned off during the export.");

    public static readonly PersonalDataExportTexts Arabic = new("ar",
        "البيانات الشخصية",
        "البيانات التي يحفظها هذا الموقع عن {0} كما كانت في {1} (بالتوقيت العالمي)، بطلب من {2}.",
        "الشخص نفسه",
        "مشرف الموقع",
        "كل مخزن بيانات يحوي شيئًا عن هذا الشخص مجلدٌ فيه صفوفه بصيغة JSON، والملفات في `files/`. "
        + "يذكر `index.json` عدد صفوف كل مخزن، والمخازن غير الموجودة هنا ولماذا. لا يوجد هنا إلا ما يخص هذا الشخص أو ما كتبه: "
        + "لا تعليقات الآخرين، ولا حقول السجلات التي لم يكتبها.",
        "الصفوف الموسومة بـ `\"noLongerReadable\": true` عن عناصر لم يعد الشخص يستطيع فتحها (مشروع غادره). لجهة التحكم أن تحجبها "
        + "قبل تسليم هذا التصدير.",
        "ما يحفظه الموقع",
        "لا شيء يصدّر هذا المخزن لشخص واحد.",
        "لا تعلن وحدته أو إضافته هذا المخزن.",
        "فشل تصديره، وسجل الموقع يذكر السبب.",
        "عُطّلت إضافته أثناء التصدير.");

}
