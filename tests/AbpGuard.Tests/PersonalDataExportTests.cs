using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using AbpGuard.Domain;
using AbpGuard.Services.Privacy;
using Xunit;

namespace AbpGuard.Tests;

/// <summary>
/// A person's data exported (PDPL): a zip with the README first and the index last, a folder a store,
/// rows on what the person can no longer open left out of their own export, and a store whose export failed or that no
/// one exports said so, not left out in silence.
/// </summary>
public class PersonalDataExportTests
{
    private static readonly PersonalDataSubject Mona = new(Guid.Parse("11111111-1111-1111-1111-111111111111"), ["mona@example.com"], []);

    private static PrivacyStoreDto Store(string key, string owner, string kind) =>
        new(key, owner, kind, new LocalizedText($"Name of {key}", $"اسم {key}"), new LocalizedText("Why", "لماذا"), [], [], [], PersonalDataSubjects.Both,
            [PersonalDataKinds.Content], PersonalDataKept.Forever, [], true, null);

    private static PrivacyMapDto Map(params PrivacyStoreDto[] stores) => new(
        stores, [], new PrivacySettingsDto(new PrivacyContactDto(null, null), new PrivacyContactDto(null, null), null, new Dictionary<string, PrivacyDestination>(), null, null),
        [], PersonalDataKinds.All, PersonalDataDestinations.All, LegalBases.All);

    private static readonly PrivacyMapDto Site = Map(
        Store("projects.comments", "projects", PrivacyStoreDto.Module),
        Store("projects.records", "projects", PrivacyStoreDto.Module),
        Store("crm.contacts", "crm", PrivacyStoreDto.Plugin),
        Store("guard.limits", "guard", PrivacyStoreDto.Module));

    private sealed class Exporter(IReadOnlyList<string> stores, Func<IPersonalDataExport, Task> export) : IPersonalDataExporter
    {
        public IReadOnlyList<string> Stores => stores;

        public Task ExportAsync(IPersonalDataExport to, CancellationToken cancellationToken = default) => export(to);
    }

    private sealed class Plugins(params (string Key, IPersonalDataExporter Exporter)[] exporters) : IGuardExtensions
    {
        public IGuardLease<T> Lease<T>(IServiceProvider services) where T : class => new Leased<T>([.. exporters.Select(e => ((string?)e.Key, (T)e.Exporter))]);

        private sealed class Leased<T>(List<(string?, T)> items) : IGuardLease<T> where T : class
        {
            public IEnumerable<(string? PluginKey, T Instance)> Items => items;

            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }

    private static readonly Exporter Comments = new(["projects.comments"], to => to.WriteAsync("projects.comments", "comments", PersonalDataRows.Of(
    [
        new JsonObject { ["text"] = "Looks good" },
        new JsonObject { ["text"] = "In a project Mona left", [PersonalDataExportKeys.NoLongerReadable] = true },
    ])));

    private static readonly Exporter Contacts = new(["contacts"], to => to.WriteAsync("contacts", "your-details", PersonalDataRows.Of([new JsonObject { ["phone"] = "+100" }])));

    private static async Task<(DataExportSummary Summary, Dictionary<string, string> Entries)> ExportAsync(IEnumerable<IPersonalDataExporter> host,
        IGuardExtensions plugins, string requestedBy = PersonalDataRequesters.Person, bool files = false)
    {
        ServiceCollection services = new();
        foreach (IPersonalDataExporter exporter in host)
        {
            services.AddSingleton(exporter);
        }

        PersonalDataExports exports = new(null!, plugins, services.BuildServiceProvider(), null!, Options.Create(new GuardOptions()),
            NullLogger<PersonalDataExports>.Instance);
        using MemoryStream zip = new();
        DataExportSummary summary = await exports.WriteAsync(zip, Site, Mona, "Mona", requestedBy, "en", files, CancellationToken.None);

        zip.Position = 0;
        using ZipArchive read = new(zip, ZipArchiveMode.Read);
        Dictionary<string, string> entries = [];
        foreach (ZipArchiveEntry entry in read.Entries)
        {
            using StreamReader text = new(entry.Open(), Encoding.UTF8);
            entries[entry.FullName] = text.ReadToEnd();
        }

        Assert.Equal("README.md", read.Entries[0].FullName);
        Assert.Equal("index.json", read.Entries[^1].FullName);
        return (summary, entries);
    }

    [Fact]
    public async Task A_folder_a_store_with_a_plugins_stores_under_its_key()
    {
        (DataExportSummary summary, Dictionary<string, string> entries) = await ExportAsync([Comments], new Plugins(("crm", Contacts)));

        Assert.Equal(["README.md", "projects.comments/comments.json", "crm.contacts/your-details.json", "index.json"], entries.Keys);
        Assert.Equal("+100", JsonNode.Parse(entries["crm.contacts/your-details.json"])![0]!["phone"]!.GetValue<string>());
        Assert.Contains("# Personal data", entries["README.md"]);
        Assert.Contains("(`crm.contacts`)", entries["README.md"]);

        Assert.Equal(["projects.records", "guard.limits"], summary.Missing.Select(m => m.Store));
        JsonNode index = JsonNode.Parse(entries["index.json"])!;
        Assert.Equal("person", index["requestedBy"]!.GetValue<string>());
        Assert.Equal("mona@example.com", index["emails"]![0]!.GetValue<string>());
        Assert.Equal(["projects.comments", "crm.contacts"], index["stores"]!.AsArray().Select(s => s!["key"]!.GetValue<string>()));

        Exporter empty = new(["projects.records"], _ => Task.CompletedTask);
        (DataExportSummary nothing, _) = await ExportAsync([empty], new Plugins());
        Assert.Equal(0, nothing.Rows["projects.records"]);
        Assert.DoesNotContain(nothing.Missing, m => m.Store == "projects.records");
    }

    [Fact]
    public async Task Rows_on_what_they_can_no_longer_open_are_left_out_of_their_own_export_and_marked_in_an_admins()
    {
        (DataExportSummary own, Dictionary<string, string> theirs) = await ExportAsync([Comments], new Plugins());
        JsonArray rows = JsonNode.Parse(theirs["projects.comments/comments.json"])!.AsArray();
        Assert.Equal(["Looks good"], rows.Select(r => r!["text"]!.GetValue<string>()));
        Assert.Equal(1, own.Rows["projects.comments"]);
        Assert.DoesNotContain("redact", theirs["README.md"]);

        (DataExportSummary admins, Dictionary<string, string> entries) = await ExportAsync([Comments], new Plugins(), PersonalDataRequesters.Admin);
        Assert.Equal(2, JsonNode.Parse(entries["projects.comments/comments.json"])!.AsArray().Count);
        Assert.Equal(2, admins.Rows["projects.comments"]);
        Assert.Equal(1, admins.NoLongerReadable["projects.comments"]);
        Assert.Contains("redact", entries["README.md"]);
    }

    [Fact]
    public async Task A_failing_exporter_is_said_in_the_index_and_the_others_still_export()
    {
        Exporter failing = new(["projects.records"], _ => throw new InvalidOperationException("Npgsql: relation \"projects.records\" does not exist"));
        (DataExportSummary summary, Dictionary<string, string> entries) = await ExportAsync([failing, Comments], new Plugins(("crm", Contacts)));

        DataExportMissing records = Assert.Single(summary.Missing, m => m.Store == "projects.records");
        Assert.False(summary.Rows.ContainsKey("projects.records"));
        Assert.Equal("Its export failed; the site's log says why.", records.Why);
        Assert.DoesNotContain("Npgsql", entries["index.json"]);
        Assert.Contains("projects.comments/comments.json", entries.Keys);
        Assert.Contains("crm.contacts/your-details.json", entries.Keys);
    }

    [Fact]
    public async Task An_exporter_writes_only_the_stores_it_exports_and_declared()
    {
        Exporter undeclared = new(["projects.nothing"], _ => Task.CompletedTask);
        Exporter strays = new(["projects.records"], to => to.WriteAsync("projects.comments", "not-mine", PersonalDataRows.Of([new JsonObject()])));
        (DataExportSummary summary, Dictionary<string, string> entries) = await ExportAsync([undeclared, strays], new Plugins());

        Assert.Equal("Its module or plugin doesn't declare this store.", Assert.Single(summary.Missing, m => m.Store == "projects.nothing").Why);
        Assert.Equal("Its export failed; the site's log says why.", Assert.Single(summary.Missing, m => m.Store == "projects.records").Why);
        Assert.DoesNotContain("projects.comments/not-mine.json", entries.Keys);
    }

    [Fact]
    public async Task A_plugin_turned_off_during_the_export_is_said_for_its_stores()
    {
        int leases = 0;
        LeaseCounting plugins = new(() => leases++ == 0);
        (DataExportSummary summary, _) = await ExportAsync([Comments], plugins);

        Assert.Equal("Its plugin was turned off during the export.", Assert.Single(summary.Missing, m => m.Store == "crm.contacts").Why);
    }

    /// <summary>Lists the CRM plugin while <paramref name="on"/> says it's on: the first lease (which plugins there are) only.</summary>
    private sealed class LeaseCounting(Func<bool> on) : IGuardExtensions
    {
        public IGuardLease<T> Lease<T>(IServiceProvider services) where T : class =>
            new Plugins(on() ? [("crm", Contacts)] : []).Lease<T>(services);
    }

    [Fact]
    public async Task Files_only_when_asked_with_names_kept_inside_their_folder()
    {
        Exporter upload = new(["projects.comments"], async to =>
        {
            await to.WriteFileAsync("projects.comments", "../../etc/passwd", new MemoryStream("one"u8.ToArray()));
            await to.WriteFileAsync("projects.comments", "passwd", new MemoryStream("two"u8.ToArray()));
        });

        (DataExportSummary without, Dictionary<string, string> none) = await ExportAsync([upload], new Plugins());
        Assert.Equal(0, without.Files);
        Assert.DoesNotContain(none.Keys, k => k.StartsWith("files/", StringComparison.Ordinal));

        (DataExportSummary with, Dictionary<string, string> entries) = await ExportAsync([upload], new Plugins(), files: true);
        Assert.Equal(2, with.Files);
        Assert.Equal("one", entries["files/projects.comments/passwd"]);
        Assert.Equal("two", entries["files/projects.comments/passwd (2)"]);
    }

    [Fact]
    public async Task The_readme_is_in_the_language_asked_for()
    {
        ServiceCollection services = new();
        PersonalDataExports exports = new(null!, new Plugins(), services.BuildServiceProvider(), null!, Options.Create(new GuardOptions()),
            NullLogger<PersonalDataExports>.Instance);
        using MemoryStream zip = new();
        await exports.WriteAsync(zip, Site, Mona, "Mona", PersonalDataRequesters.Person, "ar", false, CancellationToken.None);

        zip.Position = 0;
        using ZipArchive read = new(zip, ZipArchiveMode.Read);
        using StreamReader readme = new(read.GetEntry("README.md")!.Open(), Encoding.UTF8);
        string text = readme.ReadToEnd();
        Assert.Contains("# البيانات الشخصية", text);
        Assert.Contains("اسم crm.contacts", text);
        JsonDocument.Parse(new StreamReader(read.GetEntry("index.json")!.Open()).ReadToEnd()).Dispose();
    }

    [Fact]
    public async Task A_host_words_its_export_and_the_record_it_quotes_in_GuardOptions_Texts()
    {
        GuardOptions options = new();
        options.Texts.Export["en"] = PersonalDataExportTexts.English with { Title = "Your data, as we hold it" };
        options.Texts.Record["en"] = ProcessingRecordTexts.English with { Kept = "Held" };
        PersonalDataExports exports = new(null!, new Plugins(), new ServiceCollection().BuildServiceProvider(), null!, Options.Create(options),
            NullLogger<PersonalDataExports>.Instance);
        using MemoryStream zip = new();
        await exports.WriteAsync(zip, Site, Mona, "Mona", PersonalDataRequesters.Person, "en-GB", false, CancellationToken.None);

        zip.Position = 0;
        using ZipArchive read = new(zip, ZipArchiveMode.Read);
        using StreamReader readme = new(read.GetEntry("README.md")!.Open(), Encoding.UTF8);
        string text = readme.ReadToEnd();
        Assert.StartsWith("# Your data, as we hold it\n", text);
        Assert.Contains("Held: ", text);
    }
}
