using System.Text.Json;
using System.Text.RegularExpressions;

namespace AbpGuard;

/// <summary>A text in English and Arabic, with nothing else referenced, so the contracts stand alone.</summary>
public sealed record LocalizedText(string En, string Ar);

/// <summary>
/// What a store keeps about people (the data map). Open: a host may add its own kinds; these are the ones Guard
/// uses.
/// </summary>
public static class PersonalDataKinds
{
    public const string Identity = "identity";
    public const string Contact = "contact";
    public const string Credentials = "credentials";

    /// <summary>Addresses people come from, their devices and browsers.</summary>
    public const string Security = "security";

    /// <summary>What people did, and when.</summary>
    public const string Activity = "activity";

    /// <summary>What people write or upload.</summary>
    public const string Content = "content";

    public const string Preferences = "preferences";

    public static readonly IReadOnlyList<string> All = [Identity, Contact, Credentials, Security, Activity, Content, Preferences];
}

/// <summary>Whom a store is about: people with accounts, people known only by an address (outside), or both.</summary>
public static class PersonalDataSubjects
{
    public const string Accounts = "accounts";
    public const string Outside = "outside";
    public const string Both = "both";

    public static readonly IReadOnlyList<string> All = [Accounts, Outside, Both];
}

/// <summary>Where a store's data can leave the site. Open: a host may add its own (the marketplace has no LDAP or git hosts).</summary>
public static partial class PersonalDataDestinations
{
    public const string Mail = "mail";
    public const string Sms = "sms";
    public const string WhatsApp = "whatsapp";
    public const string Chat = "chat";
    public const string Push = "push";
    public const string Webhooks = "webhooks";
    public const string Ai = "ai";
    public const string OutsideMcp = "outside-mcp";
    public const string GitHosts = "git-hosts";
    public const string Storage = "storage";
    public const string Backups = "backups";
    public const string Directory = "directory";

    public static readonly IReadOnlyList<string> All = [Mail, Sms, WhatsApp, Chat, Push, Webhooks, Ai, OutsideMcp, GitHosts, Storage, Backups, Directory];

    /// <summary>
    /// A service outside the site a plugin sends data to, named: <c>service:stripe</c>, <c>service:acme-enrich</c> (its
    /// vendor's API, a payment provider). The site records its recipient and country as for any destination.
    /// </summary>
    public const string ServicePrefix = "service:";

    public static bool IsService(string destination) =>
        destination.StartsWith(ServicePrefix, StringComparison.Ordinal) && ServiceName().IsMatch(destination[ServicePrefix.Length..]);

    /// <summary>One of the destinations given (the host's, Guard's when none), or a named service.</summary>
    public static bool IsKnown(string destination, IReadOnlyCollection<string>? destinations = null) =>
        (destinations ?? All).Contains(destination) || IsService(destination);

    private const int TimeoutMilliseconds = 1000;

    [GeneratedRegex("^[a-z0-9]+(-[a-z0-9]+)*$", RegexOptions.None, TimeoutMilliseconds)]
    private static partial Regex ServiceName();
}

/// <summary>
/// How long a store's rows are kept today, the longest of its tables: <c>until-done</c> (deleted once they've done their
/// work: an event delivered, a code used), <c>with-account</c> (until the person's account or what they set up goes),
/// <c>days:30</c>, a setting with its default (<c>setting:Mail:KeepDays=180</c>), or <c>forever</c>.
/// </summary>
public static class PersonalDataKept
{
    public const string UntilDone = "until-done";
    public const string WithAccount = "with-account";
    public const string Forever = "forever";

    public static string Days(int days) => $"days:{days}";

    public static string Setting(string key, int defaultDays) => $"setting:{key}={defaultDays}";

    public static bool IsValid(string? kept)
    {
        if (kept is UntilDone or WithAccount or Forever)
        {
            return true;
        }

        if (kept?.StartsWith("days:", StringComparison.Ordinal) == true)
        {
            return int.TryParse(kept[5..], out int days) && days > 0;
        }

        int at = kept?.LastIndexOf('=') ?? -1;
        return kept?.StartsWith("setting:", StringComparison.Ordinal) == true && at > 8 && int.TryParse(kept[(at + 1)..], out int byDefault) && byDefault >= 0;
    }
}

/// <summary>A field of the host's own records or assets that holds people's data for a plugin (the CRM's lead email).</summary>
public sealed record PersonalDataField(string On, string Key)
{
    public const string Record = "record";
    public const string Asset = "asset";
}

/// <summary>
/// A store of personal data: tables and files about people that are handled together. <paramref name="Tables"/>
/// are <c>schema.table</c>; <paramref name="Files"/> a file store and prefix (<c>attachments:records/</c>,
/// <c>plugin-files:sample-import/</c>) or a folder (<c>folder:mail-pickup</c>). <paramref name="Kept"/> is what
/// <see cref="PersonalDataKept"/> says. Export and anonymising (steps 3 and 5 of docs/pdpl.md) come later, keyed by
/// <paramref name="Key"/>.
/// </summary>
public sealed record PersonalDataStore(
    string Key,
    string Owner,
    LocalizedText Name,
    LocalizedText Purpose,
    IReadOnlyList<string> Tables,
    IReadOnlyList<string> Files,
    string About,
    IReadOnlyList<string> Kinds,
    string Kept,
    IReadOnlyList<string> GoesTo,
    IReadOnlyList<PersonalDataField> Fields);

/// <summary>A table that holds nothing about people, and why (so every table is classified).</summary>
public sealed record NonPersonalTable(string Table, string Why);

/// <summary>
/// A module's declaration of what it keeps about people. The host's modules each register one; a plugin
/// declares its own in its manifest instead (<see cref="PersonalDataDeclaration"/>).
/// </summary>
public interface IPersonalDataDeclarations
{
    IReadOnlyList<PersonalDataStore> Stores { get; }

    IReadOnlyList<NonPersonalTable> NotPersonal { get; }
}

/// <summary>A plugin's declaration, read from its manifest: <see cref="PersonalDataDeclaration.States"/>.</summary>
public sealed record PluginPersonalData(
    string Plugin,
    string State,
    IReadOnlyList<PersonalDataStore> Stores,
    IReadOnlyList<NonPersonalTable> NotPersonal,
    IReadOnlyList<string> Problems);

/// <summary>
/// A plugin a site has, enabled, disabled, or uninstalled while what it kept may remain, with its
/// declaration; its stores' names and purposes are in the site's languages.
/// </summary>
public sealed record InstalledPlugin(string Key, LocalizedText Name, string Version, string State, DateTime? RemovedAt, PluginPersonalData PersonalData)
{
    public static class States
    {
        public const string Enabled = "enabled";
        public const string Disabled = "disabled";

        /// <summary>Uninstalled, but its schema is still there or it declared stores: what it kept may remain.</summary>
        public const string Removed = "removed";
    }
}

/// <summary>
/// The plugins a host has, for the data map Guard's default has none, so Guard on its own maps its
/// host's modules only; a host with plugins reads every plugin a site has installed, even disabled or removed.
/// </summary>
public interface IPluginPersonalDataSource
{
    Task<IReadOnlyList<InstalledPlugin>> ListAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Whose data an export is: a person with an account, by its id, with the account's own addresses so
/// what was sent to them is found too; or someone outside the site known only by an address (a requester, a mail sender, a
/// customer).
/// </summary>
public sealed record PersonalDataSubject(Guid? AccountId, IReadOnlyList<string> Emails, IReadOnlyList<string> Phones)
{
    /// <summary>The fewest digits a phone is compared by, so a short number never stands for many.</summary>
    public const int MinPhoneDigits = 6;

    /// <summary>Someone outside the site by an address: an email in lower case, as addresses are compared.</summary>
    public static PersonalDataSubject Outside(string? email, string? phone) =>
        new(null, string.IsNullOrWhiteSpace(email) ? [] : [email.Trim().ToLowerInvariant()], string.IsNullOrWhiteSpace(phone) ? [] : [phone.Trim()]);

    /// <summary>
    /// Whether a value is wholly one of the subject's: their account's id, one of their emails in any case, or one of their
    /// phones by its digits. A value that only contains one ("mali@example.com" for "ali@example.com") isn't.
    /// </summary>
    public bool Holds(string? value)
    {
        string trimmed = value?.Trim() ?? "";
        if (trimmed.Length == 0)
        {
            return false;
        }

        if (AccountId is { } id && Guid.TryParse(trimmed, out Guid guid) && guid == id)
        {
            return true;
        }

        if (Emails.Any(e => string.Equals(e, trimmed, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        string digits = Digits(trimmed);
        return digits.Length >= MinPhoneDigits && trimmed.All(c => char.IsAsciiDigit(c) || c is '+' or ' ' or '-' or '(' or ')' or '.')
            && Phones.Any(p => Digits(p) == digits);
    }

    /// <summary>A phone's digits, how phones are compared: "+966 50 123 4567" is "966501234567".</summary>
    public static string Digits(string phone) => new([.. phone.Where(char.IsAsciiDigit)]);
}

/// <summary>
/// Who asked for an export, which decides what goes in from records the person can no longer read: their own export
/// holds what they wrote on what they can still read; an admin's holds all of it, each item on what they can't read
/// marked, for the controller to redact if it must before handing it over.
/// </summary>
public static class PersonalDataRequesters
{
    public const string Person = "person";
    public const string Admin = "admin";
}

/// <summary>
/// What an exporter writes to. Rows are JSON objects, Guard's own types, so nothing of a plugin's
/// stays referenced once its export is done, and a big store streams without being held: each name is a file
/// <c>{store}/{name}.json</c>. Files go under <c>files/{store}/</c>. A store is named as its module or plugin declares
/// it; a plugin gives its short key (<c>pages</c>), and Guard qualifies it.
/// </summary>
public interface IPersonalDataExport
{
    PersonalDataSubject Subject { get; }

    /// <summary>One of <see cref="PersonalDataRequesters"/>.</summary>
    string RequestedBy { get; }

    /// <summary>The language labels are written in: <c>en</c>, <c>ar</c>, a site's other languages.</summary>
    string Language { get; }

    /// <summary>Whether files go in; without, a file's row says it was left out.</summary>
    bool Files { get; }

    Task WriteAsync(string store, string name, IAsyncEnumerable<System.Text.Json.Nodes.JsonObject> rows, CancellationToken cancellationToken = default);

    Task WriteFileAsync(string store, string name, Stream content, CancellationToken cancellationToken = default);
}

/// <summary>
/// Exports what some stores hold about one person: what's about them or by them, nothing of anyone
/// else's. The host's modules register theirs; a plugin adds one with <c>AddExtension</c>, naming its stores by their short
/// keys as in its manifest. A store it names that its module or plugin doesn't declare is reported, not trusted.
/// </summary>
public interface IPersonalDataExporter
{
    IReadOnlyList<string> Stores { get; }

    Task ExportAsync(IPersonalDataExport export, CancellationToken cancellationToken = default);
}

/// <summary>Rows for <see cref="IPersonalDataExport.WriteAsync"/>.</summary>
public static class PersonalDataRows
{
    /// <summary>Rows already in memory, as the export takes them.</summary>
    public static async IAsyncEnumerable<System.Text.Json.Nodes.JsonObject> Of(IEnumerable<System.Text.Json.Nodes.JsonObject> rows)
    {
        foreach (System.Text.Json.Nodes.JsonObject row in rows)
        {
            yield return row;
        }

        await Task.CompletedTask;
    }
}

/// <summary>Keys a row of an export may carry that Guard reads.</summary>
public static class PersonalDataExportKeys
{
    /// <summary>
    /// <c>true</c> on a row about an item the person can no longer read (a record they left): only in an admin's export,
    /// counted in its index, for the controller to redact if it must before handing the export over.
    /// </summary>
    public const string NoLongerReadable = "noLongerReadable";
}

/// <summary>
/// A plugin's personal data as its manifest declares it: the contribution <c>guard.personal-data@1</c>, an array of
/// entries. An entry is a store (<c>key</c>, <c>name</c>, <c>purpose</c>, <c>tables</c>, <c>files</c>, <c>about</c>,
/// <c>kinds</c>, <c>kept</c>, <c>goesTo</c>, <c>fields</c>) or tables that hold nothing about people (<c>none</c>:
/// true, <c>tables</c>, <c>why</c>). A plugin names tables in its own schema only (<c>people</c>, made
/// <c>plg_{key}.people</c>) and files in its own area (<c>files</c>: true, or prefixes in it). Its texts are English;
/// the translations come from its messages (<c>personalData.{key}.name</c>, <c>.purpose</c>). A declaration with
/// problems is never skipped quietly: it's read as far as it goes, and the problems are said.
/// </summary>
public static partial class PersonalDataDeclaration
{
    public const string ExtensionPoint = "guard.personal-data@1";

    /// <summary>What a plugin's manifest says about personal data.</summary>
    public static class States
    {
        /// <summary>It declares stores (and maybe tables that hold nothing).</summary>
        public const string Declared = "declared";

        /// <summary><c>"guard.personal-data@1": []</c>, or only tables that hold nothing.</summary>
        public const string KeepsNothing = "keeps-nothing";

        /// <summary>No <c>guard.personal-data@1</c> in its manifest.</summary>
        public const string DoesntSay = "doesnt-say";

        /// <summary>Its declaration has problems; what could be read is kept.</summary>
        public const string Problems = "problems";
    }

    /// <summary>
    /// Reads a plugin's contribution (null when its manifest has none). Kinds and destinations are checked against what
    /// the host knows (the host's lists unless it passes its own).
    /// </summary>
    public static PluginPersonalData Read(string plugin, JsonElement? contribution, IReadOnlyCollection<string>? kinds = null,
        IReadOnlyCollection<string>? destinations = null)
    {
        if (contribution is not { } items)
        {
            return new(plugin, States.DoesntSay, [], [], []);
        }

        kinds ??= PersonalDataKinds.All;
        destinations ??= PersonalDataDestinations.All;
        List<PersonalDataStore> stores = [];
        List<NonPersonalTable> none = [];
        List<string> problems = [];
        if (items.ValueKind != JsonValueKind.Array)
        {
            return new(plugin, States.Problems, [], [], [$"{ExtensionPoint} is a list of entries."]);
        }

        string schema = SchemaOf(plugin);
        int index = 0;
        foreach (JsonElement item in items.EnumerateArray())
        {
            index++;
            string at = $"{ExtensionPoint}[{index}]";
            if (item.ValueKind != JsonValueKind.Object)
            {
                problems.Add($"{at} isn't an entry.");
                continue;
            }

            List<string> tables = Strings(item, "tables", at, problems);
            List<string> qualified = [];
            foreach (string table in tables)
            {
                if (TableName().IsMatch(table))
                {
                    qualified.Add($"{schema}.{table}");
                }
                else
                {
                    problems.Add($"{at}: '{table}' isn't a table of the plugin's own schema (lowercase, no schema).");
                }
            }

            if (Bool(item, "none"))
            {
                string why = Text(item, "why") ?? "";
                if (why.Length == 0)
                {
                    problems.Add($"{at}: tables that hold nothing about people say why.");
                }

                if (qualified.Count == 0)
                {
                    problems.Add($"{at}: name the tables that hold nothing about people.");
                }

                none.AddRange(qualified.Select(t => new NonPersonalTable(t, why)));
                continue;
            }

            string key = Text(item, "key") ?? "";
            if (!StoreKey().IsMatch(key))
            {
                problems.Add($"{at}: a store's key is lowercase words joined by dashes.");
                continue;
            }

            at = $"{ExtensionPoint} '{key}'";
            string name = Text(item, "name") ?? "";
            string purpose = Text(item, "purpose") ?? "";
            if (name.Length == 0 || purpose.Length == 0)
            {
                problems.Add($"{at}: a store has a name and a purpose.");
            }

            string about = Text(item, "about") ?? "";
            if (!PersonalDataSubjects.All.Contains(about))
            {
                problems.Add($"{at}: about is one of {string.Join(", ", PersonalDataSubjects.All)}.");
            }

            List<string> storeKinds = Strings(item, "kinds", at, problems);
            foreach (string kind in storeKinds.Where(k => !kinds.Contains(k)))
            {
                problems.Add($"{at}: '{kind}' isn't a kind of personal data this site knows ({string.Join(", ", kinds)}).");
            }

            if (storeKinds.Count == 0)
            {
                problems.Add($"{at}: say what kinds of personal data it keeps.");
            }

            string kept = Text(item, "kept") ?? "";
            if (!PersonalDataKept.IsValid(kept))
            {
                problems.Add($"{at}: kept is until-done, with-account, days:N, setting:Key=N or forever.");
            }

            List<string> goesTo = Strings(item, "goesTo", at, problems);
            foreach (string destination in goesTo.Where(d => !PersonalDataDestinations.IsKnown(d, destinations)))
            {
                problems.Add($"{at}: '{destination}' isn't a destination this site knows ({string.Join(", ", destinations)}, or service:{{name}}).");
            }

            List<string> files = Files(item, plugin, at, problems);
            List<PersonalDataField> fields = Fields(item, at, problems);
            if (qualified.Count == 0 && files.Count == 0 && fields.Count == 0)
            {
                problems.Add($"{at}: a store names its tables, its files or the fields it keeps people's data in.");
            }

            stores.Add(new PersonalDataStore($"{plugin}.{key}", plugin, new LocalizedText(name, name), new LocalizedText(purpose, purpose), qualified,
                files, about, storeKinds, kept, goesTo, fields));
        }

        string state = problems.Count > 0 ? States.Problems : stores.Count > 0 ? States.Declared : States.KeepsNothing;
        return new(plugin, state, stores, none, problems);
    }

    /// <summary>The contribution's shape, for a plugin's author and for anyone reading a package before it's installed.</summary>
    public const string JsonSchema = """
        {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "$id": "urn:abpguard:personal-data@1",
          "title": "guard.personal-data@1",
          "description": "What a plugin keeps about people: stores of personal data, and tables that hold none.",
          "type": "array",
          "items": {
            "oneOf": [
              {
                "type": "object",
                "required": ["key", "name", "purpose", "about", "kinds", "kept"],
                "properties": {
                  "key": { "type": "string", "pattern": "^[a-z0-9]+(-[a-z0-9]+)*$" },
                  "name": { "type": "string", "minLength": 1 },
                  "purpose": { "type": "string", "minLength": 1 },
                  "tables": { "type": "array", "items": { "type": "string", "pattern": "^[a-z][a-z0-9_]*$" } },
                  "files": { "oneOf": [ { "type": "boolean" }, { "type": "array", "items": { "type": "string" } } ] },
                  "about": { "enum": ["accounts", "outside", "both"] },
                  "kinds": { "type": "array", "minItems": 1, "items": { "type": "string" } },
                  "kept": { "type": "string", "pattern": "^(until-done|with-account|forever|days:[1-9][0-9]*|setting:[^=]+=[0-9]+)$" },
                  "goesTo": { "type": "array", "items": { "type": "string", "pattern": "^([a-z]+(-[a-z]+)*|service:[a-z0-9]+(-[a-z0-9]+)*)$" } },
                  "fields": { "type": "array", "items": { "type": "object", "required": ["on", "key"],
                    "properties": { "on": { "enum": ["record", "asset"] }, "key": { "type": "string" } } } }
                }
              },
              {
                "type": "object",
                "required": ["none", "tables", "why"],
                "properties": {
                  "none": { "const": true },
                  "tables": { "type": "array", "minItems": 1, "items": { "type": "string", "pattern": "^[a-z][a-z0-9_]*$" } },
                  "why": { "type": "string", "minLength": 1 }
                }
              }
            ]
          }
        }
        """;

    /// <summary>The schema a plugin's tables are in, as a plugin host names it: "guard-ldap" is "plg_guard_ldap".</summary>
    public static string SchemaOf(string plugin) =>
        "plg_" + new string(plugin.ToLowerInvariant().Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray());

    private static string? Text(JsonElement item, string property) =>
        item.TryGetProperty(property, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString()?.Trim() : null;

    private static bool Bool(JsonElement item, string property) =>
        item.TryGetProperty(property, out JsonElement value) && value.ValueKind == JsonValueKind.True;

    private static List<string> Strings(JsonElement item, string property, string at, List<string> problems)
    {
        if (!item.TryGetProperty(property, out JsonElement value))
        {
            return [];
        }

        if (value.ValueKind != JsonValueKind.Array || value.EnumerateArray().Any(v => v.ValueKind != JsonValueKind.String))
        {
            problems.Add($"{at}: {property} is a list of strings.");
            return [];
        }

        return [.. value.EnumerateArray().Select(v => v.GetString()!.Trim()).Where(v => v.Length > 0)];
    }

    /// <summary><c>true</c>: the plugin's whole area of files; a list: prefixes in it. Never another plugin's area.</summary>
    private static List<string> Files(JsonElement item, string plugin, string at, List<string> problems)
    {
        if (!item.TryGetProperty("files", out JsonElement value) || value.ValueKind == JsonValueKind.False)
        {
            return [];
        }

        if (value.ValueKind == JsonValueKind.True)
        {
            return [$"plugin-files:{plugin}/"];
        }

        List<string> prefixes = Strings(item, "files", at, problems);
        foreach (string prefix in prefixes.Where(p => p.Contains("..", StringComparison.Ordinal) || p.StartsWith('/') || p.Contains(':', StringComparison.Ordinal)))
        {
            problems.Add($"{at}: '{prefix}' isn't a prefix in the plugin's own files.");
        }

        return [.. prefixes.Where(p => !p.Contains("..", StringComparison.Ordinal) && !p.StartsWith('/') && !p.Contains(':', StringComparison.Ordinal))
            .Select(p => $"plugin-files:{plugin}/{p}")];
    }

    private static List<PersonalDataField> Fields(JsonElement item, string at, List<string> problems)
    {
        if (!item.TryGetProperty("fields", out JsonElement value))
        {
            return [];
        }

        if (value.ValueKind != JsonValueKind.Array)
        {
            problems.Add($"{at}: fields is a list.");
            return [];
        }

        List<PersonalDataField> fields = [];
        foreach (JsonElement field in value.EnumerateArray())
        {
            string on = field.ValueKind == JsonValueKind.Object ? Text(field, "on") ?? "" : "";
            string key = field.ValueKind == JsonValueKind.Object ? Text(field, "key") ?? "" : "";
            if (on is PersonalDataField.Record or PersonalDataField.Asset && key.Length > 0)
            {
                fields.Add(new PersonalDataField(on, key));
            }
            else
            {
                problems.Add($"{at}: a field is {{\"on\": \"record\" or \"asset\", \"key\": …}}.");
            }
        }

        return fields;
    }

    /// <summary>A regular expression's time limit: Guard's contracts keep their own.</summary>
    private const int TimeoutMilliseconds = 1000;

    [GeneratedRegex("^[a-z][a-z0-9_]*$", RegexOptions.None, TimeoutMilliseconds)]
    private static partial Regex TableName();

    [GeneratedRegex("^[a-z0-9]+(-[a-z0-9]+)*$", RegexOptions.None, TimeoutMilliseconds)]
    private static partial Regex StoreKey();
}
