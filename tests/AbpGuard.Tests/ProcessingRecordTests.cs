using AbpGuard.Domain;
using AbpGuard.Services.Privacy;
using Xunit;

namespace AbpGuard.Tests;

/// <summary>
/// The record of processing (PDPL): what PDPL asks a controller to keep, in Markdown and CSV, in
/// English and Arabic, with the gaps said and nothing typed into it read as a formula.
/// </summary>
public class ProcessingRecordTests
{
    private static readonly PrivacyStoreDto Comments = Store("projects.comments", "projects", PrivacyStoreDto.Module, ["mail", "ai"],
        new PrivacyRecordedDto("projects.comments", LegalBases.Agreement, true, "=HYPERLINK(\"x\"), and more", DateTime.UtcNow, null));

    private static readonly PrivacyStoreDto Contacts = Store("crm.contacts", "crm", PrivacyStoreDto.Plugin, [], null);

    private static PrivacyStoreDto Store(string key, string owner, string kind, IReadOnlyList<string> goesTo, PrivacyRecordedDto? recorded) =>
        new(key, owner, kind, new LocalizedText($"Name of {key}", $"اسم {key}"), new LocalizedText("Why", "لماذا"), [], [], [], PersonalDataSubjects.Both,
            [PersonalDataKinds.Content], PersonalDataKept.Setting("Mail:KeepDays", 180), goesTo, true, recorded);

    private static PrivacyMapDto Map(params InstalledPlugin[] plugins) => new(
        [Comments, Contacts],
        plugins,
        new PrivacySettingsDto(new PrivacyContactDto("Acme Co.", "privacy@acme.example"), new PrivacyContactDto(null, null), "Saudi Arabia",
            new Dictionary<string, PrivacyDestination> { ["mail"] = new("Mail Corp", "Saudi Arabia", false), ["ai"] = new("Model Inc.", "Ireland", true) },
            null, null),
        [], PersonalDataKinds.All, PersonalDataDestinations.All, LegalBases.All);

    private static InstalledPlugin Plugin(string key, string state, PluginPersonalData data, string installed = InstalledPlugin.States.Enabled) =>
        new(key, new LocalizedText(key.ToUpperInvariant(), key.ToUpperInvariant()), "1.0.0", installed, null, data with { State = state });

    [Fact]
    public void Markdown_names_the_controller_each_activity_and_where_it_goes()
    {
        string md = ProcessingRecord.ToMarkdown(Map(Plugin("crm", PersonalDataDeclaration.States.Declared, new("crm", "", [], [], []))),
            ProcessingRecordTexts.English, "en", new DateTime(2026, 10, 27, 0, 0, 0, DateTimeKind.Utc));

        Assert.Contains("# Record of processing activities", md);
        Assert.Contains("on 2026-10-27", md);
        Assert.Contains("- Name: Acme Co.", md);
        Assert.Contains("## Data protection officer\n\n- Name: not recorded yet", md);
        Assert.Contains("### Name of projects.comments (`projects.comments`)", md);
        Assert.Contains("- Legal basis: an agreement with the person", md);
        Assert.Contains("- Who receives it: the mail server: Mail Corp, Saudi Arabia; AI providers: Model Inc., Ireland", md);
        Assert.Contains("## The site's country\n\nSaudi Arabia\n", md);
        Assert.Contains("- Outside the site's country: yes: AI providers (Ireland)", md);
        Assert.Contains("- Kept today: 180 days by default (Mail:KeepDays)", md);
        Assert.Contains("- May hold sensitive data: yes", md);
        Assert.Contains("- Kept by: CRM", md);
        Assert.Contains("- Who receives it: stays on the site", md);
    }

    [Fact]
    public void The_gaps_are_said()
    {
        string md = ProcessingRecord.ToMarkdown(Map(
                Plugin("agenda", PersonalDataDeclaration.States.DoesntSay, new("agenda", "", [], [], [])),
                Plugin("notes", PersonalDataDeclaration.States.Problems, new("notes", "", [], [], ["guard.personal-data@1 is a list of entries."]), InstalledPlugin.States.Removed)),
            ProcessingRecordTexts.English, "en", DateTime.UtcNow);

        Assert.Contains("**Stores with no legal basis yet**: \n- Name of crm.contacts (`crm.contacts`)", md);
        Assert.Contains("**Plugins that don't say what they keep about people**: \n- AGENDA (`agenda`)", md);
        Assert.Contains("- NOTES (`notes`): guard.personal-data@1 is a list of entries.", md);
        Assert.DoesNotContain("The site's country isn't recorded", md);
    }

    [Fact]
    public void A_site_without_its_country_has_that_gap_first()
    {
        PrivacyMapDto map = Map();
        map = map with { Settings = map.Settings with { Country = " " } };

        string md = ProcessingRecord.ToMarkdown(map, ProcessingRecordTexts.English, "en", DateTime.UtcNow);
        Assert.Contains("## The site's country\n\nnot recorded yet\n", md);
        Assert.Contains("## Gaps\n\n**The site's country isn't recorded, so what leaves it can't be said**\n\n**Stores with no legal basis yet**", md);
        Assert.Contains("لم يُسجَّل بلد الموقع", ProcessingRecord.ToMarkdown(map, ProcessingRecordTexts.Arabic, "ar", DateTime.UtcNow));
    }

    [Fact]
    public void Arabic_takes_the_stores_arabic_and_its_own_words()
    {
        string md = ProcessingRecord.ToMarkdown(Map(), ProcessingRecordTexts.Arabic, "ar", DateTime.UtcNow);

        Assert.Contains("# سجل أنشطة المعالجة", md);
        Assert.Contains("### اسم projects.comments (`projects.comments`)", md);
        Assert.Contains("- الأساس النظامي: اتفاق مع صاحب البيانات", md);
        Assert.Contains("- مدة الحفظ حاليًا: 180 يومًا افتراضيًا (Mail:KeepDays)", md);
    }

    [Fact]
    public void A_service_a_plugin_calls_is_named_and_may_be_outside_the_country()
    {
        PrivacyMapDto map = Map();
        map = map with
        {
            Stores = [Store("pay.payments", "pay", PrivacyStoreDto.Plugin, ["service:card-gateway"], null)],
            Settings = map.Settings with { Destinations = new Dictionary<string, PrivacyDestination> { ["service:card-gateway"] = new("Pay Co.", "Bahrain", true) } },
        };

        string md = ProcessingRecord.ToMarkdown(map, ProcessingRecordTexts.English, "en", DateTime.UtcNow);
        Assert.Contains("- Who receives it: the service card-gateway: Pay Co., Bahrain", md);
        Assert.Contains("- Outside the site's country: yes: the service card-gateway (Bahrain)", md);
        Assert.Contains("الخدمة card-gateway", ProcessingRecord.ToMarkdown(map, ProcessingRecordTexts.Arabic, "ar", DateTime.UtcNow));
    }

    [Fact]
    public void Csv_has_a_row_a_store_and_nothing_read_as_a_formula()
    {
        string csv = ProcessingRecord.ToCsv(Map(), ProcessingRecordTexts.English, "en");
        string[] lines = csv.TrimStart('﻿').Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        Assert.StartsWith("﻿", csv);
        Assert.Equal(3, lines.Length);
        Assert.StartsWith("key,Store,Kept by,Purpose,", lines[0]);
        Assert.StartsWith("projects.comments,Name of projects.comments,Projects,", lines[1]);
        Assert.EndsWith(",\"'=HYPERLINK(\"\"x\"\"), and more\"", lines[1]);
    }
}
