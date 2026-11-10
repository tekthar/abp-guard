using System.Text.Json;
using Xunit;

namespace AbpGuard.Tests;

/// <summary>
/// A plugin's declaration of what it keeps about people (<c>guard.personal-data@1</c>): read as far as it
/// goes, never skipped quietly, and held to its own schema and files.
/// </summary>
public class PersonalDataDeclarationTests
{
    private static PluginPersonalData Read(string json, string plugin = "sample-import") =>
        PersonalDataDeclaration.Read(plugin, JsonDocument.Parse(json).RootElement.Clone());

    [Fact]
    public void A_store_is_read_into_the_plugins_schema_and_files()
    {
        PluginPersonalData read = Read("""
            [
              { "key": "people", "name": "People from the source", "purpose": "Who did what in the imported system",
                "tables": ["people"], "files": ["backups/"], "about": "both", "kinds": ["identity", "contact"],
                "kept": "forever", "goesTo": ["backups"] },
              { "none": true, "tables": ["backup_stages"], "why": "how far an import got" }
            ]
            """);

        Assert.Equal(PersonalDataDeclaration.States.Declared, read.State);
        Assert.Empty(read.Problems);
        PersonalDataStore store = Assert.Single(read.Stores);
        Assert.Equal("sample-import.people", store.Key);
        Assert.Equal("sample-import", store.Owner);
        Assert.Equal(["plg_sample_import.people"], store.Tables);
        Assert.Equal(["plugin-files:sample-import/backups/"], store.Files);
        Assert.Equal("plg_sample_import.backup_stages", Assert.Single(read.NotPersonal).Table);
    }

    [Fact]
    public void An_empty_list_keeps_nothing_and_no_key_doesnt_say()
    {
        Assert.Equal(PersonalDataDeclaration.States.KeepsNothing, Read("[]").State);
        Assert.Equal(PersonalDataDeclaration.States.DoesntSay, PersonalDataDeclaration.Read("crm", null).State);
    }

    [Fact]
    public void Fields_in_records_and_assets_are_a_store_without_tables()
    {
        PluginPersonalData read = Read("""
            [{ "key": "customers", "name": "Customers", "purpose": "Leads and customers", "about": "outside",
               "kinds": ["contact"], "kept": "with-account",
               "fields": [{ "on": "record", "key": "crm.email" }, { "on": "asset", "key": "crm.phone" }] }]
            """, "crm");

        Assert.Empty(read.Problems);
        Assert.Equal([new PersonalDataField("record", "crm.email"), new PersonalDataField("asset", "crm.phone")], Assert.Single(read.Stores).Fields);
    }

    [Fact]
    public void Another_schema_or_area_is_refused()
    {
        PluginPersonalData read = Read("""
            [{ "key": "people", "name": "People", "purpose": "Who", "tables": ["guard.accounts", "people"],
               "files": ["../artifacts/", "attachments:x"], "about": "accounts", "kinds": ["identity"], "kept": "forever" }]
            """);

        Assert.Equal(PersonalDataDeclaration.States.Problems, read.State);
        Assert.Contains(read.Problems, p => p.Contains("'guard.accounts'", StringComparison.Ordinal));
        Assert.Contains(read.Problems, p => p.Contains("'../artifacts/'", StringComparison.Ordinal));
        Assert.Contains(read.Problems, p => p.Contains("'attachments:x'", StringComparison.Ordinal));
        PersonalDataStore store = Assert.Single(read.Stores);
        Assert.Equal(["plg_sample_import.people"], store.Tables);
        Assert.Empty(store.Files);
    }

    [Theory]
    [InlineData("""{ "key": "people" }""", "a name and a purpose")]
    [InlineData("""{ "key": "People", "name": "P", "purpose": "P", "tables": ["people"], "about": "accounts", "kinds": ["identity"], "kept": "forever" }""", "lowercase words")]
    [InlineData("""{ "key": "people", "name": "P", "purpose": "P", "tables": ["people"], "about": "everyone", "kinds": ["identity"], "kept": "forever" }""", "about is one of")]
    [InlineData("""{ "key": "people", "name": "P", "purpose": "P", "tables": ["people"], "about": "accounts", "kinds": ["dna"], "kept": "forever" }""", "'dna'")]
    [InlineData("""{ "key": "people", "name": "P", "purpose": "P", "tables": ["people"], "about": "accounts", "kinds": ["identity"], "kept": "a while" }""", "kept is")]
    [InlineData("""{ "key": "people", "name": "P", "purpose": "P", "tables": ["people"], "about": "accounts", "kinds": ["identity"], "kept": "forever", "goesTo": ["the moon"] }""", "'the moon'")]
    [InlineData("""{ "key": "people", "name": "P", "purpose": "P", "about": "accounts", "kinds": ["identity"], "kept": "forever" }""", "names its tables")]
    [InlineData("""{ "none": true, "tables": ["stages"] }""", "say why")]
    [InlineData("""42""", "isn't an entry")]
    public void A_bad_entry_is_said_not_skipped(string entry, string problem)
    {
        PluginPersonalData read = Read($"[{entry}]");

        Assert.Equal(PersonalDataDeclaration.States.Problems, read.State);
        Assert.Contains(read.Problems, p => p.Contains(problem, StringComparison.Ordinal));
    }

    [Fact]
    public void Not_a_list_is_a_problem()
    {
        Assert.Equal(PersonalDataDeclaration.States.Problems, Read("""{ "key": "people" }""").State);
    }

    [Fact]
    public void A_plugin_names_the_services_outside_the_site_it_sends_data_to()
    {
        PluginPersonalData read = Read("""
            [{ "key": "payments", "name": "Payments", "purpose": "Who paid", "tables": ["payments"], "about": "both", "kinds": ["contact"],
               "kept": "forever", "goesTo": ["mail", "service:stripe", "service:acme-enrich"] }]
            """, "payments");

        Assert.Empty(read.Problems);
        Assert.Equal(["mail", "service:stripe", "service:acme-enrich"], Assert.Single(read.Stores).GoesTo);
    }

    [Theory]
    [InlineData("service:stripe", true)]
    [InlineData("service:acme-enrich", true)]
    [InlineData("service:", false)]
    [InlineData("service:Stripe", false)]
    [InlineData("service:a b", false)]
    [InlineData("stripe", false)]
    [InlineData("mail", true)]
    public void A_destination_is_the_sites_or_a_named_service(string destination, bool known) =>
        Assert.Equal(known, PersonalDataDestinations.IsKnown(destination));

    [Fact]
    public void A_host_may_know_other_destinations()
    {
        string json = """
            [{ "key": "people", "name": "P", "purpose": "P", "tables": ["people"], "about": "accounts", "kinds": ["identity"],
               "kept": "forever", "goesTo": ["listing"] }]
            """;

        Assert.Equal(PersonalDataDeclaration.States.Problems, Read(json).State);
        Assert.Empty(PersonalDataDeclaration.Read("sample-import", JsonDocument.Parse(json).RootElement.Clone(), destinations: ["listing"]).Problems);
    }

    [Theory]
    [InlineData("until-done", true)]
    [InlineData("with-account", true)]
    [InlineData("forever", true)]
    [InlineData("days:30", true)]
    [InlineData("days:0", false)]
    [InlineData("setting:Mail:KeepDays=180", true)]
    [InlineData("setting:=180", false)]
    [InlineData("setting:Mail:KeepDays", false)]
    [InlineData("", false)]
    public void Kept_says_how_long(string kept, bool valid) => Assert.Equal(valid, PersonalDataKept.IsValid(kept));

    [Fact]
    public void The_schema_is_named_as_the_sdk_names_it() => Assert.Equal("plg_guard_ldap", PersonalDataDeclaration.SchemaOf("guard-ldap"));

    [Fact]
    public void The_json_schema_is_json() => Assert.Equal("guard.personal-data@1", JsonDocument.Parse(PersonalDataDeclaration.JsonSchema).RootElement.GetProperty("title").GetString());
}
