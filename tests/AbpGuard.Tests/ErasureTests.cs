using AbpGuard.Services;
using AbpGuard.Services.Privacy;

namespace AbpGuard.Tests;

/// <summary>Erasure: what the security log keeps, and the names kept for erased accounts.</summary>
public class ErasureTests
{
    private static readonly HashSet<string> Rita = new(["Rita", "rita7", "rita@example.test"], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// A plugin's store no eraser took holds the erasure while its data may still come back to be erased: the plugin off,
    /// uninstalled with what it kept, or enabled but held back. Fields-only stores go with the host's, naming those that failed.
    /// </summary>
    [Theory]
    [InlineData(false, InstalledPlugin.States.Disabled, false, PersonalDataErasures.PluginOff)]
    [InlineData(false, InstalledPlugin.States.Removed, false, PersonalDataErasures.PluginUninstalled)]
    [InlineData(false, InstalledPlugin.States.Enabled, false, PersonalDataErasures.PluginNotRunning)]
    [InlineData(false, InstalledPlugin.States.Enabled, true, PersonalDataErasures.NothingErases)]
    [InlineData(false, null, true, PersonalDataErasures.NothingErases)]
    [InlineData(true, InstalledPlugin.States.Disabled, false, PersonalDataErasures.Done)]
    [InlineData(true, InstalledPlugin.States.Removed, false, PersonalDataErasures.Done)]
    public void A_plugins_store_no_eraser_took_waits_while_its_data_can_come_back(bool onlyFields, string? state, bool running, string expected) =>
        Assert.Equal(expected, PersonalDataErasures.Untaken(onlyFields, state, running, []));

    [Fact]
    public void A_fields_only_store_names_the_stores_that_failed()
    {
        string outcome = PersonalDataErasures.Untaken(true, InstalledPlugin.States.Enabled, true, ["projects.records", "assets.assets"]);
        Assert.Contains("projects.records, assets.assets", outcome, StringComparison.Ordinal);
        Assert.False(PersonalDataErasures.Settled(outcome));
    }

    [Theory]
    [InlineData(PersonalDataErasures.Done, true)]
    [InlineData("skipped by admin: the plugin is gone for good", true)]
    [InlineData(PersonalDataErasures.PluginUninstalled, false)]
    [InlineData(PersonalDataErasures.NothingErases, false)]
    [InlineData(null, false)]
    public void Done_and_skipped_stores_are_settled(string? outcome, bool settled) => Assert.Equal(settled, PersonalDataErasures.Settled(outcome));

    [Fact]
    public void A_value_wholly_one_of_the_persons_names_becomes_the_pseudonym_wherever_it_is_in_the_detail()
    {
        string? detail = GuardPersonalDataEraser.Pseudonymised("""{"member":"rita7","to":["RITA@example.test","Ritaville"],"count":3}""", Rita, "Former person 4");
        Assert.Equal("""{"member":"Former person 4","to":["Former person 4","Ritaville"],"count":3}""", detail);
    }

    [Fact]
    public void A_merges_detail_names_each_erased_account_by_its_pseudonyms_username_and_anyone_elses_stays()
    {
        Dictionary<string, string> renamed = new(StringComparer.OrdinalIgnoreCase) { ["rita-old"] = "former-person-4-2", ["rita7"] = "former-person-4" };
        Assert.Equal("former-person-4-2 merged into former-person-4", GuardPersonalDataEraser.Merged("Rita-Old merged into rita7", renamed));
        Assert.Equal("former-person-4 merged into omar automatically (same address)",
            GuardPersonalDataEraser.Merged("rita7 merged into omar automatically (same address)", renamed));
        Assert.Null(GuardPersonalDataEraser.Merged("sam merged into omar", renamed));
        Assert.Null(GuardPersonalDataEraser.Merged("rita7 was renamed", renamed));
    }

    [Fact]
    public void A_value_that_only_contains_a_name_is_someone_elses_and_stays()
    {
        Assert.Null(GuardPersonalDataEraser.Pseudonymised("""{"name":"Ritaville","note":"Rita said so"}""", Rita, "Former person 4"));
        Assert.Null(GuardPersonalDataEraser.Pseudonymised("Margarita", Rita, "Former person 4"));
        Assert.Equal("Former person 4", GuardPersonalDataEraser.Pseudonymised("rita7", Rita, "Former person 4"));
    }

    [Theory]
    [InlineData("former-person-7", true)]
    [InlineData("Former-Person-12-2", true)]
    [InlineData("former-person-7@example.test", false)]
    [InlineData("former-personal", false)]
    public void Erased_accounts_usernames_are_kept_for_them(string username, bool reserved) => Assert.Equal(reserved, Usernames.IsReserved(username));

    [Theory]
    [InlineData("Former person 7", true)]
    [InlineData("former  PERSON 31", true)]
    [InlineData("Former person of the year", false)]
    public void No_one_takes_an_erased_persons_name(string name, bool reserved) => Assert.Equal(reserved, Usernames.IsReservedName(name));

    [Fact]
    public void Choosing_a_kept_name_is_refused_with_its_code()
    {
        Volo.Abp.UserFriendlyException refused = Assert.Throws<Volo.Abp.UserFriendlyException>(() => Usernames.EnsureNotReserved("dana", "Former person 2"));
        Assert.Equal(Usernames.ReservedCode, refused.Code);
        Usernames.EnsureNotReserved("dana", "Dana");
    }
}
