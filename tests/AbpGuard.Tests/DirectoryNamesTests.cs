using AbpGuard.Directories;
using AbpGuard.Domain;
using AbpGuard.Services;

namespace AbpGuard.Tests;

/// <summary>A person's name in other languages from a directory.</summary>
public class DirectoryNamesTests
{
    private static readonly UserDirectory Corp = new(Guid.NewGuid(), "Corp", "ldap", order: 1);

    private static DirectoryUser Record(Dictionary<string, string>? names) =>
        new(Guid.NewGuid(), Corp.Id, "corp:jdoe", "jdoe") { IsActive = true, DisplayName = "John Doe", DisplayNames = names };

    [Fact]
    public void A_directory_that_says_nothing_of_names_leaves_the_accounts_alone()
    {
        Account account = new(Guid.NewGuid(), "jdoe");
        account.SetDisplayNames(new Dictionary<string, string> { ["ar"] = "جون دو" });

        AccountProjector.Apply(account, Record(null), Corp);

        Assert.Equal("جون دو", account.DisplayNames["ar"]);
    }

    [Fact]
    public void A_directory_that_gives_no_names_clears_them()
    {
        Account account = new(Guid.NewGuid(), "jdoe");
        account.SetDisplayNames(new Dictionary<string, string> { ["ar"] = "جون دو" });

        AccountProjector.Apply(account, Record([]), Corp);

        Assert.Empty(account.DisplayNames);
        Assert.Null(account.OtherNames);
    }

    [Fact]
    public void A_directorys_names_replace_the_accounts_and_are_searchable()
    {
        Account account = new(Guid.NewGuid(), "jdoe");

        AccountProjector.Apply(account, Record(new() { ["ar"] = "جون دو", ["fr"] = "Jean Dupont" }), Corp);

        Assert.Equal("John Doe", account.DisplayName);
        Assert.Equal("جون دو", account.DisplayNames["ar"]);
        Assert.Contains("Jean Dupont", account.OtherNames);
    }

    [Fact]
    public void Names_given_on_a_rename_are_kept_through_a_rebuild()
    {
        // What AccountCorrections.RenameAsync does to the account and its record, then a rebuild from that record.
        DirectoryUser record = Record(null);
        Account account = new(Guid.NewGuid(), "jdoe");
        account.SetDisplayNames(new Dictionary<string, string> { ["ar"] = "جون" });
        (account.DisplayName, record.DisplayName) = ("Johnny", "Johnny");
        record.DisplayNames = new Dictionary<string, string>(account.DisplayNames);

        AccountProjector.Apply(account, record, Corp);

        Assert.Equal("Johnny", account.DisplayName);
        Assert.Equal("جون", account.DisplayNames["ar"]);
    }

    [Fact]
    public void A_sync_keeps_good_names_and_counts_the_ones_left_out()
    {
        int leftOut = 0;
        Dictionary<string, string> names = DirectorySyncService.SyncedNames(new Dictionary<string, string>
        {
            ["ar"] = "  جون دو  ",
            ["fr"] = "   ",
            ["not a code"] = "Someone",
            ["de"] = new string('x', AccountCorrections.NameLength + 50),
        }, ref leftOut);

        Assert.Equal("جون دو", names["ar"]);
        Assert.False(names.ContainsKey("fr"));
        Assert.False(names.ContainsKey("not a code"));
        Assert.Equal(AccountCorrections.NameLength, names["de"].Length);
        Assert.Equal(1, leftOut);
    }

    [Fact]
    public void A_sync_where_no_one_has_the_names_asked_for_is_noticed()
    {
        DirectoryUserRecord Person(string name, Dictionary<string, string>? names) => new(name, name, name, null) { DisplayNames = names };

        Assert.True(DirectorySyncService.NoNamesFound([Person("a", []), Person("b", [])]));
        Assert.False(DirectorySyncService.NoNamesFound([Person("a", []), Person("b", new() { ["ar"] = "ب" })]));
        Assert.False(DirectorySyncService.NoNamesFound([Person("a", null), Person("b", null)])); // not asked for
        Assert.False(DirectorySyncService.NoNamesFound([]));
    }

    [Theory]
    [InlineData("ar=displayName;lang-ar, fr=nameFr", 2)]
    [InlineData("ar=extensionAttribute1\nzh-Hant=msDS-PhoneticDisplayName", 2)]
    [InlineData("", 0)]
    [InlineData(null, 0)]
    public void The_setting_reads_language_attribute_pairs(string? text, int count)
    {
        Dictionary<string, string> map = DirectoryNames.ParseNameAttributes(text);

        Assert.Equal(count, map.Count);
        Assert.Empty(DirectoryNames.NameAttributeProblems(text, "Display name by language"));
    }

    [Fact]
    public void The_setting_keeps_ldap_options_on_the_attribute()
    {
        Dictionary<string, string> map = DirectoryNames.ParseNameAttributes("AR = displayName;lang-ar");

        Assert.Equal("displayName;lang-ar", map["ar"]);
    }

    [Theory]
    [InlineData("ar")]
    [InlineData("=displayName")]
    [InlineData("ar=")]
    [InlineData("arabic language=displayName")]
    [InlineData("ar=display name")]
    public void A_setting_entry_that_isnt_language_attribute_is_refused_and_left_out(string text)
    {
        Assert.Single(DirectoryNames.NameAttributeProblems($"fr=nameFr, {text}", "Display name by language"));
        Assert.Equal(["fr"], DirectoryNames.ParseNameAttributes($"fr=nameFr, {text}").Keys);
    }
}
