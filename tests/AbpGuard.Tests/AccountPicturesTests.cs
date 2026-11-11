namespace AbpGuard.Tests;

/// <summary>An account's picture is a path on the site itself: the shape is the security edge, so it's strict.</summary>
public class AccountPicturesTests
{
    [Theory]
    [InlineData("/api/pictures/0123abcd.png")]
    [InlineData("/api/pictures/builtin-owl.png")]
    [InlineData("/a")]
    [InlineData("/x/y_z-1.2.webp")]
    public void A_path_on_the_site_is_a_picture(string path) => Assert.True(AccountPictures.IsPath(path));

    [Theory]
    [InlineData("")]
    [InlineData("api/pictures/a.png")] // no leading "/"
    [InlineData("//host/x.png")] // protocol-relative: another host
    [InlineData("/\\host/x.png")] // a browser reads "/\" as "//"
    [InlineData("https://host/x.png")]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:image/png;base64,AAAA")]
    [InlineData("/api/pictures/a.png?x=1")]
    [InlineData("/api/pictures/a.png#x")]
    [InlineData("/api/../secrets.png")]
    [InlineData("/..")]
    [InlineData("/api//pictures/a.png")]
    [InlineData("/api/pictures/a b.png")]
    [InlineData("/api/pictures/صورة.png")]
    [InlineData("/api/pictures/a%2e%2e.png")]
    [InlineData("/api:x")]
    public void Anything_else_is_refused(string path) => Assert.False(AccountPictures.IsPath(path));

    [Fact]
    public void A_null_isnt_a_path_and_the_longest_path_is_300_characters()
    {
        Assert.False(AccountPictures.IsPath(null));
        Assert.True(AccountPictures.IsPath("/" + new string('a', AccountPictures.MaxLength - 1)));
        Assert.False(AccountPictures.IsPath("/" + new string('a', AccountPictures.MaxLength)));
    }
}
