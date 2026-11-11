using System.Security.Cryptography;
using System.Text;
using AbpGuard.Controllers;
using AbpGuard.Services;

namespace AbpGuard.Tests;

/// <summary>Breaches: the log's download is safe in a spreadsheet, and the feed's signature is what a receiver checks.</summary>
public class BreachTests
{
    [Theory]
    [InlineData("=HYPERLINK(\"http://x\")", "\"'=HYPERLINK(\"\"http://x\"\")\"")]
    [InlineData("+1 555", "'+1 555")]
    [InlineData("-2", "'-2")]
    [InlineData("@SUM(A1)", "'@SUM(A1)")]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData(null, "")]
    public void A_cell_a_spreadsheet_would_run_is_kept_as_text(string? value, string cell) => Assert.Equal(cell, SecurityEventsController.CsvCell(value));

    [Fact]
    public void The_feeds_signature_is_an_hmac_of_the_time_and_the_body()
    {
        byte[] body = Encoding.UTF8.GetBytes("""[{"type":"auth.login.failed"}]""");
        DateTimeOffset at = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        string header = SecurityFeed.Sign("the-secret", body, at)[SecurityFeed.SignatureHeader];
        byte[] signed = [.. Encoding.UTF8.GetBytes("1800000000."), .. body];
        string expected = Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes("the-secret"), signed));
        Assert.Equal($"t=1800000000,v1={expected}", header);
    }

    /// <summary>The default sender never reaches the server's own network: an address typed, or a name that points there.</summary>
    [Fact]
    public async Task The_default_feed_refuses_an_address_inside_the_network()
    {
        HttpSecurityFeedSender sender = new((host, _) => Task.FromResult(host == "metadata.example.test"
            ? new[] { System.Net.IPAddress.Parse("169.254.169.254") }
            : [System.Net.IPAddress.Parse("10.0.0.5"), System.Net.IPAddress.Parse("93.184.216.34")]));
        byte[] body = Encoding.UTF8.GetBytes("[]");
        foreach (string address in new[] { "https://127.0.0.1/in", "https://metadata.example.test/latest", "https://mixed.example.test/in", "https://[::1]/in" })
        {
            SecurityFeedResult result = await sender.SendAsync(new Uri(address), body, new Dictionary<string, string>(), CancellationToken.None);
            Assert.False(result.Delivered);
            Assert.Equal(HttpSecurityFeedSender.Inside, result.Error);
        }
    }

    [Fact]
    public void The_default_feed_goes_through_no_proxy_and_follows_no_redirect()
    {
        using System.Net.Http.SocketsHttpHandler handler = HttpSecurityFeedSender.CreateHandler((_, _) => Task.FromResult(Array.Empty<System.Net.IPAddress>()));
        Assert.False(handler.UseProxy);
        Assert.False(handler.AllowAutoRedirect);
        Assert.NotNull(handler.ConnectCallback);
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("169.254.169.254", true)]
    [InlineData("172.20.1.1", true)]
    [InlineData("100.100.1.1", true)]
    [InlineData("fd00::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("::ffff:192.168.1.1", true)]
    [InlineData("93.184.216.34", false)]
    [InlineData("2606:4700::1111", false)]
    public void Inside_the_network_is_told_apart(string address, bool inside) =>
        Assert.Equal(inside, HttpSecurityFeedSender.IsInside(System.Net.IPAddress.Parse(address)));
}
