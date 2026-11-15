using System.Net;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace AbpConnections.Tests;

/// <summary>The outbound guard's rules, and what a connection reads from an ID token.</summary>
public class OutboundGuardTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]
    [InlineData("100.64.0.1")]
    [InlineData("0.0.0.0")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fd00::1")]
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("64:ff9b::a00:1")]
    [InlineData("2002:a00:1::")]
    public void Private_and_loopback_addresses_are_private(string address) => Assert.True(OutboundGuard.IsPrivate(IPAddress.Parse(address)));

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("2606:4700:4700::1111")]
    public void Public_addresses_are_not(string address) => Assert.False(OutboundGuard.IsPrivate(IPAddress.Parse(address)));

    [Fact]
    public async Task A_private_host_is_refused_naming_the_caller_and_the_setting()
    {
        OutboundRefusedException refused = await Assert.ThrowsAsync<OutboundRefusedException>(() =>
            OutboundGuard.EnsureNotPrivateAsync(new OutboundOptions(), "127.0.0.1", 80, CancellationToken.None));
        Assert.Equal("127.0.0.1 is a private or loopback address; this server doesn't call those from here. A server admin may allow a host in Network:AllowedPrivateHosts.",
            refused.Message);

        await OutboundGuard.EnsureNotPrivateAsync(new OutboundOptions { AllowedPrivateHosts = ["127.0.0.1:80"] }, "127.0.0.1", 80, CancellationToken.None);
    }

    [Fact]
    public void Only_the_allowed_hosts_are_listed_when_some_are()
    {
        OutboundOptions none = new();
        Assert.True(OutboundGuard.Listed(none, "api.example.com", 443));

        OutboundOptions some = new() { AllowedHosts = ["*.example.com", "mail.other.org:587"] };
        Assert.True(OutboundGuard.Listed(some, "api.example.com", 443));
        Assert.True(OutboundGuard.Listed(some, "mail.other.org", 587));
        Assert.False(OutboundGuard.Listed(some, "mail.other.org", 25));
        Assert.False(OutboundGuard.Listed(some, "example.org", 443));
        OutboundRefusedException refused = Assert.Throws<OutboundRefusedException>(() => OutboundGuard.EnsureListed(some, "example.org", 443));
        Assert.StartsWith("example.org isn't in Network:AllowedHosts", refused.Message);
    }

    [Fact]
    public void A_settings_section_gives_the_options()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Network:AllowedPrivateHosts:0"] = "gitea.internal", ["Network:AllowedHosts:0"] = "*.example.com" }).Build();
        OutboundOptions options = OutboundGuard.From(configuration);
        Assert.Equal(["gitea.internal"], options.AllowedPrivateHosts);
        Assert.Equal(["*.example.com"], options.AllowedHosts);
    }

    [Fact]
    public void An_id_token_names_the_account_by_email_or_user_name()
    {
        static string Token(string claims) => "h." + Convert.ToBase64String(Encoding.UTF8.GetBytes(claims)).TrimEnd('=').Replace('+', '-').Replace('/', '_') + ".s";
        Assert.Equal("dana@example.com", ConnectionManager.AccountOf(Token("{\"email\":\"dana@example.com\",\"preferred_username\":\"dana\"}")));
        Assert.Equal("dana", ConnectionManager.AccountOf(Token("{\"preferred_username\":\"dana\"}")));
        Assert.Null(ConnectionManager.AccountOf("not-a-token"));
        Assert.Null(ConnectionManager.AccountOf(null));
    }

    [Fact]
    public void Only_a_secret_given_is_a_secret_set()
    {
        Assert.False(ConnectionManager.SetsSecrets(new ConnectionChange("A", "api", null, null)));
        Assert.False(ConnectionManager.SetsSecrets(new ConnectionChange("A", "api", null, new() { ["key"] = "" })));
        Assert.True(ConnectionManager.SetsSecrets(new ConnectionChange("A", "api", null, new() { ["key"] = "k-1" })));
    }
}
