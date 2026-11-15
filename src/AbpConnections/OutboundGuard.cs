using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AbpConnections;


/// <summary>
/// Hosts on private or loopback addresses outgoing calls may still reach (<c>Network</c>): a list of host
/// names or addresses, each with an optional port ("gitea.internal", "localhost:5191"). Empty by default: nothing private
/// is called.
/// </summary>
public sealed class OutboundOptions
{
    public List<string> AllowedPrivateHosts { get; set; } = [];

    /// <summary>
    /// The only hosts the server sends anything to, for a site whose data must stay where it's allowed
    /// to go: a host, a host and port ("mail.example.com:587"), or "*.example.com" for any name under it. Empty (the
    /// default) allows any host that isn't private. The private hosts above are allowed too.
    /// </summary>
    public List<string> AllowedHosts { get; set; } = [];
}

/// <summary>An outgoing call to a private or loopback address, refused.</summary>
public sealed class OutboundRefusedException(string message) : HttpRequestException(message);

/// <summary>
/// Outgoing calls that refuse private and loopback addresses: webhooks, MCP servers and channels call
/// addresses their admins typed, so a request could otherwise reach the server's own network (its cloud metadata, its
/// database, an internal service). The host is resolved, any private address dropped, and the call connects to the
/// address that passed, so a second lookup can't swap it (DNS rebinding). Hosts in <see cref="OutboundOptions"/> pass.
/// </summary>
public static class OutboundGuard
{
    /// <summary>
    /// Who refuses, as a refusal names it ("… is a private or loopback address; this server doesn't call those from
    /// here."): the application's name, read when a call is refused.
    /// </summary>
    public static Func<string> Caller { get; set; } = () => "this server";

    /// <summary>
    /// Gives a named client the guard. <paramref name="followRedirects"/> false for a call that carries what's only
    /// for the address typed (a webhook's signed body): a redirect is then an answer, not a second address to send it to.
    /// </summary>
    public static IHttpClientBuilder RefusePrivateAddresses(this IHttpClientBuilder builder, bool followRedirects = true) =>
        builder.ConfigurePrimaryHttpMessageHandler(services => new SocketsHttpHandler
        {
            ConnectCallback = Connect(services.GetRequiredService<IOptions<OutboundOptions>>().Value),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            AllowAutoRedirect = followRedirects,
        });

    private static Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>> Connect(OutboundOptions options) => async (context, cancellationToken) =>
    {
        (string host, int port) = (context.DnsEndPoint.Host, context.DnsEndPoint.Port);
        EnsureListed(options, host, port); // a redirect connects here too
        bool allowed = Allowed(options, host, port);
        IPAddress[] found = IPAddress.TryParse(host, out IPAddress? literal) ? [literal] : await Dns.GetHostAddressesAsync(host, cancellationToken);
        IPAddress[] passed = [.. found.Where(a => allowed || !IsPrivate(a))];
        if (passed.Length == 0)
        {
            throw new OutboundRefusedException(
                $"{host} is a private or loopback address; {Caller()} doesn't call those from here. A server admin may allow a host in Network:AllowedPrivateHosts.");
        }

        // Each address that passed, in turn, until one answers.
        SocketException? last = null;
        foreach (IPAddress target in passed)
        {
            Socket socket = new(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(target, port), cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                last = ex;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        throw last!;
    };

    /// <summary>
    /// At most this many bytes of an outside server's answer, as text: read no further, so an answer of
    /// gigabytes costs what the limit does. Ask for the answer with <see cref="HttpCompletionOption.ResponseHeadersRead"/>.
    /// </summary>
    public static async Task<string> ReadAtMostAsync(HttpContent content, int bytes, CancellationToken cancellationToken)
    {
        await using Stream stream = await content.ReadAsStreamAsync(cancellationToken);
        byte[] buffer = new byte[bytes];
        int read = 0;
        while (read < bytes && await stream.ReadAsync(buffer.AsMemory(read, bytes - read), cancellationToken) is var n and > 0)
        {
            read += n;
        }

        return System.Text.Encoding.UTF8.GetString(buffer, 0, read);
    }

    /// <summary>
    /// For a connection the client guard can't sit in (git, IMAP): refuses a host that resolves to a private or loopback
    /// address, unless the server allows it. It's checked before connecting, so the connection's own lookup
    /// could still differ; HTTP calls use the guarded clients, which connect to the address they checked.
    /// </summary>
    public static async Task EnsureNotPrivateAsync(OutboundOptions options, string host, int port, CancellationToken cancellationToken)
    {
        EnsureListed(options, host, port);
        if (Allowed(options, host, port))
        {
            return;
        }

        IPAddress[] found = IPAddress.TryParse(host, out IPAddress? literal) ? [literal] : await Dns.GetHostAddressesAsync(host, cancellationToken);
        if (found.Any(IsPrivate))
        {
            throw new OutboundRefusedException(
                $"{host} is a private or loopback address; {Caller()} doesn't call those from here. A server admin may allow a host in Network:AllowedPrivateHosts.");
        }
    }

    /// <summary>
    /// The server's list of private hosts it may call, read from its settings' <paramref name="section"/> (for classes made
    /// before options are).
    /// </summary>
    public static OutboundOptions From(Microsoft.Extensions.Configuration.IConfiguration configuration, string section = "Network") =>
        Microsoft.Extensions.Configuration.ConfigurationBinder.Get<OutboundOptions>(configuration.GetSection(section)) ?? new OutboundOptions();

    /// <summary>
    /// Whether the server may send to a host at all: any when <see cref="OutboundOptions.AllowedHosts"/>
    /// is empty, else one it lists (or a private host it allows).
    /// </summary>
    public static bool Listed(OutboundOptions options, string host, int port) =>
        options.AllowedHosts.Count == 0 || Allowed(options, host, port) || options.AllowedHosts.Any(entry => Matches(entry.Trim(), host, port));

    private static bool Matches(string entry, string host, int port) => entry.StartsWith("*.", StringComparison.Ordinal)
        ? host.EndsWith(entry[1..], StringComparison.OrdinalIgnoreCase)
        : string.Equals(entry, host, StringComparison.OrdinalIgnoreCase) || string.Equals(entry, $"{host}:{port}", StringComparison.OrdinalIgnoreCase);

    /// <summary>Refuses a host the server may not send to, naming the setting that would allow it.</summary>
    public static void EnsureListed(OutboundOptions options, string host, int port)
    {
        if (!Listed(options, host, port))
        {
            throw new OutboundRefusedException(
                $"{host} isn't in Network:AllowedHosts: this server sends data only to the hosts listed there. A server admin adds it, or empties the list.");
        }
    }

    /// <summary>Whether a host (with its port) is on the server's list of private hosts it may call.</summary>
    public static bool Allowed(OutboundOptions options, string host, int port) =>
        options.AllowedPrivateHosts.Any(h => string.Equals(h, host, StringComparison.OrdinalIgnoreCase) || string.Equals(h, $"{host}:{port}", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Loopback, private, link-local, shared (carrier-grade NAT), reserved, unspecified, multicast and broadcast addresses,
    /// for IPv4 and IPv6; an IPv6 address that carries an IPv4 one (mapped, compatible, NAT64, 6to4) is judged by it.
    /// </summary>
    public static bool IsPrivate(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte[] v6 = address.GetAddressBytes();
            // IPv4 inside IPv6: ::a.b.c.d (compatible), 64:ff9b::a.b.c.d (NAT64), 2002:aabb:ccdd:: (6to4).
            if (v6.Take(12).All(b => b == 0) && !IPAddress.IsLoopback(address) && !address.Equals(IPAddress.IPv6Any)
                || v6[0] == 0x00 && v6[1] == 0x64 && v6[2] == 0xff && v6[3] == 0x9b && v6.Skip(4).Take(8).All(b => b == 0))
            {
                return IsPrivate(new IPAddress(v6[12..16]));
            }

            if (v6[0] == 0x20 && v6[1] == 0x02)
            {
                return IsPrivate(new IPAddress(v6[2..6]));
            }

            // Teredo (2001:0::/32) hides its IPv4 address, and local-use NAT64 (64:ff9b:1::/48) is a network's own.
            if (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0 && v6[3] == 0 || v6[0] == 0x00 && v6[1] == 0x64 && v6[2] == 0xff && v6[3] == 0x9b && v6[4] == 0 && v6[5] == 1)
            {
                return true;
            }
        }

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] b = address.GetAddressBytes();
            return b[0] == 10 || b[0] == 0 || b[0] >= 224
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
                || (b[0] == 192 && b[1] == 0 && b[2] == 0) // IETF protocol assignments
                || (b[0] == 198 && (b[1] == 18 || b[1] == 19)); // benchmarking
        }

        return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast || address.IsIPv6UniqueLocal;
    }
}

/// <summary>
/// Refuses a request to a host not in <see cref="OutboundOptions.AllowedHosts"/>, for every client the
/// server's factory makes: guarded or not, the host's or a plugin's. A call to the server itself (loopback) isn't data
/// leaving it.
/// </summary>
public sealed class AllowedHostsHandler(OutboundOptions options) : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri is { IsAbsoluteUri: true, IsLoopback: false } uri)
        {
            OutboundGuard.EnsureListed(options, uri.Host, uri.Port);
        }

        return base.SendAsync(request, cancellationToken);
    }
}
