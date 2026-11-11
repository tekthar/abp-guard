using System.Net;
using System.Net.Sockets;

namespace AbpGuard;

/// <summary>What sending a feed's batch came to: the receiver's status, or why it didn't arrive.</summary>
public sealed record SecurityFeedResult(int? Status, string? Error)
{
    public bool Delivered => Status is >= 200 and < 300;
}

/// <summary>
/// Sends the security log's feed to the address a site admin set: a POST of JSON with its signature
/// headers. A host gives its own outgoing client, which refuses what the host refuses (private addresses, hosts outside
/// its allow-list); the default refuses addresses inside the server's network itself.
/// </summary>
public interface ISecurityFeedSender
{
    Task<SecurityFeedResult> SendAsync(Uri address, byte[] body, IReadOnlyDictionary<string, string> headers, CancellationToken cancellationToken);
}

/// <summary>
/// The default sender: an admin types the feed's address, so it never reaches the server's own network. The host is
/// resolved and the call connects only to an address outside it (no loopback, private, shared, link-local or unspecified
/// address, a cloud's metadata among them), to the very address checked; a redirect is an answer, not a second address.
/// Ten seconds a batch.
/// </summary>
public sealed class HttpSecurityFeedSender : ISecurityFeedSender
{
    public const string Inside = "That address is inside this network: the feed goes only to a receiver outside it.";

    private readonly HttpClient _client;

    public HttpSecurityFeedSender() : this(Dns.GetHostAddressesAsync)
    {
    }

    /// <summary>With the name lookup given (a test's).</summary>
    public HttpSecurityFeedSender(Func<string, CancellationToken, Task<IPAddress[]>> resolve)
    {
        _client = new HttpClient(CreateHandler(resolve)) { Timeout = TimeSpan.FromSeconds(10) };
    }

    /// <summary>
    /// The handler: no proxy (one would be what the check sees, and would reach inside on the feed's behalf), no
    /// redirect, and a connection only to an address outside the network.
    /// </summary>
    internal static SocketsHttpHandler CreateHandler(Func<string, CancellationToken, Task<IPAddress[]>> resolve) =>
        new()
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectCallback = async (context, cancellationToken) =>
            {
                string host = context.DnsEndPoint.Host;
                IPAddress[] found = IPAddress.TryParse(host, out IPAddress? literal) ? [literal] : await resolve(host, cancellationToken);
                IPAddress target = found.FirstOrDefault(a => !IsInside(a)) ?? throw new HttpRequestException(Inside);
                if (found.Any(IsInside))
                {
                    throw new HttpRequestException(Inside); // a name that also points inside is refused whole
                }

                Socket socket = new(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(target, context.DnsEndPoint.Port), cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };

    /// <summary>Loopback, private (10/8, 172.16/12, 192.168/16, fc00::/7), shared (100.64/10), link-local (169.254/16, fe80::/10) and unspecified.</summary>
    public static bool IsInside(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.IPv6None))
        {
            return true;
        }

        byte[] b = address.GetAddressBytes();
        return address.AddressFamily == AddressFamily.InterNetwork
            ? b[0] is 10 or 0 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] is >= 64 and <= 127)
            : (b[0] & 0xfe) == 0xfc || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80);
    }

    public async Task<SecurityFeedResult> SendAsync(Uri address, byte[] body, IReadOnlyDictionary<string, string> headers, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, address) { Content = new ByteArrayContent(body) };
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        foreach ((string name, string value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        try
        {
            using HttpResponseMessage response = await _client.SendAsync(request, cancellationToken);
            return new SecurityFeedResult((int)response.StatusCode, response.IsSuccessStatusCode ? null : $"The receiver answered {(int)response.StatusCode}.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return new SecurityFeedResult(null, ex.InnerException is HttpRequestException { Message: Inside } ? Inside : ex.Message);
        }
    }
}
