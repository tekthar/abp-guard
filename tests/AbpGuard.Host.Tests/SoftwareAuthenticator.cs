using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AbpGuard.Host.Tests;

/// <summary>
/// A passkey made in software, answering the browser's WebAuthn calls as a phone or a password manager would: an ECDSA
/// P-256 key, "none" attestation, authenticator data with the relying party's hash and the user present and verified
/// flags, and client data with the challenge and the page's origin. Its answers are the credential's <c>toJSON()</c>.
/// </summary>
internal sealed class SoftwareAuthenticator : IDisposable
{
    /// <summary>The sample host's address (Guard:PublicUrl), which passkeys' origin must be.</summary>
    public const string SiteOrigin = "http://localhost:5297";

    /// <summary>iCloud Keychain's AAGUID, which Guard names.</summary>
    public static readonly Guid ICloudKeychain = Guid.Parse("fbfc3007-154e-4ecc-8c0b-6e020557d7bd");

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(16);

    /// <summary>The account's handle the passkey was made for, which it gives back when it signs.</summary>
    public byte[]? UserHandle { get; private set; }

    /// <summary>The signature count it gives next; each answer moves it on by one.</summary>
    public uint Counter { get; set; } = 1;

    public Guid AaGuid { get; init; } = ICloudKeychain;

    /// <summary>Whether it's synced (the backup flags).</summary>
    public bool Synced { get; init; } = true;

    public string Id => B64(CredentialId);

    /// <summary>Answers creation options: a new credential for their relying party and user.</summary>
    public JsonObject Register(JsonElement options, string origin = SiteOrigin)
    {
        string rpId = options.GetProperty("rp").GetProperty("id").GetString()!;
        UserHandle = FromB64(options.GetProperty("user").GetProperty("id").GetString()!);
        byte[] clientData = ClientData("webauthn.create", options.GetProperty("challenge").GetString()!, origin);

        ECParameters key = _key.ExportParameters(false);
        CborWriter cose = new(CborConformanceMode.Ctap2Canonical);
        cose.WriteStartMap(5);
        cose.WriteInt32(1);
        cose.WriteInt32(2); // kty: EC2
        cose.WriteInt32(3);
        cose.WriteInt32(-7); // alg: ES256
        cose.WriteInt32(-1);
        cose.WriteInt32(1); // crv: P-256
        cose.WriteInt32(-2);
        cose.WriteByteString(key.Q.X!);
        cose.WriteInt32(-3);
        cose.WriteByteString(key.Q.Y!);
        cose.WriteEndMap();

        List<byte> attested = [.. AuthenticatorData(rpId, attested: true)];
        attested.AddRange(AaGuid.ToByteArray(bigEndian: true));
        attested.Add((byte)(CredentialId.Length >> 8));
        attested.Add((byte)CredentialId.Length);
        attested.AddRange(CredentialId);
        attested.AddRange(cose.Encode());

        CborWriter attestation = new(CborConformanceMode.Ctap2Canonical);
        attestation.WriteStartMap(3);
        attestation.WriteTextString("fmt");
        attestation.WriteTextString("none");
        attestation.WriteTextString("attStmt");
        attestation.WriteStartMap(0);
        attestation.WriteEndMap();
        attestation.WriteTextString("authData");
        attestation.WriteByteString([.. attested]);
        attestation.WriteEndMap();

        return new JsonObject
        {
            ["id"] = Id,
            ["rawId"] = Id,
            ["type"] = "public-key",
            ["authenticatorAttachment"] = "platform",
            ["response"] = new JsonObject
            {
                ["clientDataJSON"] = B64(clientData),
                ["attestationObject"] = B64(attestation.Encode()),
                ["transports"] = new JsonArray("internal", "hybrid"),
            },
            ["clientExtensionResults"] = new JsonObject(),
        };
    }

    /// <summary>Answers request options: signs their challenge, with the next signature count unless one is given.</summary>
    public JsonObject Assert(JsonElement options, string origin = SiteOrigin, uint? counter = null)
    {
        string rpId = options.GetProperty("rpId").GetString()!;
        byte[] clientData = ClientData("webauthn.get", options.GetProperty("challenge").GetString()!, origin);
        byte[] data = AuthenticatorData(rpId, attested: false, counter);
        byte[] signature = _key.SignData([.. data, .. SHA256.HashData(clientData)], HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return new JsonObject
        {
            ["id"] = Id,
            ["rawId"] = Id,
            ["type"] = "public-key",
            ["authenticatorAttachment"] = "platform",
            ["response"] = new JsonObject
            {
                ["clientDataJSON"] = B64(clientData),
                ["authenticatorData"] = B64(data),
                ["signature"] = B64(signature),
                ["userHandle"] = UserHandle is null ? null : B64(UserHandle),
            },
            ["clientExtensionResults"] = new JsonObject(),
        };
    }

    /// <summary>The relying party's hash, the flags (user present and verified, backup eligible and state, attested data) and the count.</summary>
    private byte[] AuthenticatorData(string rpId, bool attested, uint? counter = null)
    {
        byte flags = 0x01 | 0x04;
        if (Synced)
        {
            flags |= 0x08 | 0x10;
        }

        if (attested)
        {
            flags |= 0x40;
        }

        uint count = counter ?? Counter++;
        return [.. SHA256.HashData(Encoding.UTF8.GetBytes(rpId)), flags, (byte)(count >> 24), (byte)(count >> 16), (byte)(count >> 8), (byte)count];
    }

    private static byte[] ClientData(string type, string challenge, string origin) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { type, challenge, origin, crossOrigin = false }));

    public static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromB64(string text)
    {
        string padded = text.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + ((4 - (padded.Length % 4)) % 4), '='));
    }

    public void Dispose() => _key.Dispose();
}
