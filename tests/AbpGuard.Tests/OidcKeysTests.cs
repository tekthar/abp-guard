using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using AbpGuard.Services;

namespace AbpGuard.Tests;

/// <summary>Sign-in's keys: certificates when they're named, a folder when one is, else Postgres (the e2e covers that).</summary>
public sealed class OidcKeysTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "guard-oidc-keys-" + Guid.NewGuid().ToString("N"));

    private static IConfiguration Config(params (string Key, string Value)[] settings) =>
        new ConfigurationBuilder().AddInMemoryCollection(settings.Select(s => KeyValuePair.Create(s.Key, (string?)s.Value))).Build();

    [Fact]
    public void Guards_data_folder_is_Guard_DataRoot_else_the_hosts()
    {
        Assert.Equal("/guard", AbpGuardModule.DataRoot(Config(("Guard:DataRoot", "/guard"), ("Host:DataRoot", "/data"))));
        // Another setting of the host's is the host's to give (GuardStartupOptions); a host gives its own.
        Assert.Null(AbpGuardModule.DataRoot(Config(("Host:DataRoot", "/data"))));
        Assert.Null(AbpGuardModule.DataRoot(Config()));
    }

    private string Pfx(string name)
    {
        Directory.CreateDirectory(_root);
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        string path = Path.Combine(_root, name + ".pfx");
        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, "pfx-password"));
        return path;
    }

    [Fact]
    public void Certificates_named_in_configuration_come_first()
    {
        (SecurityKey signing, SecurityKey encryption) = OidcKeys.Resolve(Config(
            ("Guard:Oidc:SigningCertificate:Path", Pfx("signing")), ("Guard:Oidc:SigningCertificate:Password", "pfx-password"),
            ("Guard:Oidc:EncryptionCertificate:Path", Pfx("encryption")), ("Guard:Oidc:EncryptionCertificate:Password", "pfx-password")), _root);

        Assert.Equal("CN=signing", Assert.IsType<X509SecurityKey>(signing).Certificate.Subject);
        Assert.Equal("CN=encryption", Assert.IsType<X509SecurityKey>(encryption).Certificate.Subject);
    }

    [Fact]
    public void A_folder_named_in_configuration_keeps_its_keys_across_starts()
    {
        string folder = Path.Combine(_root, "mounted");
        IConfiguration config = Config(("Guard:Oidc:KeysPath", folder));

        (SecurityKey signing, SecurityKey encryption) = OidcKeys.Resolve(config, _root);
        (SecurityKey again, SecurityKey againEncryption) = OidcKeys.Resolve(config, _root);

        Assert.True(File.Exists(Path.Combine(folder, "signing.pem")));
        Assert.Equal(signing.KeyId, again.KeyId);
        Assert.Equal(encryption.KeyId, againEncryption.KeyId);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }
}
