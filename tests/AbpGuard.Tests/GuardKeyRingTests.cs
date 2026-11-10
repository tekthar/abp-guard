using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AbpGuard.Tests;

/// <summary>Guard's start-up check that the host keeps its Data Protection key ring somewhere it chose.</summary>
public class GuardKeyRingTests
{
    [Fact]
    public void A_ring_the_host_keeps_passes_and_one_it_left_to_the_fallback_doesnt()
    {
        string folder = Path.Combine(Path.GetTempPath(), "guard-keys-" + Guid.NewGuid().ToString("N"));

        Assert.Null(GuardKeyRing.Problem(new KeyManagementOptions { XmlRepository = new Database() }));
        Assert.Null(GuardKeyRing.Problem(new KeyManagementOptions { XmlRepository = new FileSystemXmlRepository(new DirectoryInfo(folder), Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance) }));
        Assert.Contains("nowhere it chose", GuardKeyRing.Problem(new KeyManagementOptions()));
        if (FileSystemXmlRepository.DefaultKeyStorageDirectory is { } fallback)
        {
            Assert.Contains("fallback folder", GuardKeyRing.Problem(new KeyManagementOptions { XmlRepository = new FileSystemXmlRepository(fallback, Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance) }));
        }
    }

    [Fact]
    public void A_host_may_encrypt_the_ring_at_rest_with_a_certificate_and_it_reads_its_keys_back()
    {
        using System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create(2048);
        System.Security.Cryptography.X509Certificates.CertificateRequest request = new("CN=guard-key-ring", rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using System.Security.Cryptography.X509Certificates.X509Certificate2 certificate =
            request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        Microsoft.Extensions.DependencyInjection.ServiceCollection services = new();
        services.AddSingleton<Microsoft.Extensions.Configuration.IConfiguration>(new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection([new("ConnectionStrings:Guard", "Host=localhost;Database=unused")]).Build());
        services.AddDataProtection().AddGuardKeyRing(certificate);
        using ServiceProvider provider = services.BuildServiceProvider();
        KeyManagementOptions options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<KeyManagementOptions>>().Value;

        Assert.IsType<GuardKeyRingRepository>(options.XmlRepository);
        Assert.IsType<Microsoft.AspNetCore.DataProtection.XmlEncryption.CertificateXmlEncryptor>(options.XmlEncryptor);
        Assert.Null(GuardKeyRing.Problem(options));

        // What it encrypts, it reads back with the certificate.
        XElement key = new("key", new XElement("secret", "s3cret"));
        Microsoft.AspNetCore.DataProtection.XmlEncryption.EncryptedXmlInfo encrypted = options.XmlEncryptor!.Encrypt(key);
        Assert.DoesNotContain("s3cret", encrypted.EncryptedElement.ToString());
        Microsoft.AspNetCore.DataProtection.XmlEncryption.IXmlDecryptor decryptor = (Microsoft.AspNetCore.DataProtection.XmlEncryption.IXmlDecryptor)
            ActivatorUtilities.CreateInstance(provider, encrypted.DecryptorType);
        Assert.Equal("s3cret", decryptor.Decrypt(encrypted.EncryptedElement).Element("secret")!.Value);

        Assert.Throws<ArgumentException>(() => new ServiceCollection().AddDataProtection()
            .AddGuardKeyRing(System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert))));
    }

    /// <summary>A ring kept somewhere the host chose, as in Postgres.</summary>
    private sealed class Database : IXmlRepository
    {
        public IReadOnlyCollection<XElement> GetAllElements() => [];

        public void StoreElement(XElement element, string friendlyName)
        {
        }
    }
}
