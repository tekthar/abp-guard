using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using AbpGuard.Directories;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// Encrypts secret directory settings (bind passwords) at rest. They have to be reversible because the
/// password is replayed to bind, so they are encrypted rather than hashed, and never returned by the API.
/// </summary>
public class DirectorySecrets(IDataProtectionProvider dataProtection, Microsoft.Extensions.Options.IOptions<GuardNames> names) : ISingletonDependency
{
    private readonly IDataProtector _protector = dataProtection.CreateProtector(names.Value.Purpose("DirectorySecrets.v1"));

    public const string Mask = "********";

    public string? Protect(IReadOnlyDictionary<string, string> secrets) =>
        secrets.Count == 0 ? null : _protector.Protect(JsonSerializer.Serialize(secrets));

    public Dictionary<string, string> Unprotect(string? protectedSecrets) =>
        TryUnprotect(protectedSecrets, out Dictionary<string, string> secrets) ? secrets : new Dictionary<string, string>();

    /// <summary>
    /// False when the stored secrets can't be decrypted, for example after the data-protection keys were lost
    /// or the database was restored on another server. Callers carry on without the secrets; the admin re-enters them.
    /// </summary>
    public bool TryUnprotect(string? protectedSecrets, out Dictionary<string, string> secrets)
    {
        secrets = new Dictionary<string, string>();
        if (string.IsNullOrEmpty(protectedSecrets))
        {
            return true;
        }

        try
        {
            secrets = JsonSerializer.Deserialize<Dictionary<string, string>>(_protector.Unprotect(protectedSecrets)) ?? new();
            return true;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return false;
        }
    }
}

/// <summary>Finds the connector for a directory type among core and plugin-provided extensions.</summary>
public class ConnectorCatalog(IGuardExtensions extensions, IServiceProvider services, DirectorySecrets secrets) : ITransientDependency
{
    public async Task<T> WithConnectorAsync<T>(string type, Func<IDirectoryConnector?, string?, Task<T>> work)
    {
        await using IGuardLease<IDirectoryConnector> lease = extensions.Lease<IDirectoryConnector>(services);
        (string? pluginKey, IDirectoryConnector? connector) = lease.Items.FirstOrDefault(i => i.Instance.Type == type);
        return await work(connector, pluginKey);
    }

    public async Task<List<ConnectorDescription>> DescribeAllAsync()
    {
        await using IGuardLease<IDirectoryConnector> lease = extensions.Lease<IDirectoryConnector>(services);
        return lease.Items
            .Select(i => new ConnectorDescription(i.Instance.Type, i.Instance.DisplayName, i.Instance.Capabilities, i.Instance.Settings.ToList(), i.PluginKey))
            .ToList();
    }

    public DirectoryConnectionContext BuildContext(UserDirectory directory)
    {
        Dictionary<string, string> settings = JsonSerializer.Deserialize<Dictionary<string, string>>(directory.SettingsJson) ?? new();
        foreach ((string name, string value) in secrets.Unprotect(directory.ProtectedSecrets))
        {
            settings[name] = value;
        }

        return new DirectoryConnectionContext(directory.Id, directory.Name, settings);
    }
}

public sealed record ConnectorDescription(
    string Type,
    string DisplayName,
    DirectoryCapabilities Capabilities,
    List<DirectorySettingDefinition> Settings,
    string? PluginKey);
