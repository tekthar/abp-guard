using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using Npgsql;

namespace AbpGuard.Host.Tests;

/// <summary>
/// Guard's API document, kept in docs/openapi/abpguard.json: what a host's screens generate their types from (@abpjs/ui's
/// guard area). The sample serves it at /openapi/abpguard.json; this fails when the kept copy differs, as it does after
/// any change to the API or the version, and ABP_GUARD_UPDATE_OPENAPI=1 writes it instead.
/// Needs Postgres: localhost:5432 (postgres/postgres), or the server GUARD_TEST_POSTGRES names.
/// </summary>
[Collection(SampleHost.Collection)]
public sealed class OpenApiContractTests : IAsyncLifetime
{
    private static readonly string Server =
        Environment.GetEnvironmentVariable("GUARD_TEST_POSTGRES") is { Length: > 0 } server ? server : "Host=localhost;Port=5432;Username=postgres;Password=postgres";

    private readonly string _database = "guard_openapi_" + Guid.NewGuid().ToString("N")[..12];
    private WebApplicationFactory<Program>? _factory;

    public Task InitializeAsync()
    {
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("ConnectionStrings__Guard", $"{Server};Database={_database}");
        Environment.SetEnvironmentVariable("Guard__Seed__AdminPassword", "OpenApi-Admin-Pass-1");
        _factory = new WebApplicationFactory<Program>();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }

        NpgsqlConnection.ClearAllPools();
        await using NpgsqlConnection connection = new($"{Server};Database=postgres");
        await connection.OpenAsync();
        await using NpgsqlCommand drop = new($"DROP DATABASE IF EXISTS \"{_database}\" WITH (FORCE)", connection);
        await drop.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task The_kept_document_is_the_one_the_API_serves()
    {
        HttpClient client = _factory!.CreateClient();
        string served = await client.GetStringAsync("/openapi/abpguard.json");
        JsonNode document = JsonNode.Parse(served)!;

        // Guard's actions: the paged lists, second factors and passkeys among them.
        string[] paths = [.. document["paths"]!.AsObject().Select(p => p.Key)];
        Assert.Contains("/api/guard/accounts/page", paths);
        Assert.Contains("/api/guard/me/passkeys", paths);
        Assert.Contains("/api/guard/session/step-up", paths);
        Assert.Equal(AbpGuardModule.Version, (string?)document["info"]!["version"]);

        string text = document.ToJsonString(new JsonSerializerOptions { WriteIndented = true }).Replace("\r\n", "\n") + "\n";
        string kept = Path.Combine(RepositoryRoot(), "docs", "openapi", "abpguard.json");
        if (Environment.GetEnvironmentVariable("ABP_GUARD_UPDATE_OPENAPI") == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(kept)!);
            await File.WriteAllTextAsync(kept, text);
            return;
        }

        Assert.True(File.Exists(kept), "docs/openapi/abpguard.json is missing: run the host tests with ABP_GUARD_UPDATE_OPENAPI=1.");
        string expected = (await File.ReadAllTextAsync(kept)).Replace("\r\n", "\n");
        Assert.True(expected == text,
            "docs/openapi/abpguard.json differs from the API: run the host tests with ABP_GUARD_UPDATE_OPENAPI=1 and commit the change, "
            + "then regenerate the screens' types from it.");
    }

    private static string RepositoryRoot()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AbpGuard.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("AbpGuard.slnx not found above the test's folder.");
    }
}
