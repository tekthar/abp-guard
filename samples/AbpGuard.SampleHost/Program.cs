using Microsoft.AspNetCore.DataProtection;
using AbpGuard;
using AbpGuard.SampleHost;

// A host of Guard alone: accounts, sign-up, sign-in, sessions and who may do what, with Guard's defaults for
// everything a host may give (mail to a pickup folder, locks and limits in Postgres, no CAPTCHA, no plugins).
WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Host.UseAutofac();
// Guard protects secrets with the key ring: kept in Guard's database, so every server and restart reads the same keys.
builder.Services.AddDataProtection().SetApplicationName("guard-sample").AddGuardKeyRing();
await builder.AddApplicationAsync<SampleHostModule>();

WebApplication app = builder.Build();
await GuardDatabase.MigrateAsync(app.Services);
await GuardDatabase.SeedAsync(app.Services);
await app.InitializeApplicationAsync();
await app.RunAsync();

/// <summary>The program, for the tests' WebApplicationFactory.</summary>
public partial class Program;
