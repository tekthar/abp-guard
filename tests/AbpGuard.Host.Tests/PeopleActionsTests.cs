using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AbpGuard.Host.Tests;

/// <summary>
/// The people actions of 0.9.0: deactivate and activate, deleting an unused account, an admin's password link,
/// invitations, a role for anonymous visitors in a place the host lists, and the lists' directory filter, groups and
/// exports. Each shows what's refused as well as what works.
/// </summary>
public sealed partial class SecurityTests
{
    [Fact]
    public async Task Deactivating_stops_sign_in_and_wins_over_a_lock_until_activated()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Guid gone = await CreateAccountAsync(admin, "gone", "gone@example.test");
        Session theirs = await SignInAsync("gone", Password);
        Assert.Equal(HttpStatusCode.OK, (await theirs.SendAsync(HttpMethod.Get, "/api/guard/me")).Code);

        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{gone}/deactivate");
        Assert.True(code == HttpStatusCode.OK, body);
        JsonElement account = JsonDocument.Parse(body).RootElement;
        Assert.Equal("Inactive", account.GetProperty("status").GetString());
        Assert.StartsWith("Deactivated in ", account.GetProperty("statusReason").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await theirs.SendAsync(HttpMethod.Get, "/api/guard/me")).Code);
        Assert.NotEqual(HttpStatusCode.OK, (await Client().PostAsJsonAsync("/api/guard/session", new { username = "gone", password = Password })).StatusCode);

        // Locked as well: still deactivated, the reason that shows; activated, the lock is what's left.
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{gone}/lock")).Code);
        Assert.Equal("Inactive", await StatusAsync(admin, gone));
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{gone}/activate")).Code);
        Assert.Equal("Locked", await StatusAsync(admin, gone));
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{gone}/unlock")).Code);
        Assert.Equal("Active", await StatusAsync(admin, gone));
        Assert.Equal(HttpStatusCode.OK, (await SignInAsync("gone", Password).ContinueWith(t => t.Result.SendAsync(HttpMethod.Get, "/api/guard/me")).Unwrap()).Code);

        // Not yourself; not for a helpdesk, which may lock.
        Guid adminId = await MyIdAsync(admin);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{adminId}/deactivate")).Code);
        Guid desk = await CreateAccountAsync(admin, "desk-d", "desk-d@example.test");
        await GrantAsync(admin, Helpdesk, desk, new { directoryIds = new[] { Internal } });
        Session d = await SignInAsync("desk-d", Password);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{gone}/deactivate")).Code);
        Assert.False((await NewCanAsync(d, gone))["deactivate"]);
        Assert.True((await NewCanAsync(admin, gone))["deactivate"]);
    }

    [Fact]
    public async Task Only_an_account_nobody_used_is_deleted()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Guid unused = await CreateAccountAsync(admin, "typo", "typo@example.test");
        Assert.True((await NewCanAsync(admin, unused))["delete"]);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.SendAsync(HttpMethod.Delete, $"/api/guard/accounts/{unused}")).Code);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.SendAsync(HttpMethod.Get, $"/api/guard/accounts/{unused}")).Code);
        Assert.Contains("account.deleted", await EventTypesAsync("account."));

        // Signed in once: it has a history.
        Guid used = await CreateAccountAsync(admin, "used", "used@example.test");
        await SignInAsync("used", Password);
        Assert.False((await NewCanAsync(admin, used))["delete"]);
        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Delete, $"/api/guard/accounts/{used}");
        Assert.Equal(HttpStatusCode.Conflict, code);
        Assert.Contains("account_signed_in", body);

        // Held by something the host keeps: what a merge would move counts.
        Guid held = await CreateAccountAsync(admin, "held", "held@example.test");
        await using WebApplicationFactory<Program> host = _factory!.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
            s.AddSingleton<IAccountMergeParticipant>(new HoldsOne(held))));
        Session hostAdmin = await SignInOnAsync(host, "admin", AdminPassword);
        (code, body) = await hostAdmin.SendAsync(HttpMethod.Delete, $"/api/guard/accounts/{held}");
        Assert.Equal(HttpStatusCode.Conflict, code);
        Assert.Contains("account_in_use", body);
        Assert.Contains("records.reporter", body);

        // Never yourself.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.SendAsync(HttpMethod.Delete, $"/api/guard/accounts/{await MyIdAsync(admin)}")).Code);
    }

    [Fact]
    public async Task An_admin_mails_a_link_to_choose_a_new_password_and_the_old_one_works_until_then()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Guid pat = await CreateAccountAsync(admin, "pat", "pat@example.test");
        Assert.True((await NewCanAsync(admin, pat))["resetPassword"]);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{pat}/password-reset")).Code);
        string mail = await LastMailToAsync("pat@example.test");
        Assert.Contains("administrator asked", mail);
        await SignInAsync("pat", Password); // still works

        HttpClient anyone = Client();
        string token = TokenIn(mail);
        Assert.Equal(HttpStatusCode.OK, (await anyone.PostAsJsonAsync("/api/guard/password/reset", new { token, password = "Pat-New-Pass-12" })).StatusCode);
        await SignInAsync("pat", "Pat-New-Pass-12");
        Assert.NotEqual(HttpStatusCode.OK, (await anyone.PostAsJsonAsync("/api/guard/password/reset", new { token, password = "Pat-Again-Pass-12" })).StatusCode);

        // No address to mail it to.
        (HttpStatusCode made, string body) = await admin.SendAsync(HttpMethod.Post, "/api/guard/accounts", new { username = "no-mail", displayName = "No Mail", password = Password });
        Assert.Equal(HttpStatusCode.OK, made);
        Guid noMail = JsonDocument.Parse(body).RootElement.GetProperty("id").GetGuid();
        (HttpStatusCode code, string refused) = await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{noMail}/password-reset");
        Assert.Equal(HttpStatusCode.Conflict, code);
        Assert.Contains("no_email", refused);
    }

    [Fact]
    public async Task An_invitation_makes_an_account_whose_person_chooses_the_password()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        await CreateAccountAsync(admin, "nia", "someone-else@example.test");
        await CreateAccountAsync(admin, "taken", "taken@example.test");
        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Post, "/api/guard/accounts/invitations", new
        {
            people = new object[]
            {
                new { email = "nia@example.test", displayName = "Nia Rowe" },
                new { email = "not-an-address" },
                new { email = "NIA@example.test" },
                new { email = "taken@example.test" },
            },
        });
        Assert.True(code == HttpStatusCode.OK, body);
        JsonElement result = JsonDocument.Parse(body).RootElement;
        JsonElement invited = Assert.Single(result.GetProperty("invited").EnumerateArray());
        Assert.Equal("nia2", invited.GetProperty("username").GetString()); // "nia" was taken
        Assert.Equal("Nia Rowe", invited.GetProperty("displayName").GetString());
        Assert.True(invited.GetProperty("invited").GetBoolean());
        Assert.Equal(3, result.GetProperty("refused").GetArrayLength());
        Guid nia = invited.GetProperty("id").GetGuid();

        // No password yet; the mailed link sets one, and it's sent again on asking.
        Assert.NotEqual(HttpStatusCode.OK, (await Client().PostAsJsonAsync("/api/guard/session", new { username = "nia2", password = Password })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{nia}/invitation")).Code);
        string mail = await LastMailToAsync("nia@example.test");
        Assert.Contains("invited you", mail);
        Assert.Equal(HttpStatusCode.OK, (await Client().PostAsJsonAsync("/api/guard/password/reset", new { token = TokenIn(mail), password = "Nia-Chosen-Pass-1" })).StatusCode);
        await SignInAsync("nia2", "Nia-Chosen-Pass-1");
        Assert.Equal(HttpStatusCode.Conflict, (await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{nia}/invitation")).Code);
        Assert.False(JsonDocument.Parse((await admin.SendAsync(HttpMethod.Get, $"/api/guard/accounts/{nia}")).Body).RootElement.GetProperty("account").GetProperty("invited").GetBoolean());

        // Cancelling one nobody accepted is deleting the unused account.
        (code, body) = await admin.SendAsync(HttpMethod.Post, "/api/guard/accounts/invitations", new { people = new[] { new { email = "late@example.test" } } });
        Guid late = JsonDocument.Parse(body).RootElement.GetProperty("invited")[0].GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.SendAsync(HttpMethod.Delete, $"/api/guard/accounts/{late}")).Code);
    }

    [Fact]
    public async Task Anonymous_visitors_get_a_role_only_where_the_host_lists_it_and_only_one_that_keeps_to_it()
    {
        TestSubjects.EnsureRegistered();
        Session admin = await SignInAsync("admin", AdminPassword);
        Guid reader = await CreateRoleAsync(admin, "page-reader", """{"action":"read","subject":"Page","conditions":{"placeId":"${grant.placeId}"}}""");
        Guid loose = await CreateRoleAsync(admin, "page-loose", """{"action":"read","subject":"Page","conditions":{"$or":[{"placeId":"${grant.placeId}"},{"public":true}]}}""");
        Guid people = await CreateRoleAsync(admin, "people-reader", """{"action":"read","subject":"Account"}""");
        Guid other = await CreateRoleAsync(admin, "page-other", """{"action":"read","subject":"Page","conditions":{"placeId":"${grant.placeId}"}}""");
        Guid place = Guid.NewGuid();
        GrantScopeOption help = new($"place:{place}", new JsonObject { ["placeId"] = place.ToString() }, "Help centre", [reader, loose, people])
        {
            Code = "/help",
            Subjects = ["Page"],
        };
        await using WebApplicationFactory<Program> host = _factory!.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
            s.AddSingleton<IGrantScopeCatalog>(new Places(help))));
        Session a = await SignInOnAsync(host, "admin", AdminPassword);

        (HttpStatusCode code, string body) = await a.SendAsync(HttpMethod.Get, "/api/guard/anonymous/places");
        Assert.True(code == HttpStatusCode.OK, body);
        JsonElement listed = Assert.Single(JsonDocument.Parse(body).RootElement.EnumerateArray());
        Assert.Equal("/help", listed.GetProperty("code").GetString());
        Assert.Equal(3, listed.GetProperty("roles").GetArrayLength());

        // A role the place doesn't list; one that escapes the place under $or; one that reads people.
        Assert.Equal(HttpStatusCode.BadRequest, (await a.SendAsync(HttpMethod.Post, "/api/guard/anonymous", new { roleId = other, scopeKey = help.ScopeKey })).Code);
        Assert.Equal(HttpStatusCode.Conflict, (await a.SendAsync(HttpMethod.Post, "/api/guard/anonymous", new { roleId = loose, scopeKey = help.ScopeKey })).Code);
        Assert.Equal(HttpStatusCode.Conflict, (await a.SendAsync(HttpMethod.Post, "/api/guard/anonymous", new { roleId = people, scopeKey = help.ScopeKey })).Code);
        Assert.Equal(HttpStatusCode.BadRequest, (await a.SendAsync(HttpMethod.Post, "/api/guard/anonymous", new { roleId = reader, scopeKey = "place:elsewhere" })).Code);

        (code, body) = await a.SendAsync(HttpMethod.Post, "/api/guard/anonymous", new { roleId = reader, scopeKey = help.ScopeKey });
        Assert.True(code == HttpStatusCode.OK, body);
        Guid grant = JsonDocument.Parse(body).RootElement.GetProperty("id").GetGuid();
        Assert.Equal("page-reader", JsonDocument.Parse(body).RootElement.GetProperty("roleKey").GetString());

        // Changed in one step, with the same checks.
        Assert.Equal(HttpStatusCode.Conflict, (await a.SendAsync(HttpMethod.Put, $"/api/guard/anonymous/{grant}", new { roleId = loose })).Code);
        (code, body) = await a.SendAsync(HttpMethod.Get, "/api/guard/anonymous");
        Assert.Single(JsonDocument.Parse(body).RootElement.EnumerateArray());
    }

    [Fact]
    public async Task Lists_filter_by_directory_group_with_true_totals_and_export_safely()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Post, "/api/guard/accounts",
            new { username = "formula", displayName = "=SUM(1,2)", email = "formula@example.test", password = Password })).Code);
        Guid locked = await CreateAccountAsync(admin, "locked-one", "locked-one@example.test");
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{locked}/lock")).Code);

        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Get, $"/api/guard/accounts/page?groupBy=status&maxResultCount=1&directoryId={Internal}");
        Assert.True(code == HttpStatusCode.OK, body);
        JsonElement page = JsonDocument.Parse(body).RootElement;
        Dictionary<string, int> groups = page.GetProperty("groups").EnumerateArray().ToDictionary(g => g.GetProperty("key").GetString()!, g => g.GetProperty("count").GetInt32());
        Assert.Equal(1, groups["Locked"]);
        Assert.Equal(page.GetProperty("totalCount").GetInt32(), groups.Values.Sum());
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.SendAsync(HttpMethod.Get, "/api/guard/accounts/page?groupBy=colour")).Code);
        (code, body) = await admin.SendAsync(HttpMethod.Get, $"/api/guard/accounts/page?directoryId={Guid.NewGuid()}");
        Assert.Equal(0, JsonDocument.Parse(body).RootElement.GetProperty("totalCount").GetInt32());

        HttpResponseMessage export = await admin.Http.SendAsync(WithCsrf(admin, HttpMethod.Get, "/api/guard/accounts/export?sorting=username"));
        Assert.Equal(HttpStatusCode.OK, export.StatusCode);
        string csv = await export.Content.ReadAsStringAsync();
        Assert.StartsWith("Username,Display name,Email", csv.TrimStart('﻿'));
        Assert.Contains("'=SUM(1,2)", csv);
        Assert.Contains("account.exported", await EventTypesAsync("account."));

        (code, body) = await admin.SendAsync(HttpMethod.Get, "/api/guard/groups/page?groupBy=kind");
        Assert.True(code == HttpStatusCode.OK, body);
        Assert.True(JsonDocument.Parse(body).RootElement.GetProperty("groups").GetArrayLength() > 0);
        Assert.Equal(HttpStatusCode.OK, (await admin.Http.SendAsync(WithCsrf(admin, HttpMethod.Get, "/api/guard/groups/export"))).StatusCode);

        (code, body) = await admin.SendAsync(HttpMethod.Get, "/api/guard/password/policy");
        Assert.True(code == HttpStatusCode.OK, body);
        Assert.Equal(10, JsonDocument.Parse(body).RootElement.GetProperty("minLength").GetInt32());
    }

    /// <summary>The security log's event types that start so, oldest first.</summary>
    private async Task<List<string>> EventTypesAsync(string prefix)
    {
        await using Npgsql.NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        await using Npgsql.NpgsqlCommand read = new("""SELECT "Type" FROM guard.security_events WHERE "Type" LIKE @p ORDER BY "Time" """, connection);
        read.Parameters.AddWithValue("p", prefix + "%");
        await using Npgsql.NpgsqlDataReader rows = await read.ExecuteReaderAsync();
        List<string> types = [];
        while (await rows.ReadAsync())
        {
            types.Add(rows.GetString(0));
        }

        return types;
    }

    private static HttpRequestMessage WithCsrf(Session session, HttpMethod method, string url)
    {
        HttpRequestMessage request = new(method, url);
        request.Headers.Add(CsrfHeader, session.Csrf);
        return request;
    }

    private static async Task<string?> StatusAsync(Session admin, Guid account) =>
        JsonDocument.Parse((await admin.SendAsync(HttpMethod.Get, $"/api/guard/accounts/{account}")).Body).RootElement.GetProperty("account").GetProperty("status").GetString();

    /// <summary>0.9.0's can flags: deactivate, activate, resetPassword, delete.</summary>
    private static async Task<Dictionary<string, bool>> NewCanAsync(Session caller, Guid account)
    {
        (HttpStatusCode code, string body) = await caller.SendAsync(HttpMethod.Get, $"/api/guard/accounts/{account}");
        Assert.True(code == HttpStatusCode.OK, $"{(int)code}: {body}");
        JsonElement can = JsonDocument.Parse(body).RootElement.GetProperty("can");
        return new[] { "deactivate", "activate", "resetPassword", "delete" }.ToDictionary(k => k, k => can.GetProperty(k).GetBoolean());
    }

    private static async Task<Session> SignInOnAsync(WebApplicationFactory<Program> host, string username, string password)
    {
        HttpClient client = host.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });
        HttpResponseMessage signedIn = await client.PostAsJsonAsync("/api/guard/session", new { username, password });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        string prefix = new GuardCookieOptions().Csrf + "=";
        string cookie = signedIn.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(prefix, StringComparison.Ordinal));
        return new Session(client, Uri.UnescapeDataString(cookie[prefix.Length..].Split(';')[0]));
    }

    /// <summary>A host module whose records name one account: what a merge would move holds it.</summary>
    private sealed class HoldsOne(Guid account) : IAccountMergeParticipant
    {
        public Task<IReadOnlyList<AccountMergeCount>> PreviewAsync(Guid sourceId, Guid survivorId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AccountMergeCount>>([new("records.reporter", sourceId == account ? 2 : 0)]);

        public Task<IReadOnlyList<AccountMergeCount>> MergeAsync(AccountMerge merge, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AccountMergeCount>>([]);
    }

    /// <summary>A host's one place for anonymous visitors.</summary>
    private sealed class Places(GrantScopeOption place) : IGrantScopeCatalog
    {
        public Task<IReadOnlyList<GrantScopeOption>> ListAsync(string purpose, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<GrantScopeOption>>(purpose == GrantPurposes.Anonymous ? [place] : []);
    }

    /// <summary>A host's own subject, a page in a place, added to the shared registry once.</summary>
    private static class TestSubjects
    {
        private static int _registered;

        public static void EnsureRegistered()
        {
            if (Interlocked.Exchange(ref _registered, 1) == 0)
            {
                AbilitySubjects.Registry.Add<TestPage>("Page", s => s.ConditionFields("placeId", "public"));
            }
        }
    }

    private sealed class TestPage
    {
        public Guid PlaceId { get; set; }
        public bool Public { get; set; }
    }
}
