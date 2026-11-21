using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AbpConnections;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Volo.Abp;

namespace AbpNotify.Tests;

/// <summary>
/// Push to phones: the statement a service account signs to get an access token, what FCM's answers mean, an access
/// token kept across sends, and what a push says by default.
/// </summary>
public class PushTests
{
    private static readonly RSA Key = RSA.Create(2048);

    private static ConnectionInUse Connection(Dictionary<string, string>? settings = null, string? serviceAccount = null) =>
        new(Guid.NewGuid(), "Push", FcmConnectionKind.Key, null, settings ?? [], new Dictionary<string, string>
        {
            ["serviceAccount"] = serviceAccount ?? new JsonObject
            {
                ["type"] = "service_account",
                ["project_id"] = "notify-test",
                ["private_key_id"] = "k1",
                ["private_key"] = Key.ExportPkcs8PrivateKeyPem(),
                ["client_email"] = "push@notify-test.example",
                ["token_uri"] = "https://tokens.example/token",
            }.ToJsonString(),
        }, null, null);

    private static JsonObject Part(string jwt, int index)
    {
        string part = jwt.Split('.')[index].Replace('-', '+').Replace('_', '/');
        return JsonNode.Parse(Convert.FromBase64String(part.PadRight(part.Length + (4 - part.Length % 4) % 4, '=')))!.AsObject();
    }

    [Fact]
    public void A_service_account_signs_for_an_hour_of_sending_and_its_public_key_checks_it()
    {
        string jwt = FcmAccount.From(Connection()).Assertion(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));

        Assert.Equal("""{"alg":"RS256","typ":"JWT","kid":"k1"}""", Part(jwt, 0).ToJsonString());
        JsonObject claims = Part(jwt, 1);
        Assert.Equal(("push@notify-test.example", "https://www.googleapis.com/auth/firebase.messaging", "https://tokens.example/token"),
            ((string?)claims["iss"], (string?)claims["scope"], (string?)claims["aud"]));
        Assert.Equal((1_800_000_000L, 1_800_003_600L), ((long?)claims["iat"], (long?)claims["exp"]));
        string[] parts = jwt.Split('.');
        string signature = parts[2].Replace('-', '+').Replace('_', '/');
        byte[] signed = Convert.FromBase64String(signature.PadRight(signature.Length + (4 - signature.Length % 4) % 4, '='));
        using RSA publicKey = RSA.Create();
        publicKey.ImportFromPem(Key.ExportSubjectPublicKeyInfoPem());
        Assert.True(publicKey.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), signed, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.False(publicKey.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}x"), signed, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void The_connections_settings_stand_before_the_keys_own()
    {
        FcmAccount own = FcmAccount.From(Connection());
        Assert.Equal(("notify-test", "https://tokens.example/token", "https://fcm.googleapis.com"), (own.ProjectId, own.TokenUrl, own.ApiUrl));

        FcmAccount set = FcmAccount.From(Connection(new() { ["projectId"] = "other", ["tokenUrl"] = "http://localhost:5229/google/token", ["apiUrl"] = "http://localhost:5229/fcm/" }));
        Assert.Equal(("other", "http://localhost:5229/google/token", "http://localhost:5229/fcm"), (set.ProjectId, set.TokenUrl, set.ApiUrl));
        Assert.NotEqual(own.Fingerprint, set.Fingerprint); // another token address: another access token
    }

    [Theory]
    [InlineData("not json", "isn't JSON")]
    [InlineData("""{"private_key":"x","project_id":"p"}""", "client_email")]
    [InlineData("""{"client_email":"a@b","project_id":"p"}""", "private_key")]
    [InlineData("""{"client_email":"a@b","private_key":"x"}""", "project")]
    public void A_key_that_isnt_one_is_said_plainly(string key, string said) =>
        Assert.Contains(said, Assert.Throws<UserFriendlyException>(() => FcmAccount.From(Connection(serviceAccount: key))).Message);

    [Fact]
    public void A_private_key_that_cant_be_read_is_said_plainly() =>
        Assert.Contains("private_key", Assert.Throws<UserFriendlyException>(() =>
            FcmAccount.From(Connection(serviceAccount: """{"client_email":"a@b","private_key":"-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n","project_id":"p"}"""))
                .Assertion(DateTimeOffset.UtcNow)).Message);

    private static string Error(int code, string status, string message, string? errorCode = null, string? field = null) => new JsonObject
    {
        ["error"] = new JsonObject
        {
            ["code"] = code, ["message"] = message, ["status"] = status,
            ["details"] = new JsonArray(
                errorCode is null ? null : new JsonObject { ["@type"] = "type.googleapis.com/google.firebase.fcm.v1.FcmError", ["errorCode"] = errorCode },
                field is null ? null : new JsonObject
                {
                    ["@type"] = "type.googleapis.com/google.rpc.BadRequest",
                    ["fieldViolations"] = new JsonArray(new JsonObject { ["field"] = field, ["description"] = "Invalid registration token" }),
                }),
        },
    }.ToJsonString();

    [Fact]
    public void FCMs_answers_say_whether_a_phone_is_gone_or_to_try_again()
    {
        Assert.Equal(FcmResult.Sent, FcmOutcome.Classify(200, """{"name":"projects/p/messages/1"}""").Result);
        Assert.Equal(FcmResult.Dead, FcmOutcome.Classify(404, Error(404, "NOT_FOUND", "Requested entity was not found.", "UNREGISTERED")).Result);
        Assert.Equal(FcmResult.Dead, FcmOutcome.Classify(400, Error(400, "INVALID_ARGUMENT", "The registration token is not a valid FCM registration token", "INVALID_ARGUMENT")).Result);
        Assert.Equal(FcmResult.Dead, FcmOutcome.Classify(400, Error(400, "INVALID_ARGUMENT", "Request contains an invalid argument.", "INVALID_ARGUMENT", "message.token")).Result);
        Assert.Equal(FcmResult.Dead, FcmOutcome.Classify(403, Error(403, "PERMISSION_DENIED", "SenderId mismatch", "SENDER_ID_MISMATCH")).Result);
        Assert.Equal(FcmResult.Unauthorized, FcmOutcome.Classify(401, Error(401, "UNAUTHENTICATED", "Request had invalid authentication credentials.")).Result);
        Assert.Equal(FcmResult.Transient, FcmOutcome.Classify(429, Error(429, "RESOURCE_EXHAUSTED", "Quota exceeded.", "QUOTA_EXCEEDED")).Result);
        Assert.Equal(FcmResult.Transient, FcmOutcome.Classify(503, Error(503, "UNAVAILABLE", "The service is currently unavailable.", "UNAVAILABLE")).Result);
        Assert.Equal(FcmResult.Transient, FcmOutcome.Classify(502, "<html>Bad gateway</html>").Result);
        Assert.Equal(FcmResult.Refused, FcmOutcome.Classify(400, """{"error":"bad request","details":["x"]}""").Result);
        // Nothing about the phone: a wrong project, a message FCM won't take, a key without the right: never forget the phone.
        Assert.Equal(FcmResult.Refused, FcmOutcome.Classify(404, Error(404, "NOT_FOUND", "Requested entity was not found.")).Result);
        Assert.Equal(FcmResult.Refused, FcmOutcome.Classify(400, Error(400, "INVALID_ARGUMENT", "Invalid value at 'message.data[0].value'", "INVALID_ARGUMENT")).Result);
        Assert.Equal(FcmResult.Refused, FcmOutcome.Classify(403, Error(403, "PERMISSION_DENIED", "Permission 'cloudmessaging.messages.create' denied.")).Result);
    }

    /// <summary>A Google and an FCM in one handler: tokens it minted are good until it forgets them.</summary>
    private sealed class FakeGoogle : HttpMessageHandler
    {
        public int Minted { get; private set; }
        public List<string> Sent { get; } = [];
        public HashSet<string> Good { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == "/token")
            {
                string form = await request.Content!.ReadAsStringAsync(cancellationToken);
                Assert.Contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer", form);
                string token = $"access-{++Minted}";
                Good.Add(token);
                return Json(HttpStatusCode.OK, new JsonObject { ["access_token"] = token, ["expires_in"] = 3599, ["token_type"] = "Bearer" });
            }

            Assert.Equal("/v1/projects/notify-test/messages:send", request.RequestUri.AbsolutePath);
            if (!Good.Contains(request.Headers.Authorization?.Parameter ?? ""))
            {
                return Json(HttpStatusCode.Unauthorized, JsonNode.Parse(Error(401, "UNAUTHENTICATED", "Request had invalid authentication credentials."))!);
            }

            Sent.Add((string)JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!["message"]!["token"]!);
            return Json(HttpStatusCode.OK, new JsonObject { ["name"] = "projects/notify-test/messages/1" });
        }

        private static HttpResponseMessage Json(HttpStatusCode status, JsonNode body) =>
            new(status) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };
    }

    private sealed class Clients(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private static NotifyDelivery Delivery(string? subject, string text) => new(Guid.NewGuid(), "person", null, subject, text, text, "", "en", "<m@app.test>");

    [Fact]
    public async Task An_access_token_is_kept_across_sends_and_minted_again_when_refused()
    {
        FakeGoogle google = new();
        FcmClient client = new(new Clients(google), NullLogger<FcmClient>.Instance, Options.Create(new NotifyOptions()));
        FcmAccount account = FcmAccount.From(Connection(new() { ["tokenUrl"] = "https://google.test/token", ["apiUrl"] = "https://fcm.test" }));
        PlainPushMessages pushes = new(Options.Create(new NotifyOptions()));

        Assert.Equal(FcmResult.Sent, (await client.SendAsync(account, pushes.Message(Delivery(null, "Hi"), "phone-1"), default)).Result);
        Assert.Equal(FcmResult.Sent, (await client.SendAsync(account, pushes.Message(Delivery(null, "Hi"), "phone-2"), default)).Result);
        Assert.Equal(1, google.Minted);

        google.Good.Clear(); // Google forgot it before it expired
        Assert.Equal(FcmResult.Sent, (await client.SendAsync(account, pushes.Message(Delivery(null, "Hi"), "phone-3"), default)).Result);
        Assert.Equal(2, google.Minted);
        Assert.Equal(["phone-1", "phone-2", "phone-3"], google.Sent);
    }

    [Fact]
    public void A_push_says_its_subject_and_text_and_carries_its_id()
    {
        PlainPushMessages pushes = new(Options.Create(new NotifyOptions { ApplicationName = "Example" }));
        NotifyDelivery said = Delivery("PAY-1 moved", "  Ali moved it to Done  ");
        JsonObject push = pushes.Message(said, "phone-1");
        Assert.Equal(("phone-1", "PAY-1 moved", "Ali moved it to Done", said.Id.ToString(), "high"),
            ((string?)push["token"], (string?)push["notification"]!["title"], (string?)push["notification"]!["body"], (string?)push["data"]!["noticeId"],
                (string?)push["android"]!["priority"]));

        JsonObject plain = pushes.Message(Delivery(null, new string('x', 1500)), "phone-1");
        Assert.Equal("Example", (string?)plain["notification"]!["title"]);
        Assert.Equal(PlainPushMessages.MaxBody, ((string)plain["notification"]!["body"]!).Length);
    }
}
