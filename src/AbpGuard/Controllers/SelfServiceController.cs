using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AbpGuard.Services;
using AbpGuard.Acting;
using Volo.Abp;

namespace AbpGuard.Controllers;

/// <summary>
/// What people do for themselves without signing in: sign up where the site allows it, confirm their email,
/// and reset a forgotten password by mail. Limited per address and per email. Each action allows anonymous callers
/// on its own: [AllowAnonymous] on a controller would override any admin policy on its actions.
/// </summary>
[Route("api/guard")]
public class SelfServiceController(SelfService self, SelfServiceLimiter limiter, ISignUpChallenges challenges, TestAccounts testAccounts)
    : GuardControllerBase
{
    /// <summary>The accounts a test site shows on its sign-in page, with their passwords; none on any other site.</summary>
    [AllowAnonymous]
    [HttpGet("signin/test-accounts")]
    public IReadOnlyList<TestAccountDto> TestAccounts() => testAccounts.List();

    /// <summary>Whether people may sign up here, and with which email domains (all when empty).</summary>
    [AllowAnonymous]
    [HttpGet("signup")]
    [GuardFeature(nameof(GuardFeatures.SignUp))]
    public Task<SignUpInfoDto> Info(CancellationToken cancellationToken) => self.InfoAsync(cancellationToken);

    /// <summary>Creates an account that's active once its email is confirmed, and mails the link.</summary>
    [AllowAnonymous]
    [HttpPost("signup")]
    [GuardFeature(nameof(GuardFeatures.SignUp))]
    public async Task<NoContentResult> SignUp([FromBody] SignUpInput input, CancellationToken cancellationToken)
    {
        await LimitAsync("signup", input.Email, cancellationToken);
        if (!await challenges.VerifyAsync(input.Captcha, HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken))
        {
            throw new UserFriendlyException("Answer the question that shows you're a person.");
        }

        await self.SignUpAsync(input, cancellationToken);
        return NoContent();
    }

    /// <summary>Confirms an email from the link in the mail; the account can sign in from then on.</summary>
    [AllowAnonymous]
    [HttpPost("signup/verify")]
    [GuardFeature(nameof(GuardFeatures.SignUp))]
    public async Task<object> Verify([FromBody] TokenInput input, CancellationToken cancellationToken)
    {
        await LimitAsync("verify", null, cancellationToken);
        (string username, List<object> events) = await self.VerifyAsync(input.Token, cancellationToken);
        await PublishAsync(events);
        return new { username };
    }

    /// <summary>Mails a reset link if an account Guard keeps has this email. Always the same answer.</summary>
    [AllowAnonymous]
    [HttpPost("password/forgot")]
    public async Task<NoContentResult> Forgot([FromBody] ForgotPasswordInput input, CancellationToken cancellationToken)
    {
        await LimitAsync("forgot", input.Email, cancellationToken);
        await self.ForgotAsync(input.Email, cancellationToken);
        return NoContent();
    }

    /// <summary>Sets a new password from a reset link.</summary>
    [AllowAnonymous]
    [HttpPost("password/reset")]
    public async Task<object> Reset([FromBody] ResetPasswordInput input, CancellationToken cancellationToken)
    {
        await LimitAsync("reset", null, cancellationToken);
        return new { username = await self.ResetAsync(input.Token, input.Password, cancellationToken) };
    }

    private async Task LimitAsync(string action, string? email, CancellationToken cancellationToken)
    {
        if (!await limiter.AllowAsync(action, HttpContext.Connection.RemoteIpAddress?.ToString(), email, cancellationToken))
        {
            throw new UserFriendlyException("Too many tries. Wait a while and try again.", GuardErrorCodes.TooManyRequests);
        }
    }
}

/// <summary>Sign-up as site admins set it: on or off, the internal directory accounts go to, and the email domains it takes.</summary>
[Route("api/guard/signup/settings")]
[Authorize(Policy = GuardPolicies.Admin)]
[GuardFeature(nameof(GuardFeatures.SignUp))]
public class SignUpSettingsController(SelfService self) : GuardControllerBase
{
    [HttpGet]
    public Task<SignUpSettingsDto> Get(CancellationToken cancellationToken) => self.SettingsAsync(cancellationToken);

    [HttpPut]
    [StepUp]
    public Task<SignUpSettingsDto> Save([FromBody] SignUpSettingsInput input, CancellationToken cancellationToken) => self.SaveSettingsAsync(input, cancellationToken);
}
