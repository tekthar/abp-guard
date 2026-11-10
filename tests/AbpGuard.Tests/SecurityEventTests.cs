using AbpGuard.Domain;

namespace AbpGuard.Tests;

/// <summary>A security event keeps what was typed at sign-in, but no more of it than a username can be.</summary>
public class SecurityEventTests
{
    [Fact]
    public void A_long_username_is_cut_to_the_longest_kept()
    {
        SecurityEvent typed = new(Guid.NewGuid(), "auth.login.failed", new string('a', 70_000), null, "wrong_password", "203.0.113.7");
        Assert.Equal(SecurityEvent.MaxUsernameLength, typed.Username!.Length);

        SecurityEvent ordinary = new(Guid.NewGuid(), "auth.login.failed", "dana@example.test", null, "wrong_password", null);
        Assert.Equal("dana@example.test", ordinary.Username);
        Assert.Null(new SecurityEvent(Guid.NewGuid(), "auth.login.failed", null, null, null, null).Username);
    }
}
