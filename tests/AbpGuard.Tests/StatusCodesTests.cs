using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Volo.Abp;
using Volo.Abp.AspNetCore.ExceptionHandling;

namespace AbpGuard.Tests;

/// <summary>Guard's statuses for a host without its own finder: 400 for input a rule refused, 403 and 429 for its codes.</summary>
public class StatusCodesTests
{
    private static readonly GuardHttpExceptionStatusCodeFinder Finder = new(Options.Create(new AbpExceptionHttpStatusCodeOptions()));

    [Fact]
    public void A_refused_input_is_400_and_Guards_codes_keep_their_statuses()
    {
        HttpContext http = new DefaultHttpContext();

        Assert.Equal(HttpStatusCode.BadRequest, Finder.GetStatusCode(http, new UserFriendlyException("Passwords need at least 10 characters.")));
        Assert.Equal(HttpStatusCode.Forbidden, Finder.GetStatusCode(http, new UserFriendlyException("No.", GuardErrorCodes.Forbidden)));
        Assert.Equal(HttpStatusCode.Forbidden, Finder.GetStatusCode(http, new UserFriendlyException("Confirm.", GuardErrorCodes.StepUpRequired)));
        Assert.Equal(HttpStatusCode.TooManyRequests, Finder.GetStatusCode(http, new UserFriendlyException("Wait.", GuardErrorCodes.TooManyRequests)));
    }

    [Fact]
    public void A_code_the_host_mapped_keeps_the_hosts_status()
    {
        AbpExceptionHttpStatusCodeOptions mappings = new();
        mappings.Map("Host:Forbidden", HttpStatusCode.Forbidden);
        mappings.Map("Host:Conflict", HttpStatusCode.Conflict);
        GuardHttpExceptionStatusCodeFinder finder = new(Options.Create(mappings));
        HttpContext http = new DefaultHttpContext();

        Assert.Equal(HttpStatusCode.Forbidden, finder.GetStatusCode(http, new BusinessException("Host:Forbidden")));
        Assert.Equal(HttpStatusCode.Forbidden, finder.GetStatusCode(http, new UserFriendlyException("Not yours.", "Host:Forbidden")));
        Assert.Equal(HttpStatusCode.Conflict, finder.GetStatusCode(http, new BusinessException("Host:Conflict")));
        // A code no one mapped is still a refused input.
        Assert.Equal(HttpStatusCode.BadRequest, finder.GetStatusCode(http, new BusinessException("Host:Unmapped")));
        Assert.Equal(HttpStatusCode.BadRequest, finder.GetStatusCode(http, new UserFriendlyException("Passwords need at least 10 characters.")));
    }

    [Fact]
    public void Guards_finder_replaces_only_ABPs_default()
    {
        ServiceCollection plain = new();
        plain.AddTransient<IHttpExceptionStatusCodeFinder, DefaultHttpExceptionStatusCodeFinder>();
        GuardHttpExceptionStatusCodeFinder.UseUnlessTheHostHasItsOwn(plain);
        Assert.Equal(typeof(GuardHttpExceptionStatusCodeFinder), plain.Last(d => d.ServiceType == typeof(IHttpExceptionStatusCodeFinder)).ImplementationType);

        ServiceCollection host = new();
        host.AddTransient<IHttpExceptionStatusCodeFinder, HostsOwn>();
        GuardHttpExceptionStatusCodeFinder.UseUnlessTheHostHasItsOwn(host);
        Assert.Equal(typeof(HostsOwn), host.Last(d => d.ServiceType == typeof(IHttpExceptionStatusCodeFinder)).ImplementationType);
    }

    private sealed class HostsOwn(IOptions<AbpExceptionHttpStatusCodeOptions> options) : DefaultHttpExceptionStatusCodeFinder(options);
}
