namespace AbpGuard;

/// <summary>Guard's authorization policies; the host's own admin endpoints use the same names.</summary>
public static class GuardPolicies
{
    /// <summary>
    /// A site admin: may "manage" "all", which the Administrator role granted to the admins group gives, nested groups
    /// included, with the request's limits applied. The host's own admin endpoints use the same name.
    /// </summary>
    public const string Admin = "GuardAdmin";
}
