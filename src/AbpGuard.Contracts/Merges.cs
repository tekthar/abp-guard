namespace AbpGuard;

/// <summary>An account being folded into another: everything the source has, the survivor gets.</summary>
public sealed record AccountMerge(Guid MergeId, Guid SourceId, string SourceUsername, Guid SurvivorId, string SurvivorUsername, string SurvivorDisplayName);

/// <summary>
/// What a participant moved, or would: a key ("records.reporter"), how many, and for a plugin a label in the request's
/// language (a host labels its own modules' keys).
/// </summary>
public sealed record AccountMergeCount(string Key, int Count, string? Label = null);

/// <summary>
/// Implemented by every module and plugin that stores account ids, and registered as an extension
/// (<c>AddExtension&lt;IAccountMergeParticipant, T&gt;()</c>). The host's own modules run in the merge's transaction; a plugin
/// runs after it commits, and again when a merge it didn't finish is resumed, so moving must be safe to run twice.
/// </summary>
public interface IAccountMergeParticipant
{
    /// <summary>What would move, without moving anything. Only counts above zero matter.</summary>
    Task<IReadOnlyList<AccountMergeCount>> PreviewAsync(Guid sourceId, Guid survivorId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Moves everything that names the source to the survivor: ids in columns, lists and documents. Where the survivor
    /// is there already (a list, a unique key), the source's entry goes. Returns what moved.
    /// </summary>
    Task<IReadOnlyList<AccountMergeCount>> MergeAsync(AccountMerge merge, CancellationToken cancellationToken = default);
}
