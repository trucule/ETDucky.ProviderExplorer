using System;
using System.Collections.Generic;

namespace ETDucky.ProviderExplorer.Models;

/// <summary>
/// What we know about a single ETW provider, gathered from the provider's
/// manifest registration via TDH (TraceEventProviders APIs).
///
/// Pure DTO — no behaviour. Service-layer code (ProviderEnumerator) constructs
/// these; the UI layer reads them and the sniffer consumes Guid + Name.
/// </summary>
public sealed class ProviderInfo
{
    /// <summary>Provider GUID — the canonical identifier for ETW.</summary>
    public Guid Guid { get; init; }

    /// <summary>
    /// Friendly name as registered in the manifest, e.g.
    /// "Microsoft-Windows-Kernel-Process". Falls back to the GUID string
    /// when the OS can't resolve a name.
    /// </summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>
    /// Manifest-declared keyword bits, mapped to their friendly names.
    /// Empty for providers whose manifest doesn't declare keywords or whose
    /// metadata isn't accessible to the current process.
    /// </summary>
    public IReadOnlyList<KeywordInfo> Keywords { get; init; } = Array.Empty<KeywordInfo>();

    /// <summary>Manifest-declared severity levels (Critical, Error, Warning, Info, Verbose).</summary>
    public IReadOnlyList<LevelInfo> Levels { get; init; } = Array.Empty<LevelInfo>();

    /// <summary>
    /// Number of distinct event IDs the manifest declares. Useful as a rough
    /// "how rich is this provider" signal in the list view.
    /// </summary>
    public int DeclaredEventCount { get; init; }

    /// <summary>
    /// Whether the provider is currently enabled in at least one running
    /// trace session on this host. Live signal — refreshed when the user
    /// asks for it.
    /// </summary>
    public bool IsActiveInAnySession { get; init; }
}

/// <summary>One keyword as declared in a provider's manifest.</summary>
public sealed record KeywordInfo(string Name, ulong Mask);

/// <summary>One severity level as declared in a provider's manifest.</summary>
public sealed record LevelInfo(string Name, byte Value);
