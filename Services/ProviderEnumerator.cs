using System;
using System.Collections.Generic;
using System.Linq;
using ETDucky.ProviderExplorer.Models;
using Microsoft.Diagnostics.Tracing.Session;

namespace ETDucky.ProviderExplorer.Services;

/// <summary>
/// Enumerates manifest-registered ETW providers on the host and resolves each
/// one's metadata (name, keywords, severity levels) via the TraceEvent
/// library's <see cref="TraceEventProviders"/> APIs — the same mechanism
/// `logman query providers` uses internally, surfaced as a typed catalog.
///
/// Every TDH lookup is wrapped in try/catch: a malformed manifest, a missing
/// permission, or a provider that's been unloaded mid-enumeration shouldn't
/// kill the whole listing. The enumeration falls through, omitting the
/// problematic field rather than the row.
/// </summary>
public static class ProviderEnumerator
{
    /// <summary>
    /// Returns every published ETW provider visible to the current process,
    /// each with as much metadata as the host's TDH lookups can resolve.
    /// Order is unspecified — caller sorts.
    /// </summary>
    public static List<ProviderInfo> EnumerateAll()
    {
        var result = new List<ProviderInfo>();

        Guid[] guids;
        try
        {
            guids = TraceEventProviders.GetPublishedProviders().ToArray();
        }
        catch (Exception)
        {
            // No published providers visible (typically: not running elevated
            // on a stripped-down SKU). Return an empty list — the UI can
            // surface a hint.
            return result;
        }

        foreach (var guid in guids)
        {
            result.Add(new ProviderInfo
            {
                Guid     = guid,
                Name     = ResolveName(guid),
                Keywords = ResolveKeywords(guid),
                Levels   = ResolveLevels(guid),
            });
        }

        return result;
    }

    private static string ResolveName(Guid guid)
    {
        try
        {
            var name = TraceEventProviders.GetProviderName(guid);
            return string.IsNullOrEmpty(name) ? guid.ToString("B") : name;
        }
        catch
        {
            return guid.ToString("B");
        }
    }

    private static IReadOnlyList<KeywordInfo> ResolveKeywords(Guid guid)
    {
        try
        {
            var items = TraceEventProviders.GetProviderKeywords(guid);
            if (items == null || items.Count == 0) return Array.Empty<KeywordInfo>();
            return items
                .Select(k => new KeywordInfo(k.Name ?? string.Empty, unchecked((ulong)k.Value)))
                .ToList();
        }
        catch
        {
            return Array.Empty<KeywordInfo>();
        }
    }

    /// <summary>
    /// Standard ETW severity levels (per the protocol's TraceEventLevel enum).
    /// Every provider supports these regardless of which subset it emits at —
    /// per-provider level <i>usage</i> is observable only by sniffing.
    /// TraceEvent 3.2.x doesn't expose a per-provider level enumeration API
    /// (older versions did via GetProviderLevels; that was removed), so we
    /// return the standard set as universal metadata.
    /// </summary>
    private static readonly IReadOnlyList<LevelInfo> StandardEtwLevels = new[]
    {
        new LevelInfo("Critical",      1),
        new LevelInfo("Error",         2),
        new LevelInfo("Warning",       3),
        new LevelInfo("Informational", 4),
        new LevelInfo("Verbose",       5),
    };

    private static IReadOnlyList<LevelInfo> ResolveLevels(Guid guid) => StandardEtwLevels;
}
