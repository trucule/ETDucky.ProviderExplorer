using System;
using System.Collections.Generic;

namespace ETDucky.ProviderExplorer.Models;

/// <summary>
/// Outcome of subscribing to a provider for a short window. Captures enough
/// to budget the provider in the main agent: total event volume, per-event-id
/// breakdown, and a sample-error indicator so noisy results aren't taken at
/// face value.
/// </summary>
public sealed class SniffResult
{
    public Guid ProviderGuid { get; init; }
    public string ProviderName { get; init; } = string.Empty;
    public DateTime StartedAtUtc { get; init; }
    public TimeSpan Duration { get; init; }

    /// <summary>Total events captured during the sniff window.</summary>
    public long TotalEvents { get; init; }

    /// <summary>
    /// Events captured grouped by (event id, opcode, task name). Reported as a
    /// flat list ordered by count desc so the UI can show the top contributors
    /// without further sorting.
    /// </summary>
    public IReadOnlyList<EventBreakdown> Breakdown { get; init; } = Array.Empty<EventBreakdown>();

    /// <summary>
    /// Per-(EventId, Opcode, Task) sample payloads. Capped at a small number per
    /// group so the explorer can show users "here is what an actual event of
    /// this shape looks like" without blowing memory on a high-volume provider.
    /// </summary>
    public IReadOnlyDictionary<EventBreakdownKey, IReadOnlyList<EventSample>> Samples { get; init; }
        = new Dictionary<EventBreakdownKey, IReadOnlyList<EventSample>>();

    /// <summary>True when the sniff was stopped early (timeout, error, user cancel) in bounded mode.</summary>
    public bool WasIncomplete { get; init; }

    /// <summary>
    /// True when the sniff was run in continuous mode (unbounded duration, ends only when the
    /// caller cancels). In this mode <see cref="WasIncomplete"/> stays false on cancel because
    /// "user clicked Stop" is the normal completion path, not an early termination.
    /// </summary>
    public bool IsContinuous { get; init; }

    /// <summary>
    /// True when this result is a periodic in-progress snapshot of an ongoing sniff (vs the
    /// final result delivered when the session tears down). The UI uses this to label the
    /// summary as "live" instead of a finished tally.
    /// </summary>
    public bool IsLiveSnapshot { get; init; }

    /// <summary>Non-empty when the sniff hit an error (provider not found, no privilege, etc.).</summary>
    public string? Error { get; init; }

    /// <summary>Events per second over the sniff window (0 when Duration is zero).</summary>
    public double EventsPerSecond =>
        Duration.TotalSeconds > 0 ? TotalEvents / Duration.TotalSeconds : 0;
}

/// <summary>One row in the sniff breakdown.</summary>
public sealed record EventBreakdown(int EventId, string TaskName, string Opcode, long Count);

/// <summary>
/// Composite identity for an event-breakdown row. Exposed publicly (rather than
/// being a private sniffer detail) so the UI can index <see cref="SniffResult.Samples"/>
/// with the same key that the breakdown rows use.
/// </summary>
public readonly record struct EventBreakdownKey(int EventId, string TaskName, string OpcodeName);

/// <summary>
/// One decoded sample event captured during the sniff. <see cref="FormattedMessage"/>
/// comes from the provider's manifest (when present); the payload fields are
/// the parsed (name, value) pairs from the event's data section. Either may be
/// empty depending on what the provider exposes and what TDH can decode.
/// </summary>
public sealed record EventSample(
    DateTime TimestampUtc,
    int ProcessId,
    int ThreadId,
    string FormattedMessage,
    IReadOnlyList<EventPayloadField> Payload);

/// <summary>A single (name, value) pair from a decoded event's payload.</summary>
public sealed record EventPayloadField(string Name, string Value);
