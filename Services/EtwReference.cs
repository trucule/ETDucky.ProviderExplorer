using System;
using System.Collections.Generic;

namespace ETDucky.ProviderExplorer.Services;

/// <summary>
/// Reference lookups for the standard ETW concepts every event carries:
/// opcode, level, channel. Sourced from Microsoft's published <c>winmeta.xml</c>
/// (the manifest schema that ships in the Windows SDK) so a user staring at
/// "Opcode 20" or "Level 4" can find out what that means without leaving the app.
///
/// Provider-specific opcodes (values 11 and above) are not in this table —
/// those names come from each provider's own manifest and are surfaced by the
/// sniffer's per-event OpcodeName field. This class covers the protocol-level
/// values that are the same across every provider.
/// </summary>
public static class EtwReference
{
    // ── Standard opcodes (winmeta:OpcodeType, values 0–10 reserved by ETW) ───
    private static readonly IReadOnlyDictionary<int, OpcodeEntry> StandardOpcodes
        = new Dictionary<int, OpcodeEntry>
        {
            [0]  = new("Info",      "Default opcode. The event records a state observation or a discrete fact; not part of a Start/Stop pair."),
            [1]  = new("Start",     "Marks the beginning of an activity. A matching Stop event with the same ActivityID closes the activity. Used to measure duration and to scope correlated events."),
            [2]  = new("Stop",      "Marks the end of an activity that began with a Start opcode on the same provider with the same ActivityID."),
            [3]  = new("DCStart",   "Data Collection Start. Rundown event emitted when a tracing session begins, so the consumer learns the state that already existed before the session attached (e.g. processes already running)."),
            [4]  = new("DCStop",    "Data Collection Stop. Rundown event emitted when a tracing session ends, mirroring DCStart for state that outlives the session."),
            [5]  = new("Extension", "Indicates an event that extends another event. Rarely seen in user-mode providers."),
            [6]  = new("Reply",     "Reply leg of a request/reply pair. Used by transport providers."),
            [7]  = new("Resume",    "Resumes a previously suspended activity."),
            [8]  = new("Suspend",   "Suspends an in-progress activity. A Resume opcode is expected to follow."),
            [9]  = new("Send",      "Outgoing message in a transport provider. Pairs with Receive on the peer."),
            [10] = new("Receive",   "Incoming message in a transport provider. Pairs with Send on the peer."),
        };

    // ── Standard severity levels (winmeta:LevelType) ─────────────────────────
    private static readonly IReadOnlyDictionary<int, LevelEntry> StandardLevels
        = new Dictionary<int, LevelEntry>
        {
            [0] = new("LogAlways",     "Always emitted regardless of the session's level filter. Used for events that must never be dropped (e.g. provider shutdown notices)."),
            [1] = new("Critical",      "Abnormal termination. The provider is reporting that something has failed in a way that prevents further useful work."),
            [2] = new("Error",         "A failure occurred but the provider continued. Equivalent to a logged exception."),
            [3] = new("Warning",       "Something unusual happened that did not cause a failure but may indicate a developing problem."),
            [4] = new("Informational", "Routine activity. Most production-tier events sit at this level."),
            [5] = new("Verbose",       "Detailed activity intended for debugging. Often high-volume; enabling Verbose on a busy provider can produce thousands of events per second."),
        };

    // ── Standard channels (winmeta:ChannelType) ──────────────────────────────
    // Channels are how Windows routes events to specific Event Log views.
    // The Provider Explorer sniffs raw ETW so the channel is rarely surfaced
    // directly, but it is a concept users will encounter in winmeta-based docs.
    private static readonly IReadOnlyDictionary<int, ChannelEntry> StandardChannels
        = new Dictionary<int, ChannelEntry>
        {
            [16] = new("Admin",       "Surfaced to administrators in the main Event Log views. Events here are written for an end-user audience and should be actionable."),
            [17] = new("Operational", "Surfaced under Applications and Services Logs. Routine operational events that diagnostic tools consume."),
            [18] = new("Analytic",    "High-volume diagnostic events that the Event Log keeps disabled by default. Enabled on demand for deep analysis."),
            [19] = new("Debug",       "Developer-targeted events, disabled by default. Equivalent to Analytic for the debugging audience."),
        };

    /// <summary>
    /// Look up an opcode by numeric value. Returns null when the value is
    /// outside the standard 0–10 range — those values are provider-defined and
    /// the friendly name comes from the provider's own manifest, surfaced in
    /// the sniffer's <c>OpcodeName</c> field.
    /// </summary>
    public static OpcodeEntry? LookupOpcode(int value)
        => StandardOpcodes.TryGetValue(value, out var entry) ? entry : null;

    /// <summary>
    /// Look up an opcode by its name as reported by TDH. Names like "Start",
    /// "Stop", "Info" map back to the standard table; provider-specific names
    /// return null. Comparison is case-insensitive.
    /// </summary>
    public static OpcodeEntry? LookupOpcodeByName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        foreach (var (_, entry) in StandardOpcodes)
            if (string.Equals(entry.Name, name, StringComparison.OrdinalIgnoreCase))
                return entry;
        return null;
    }

    /// <summary>
    /// Parse the value out of TDH's <c>"Opcode(NN)"</c> wrapper string and
    /// return the numeric component. Returns null when the string doesn't
    /// match the wrapper pattern.
    /// </summary>
    public static int? TryParseOpcodeValue(string? opcodeText)
    {
        if (string.IsNullOrWhiteSpace(opcodeText)) return null;

        // Common shapes from TDH: "Opcode(20)", "Start", "Stop", "Info".
        var open  = opcodeText.IndexOf('(');
        var close = opcodeText.IndexOf(')');
        if (open >= 0 && close > open + 1)
        {
            var inner = opcodeText.AsSpan(open + 1, close - open - 1);
            if (int.TryParse(inner, out var n)) return n;
        }

        // No parentheses — see if the bare token matches a known opcode name.
        var named = LookupOpcodeByName(opcodeText);
        if (named is not null)
        {
            foreach (var (k, v) in StandardOpcodes)
                if (string.Equals(v.Name, opcodeText, StringComparison.OrdinalIgnoreCase))
                    return k;
        }
        return null;
    }

    /// <summary>Look up a severity level by its numeric value (0–5).</summary>
    public static LevelEntry? LookupLevel(int value)
        => StandardLevels.TryGetValue(value, out var entry) ? entry : null;

    /// <summary>Enumerate every standard level, for help-tab rendering.</summary>
    public static IEnumerable<KeyValuePair<int, LevelEntry>> EnumerateLevels()
        => StandardLevels;

    /// <summary>Enumerate every standard opcode, for help-tab rendering.</summary>
    public static IEnumerable<KeyValuePair<int, OpcodeEntry>> EnumerateOpcodes()
        => StandardOpcodes;

    /// <summary>Enumerate every standard channel, for help-tab rendering.</summary>
    public static IEnumerable<KeyValuePair<int, ChannelEntry>> EnumerateChannels()
        => StandardChannels;

    /// <summary>
    /// Plain-language explanation of what an Event ID actually is. The same
    /// integer means completely different things on different providers, so
    /// the explanation has to be generic; this method exists so the UI has
    /// one canonical place to surface that point.
    /// </summary>
    public static string ExplainEventId(int eventId, string providerName)
        => $"Event ID {eventId} is the identifier the {providerName} provider " +
           "assigned to this specific message in its manifest. Event IDs are " +
           "scoped to a single provider — the same number on a different " +
           "provider means something completely different. The provider's " +
           "manifest is the authoritative source for what fields and meaning " +
           "this event carries.";
}

/// <summary>One row of the standard opcode glossary.</summary>
public sealed record OpcodeEntry(string Name, string Description);

/// <summary>One row of the standard severity-level glossary.</summary>
public sealed record LevelEntry(string Name, string Description);

/// <summary>One row of the standard channel glossary.</summary>
public sealed record ChannelEntry(string Name, string Description);
