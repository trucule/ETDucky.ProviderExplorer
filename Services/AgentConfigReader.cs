using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace ETDucky.ProviderExplorer.Services;

/// <summary>
/// Parses an <c>AgentConfig.json</c> file and surfaces the provider-subscription
/// fields the explorer cares about: <c>KernelProviders</c> (kernel-trace keyword
/// names) and <c>UserModeProviders</c> (manifest-registered provider names or
/// GUIDs). Other fields on AgentConfig (cloud endpoint, bearer token, etc.) are
/// deliberately not read — there's no reason for a diagnostic tool to touch them.
/// </summary>
public static class AgentConfigReader
{
    /// <summary>The default production install path for the agent's config.</summary>
    public const string DefaultProductionPath =
        @"C:\ProgramData\ETDucky\Agent\AgentConfig.json";

    /// <summary>
    /// Read <paramref name="path"/> and return what the explorer can use.
    /// Returns null on any failure (file missing, malformed JSON, permission denied)
    /// — the UI surfaces that as a friendly empty state instead of a crash.
    /// </summary>
    public static AgentConfigSummary? TryRead(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;

            var json = File.ReadAllText(path);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            return new AgentConfigSummary
            {
                Path                  = path,
                KernelProviders       = ReadStringArray(root, "KernelProviders"),
                UserModeProviders     = ReadStringArray(root, "UserModeProviders"),
                EnableJournaldCapture = TryReadBool(root, "EnableJournaldCapture"),
                EnableAuditdCapture   = TryReadBool(root, "EnableAuditdCapture"),
            };
        }
        catch (UnauthorizedAccessException)
        {
            // Production AgentConfig.json is mode 0600 / Admin-only. If we get
            // here without elevation, the explorer's UAC manifest didn't fire
            // (e.g. caller debug-launched it from VS without elevation).
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static IReadOnlyList<string> ReadStringArray(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var el)) return Array.Empty<string>();
        if (el.ValueKind != JsonValueKind.Array)    return Array.Empty<string>();

        return el.EnumerateArray()
            .Where(e => e.ValueKind == JsonValueKind.String)
            .Select(e => e.GetString() ?? string.Empty)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList();
    }

    private static bool TryReadBool(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var el)) return false;
        return el.ValueKind == JsonValueKind.True;
    }
}

/// <summary>Summary view of an AgentConfig — only the provider-relevant fields.</summary>
public sealed class AgentConfigSummary
{
    public string Path { get; init; } = string.Empty;

    /// <summary>
    /// Kernel-trace keyword names as the agent declares them. These map to
    /// <c>KernelTraceEventParser.Keywords</c> values (e.g. "Process", "FileIO",
    /// "Registry", "NetworkTCPIP").
    /// </summary>
    public IReadOnlyList<string> KernelProviders { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Manifest-registered user-mode providers — names like
    /// "Microsoft-Windows-Kernel-Process" or GUID strings.
    /// </summary>
    public IReadOnlyList<string> UserModeProviders { get; init; } = Array.Empty<string>();

    /// <summary>True if the Linux journald capture is enabled (Linux-only fields, surfaced for completeness).</summary>
    public bool EnableJournaldCapture { get; init; }

    /// <summary>True if the Linux auditd capture is enabled.</summary>
    public bool EnableAuditdCapture { get; init; }
}
