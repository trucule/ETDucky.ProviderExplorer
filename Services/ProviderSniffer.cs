using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ETDucky.ProviderExplorer.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace ETDucky.ProviderExplorer.Services;

/// <summary>
/// Subscribes to a single ETW provider for a bounded window and counts the
/// events that arrive, grouped by (event id, task, opcode). This is the
/// measurement primitive behind per-provider cost profiling — the answer to
/// "if ETDucky enables provider X, what will it cost?"
///
/// Limitations of v1:
///   • Kernel provider sniffs require that no other kernel ETW session is
///     active on the host (the agent's own capture engine is one such
///     session — stop the agent service before sniffing kernel providers).
///   • Sniffs use the broadest keyword mask (<see cref="ulong.MaxValue"/>)
///     and Verbose level. The intent is to answer "what's the worst case?"
///     before the user narrows in real captures.
/// </summary>
public static class ProviderSniffer
{
    /// <summary>
    /// Maximum number of sample payloads retained per (EventId, Opcode, Task)
    /// group. Bounded so a high-volume provider does not exhaust memory; three
    /// is enough for the details panel to show "yes, the event carries field X"
    /// without keeping every payload around.
    /// </summary>
    private const int MaxSamplesPerKey = 3;

    /// <summary>
    /// Maximum number of payload fields decoded from any one event. TDH can
    /// expose dozens of fields on rich providers; the explorer's details panel
    /// only needs enough to characterise the event shape.
    /// </summary>
    private const int MaxPayloadFieldsPerSample = 32;

    /// <summary>
    /// Maximum rendered length for any one payload field's string value.
    /// Stops a single long string payload (e.g. a full PowerShell script
    /// block) from dominating the sample buffer.
    /// </summary>
    private const int MaxPayloadFieldValueChars = 512;

    /// <summary>
    /// Subscribe to <paramref name="providerGuid"/> for <paramref name="duration"/>
    /// and return the per-event-id histogram. The session is torn down before
    /// this method returns.
    ///
    /// <para>
    /// Continuous mode: pass <see cref="TimeSpan.MaxValue"/> for
    /// <paramref name="duration"/>. The sniff runs until the caller cancels;
    /// <c>WasIncomplete</c> stays false because cancellation IS the completion
    /// contract in this mode.
    /// </para>
    ///
    /// <para>
    /// Pass an <paramref name="progress"/> reporter to receive periodic
    /// snapshots of the running tally (each marked <c>IsLiveSnapshot=true</c>).
    /// Useful for watching events stream in during a continuous sniff. The
    /// final returned result is always <c>IsLiveSnapshot=false</c>.
    /// </para>
    /// </summary>
    public static async Task<SniffResult> SniffAsync(
        Guid providerGuid,
        string providerName,
        TimeSpan duration,
        CancellationToken ct = default,
        IProgress<SniffResult>? progress = null,
        TimeSpan? progressInterval = null)
    {
        var isContinuous = duration == TimeSpan.MaxValue;
        var reportEvery  = progressInterval ?? TimeSpan.FromSeconds(1);
        var startedAt = DateTime.UtcNow;
        var counts    = new ConcurrentDictionary<EventBreakdownKey, long>();
        var samples   = new ConcurrentDictionary<EventBreakdownKey, ConcurrentQueue<EventSample>>();
        var sessionName = $"ETDuckyExplorer_{Guid.NewGuid():N}".Substring(0, 32);

        TraceEventSession? session = null;
        try
        {
            // Stale leftover from a previous crashed run? Dispose first so the
            // bind doesn't race the kernel's accounting.
            try { TraceEventSession.GetActiveSession(sessionName)?.Dispose(); }
            catch { /* best effort */ }

            session = new TraceEventSession(sessionName) { StopOnDispose = true };

            // Kernel providers route through their own EnableKernelProvider API;
            // every other provider uses the generic EnableProvider call.
            if (providerGuid == KernelTraceEventParser.ProviderGuid)
            {
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.All);
            }
            else
            {
                session.EnableProvider(providerGuid, TraceEventLevel.Verbose, ulong.MaxValue);
            }

            // Single fan-in hook on the raw ETW source — fires for every event
            // regardless of whether the manifest parser recognises it. (Using
            // Dynamic.All here misses TraceLogging-style providers and any
            // event whose manifest isn't locally resolvable, which produced
            // false-negative "0 events" sniffs.)
            session.Source.AllEvents += data =>
            {
                var key = new EventBreakdownKey((int)data.ID, data.TaskName ?? "", data.OpcodeName ?? "");
                counts.AddOrUpdate(key, 1L, (_, prev) => prev + 1L);
                TryCaptureSample(samples, key, data);
            };

            // Source.Process() is synchronous — push it to a worker so we can
            // await the sniff duration on the calling context.
            var processTask = Task.Run(() =>
            {
                try { session.Source.Process(); }
                catch { /* session disposed / cancelled mid-process — expected */ }
            }, CancellationToken.None);

            bool wasIncomplete = false;
            var deadline = isContinuous ? DateTime.MaxValue : startedAt + duration;

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var now = DateTime.UtcNow;
                    if (now >= deadline) break;

                    var wait = reportEvery;
                    if (!isContinuous)
                    {
                        var remaining = deadline - now;
                        if (remaining < wait) wait = remaining;
                    }
                    if (wait <= TimeSpan.Zero) break;

                    await Task.Delay(wait, ct);

                    // Periodic snapshot — only if the caller asked for live
                    // updates. When progress is null this loop is functionally
                    // equivalent to the old single Task.Delay.
                    progress?.Report(BuildResult(
                        providerGuid, providerName, startedAt, counts, samples,
                        wasIncomplete: false, isContinuous, isLiveSnapshot: true));
                }
            }
            catch (OperationCanceledException)
            {
                // Bounded mode: cancel = early termination, surface as
                // incomplete. Continuous mode: cancel is the expected
                // end-of-life signal, so don't flag the result as incomplete.
                wasIncomplete = !isContinuous;
            }

            try { session.Source.StopProcessing(); }
            catch { /* race with dispose — fine */ }

            // Give the processing thread a moment to drain; cap so we don't
            // hang the UI on a stuck session.
            await Task.WhenAny(processTask, Task.Delay(TimeSpan.FromSeconds(2)));

            return BuildResult(
                providerGuid, providerName, startedAt, counts, samples,
                wasIncomplete, isContinuous, isLiveSnapshot: false);
        }
        catch (UnauthorizedAccessException ex)
        {
            return ErrorResult(providerGuid, providerName, startedAt,
                "Access denied. The Provider Explorer must run as Administrator.", ex);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("kernel session", StringComparison.OrdinalIgnoreCase)
                                                || ex.Message.Contains("NT Kernel Logger", StringComparison.OrdinalIgnoreCase))
        {
            return ErrorResult(providerGuid, providerName, startedAt,
                "A kernel ETW session is already active on this host (typically the ET Ducky agent). " +
                "Stop the agent service and try again, or pick a user-mode provider.", ex);
        }
        catch (Exception ex)
        {
            return ErrorResult(providerGuid, providerName, startedAt,
                $"Sniff failed: {ex.GetType().Name}: {ex.Message}", ex);
        }
        finally
        {
            try { session?.Dispose(); } catch { }
        }
    }

    /// <summary>
    /// Decode a few sample payloads per (EventId, Opcode, Task) group so the
    /// UI can show users what an actual event of that shape looks like. Bounded
    /// queue per group keeps the memory footprint small even on high-volume
    /// providers. Decoding failures swallow silently — the count side of the
    /// breakdown is still authoritative.
    /// </summary>
    private static void TryCaptureSample(
        ConcurrentDictionary<EventBreakdownKey, ConcurrentQueue<EventSample>> samples,
        EventBreakdownKey key,
        TraceEvent data)
    {
        try
        {
            var queue = samples.GetOrAdd(key, _ => new ConcurrentQueue<EventSample>());
            if (queue.Count >= MaxSamplesPerKey) return;

            var fields = new List<EventPayloadField>();
            var names  = data.PayloadNames ?? Array.Empty<string>();
            var fieldCount = Math.Min(names.Length, MaxPayloadFieldsPerSample);
            for (var i = 0; i < fieldCount; i++)
            {
                object? value;
                try { value = data.PayloadValue(i); }
                catch { value = "<decode failed>"; }

                var rendered = RenderValue(value);
                if (rendered.Length > MaxPayloadFieldValueChars)
                    rendered = rendered.Substring(0, MaxPayloadFieldValueChars) + "… (truncated)";

                fields.Add(new EventPayloadField(names[i] ?? $"field{i}", rendered));
            }

            string formatted;
            try { formatted = data.FormattedMessage ?? string.Empty; }
            catch { formatted = string.Empty; }

            // TraceEvent reuses the data buffer per callback — every field has
            // to be materialised to a string before we enqueue, or the sample
            // will reflect whatever event happens to arrive next.
            var sample = new EventSample(
                TimestampUtc:     data.TimeStamp.ToUniversalTime(),
                ProcessId:        data.ProcessID,
                ThreadId:         data.ThreadID,
                FormattedMessage: formatted,
                Payload:          fields);

            // Re-check under lock-style semantics: another thread may have
            // filled the queue between our count check and the enqueue.
            if (queue.Count < MaxSamplesPerKey)
                queue.Enqueue(sample);
        }
        catch
        {
            // Sampling is best-effort. Whatever went wrong, swallow it — the
            // counts side of the breakdown is the part users rely on.
        }
    }

    /// <summary>
    /// Convert a TDH-decoded payload value into a printable string. Byte
    /// arrays render as hex; primitives use their ToString(); everything else
    /// gets InvariantCulture formatting so the sample is locale-stable.
    /// </summary>
    private static string RenderValue(object? value)
    {
        if (value is null) return "<null>";
        if (value is byte[] bytes)
        {
            var len = Math.Min(bytes.Length, 64);
            var hex = BitConverter.ToString(bytes, 0, len).Replace('-', ' ');
            return bytes.Length > len ? $"{hex} … ({bytes.Length} bytes)" : hex;
        }
        if (value is IFormattable formattable)
            return formattable.ToString(null, System.Globalization.CultureInfo.InvariantCulture);
        return value.ToString() ?? "<null>";
    }

    private static SniffResult ErrorResult(Guid guid, string name, DateTime startedAt, string message, Exception _)
        => new()
        {
            ProviderGuid  = guid,
            ProviderName  = name,
            StartedAtUtc  = startedAt,
            Duration      = DateTime.UtcNow - startedAt,
            TotalEvents   = 0,
            Breakdown     = Array.Empty<EventBreakdown>(),
            Samples       = new Dictionary<EventBreakdownKey, IReadOnlyList<EventSample>>(),
            WasIncomplete = true,
            Error         = message,
        };

    /// <summary>
    /// Builds a SniffResult from the current counts dictionary. Called both
    /// during the run (live snapshots reported via IProgress) and once at the
    /// end (the final returned value). The dictionary is read with a
    /// concurrent snapshot — counts may continue ticking up after we read.
    /// </summary>
    private static SniffResult BuildResult(
        Guid guid, string name, DateTime startedAt,
        ConcurrentDictionary<EventBreakdownKey, long> counts,
        ConcurrentDictionary<EventBreakdownKey, ConcurrentQueue<EventSample>> samples,
        bool wasIncomplete, bool isContinuous, bool isLiveSnapshot)
    {
        var breakdown = counts
            .Select(kv => new EventBreakdown(kv.Key.EventId, kv.Key.TaskName, kv.Key.OpcodeName, kv.Value))
            .OrderByDescending(b => b.Count)
            .ToList();

        var sampleSnapshot = samples.ToDictionary(
            kv => kv.Key,
            kv => (IReadOnlyList<EventSample>)kv.Value.ToArray());

        return new SniffResult
        {
            ProviderGuid   = guid,
            ProviderName   = name,
            StartedAtUtc   = startedAt,
            Duration       = DateTime.UtcNow - startedAt,
            TotalEvents    = counts.Values.Sum(),
            Breakdown      = breakdown,
            Samples        = sampleSnapshot,
            WasIncomplete  = wasIncomplete,
            IsContinuous   = isContinuous,
            IsLiveSnapshot = isLiveSnapshot,
        };
    }
}
