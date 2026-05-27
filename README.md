# ET Ducky Provider Explorer

A standalone Windows tool for enumerating, profiling, and learning about
**ETW providers** (Event Tracing for Windows). MIT-licensed, no telemetry,
no cloud dependency, no agent required at runtime.

Built on `Microsoft.Diagnostics.Tracing.TraceEvent`, the same library that
backs PerfView and several Microsoft diagnostic tools.

## What it does

Four tabs:

- **Providers** — every ETW provider registered on the host, with its GUID,
  keyword count, and severity-level count. Filterable by name or GUID.
- **Sniff** — subscribe to one provider for a bounded or continuous window
  and watch events stream in. Per-event breakdown by (Event ID, Task, Opcode)
  with a details panel that explains what each value means and shows
  decoded sample payloads.
- **Agent Diff** — load an `AgentConfig.json` and compare what the ET Ducky
  agent is subscribing to against what's available on the host.
- **Help** — built-in primer on ETW concepts: providers, sessions, event
  IDs, opcodes, levels, keywords, channels, kernel vs user-mode.

## Why it exists

Most ETW tooling (`logman query providers`, `wevtutil`, PerfView's provider
browser) is functional but does not explain itself. A user looking at
"Opcode 20" or "Event ID 7937" with no context gets no help from the
existing tools.

The Provider Explorer is built to be the opposite: every column has a
tooltip, every selected event gets an explanation pane, and the Help tab is
a printable primer on the protocol.

## Download

Pre-built signed Windows executables are published on the [Releases](../../releases)
page. Download the latest `ETDucky.ProviderExplorer.exe`, right-click,
**Properties**, **Unblock** (Windows mark-of-the-web), then run.

The app requires Administrator (UAC prompt on launch) because ETW provider
enumeration via TDH and session creation both require elevation.

## Build from source

Requirements:

- Windows 10 or later
- .NET 10 SDK
- Visual Studio 2026 or `dotnet` CLI

```powershell
git clone https://github.com/trucule/ETDucky.ProviderExplorer.git
cd ETDucky.ProviderExplorer
dotnet build -c Release
```

The build output drops in `bin\Release\net10.0-windows10.0.19041\win-x64\`.
The csproj's `CopyTraceEventNativeDLLs` target copies the native
`Microsoft.Diagnostics.Tracing.TraceEvent` DLLs into the output directory
automatically; kernel-provider sniffs depend on those.

To produce a single-file self-contained exe:

```powershell
dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true
```

## Use

### Providers tab

Every published ETW provider visible to the current process, sorted by name.
Type in the filter box to narrow by name or GUID substring. Click a row to
see the provider's manifest-declared keywords and severity levels in the
lower pane. **Sniff this provider →** sends the selection to the Sniff
tab.

### Sniff tab

Pick a provider (or arrive here from the Providers tab), set a duration,
hit **▶ Sniff**. The session subscribes with the broadest keyword mask
(`0xFFFFFFFFFFFFFFFF`) and Verbose level — answering the worst-case "what's
the maximum event volume this provider can produce" question.

The breakdown grid groups events by (Event ID, Task, Opcode) and shows the
count for each combination. Click any row to populate the details panel on
the right:

- Event ID and what it means in this provider's context
- Opcode value with a plain-language explanation (standard ETW opcodes
  0–10 use the protocol-defined names; values 11+ are provider-defined)
- Up to three decoded sample payloads showing the event's fields and
  values as TDH parsed them

**Continuous mode**: tick the checkbox to run until you click Cancel. The
details panel updates live as sample payloads arrive.

**Kernel-provider sniffs require that no other kernel ETW session is
running** — that includes the ET Ducky agent's own capture engine, PerfView,
xperf, or anyone else holding the kernel logger. Stop the conflicting
session first.

### Agent Diff tab

Loads `AgentConfig.json` (default:
`C:\ProgramData\ETDucky\Agent\AgentConfig.json`) and shows two side-by-side
panels:

- **ETDucky subscriptions** — every provider the agent has enabled, with
  resolution status. `✓` means the name (or GUID) resolves to a provider
  present on this host; `✗` means it doesn't.
- **Available providers not in config** — everything published on the host
  that the agent isn't currently capturing.

This tab is useful for ET Ducky users specifically, but it also serves as a
worked example of how to parse an ETW subscription config and reconcile it
against the host's published-provider inventory.

### Help tab

Built-in primer covering the ETW concepts the rest of the UI references:
provider, session, event ID, task, opcode (including the full standard
opcode table), level, keyword, channel, and the kernel vs user-mode
distinction. The same content the details panel pulls from.

## Architecture

```
ETDucky.ProviderExplorer/
├── MainForm.cs              WinForms UI, four tabs
├── Program.cs               Entry point
├── app.manifest             Requests Administrator elevation on launch
├── Models/
│   ├── ProviderInfo.cs      DTO: name, GUID, keywords, levels
│   └── SniffResult.cs       DTO: counts + decoded sample payloads
└── Services/
    ├── ProviderEnumerator.cs   Lists every published provider via TDH
    ├── ProviderSniffer.cs      Bounded/continuous subscribe + count + sample
    ├── AgentConfigReader.cs    Parses AgentConfig.json (raw JSON)
    └── EtwReference.cs         Built-in glossary of standard opcodes/levels
```

No external services. No telemetry. The app reads ETW manifests via the
local Windows TDH APIs, subscribes to providers via `TraceEventSession`, and
writes nothing to disk.

## Caveats

- Windows-only. ETW is a Windows subsystem; there is no Linux equivalent
  of this tool because eBPF and auditd have different surface area.
- Administrator required. The manifest requests elevation; if you launch
  without it, provider enumeration returns empty and every sniff fails
  with "Access denied".
- Kernel sniffs are mutually exclusive across the host. If the ET Ducky
  agent or any other tool holds the kernel logger, kernel-provider sniffs
  fail until the holder releases it.
- The sniffer enables every provider with the broadest keyword mask and
  Verbose level. Numbers it reports are worst-case ceilings, not what a
  production subscription with a narrow mask would see.

## Relationship to ET Ducky

ET Ducky (https://etducky.com) is a commercial cross-platform diagnostic
agent that uses ETW on Windows and eBPF on Linux. This tool is a focused
slice of that work: the provider catalog, the sniffer, and the
manifest-driven decoder, with the educational surface added on top.

The two repositories are independent. The agent uses a similar sniffer
internally for cost profiling; this tool is the user-facing equivalent.

## License

MIT. See [LICENSE](LICENSE).

## Contributing

Pull requests welcome. The codebase is small (one form, a few service
classes, no Designer files) so changes are easy to review. Behavioral
changes should add an entry to the README's Caveats section if they change
the contract the user sees on screen.
