using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using ETDucky.ProviderExplorer.Models;
using ETDucky.ProviderExplorer.Services;

namespace ETDucky.ProviderExplorer;

/// <summary>
/// Three-tab shell: browse providers, sniff one, diff against an AgentConfig.
/// All UI built in code (no Designer file) for diff-friendliness and so the
/// layout lives next to the logic that drives it.
/// </summary>
public sealed class MainForm : Form
{
    // ── Palette (mirror of the agent applets so the family feels coherent) ──
    private static readonly Color BgPage       = Color.FromArgb(18, 18, 24);
    private static readonly Color BgCard       = Color.FromArgb(30, 30, 42);
    private static readonly Color BgInput      = Color.FromArgb(26, 26, 38);
    private static readonly Color Accent       = Color.FromArgb(0, 180, 219);
    private static readonly Color Subtle       = Color.FromArgb(50, 50, 65);
    private static readonly Color TextPrimary  = Color.FromArgb(220, 220, 230);
    private static readonly Color TextMuted    = Color.FromArgb(120, 120, 140);
    private static readonly Color Border       = Color.FromArgb(40, 40, 55);
    private static readonly Color Success      = Color.FromArgb(34, 197, 94);
    private static readonly Color Warning      = Color.FromArgb(217, 140, 0);
    private static readonly Color Danger       = Color.FromArgb(239, 68, 68);

    // ── State ────────────────────────────────────────────────────────────────
    private List<ProviderInfo> _allProviders = new();
    private SniffResult?       _lastSniff;
    private AgentConfigSummary? _currentConfig;
    private CancellationTokenSource? _sniffCts;

    // ── Top-level controls ──────────────────────────────────────────────────
    private readonly TabControl _tabs;

    public MainForm()
    {
        Text            = "ET Ducky Provider Explorer";
        ClientSize      = new Size(1200, 720);
        MinimumSize     = new Size(900, 560);
        StartPosition   = FormStartPosition.CenterScreen;
        BackColor       = BgPage;
        ForeColor       = TextPrimary;
        Font            = new Font("Segoe UI", 9f);

        _tabs = new TabControl
        {
            Dock      = DockStyle.Fill,
            Appearance = TabAppearance.Normal,
            SizeMode  = TabSizeMode.Normal,
        };
        _tabs.TabPages.Add(BuildProvidersTab());
        _tabs.TabPages.Add(BuildSnifferTab());
        _tabs.TabPages.Add(BuildDiffTab());
        _tabs.TabPages.Add(BuildHelpTab());
        Controls.Add(_tabs);

        // Kick off provider enumeration on a background thread so the UI
        // is responsive immediately. Enumeration on a busy host can take
        // a second or two as TDH walks every manifest.
        Shown += async (_, _) => await RefreshProvidersAsync();
    }

    // =========================================================================
    // TAB 1 — PROVIDERS
    // =========================================================================

    private DataGridView? _providerGrid;
    private TextBox?      _providerFilter;
    private Label?        _providerStatus;
    private TextBox?      _providerDetail;
    private Button?       _btnSniffSelected;

    private TabPage BuildProvidersTab()
    {
        var page = new TabPage("Providers") { BackColor = BgPage };

        var root = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 1,
            RowCount    = 3,
            BackColor   = BgPage,
            Padding     = new Padding(8),
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        root.RowStyles.Add(new RowStyle(SizeType.Percent,  60));
        root.RowStyles.Add(new RowStyle(SizeType.Percent,  40));

        // ── Filter + status ──
        var top = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 4,
            RowCount    = 1,
            BackColor   = BgPage,
        };
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 60));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,  100));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 200));

        top.Controls.Add(new Label { Text = "Filter:", ForeColor = TextMuted, TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill }, 0, 0);
        _providerFilter = new TextBox
        {
            Dock        = DockStyle.Fill,
            BackColor   = BgInput,
            ForeColor   = TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "type to filter by name or GUID…",
        };
        _providerFilter.TextChanged += (_, _) => ApplyProviderFilter();
        top.Controls.Add(_providerFilter, 1, 0);

        var btnRefresh = NewButton("↻ Refresh");
        btnRefresh.Click += async (_, _) => await RefreshProvidersAsync();
        top.Controls.Add(btnRefresh, 2, 0);

        _providerStatus = new Label
        {
            Dock      = DockStyle.Fill,
            ForeColor = TextMuted,
            TextAlign = ContentAlignment.MiddleRight,
            Text      = "Loading…",
        };
        top.Controls.Add(_providerStatus, 3, 0);
        root.Controls.Add(top, 0, 0);

        // ── Provider grid ──
        _providerGrid = NewGrid();
        _providerGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Name",     DataPropertyName = "Name",          AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill, ToolTipText = "Friendly name as registered in the provider's manifest. The Help tab explains what a provider is." });
        _providerGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "GUID",     DataPropertyName = "GuidDisplay",   Width = 280, ToolTipText = "Canonical identifier for the provider. ETW sessions subscribe by GUID; the friendly name is convenience metadata only." });
        _providerGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Keywords", DataPropertyName = "KeywordCount",  Width = 80, ToolTipText = "Number of keyword bits the provider declares in its manifest. Keywords are how subscribers filter which subsets of the provider's events they receive." });
        _providerGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Levels",   DataPropertyName = "LevelCount",    Width = 80, ToolTipText = "Number of severity levels available (always 5 standard levels: Critical, Error, Warning, Informational, Verbose)." });
        _providerGrid.SelectionChanged += (_, _) => ShowProviderDetail();

        // Right-click → select the row under the cursor and show the context
        // menu. By default, DataGridView only selects on left-click, which is
        // confusing when the menu acts on "the selected row" — without this
        // handler, right-clicking row N while row M is selected would sniff M.
        _providerGrid.CellMouseDown += (_, e) =>
        {
            if (e.Button == MouseButtons.Right && e.RowIndex >= 0)
            {
                _providerGrid.ClearSelection();
                _providerGrid.Rows[e.RowIndex].Selected = true;
            }
        };

        // Double-click is the second easy way to launch a sniff — same effect
        // as the button below or the context menu item.
        _providerGrid.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex >= 0) SendSelectedToSniffer();
        };

        var providerContextMenu = new ContextMenuStrip
        {
            BackColor = BgCard,
            ForeColor = TextPrimary,
        };
        var miSniff = new ToolStripMenuItem("Sniff this provider");
        miSniff.Click += (_, _) => SendSelectedToSniffer();
        providerContextMenu.Items.Add(miSniff);
        _providerGrid.ContextMenuStrip = providerContextMenu;

        root.Controls.Add(_providerGrid, 0, 1);

        // ── Detail pane ──
        var detail = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 1,
            RowCount    = 2,
            BackColor   = BgCard,
        };
        detail.RowStyles.Add(new RowStyle(SizeType.Percent,  100));
        detail.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));

        _providerDetail = new TextBox
        {
            Dock        = DockStyle.Fill,
            Multiline   = true,
            ReadOnly    = true,
            ScrollBars  = ScrollBars.Vertical,
            BackColor   = BgCard,
            ForeColor   = TextPrimary,
            BorderStyle = BorderStyle.None,
            Font        = new Font("Consolas", 9f),
        };
        detail.Controls.Add(_providerDetail, 0, 0);

        var actions = new FlowLayoutPanel
        {
            Dock          = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            BackColor     = BgCard,
            Padding       = new Padding(8),
        };
        _btnSniffSelected = NewButton("Sniff this provider →", primary: true);
        _btnSniffSelected.Enabled = false;
        _btnSniffSelected.Click += (_, _) => SendSelectedToSniffer();
        actions.Controls.Add(_btnSniffSelected);
        detail.Controls.Add(actions, 0, 1);

        root.Controls.Add(detail, 0, 2);

        page.Controls.Add(root);
        return page;
    }

    private async Task RefreshProvidersAsync()
    {
        if (_providerStatus != null) _providerStatus.Text = "Enumerating…";
        var providers = await Task.Run(ProviderEnumerator.EnumerateAll);
        _allProviders = providers.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
        if (_providerStatus != null)
            _providerStatus.Text = $"{_allProviders.Count:N0} providers";
        ApplyProviderFilter();
    }

    private void ApplyProviderFilter()
    {
        if (_providerGrid == null) return;
        var filter = (_providerFilter?.Text ?? string.Empty).Trim();

        IEnumerable<ProviderInfo> visible = _allProviders;
        if (!string.IsNullOrEmpty(filter))
        {
            visible = _allProviders.Where(p =>
                p.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)
             || p.Guid.ToString().Contains(filter, StringComparison.OrdinalIgnoreCase));
        }

        var rows = visible
            .Select(p => new ProviderRowViewModel
            {
                Name          = p.Name,
                GuidDisplay   = p.Guid.ToString("B"),
                KeywordCount  = p.Keywords.Count,
                LevelCount    = p.Levels.Count,
                Source        = p,
            })
            .ToList();

        _providerGrid.DataSource = rows;
    }

    private void ShowProviderDetail()
    {
        if (_providerGrid == null || _providerDetail == null || _btnSniffSelected == null) return;
        var row = _providerGrid.SelectedRows.Cast<DataGridViewRow>().FirstOrDefault();
        if (row?.DataBoundItem is not ProviderRowViewModel vm)
        {
            _providerDetail.Clear();
            _btnSniffSelected.Enabled = false;
            return;
        }

        var p = vm.Source;
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Name      : {p.Name}");
        sb.AppendLine($"GUID      : {p.Guid:B}");
        sb.AppendLine();
        sb.AppendLine($"Keywords ({p.Keywords.Count}):");
        if (p.Keywords.Count == 0) sb.AppendLine("  (none declared in the manifest visible to this process)");
        foreach (var k in p.Keywords.OrderBy(k => k.Mask))
            sb.AppendLine($"  0x{k.Mask:X16}  {k.Name}");
        sb.AppendLine();
        sb.AppendLine($"Levels ({p.Levels.Count}):");
        if (p.Levels.Count == 0) sb.AppendLine("  (none declared)");
        foreach (var l in p.Levels.OrderBy(l => l.Value))
            sb.AppendLine($"  {l.Value}  {l.Name}");

        _providerDetail.Text = sb.ToString();
        _btnSniffSelected.Enabled = true;
    }

    private void SendSelectedToSniffer()
    {
        if (_providerGrid == null || _snifferGuidBox == null || _snifferNameLabel == null) return;
        var row = _providerGrid.SelectedRows.Cast<DataGridViewRow>().FirstOrDefault();
        if (row?.DataBoundItem is not ProviderRowViewModel vm) return;

        _snifferGuidBox.Text   = vm.Source.Guid.ToString("B");
        _snifferNameLabel.Text = vm.Source.Name;
        _tabs.SelectedIndex    = 1;
    }

    // =========================================================================
    // TAB 2 — SNIFFER
    // =========================================================================

    private TextBox?     _snifferGuidBox;
    private Label?       _snifferNameLabel;
    private NumericUpDown? _snifferDuration;
    private CheckBox?    _snifferContinuous;
    private Button?      _btnSniffStart;
    private Button?      _btnSniffCancel;
    private Label?       _snifferSummary;
    private DataGridView? _sniffGrid;
    private ProgressBar? _sniffProgress;
    private TextBox?     _sniffDetail;
    private Label?       _sniffDetailHeader;

    private TabPage BuildSnifferTab()
    {
        var page = new TabPage("Sniff") { BackColor = BgPage };

        var root = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 1,
            RowCount    = 4,
            BackColor   = BgPage,
            Padding     = new Padding(8),
        };
        // Heights are explicit so labels with multi-line/tall text don't get
        // clipped at the row boundary. The summary row in particular has to
        // accommodate the multi-line "no events captured" hint.
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 130));  // ctrl panel
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 6));    // progress
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 90));   // summary (multi-line tip when no events)
        root.RowStyles.Add(new RowStyle(SizeType.Percent,  100));  // breakdown grid

        // ── Control panel ──
        var ctrl = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 5,
            RowCount    = 3,
            BackColor   = BgCard,
            Padding     = new Padding(10),
        };
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,  100));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
        // Explicit row heights so text isn't decapitated. Without these the
        // three rows would split the panel's 130px evenly and ascenders
        // would clip into the row above.
        ctrl.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        ctrl.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        ctrl.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));

        ctrl.Controls.Add(NewMutedLabel("Provider:"), 0, 0);
        _snifferGuidBox = new TextBox
        {
            Dock        = DockStyle.Fill,
            BackColor   = BgInput,
            ForeColor   = TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font        = new Font("Consolas", 9f),
            PlaceholderText = "{GUID} — pick one from the Providers tab",
        };
        // When the user types or pastes a GUID directly, look it up against the
        // enumerated provider list and update the name label so they can see
        // they got the right one before they hit Sniff.
        _snifferGuidBox.TextChanged += (_, _) => ResolveTypedSniffGuid();
        ctrl.Controls.Add(_snifferGuidBox, 1, 0);

        ctrl.Controls.Add(NewMutedLabel("Duration:"), 2, 0);
        _snifferDuration = new NumericUpDown
        {
            Dock      = DockStyle.Fill,
            BackColor = BgInput,
            ForeColor = TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Minimum   = 1,
            Maximum   = 600,
            Value     = 10,
            Increment = 1,
        };
        ctrl.Controls.Add(_snifferDuration, 3, 0);

        _btnSniffStart = NewButton("▶  Sniff", primary: true);
        _btnSniffStart.Click += async (_, _) => await StartSniffAsync();
        ctrl.Controls.Add(_btnSniffStart, 4, 0);

        ctrl.Controls.Add(NewMutedLabel("Name:"), 0, 1);
        _snifferNameLabel = new Label
        {
            Dock      = DockStyle.Fill,
            ForeColor = TextPrimary,
            TextAlign = ContentAlignment.MiddleLeft,
            Text      = "(none selected)",
        };
        ctrl.SetColumnSpan(_snifferNameLabel, 2);
        ctrl.Controls.Add(_snifferNameLabel, 1, 1);

        // Continuous mode toggle. Sits visually beneath the Duration spinner
        // because it modifies that field's behaviour — when checked the
        // duration is ignored, the spinner greys out, and the sniff runs
        // until the user clicks Stop. Live snapshots of the breakdown grid
        // refresh once a second via IProgress<SniffResult>.
        _snifferContinuous = new CheckBox
        {
            Text      = "Continuous",
            Dock      = DockStyle.Fill,
            BackColor = BgCard,
            ForeColor = TextPrimary,
            TextAlign = ContentAlignment.MiddleLeft,
            FlatStyle = FlatStyle.Flat,
        };
        _snifferContinuous.CheckedChanged += (_, _) =>
        {
            if (_snifferDuration != null)
                _snifferDuration.Enabled = !_snifferContinuous.Checked;
        };
        ctrl.Controls.Add(_snifferContinuous, 3, 1);

        _btnSniffCancel = NewButton("✖  Cancel");
        _btnSniffCancel.Enabled = false;
        _btnSniffCancel.Click += (_, _) => _sniffCts?.Cancel();
        ctrl.Controls.Add(_btnSniffCancel, 4, 1);

        var hint = new Label
        {
            Dock      = DockStyle.Fill,
            ForeColor = TextMuted,
            Font      = new Font("Segoe UI", 8f),
            TextAlign = ContentAlignment.MiddleLeft,
            Text      = "v1 subscribes with the broadest keyword mask and Verbose level — a worst-case event-volume measurement.",
        };
        ctrl.SetColumnSpan(hint, 5);
        ctrl.Controls.Add(hint, 0, 2);

        root.Controls.Add(ctrl, 0, 0);

        // ── Progress bar ──
        _sniffProgress = new ProgressBar
        {
            Dock    = DockStyle.Fill,
            Style   = ProgressBarStyle.Marquee,
            Visible = false,
        };
        root.Controls.Add(_sniffProgress, 0, 1);

        // ── Summary ──
        // TopLeft so multi-line text (the no-events tip can wrap across
        // several lines at narrower widths) starts at the top of the row
        // instead of being vertically centred and clipped.
        _snifferSummary = new Label
        {
            Dock         = DockStyle.Fill,
            TextAlign    = ContentAlignment.TopLeft,
            ForeColor    = TextMuted,
            AutoEllipsis = false,
            Text         = "Run a sniff to populate the breakdown.",
        };
        root.Controls.Add(_snifferSummary, 0, 2);

        // ── Breakdown grid + details panel (split horizontally) ──
        // Left: same per-event breakdown table the v1 tool had.
        // Right: educational details panel that explains the selected row,
        // shows what its opcode means in the standard ETW protocol, and
        // surfaces sample decoded payloads so the user can see what the
        // event actually carries.
        _sniffGrid = NewGrid();
        // Name= is set in addition to DataPropertyName= so cells can be looked
        // up by string indexer (Cells["EventId"]) in RenderSelectedSniffDetail.
        // Without Name=, the column's Name property defaults to empty and the
        // string indexer throws.
        _sniffGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "EventId",  HeaderText = "Event ID", DataPropertyName = "EventId", Width = 100, ToolTipText = "Provider-assigned identifier for this specific message. Scoped to the provider — the same number on a different provider means something different." });
        _sniffGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "TaskName", HeaderText = "Task",     DataPropertyName = "TaskName", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill, ToolTipText = "Provider-defined category for the event. Often the subsystem or function area inside the provider (e.g. 'Process', 'Disk')." });
        _sniffGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Opcode",   HeaderText = "Opcode",   DataPropertyName = "Opcode",   Width = 200, ToolTipText = "What kind of point in time this event represents. Standard values (Start, Stop, Info, etc.) come from the ETW protocol; values 11+ are provider-defined." });
        _sniffGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Count",    HeaderText = "Count",    DataPropertyName = "Count",    Width = 120, ToolTipText = "Number of times this exact (Event ID, Task, Opcode) combination fired during the sniff window." });

        _sniffGrid.SelectionChanged += (_, _) => RenderSelectedSniffDetail();

        var split = new SplitContainer
        {
            Dock              = DockStyle.Fill,
            Orientation       = Orientation.Vertical,
            BackColor         = BgPage,
            SplitterWidth     = 6,
            FixedPanel        = FixedPanel.Panel2,
        };
        split.Panel1.Controls.Add(_sniffGrid);

        // Right-side detail panel: header + scrollable text.
        var detailPanel = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 1,
            RowCount    = 2,
            BackColor   = BgCard,
        };
        detailPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        detailPanel.RowStyles.Add(new RowStyle(SizeType.Percent,  100));

        _sniffDetailHeader = new Label
        {
            Dock      = DockStyle.Fill,
            ForeColor = TextMuted,
            Font      = new Font("Segoe UI", 8f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            Padding   = new Padding(10, 0, 8, 0),
            Text      = "EVENT DETAILS",
        };
        detailPanel.Controls.Add(_sniffDetailHeader, 0, 0);

        _sniffDetail = new TextBox
        {
            Dock        = DockStyle.Fill,
            Multiline   = true,
            ReadOnly    = true,
            ScrollBars  = ScrollBars.Vertical,
            BackColor   = BgCard,
            ForeColor   = TextPrimary,
            BorderStyle = BorderStyle.None,
            Font        = new Font("Consolas", 9f),
            Text        = "Select a row in the breakdown grid to see what the event ID, opcode, and sampled payloads mean.",
            WordWrap    = true,
        };
        detailPanel.Controls.Add(_sniffDetail, 0, 1);
        split.Panel2.Controls.Add(detailPanel);

        root.Controls.Add(split, 0, 3);

        // SplitterDistance can only be set once the container has a size,
        // which happens after the layout pass runs. Defer to HandleCreated.
        split.HandleCreated += (_, _) =>
        {
            try { split.SplitterDistance = Math.Max(400, split.Width - 420); }
            catch { /* tolerate edge cases where the size hasn't settled */ }
        };

        page.Controls.Add(root);
        return page;
    }

    /// <summary>
    /// Render the educational details panel for whichever row in the
    /// breakdown grid is currently selected. Pulls the per-event sample
    /// payloads from the last sniff result and explains opcode semantics
    /// from <see cref="EtwReference"/>.
    /// </summary>
    private void RenderSelectedSniffDetail()
    {
        if (_sniffDetail == null || _sniffGrid == null) return;
        var row = _sniffGrid.SelectedRows.Cast<DataGridViewRow>().FirstOrDefault();
        if (row?.DataBoundItem is null || _lastSniff is null)
        {
            _sniffDetail.Text = "Select a row in the breakdown grid to see what the event ID, opcode, and sampled payloads mean.";
            return;
        }

        // The grid is bound to anonymous-object rows; read the columns by name.
        int eventId   = (int)(row.Cells["EventId"].Value ?? 0);
        string task   = row.Cells["TaskName"].Value?.ToString() ?? "";
        string opcode = row.Cells["Opcode"].Value?.ToString() ?? "";
        long count    = Convert.ToInt64(row.Cells["Count"].Value ?? 0L);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Provider : {_lastSniff.ProviderName}");
        sb.AppendLine($"Event ID : {eventId}");
        sb.AppendLine($"Task     : {(string.IsNullOrEmpty(task) ? "(none declared by the provider)" : task)}");
        sb.AppendLine($"Opcode   : {(string.IsNullOrEmpty(opcode) ? "(none declared)" : opcode)}");
        sb.AppendLine($"Count    : {count:N0} over {_lastSniff.Duration.TotalSeconds:0.0}s ({(count / Math.Max(_lastSniff.Duration.TotalSeconds, 0.001)):N1}/s)");
        sb.AppendLine();

        // Event ID explanation — generic but factual, since the meaning of an
        // event ID is provider-defined.
        sb.AppendLine("EVENT ID");
        sb.AppendLine(WordWrap(EtwReference.ExplainEventId(eventId, _lastSniff.ProviderName), 80));
        sb.AppendLine();

        // Opcode explanation — look up against the standard table first, fall
        // back to a "provider-defined" note for values outside 0–10.
        sb.AppendLine("OPCODE");
        var opcodeNum = EtwReference.TryParseOpcodeValue(opcode);
        OpcodeEntry? opcodeEntry = null;
        if (opcodeNum.HasValue) opcodeEntry = EtwReference.LookupOpcode(opcodeNum.Value);
        if (opcodeEntry is null) opcodeEntry = EtwReference.LookupOpcodeByName(opcode);

        if (opcodeEntry != null)
        {
            sb.AppendLine($"{opcodeEntry.Name} — standard ETW opcode.");
            sb.AppendLine(WordWrap(opcodeEntry.Description, 80));
        }
        else if (opcodeNum.HasValue)
        {
            sb.AppendLine($"Value {opcodeNum.Value} — provider-defined opcode.");
            sb.AppendLine("Standard ETW reserves values 0–10 for protocol opcodes (Info, Start, Stop, DCStart, DCStop, Extension, Reply, Resume, Suspend, Send, Receive). Values 11 and above are defined by the provider in its own manifest; the friendly name (when present) appears above next to 'Opcode'.");
        }
        else
        {
            sb.AppendLine("Opcode value not reported by the parser.");
        }
        sb.AppendLine();

        // Sample payloads — show up to MaxSamplesPerKey decoded events. The
        // sampling cap is in ProviderSniffer; this code just renders whatever
        // arrived.
        sb.AppendLine("SAMPLES");
        var key = new EventBreakdownKey(eventId, task, opcode);
        if (_lastSniff.Samples.TryGetValue(key, out var samples) && samples.Count > 0)
        {
            sb.AppendLine($"{samples.Count} decoded sample(s) of this event captured during the sniff:");
            sb.AppendLine();
            for (var i = 0; i < samples.Count; i++)
            {
                var s = samples[i];
                sb.AppendLine($"── Sample {i + 1} ──");
                sb.AppendLine($"timestamp : {s.TimestampUtc:yyyy-MM-dd HH:mm:ss.fff} UTC");
                sb.AppendLine($"process   : PID {s.ProcessId}, TID {s.ThreadId}");

                if (!string.IsNullOrWhiteSpace(s.FormattedMessage))
                {
                    sb.AppendLine();
                    sb.AppendLine("message:");
                    sb.AppendLine(WordWrap(s.FormattedMessage, 78, indent: "  "));
                }

                if (s.Payload.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("payload fields:");
                    foreach (var field in s.Payload)
                        sb.AppendLine($"  {field.Name} = {field.Value}");
                }
                else
                {
                    sb.AppendLine();
                    sb.AppendLine("payload: (no fields decoded by TDH)");
                }
                sb.AppendLine();
            }
        }
        else
        {
            sb.AppendLine("No decoded samples available for this event.");
            sb.AppendLine();
            sb.AppendLine("Sampling is bounded — the sniffer keeps up to 3 decoded events per (Event ID, Opcode, Task) combination. High-volume events may have all their slots filled before this row's first event arrived in a continuous sniff; bounded sniffs fill samples in arrival order.");
        }

        _sniffDetail.Text = sb.ToString();
        if (_sniffDetailHeader != null)
            _sniffDetailHeader.Text = $"EVENT DETAILS  ·  ID {eventId} · {(string.IsNullOrEmpty(opcode) ? "no opcode" : opcode)}";
    }

    /// <summary>
    /// Simple word-wrap for the details panel. The TextBox does its own
    /// wrapping at the control boundary, but pre-wrapping at a fixed column
    /// keeps the educational paragraphs readable regardless of split width.
    /// </summary>
    private static string WordWrap(string text, int width, string indent = "")
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        var words = text.Split(' ');
        var sb = new System.Text.StringBuilder();
        var lineLen = 0;
        sb.Append(indent);
        foreach (var word in words)
        {
            if (lineLen > 0 && lineLen + word.Length + 1 > width)
            {
                sb.AppendLine();
                sb.Append(indent);
                lineLen = 0;
            }
            if (lineLen > 0) { sb.Append(' '); lineLen++; }
            sb.Append(word);
            lineLen += word.Length;
        }
        return sb.ToString();
    }

    private async Task StartSniffAsync()
    {
        if (_snifferGuidBox == null || _snifferDuration == null) return;

        var guidText = _snifferGuidBox.Text.Trim().Trim('{', '}');
        if (!Guid.TryParse(guidText, out var guid))
        {
            MessageBox.Show(this,
                "That doesn't parse as a GUID. Pick a provider on the Providers tab and click 'Sniff this provider →'.",
                "Provider Explorer", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var name         = _snifferNameLabel?.Text ?? guid.ToString("B");
        var isContinuous = _snifferContinuous?.Checked == true;
        var duration     = isContinuous
            ? TimeSpan.MaxValue
            : TimeSpan.FromSeconds((double)_snifferDuration.Value);

        _sniffCts?.Dispose();
        _sniffCts = new CancellationTokenSource();

        SetSniffRunning(true);
        if (_snifferSummary != null)
        {
            _snifferSummary.Text = isContinuous
                ? $"Live · {name}  —  starting…  (click Cancel to stop)"
                : $"Sniffing {name} for {duration.TotalSeconds:0}s…";
        }

        // Progress<T> captures the current SynchronizationContext (the UI
        // thread when invoked here), so RenderSniffResult is marshalled back
        // onto the UI thread automatically. Used only in continuous mode;
        // bounded mode keeps the historical one-shot pattern.
        // _lastSniff is updated inside the progress callback as well so the
        // details panel can look up sample payloads against the latest
        // snapshot while the sniff is still streaming.
        IProgress<SniffResult>? progress = isContinuous
            ? new Progress<SniffResult>(snap => { _lastSniff = snap; RenderSniffResult(snap); })
            : null;

        try
        {
            var result = await ProviderSniffer.SniffAsync(
                guid, name, duration, _sniffCts.Token, progress);
            _lastSniff = result;
            RenderSniffResult(result);
        }
        finally
        {
            SetSniffRunning(false);
        }
    }

    private void SetSniffRunning(bool running)
    {
        if (_btnSniffStart  != null) _btnSniffStart.Enabled  = !running;
        if (_btnSniffCancel != null) _btnSniffCancel.Enabled = running;
        if (_sniffProgress  != null) _sniffProgress.Visible  = running;
    }

    private void RenderSniffResult(SniffResult result)
    {
        if (_snifferSummary == null || _sniffGrid == null) return;

        if (!string.IsNullOrEmpty(result.Error))
        {
            _snifferSummary.ForeColor = Danger;
            _snifferSummary.Text = result.Error;
            _sniffGrid.DataSource = null;
            return;
        }

        // Mode prefix communicates the contract: "Live · " while a continuous
        // sniff is still streaming, "Stopped · " once the user clicks Cancel,
        // empty for bounded sniffs (their duration is in the rest of the text).
        var modePrefix = result.IsContinuous
            ? (result.IsLiveSnapshot ? "Live · " : "Stopped · ")
            : "";

        // Zero-event case is almost always "no associated activity happened
        // during the sniff window" rather than a bug. Spell that out so users
        // don't get stuck thinking the tool is broken.
        if (result.TotalEvents == 0)
        {
            _snifferSummary.ForeColor = TextMuted;
            _snifferSummary.Text = result.IsContinuous && result.IsLiveSnapshot
                ? $"{modePrefix}{result.ProviderName}  —  no events yet (running for {result.Duration.TotalSeconds:0}s). "
                + "Most providers only emit while their associated activity runs — try generating activity."
                : $"{modePrefix}{result.ProviderName}  —  0 events over {result.Duration.TotalSeconds:0.0}s. "
                + "Most providers only emit while their associated activity runs "
                + "(e.g. Microsoft-Windows-PowerShell only emits when powershell.exe is actually executing). "
                + "Try generating activity for this provider and re-sniffing, or pick a busier one like "
                + "Microsoft-Windows-WMI-Activity or Microsoft-Windows-Kernel-PnP."
                + (result.WasIncomplete ? "  ·  cancelled" : "");
            _sniffGrid.DataSource = null;
            return;
        }

        _snifferSummary.ForeColor = Success;
        _snifferSummary.Text =
            $"{modePrefix}{result.ProviderName}  —  {result.TotalEvents:N0} events over {result.Duration.TotalSeconds:0.0}s "
          + $"({result.EventsPerSecond:N1}/s) · {result.Breakdown.Count} distinct event types"
          + (result.WasIncomplete ? "  ·  cancelled" : "");

        var rows = result.Breakdown.Select(b => new
        {
            b.EventId,
            b.TaskName,
            Opcode = b.Opcode,
            b.Count,
        }).ToList();
        _sniffGrid.DataSource = rows;

        // Live snapshots arrive every second during continuous mode; the
        // selected row may now have new sample data. Re-render the details
        // panel against the latest snapshot so users watching a streaming
        // sniff see decoded payloads as they show up.
        RenderSelectedSniffDetail();
    }

    /// <summary>
    /// Called whenever the user types or pastes into the sniffer GUID box —
    /// resolves the GUID against the enumerated provider list and refreshes
    /// the friendly-name label so the user can confirm they have the right
    /// provider before kicking off a sniff.
    /// </summary>
    private void ResolveTypedSniffGuid()
    {
        if (_snifferGuidBox == null || _snifferNameLabel == null) return;
        var text = _snifferGuidBox.Text.Trim().Trim('{', '}');
        if (string.IsNullOrEmpty(text))
        {
            _snifferNameLabel.Text = "(none selected)";
            return;
        }
        if (!Guid.TryParse(text, out var guid))
        {
            _snifferNameLabel.Text = "(not a valid GUID yet)";
            return;
        }
        var match = _allProviders.FirstOrDefault(p => p.Guid == guid);
        _snifferNameLabel.Text = match?.Name ?? "(unknown — not enumerated on this host)";
    }

    // =========================================================================
    // TAB 3 — AGENT CONFIG DIFF
    // =========================================================================

    private TextBox?      _diffPath;
    private Label?        _diffStatus;
    private DataGridView? _diffSubscribedGrid;
    private DataGridView? _diffAvailableGrid;

    private TabPage BuildDiffTab()
    {
        var page = new TabPage("Agent Diff") { BackColor = BgPage };

        var root = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 1,
            RowCount    = 3,
            BackColor   = BgPage,
            Padding     = new Padding(8),
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        root.RowStyles.Add(new RowStyle(SizeType.Percent,  100));

        // ── Path picker ──
        var pathPanel = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 4,
            RowCount    = 2,
            BackColor   = BgCard,
            Padding     = new Padding(10),
        };
        pathPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
        pathPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,  100));
        pathPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
        pathPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));

        pathPanel.Controls.Add(NewMutedLabel("Config:"), 0, 0);
        _diffPath = new TextBox
        {
            Dock        = DockStyle.Fill,
            BackColor   = BgInput,
            ForeColor   = TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Text        = AgentConfigReader.DefaultProductionPath,
        };
        pathPanel.Controls.Add(_diffPath, 1, 0);

        var btnBrowse = NewButton("Browse…");
        btnBrowse.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog
            {
                Title  = "Select AgentConfig.json",
                Filter = "AgentConfig.json|AgentConfig.json|JSON files (*.json)|*.json|All files (*.*)|*.*",
                InitialDirectory = System.IO.Path.GetDirectoryName(_diffPath.Text) ?? @"C:\ProgramData\ETDucky\Agent",
            };
            if (dlg.ShowDialog(this) == DialogResult.OK) _diffPath.Text = dlg.FileName;
        };
        pathPanel.Controls.Add(btnBrowse, 2, 0);

        var btnLoad = NewButton("Load", primary: true);
        btnLoad.Click += (_, _) => LoadAgentConfig();
        pathPanel.Controls.Add(btnLoad, 3, 0);

        var pathHint = new Label
        {
            Dock      = DockStyle.Fill,
            ForeColor = TextMuted,
            Font      = new Font("Segoe UI", 8f),
            TextAlign = ContentAlignment.MiddleLeft,
            Text      = "Defaults to the production install path. The file is mode 0600 on Linux and ACL-restricted on Windows — admin elevation may be required.",
        };
        pathPanel.SetColumnSpan(pathHint, 4);
        pathPanel.Controls.Add(pathHint, 0, 1);

        root.Controls.Add(pathPanel, 0, 0);

        // ── Status ──
        _diffStatus = new Label
        {
            Dock      = DockStyle.Fill,
            ForeColor = TextMuted,
            TextAlign = ContentAlignment.MiddleLeft,
            Text      = "Load an AgentConfig.json to see which providers the ET Ducky agent has enabled.",
        };
        root.Controls.Add(_diffStatus, 0, 1);

        // ── Two grids side by side ──
        var grids = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 2,
            RowCount    = 1,
            BackColor   = BgPage,
        };
        grids.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        grids.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

        _diffSubscribedGrid = NewGrid();
        _diffSubscribedGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Subscribed by ETDucky", DataPropertyName = "Name",    AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _diffSubscribedGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Type",                  DataPropertyName = "Kind",    Width = 90 });
        _diffSubscribedGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Status",                DataPropertyName = "Status",  Width = 140 });
        grids.Controls.Add(WrapWithHeader("ETDucky subscriptions", _diffSubscribedGrid), 0, 0);

        _diffAvailableGrid = NewGrid();
        _diffAvailableGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Available but NOT subscribed", DataPropertyName = "Name", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _diffAvailableGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "GUID",                          DataPropertyName = "Guid", Width = 280 });
        grids.Controls.Add(WrapWithHeader("Available providers not in config", _diffAvailableGrid), 1, 0);

        root.Controls.Add(grids, 0, 2);

        page.Controls.Add(root);
        return page;
    }

    private void LoadAgentConfig()
    {
        if (_diffPath == null || _diffStatus == null) return;

        var summary = AgentConfigReader.TryRead(_diffPath.Text.Trim());
        if (summary is null)
        {
            _currentConfig = null;
            _diffStatus.ForeColor = Danger;
            _diffStatus.Text = "Could not read config (file missing, malformed, or access denied).";
            if (_diffSubscribedGrid != null) _diffSubscribedGrid.DataSource = null;
            if (_diffAvailableGrid  != null) _diffAvailableGrid.DataSource  = null;
            return;
        }

        _currentConfig = summary;
        _diffStatus.ForeColor = TextMuted;
        _diffStatus.Text =
            $"Loaded {_currentConfig.Path}  ·  "
          + $"{summary.KernelProviders.Count} kernel keyword(s), "
          + $"{summary.UserModeProviders.Count} user-mode provider(s)";

        RenderDiff();
    }

    private void RenderDiff()
    {
        if (_currentConfig == null || _diffSubscribedGrid == null || _diffAvailableGrid == null) return;

        // Subscribed side: every entry from the config, with resolution status.
        var availableByName = _allProviders.ToDictionary(p => p.Name, p => p, StringComparer.OrdinalIgnoreCase);
        var availableByGuid = _allProviders.ToDictionary(p => p.Guid, p => p);

        var subscribed = new List<object>();
        foreach (var name in _currentConfig.KernelProviders)
        {
            subscribed.Add(new
            {
                Name   = name,
                Kind   = "kernel",
                Status = "kernel keyword",
            });
        }
        foreach (var entry in _currentConfig.UserModeProviders)
        {
            var resolved = ResolveProviderEntry(entry, availableByName, availableByGuid);
            subscribed.Add(new
            {
                Name   = entry,
                Kind   = "user-mode",
                Status = resolved is null ? "✗ not found on this host" : $"✓ {resolved.Name}",
            });
        }
        _diffSubscribedGrid.DataSource = subscribed;

        // Available side: providers present on the host but NOT in config.
        var subscribedGuids = new HashSet<Guid>();
        foreach (var entry in _currentConfig.UserModeProviders)
        {
            var resolved = ResolveProviderEntry(entry, availableByName, availableByGuid);
            if (resolved != null) subscribedGuids.Add(resolved.Guid);
        }

        var available = _allProviders
            .Where(p => !subscribedGuids.Contains(p.Guid))
            .Select(p => new { Name = p.Name, Guid = p.Guid.ToString("B") })
            .ToList<object>();
        _diffAvailableGrid.DataSource = available;
    }

    private static ProviderInfo? ResolveProviderEntry(
        string entry,
        IReadOnlyDictionary<string, ProviderInfo> byName,
        IReadOnlyDictionary<Guid, ProviderInfo> byGuid)
    {
        if (byName.TryGetValue(entry, out var byname)) return byname;
        if (Guid.TryParse(entry.Trim('{', '}'), out var guid) && byGuid.TryGetValue(guid, out var byguid))
            return byguid;
        return null;
    }

    // =========================================================================
    // TAB 4 — HELP
    // =========================================================================

    private TabPage BuildHelpTab()
    {
        var page = new TabPage("Help") { BackColor = BgPage };

        // Single scrollable text area. WinForms RichTextBox would let us use
        // bold headings, but Consolas plain text keeps the rendering
        // deterministic across themes and DPI scales. The content is the
        // tool's built-in primer on ETW — same concepts the details panel
        // references, gathered in one place.
        var textBox = new TextBox
        {
            Dock        = DockStyle.Fill,
            Multiline   = true,
            ReadOnly    = true,
            ScrollBars  = ScrollBars.Vertical,
            BackColor   = BgPage,
            ForeColor   = TextPrimary,
            BorderStyle = BorderStyle.None,
            Font        = new Font("Consolas", 9.5f),
            WordWrap    = true,
        };

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("ETW Concepts");
        sb.AppendLine("============");
        sb.AppendLine();
        sb.AppendLine("Event Tracing for Windows is a kernel-resident infrastructure for");
        sb.AppendLine("streaming structured events from publishers (drivers, services, the kernel");
        sb.AppendLine("itself, and any application that registers a manifest) to subscribing");
        sb.AppendLine("sessions. The Provider Explorer is one such subscriber.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Provider");
        sb.AppendLine("--------");
        sb.AppendLine("A named source of events. Identified by a GUID and a friendly name");
        sb.AppendLine("registered via a manifest. Examples on a typical Windows host include");
        sb.AppendLine("Microsoft-Windows-Kernel-Process, Microsoft-Windows-PowerShell, and");
        sb.AppendLine("Microsoft-Windows-WMI-Activity. Run the Providers tab to see every");
        sb.AppendLine("manifest-registered provider visible to the current process.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Session");
        sb.AppendLine("-------");
        sb.AppendLine("A subscription that receives events from one or more providers. Each");
        sb.AppendLine("session has a name and an in-kernel buffer. The Provider Explorer creates");
        sb.AppendLine("a transient session for every sniff, named 'ETDuckyExplorer_<random>',");
        sb.AppendLine("and tears it down when the sniff ends. Tools like logman, wpr, and");
        sb.AppendLine("PerfView all create their own sessions the same way.");
        sb.AppendLine();
        sb.AppendLine("Kernel providers have a hard constraint: only one session can subscribe");
        sb.AppendLine("to the kernel rundown providers at a time. If the ET Ducky agent (or any");
        sb.AppendLine("other tool) already holds the kernel session, a sniff against a kernel");
        sb.AppendLine("provider will fail until the other session releases it.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Event ID");
        sb.AppendLine("--------");
        sb.AppendLine("A provider-assigned integer that names a specific message inside that");
        sb.AppendLine("provider's manifest. Event IDs are scoped to a single provider — Event");
        sb.AppendLine("ID 5 on Microsoft-Windows-PowerShell means something entirely different");
        sb.AppendLine("from Event ID 5 on Microsoft-Windows-Kernel-Network. The provider's");
        sb.AppendLine("manifest is the authoritative source for what each ID represents.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Task");
        sb.AppendLine("----");
        sb.AppendLine("An optional provider-defined category. Tasks group related events inside");
        sb.AppendLine("a provider — for example, the file-I/O provider uses tasks like 'Create',");
        sb.AppendLine("'Read', and 'Write' so a single provider can emit events for several");
        sb.AppendLine("distinct operations without exploding the event-ID space.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Opcode");
        sb.AppendLine("------");
        sb.AppendLine("A small integer that says what kind of point in time the event represents.");
        sb.AppendLine("Values 0 through 10 are reserved by the ETW protocol and have the same");
        sb.AppendLine("meaning across every provider. Values 11 and above are provider-defined.");
        sb.AppendLine();
        sb.AppendLine("Standard opcodes:");
        foreach (var (value, entry) in EtwReference.EnumerateOpcodes())
        {
            sb.AppendLine();
            sb.AppendLine($"  {value,2}  {entry.Name}");
            sb.AppendLine(WordWrap(entry.Description, 76, indent: "      "));
        }
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Level");
        sb.AppendLine("-----");
        sb.AppendLine("Severity of the event. A subscriber requests a maximum level, and the");
        sb.AppendLine("provider only emits events at or below that level. The Provider Explorer");
        sb.AppendLine("sniffs at Verbose (level 5) to surface the worst-case event volume.");
        sb.AppendLine();
        sb.AppendLine("Standard levels:");
        foreach (var (value, entry) in EtwReference.EnumerateLevels())
        {
            sb.AppendLine();
            sb.AppendLine($"  {value}  {entry.Name}");
            sb.AppendLine(WordWrap(entry.Description, 76, indent: "     "));
        }
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Keyword");
        sb.AppendLine("-------");
        sb.AppendLine("A 64-bit bitmask the provider uses to categorise its events. A subscriber");
        sb.AppendLine("passes a keyword mask when enabling the provider; events whose own");
        sb.AppendLine("keyword bits don't overlap with the requested mask are dropped before");
        sb.AppendLine("delivery. The Provider Explorer enables every provider with");
        sb.AppendLine("0xFFFFFFFFFFFFFFFF (every bit set) so no events are filtered out — this");
        sb.AppendLine("answers the 'what's the maximum volume?' question rather than the");
        sb.AppendLine("typical-deployment question.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Channel");
        sb.AppendLine("-------");
        sb.AppendLine("Routing destination for events that also appear in the Windows Event Log.");
        sb.AppendLine("Most ETW providers do not set a channel; those that do use one of:");
        foreach (var (value, entry) in EtwReference.EnumerateChannels())
        {
            sb.AppendLine();
            sb.AppendLine($"  {value}  {entry.Name}");
            sb.AppendLine(WordWrap(entry.Description, 76, indent: "      "));
        }
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Kernel vs user-mode providers");
        sb.AppendLine("-----------------------------");
        sb.AppendLine("Kernel providers (process, thread, disk, network, registry, etc.) are");
        sb.AppendLine("routed through a dedicated kernel logger session and have system-wide");
        sb.AppendLine("constraints — historically only one consumer at a time. User-mode");
        sb.AppendLine("providers (everything else) are routed through ordinary ETW sessions");
        sb.AppendLine("and multiple consumers can subscribe to the same provider concurrently.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Why a sniff sometimes reports 0 events");
        sb.AppendLine("--------------------------------------");
        sb.AppendLine("Most providers only emit while their associated activity runs. The");
        sb.AppendLine("PowerShell provider stays silent unless powershell.exe is actually");
        sb.AppendLine("executing. The DNS-Client provider stays silent unless a DNS lookup");
        sb.AppendLine("happens during the window. A zero-count sniff is rarely a tool failure;");
        sb.AppendLine("it usually means the activity didn't happen. Use continuous mode and");
        sb.AppendLine("generate the activity manually to see events stream in live.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Where to read more");
        sb.AppendLine("------------------");
        sb.AppendLine("- Microsoft docs: 'About Event Tracing' on learn.microsoft.com");
        sb.AppendLine("- 'winmeta.xml' in the Windows SDK — the canonical schema for opcodes,");
        sb.AppendLine("  levels, channels, and task definitions");
        sb.AppendLine("- 'logman query providers' on any Windows host — the same provider list");
        sb.AppendLine("  this tool shows on the Providers tab, in a console");

        textBox.Text = sb.ToString();
        page.Controls.Add(textBox);
        return page;
    }

    // =========================================================================
    // SHARED UI HELPERS
    // =========================================================================

    private static Label NewMutedLabel(string text) => new()
    {
        Text      = text,
        ForeColor = TextMuted,
        TextAlign = ContentAlignment.MiddleLeft,
        Dock      = DockStyle.Fill,
    };

    private static Button NewButton(string text, bool primary = false)
    {
        var b = new Button
        {
            Text      = text,
            Dock      = DockStyle.Fill,
            Height    = 28,
            Margin    = new Padding(4),
            BackColor = primary ? Accent : Subtle,
            ForeColor = primary ? Color.White : TextPrimary,
            FlatStyle = FlatStyle.Flat,
            Font      = new Font("Segoe UI", 9f),
        };
        b.FlatAppearance.BorderSize = 0;
        return b;
    }

    private static DataGridView NewGrid() => new()
    {
        Dock                            = DockStyle.Fill,
        BackgroundColor                 = BgCard,
        GridColor                       = Border,
        BorderStyle                     = BorderStyle.None,
        RowHeadersVisible               = false,
        AutoGenerateColumns             = false,
        AllowUserToAddRows              = false,
        AllowUserToDeleteRows           = false,
        AllowUserToResizeRows           = false,
        ReadOnly                        = true,
        SelectionMode                   = DataGridViewSelectionMode.FullRowSelect,
        MultiSelect                     = false,
        EnableHeadersVisualStyles       = false,
        ColumnHeadersHeightSizeMode     = DataGridViewColumnHeadersHeightSizeMode.AutoSize,
        ColumnHeadersDefaultCellStyle   = new DataGridViewCellStyle
        {
            BackColor          = BgCard,
            ForeColor          = TextMuted,
            SelectionBackColor = BgCard,
            SelectionForeColor = TextMuted,
            Font               = new Font("Segoe UI", 8.5f, FontStyle.Bold),
            Alignment          = DataGridViewContentAlignment.MiddleLeft,
            Padding            = new Padding(8, 4, 4, 4),
        },
        DefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor          = BgPage,
            ForeColor          = TextPrimary,
            SelectionBackColor = Accent,
            SelectionForeColor = Color.White,
            Padding            = new Padding(8, 2, 4, 2),
        },
    };

    private static Control WrapWithHeader(string title, Control inner)
    {
        var panel = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 1,
            RowCount    = 2,
            BackColor   = BgPage,
            Margin      = new Padding(4),
        };
        panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent,  100));
        panel.Controls.Add(new Label
        {
            Text      = title.ToUpperInvariant(),
            Dock      = DockStyle.Fill,
            ForeColor = TextMuted,
            Font      = new Font("Segoe UI", 8f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            Padding   = new Padding(4, 0, 0, 0),
        }, 0, 0);
        panel.Controls.Add(inner, 0, 1);
        return panel;
    }

    private sealed class ProviderRowViewModel
    {
        public string Name         { get; set; } = string.Empty;
        public string GuidDisplay  { get; set; } = string.Empty;
        public int    KeywordCount { get; set; }
        public int    LevelCount   { get; set; }
        public required ProviderInfo Source { get; init; }
    }
}
