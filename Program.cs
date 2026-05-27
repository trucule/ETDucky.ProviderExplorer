using System;
using System.Windows.Forms;

namespace ETDucky.ProviderExplorer;

/// <summary>
/// ETDucky Provider Explorer — a standalone WinForms tool for enumerating and
/// profiling Windows ETW providers. No AI, no cloud, no agent dependency at
/// runtime: just admin rights and a system with ETW.
///
/// Built on the same `Microsoft.Diagnostics.Tracing.TraceEvent` library that
/// powers ETDucky Desktop Diagnostics. See README.md for usage.
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
