// =====================================================================================================
//  HVGuard.exe - self-contained launcher (thin stub; does NOT reimplement anything).
//  Embeds the whole script tree (launcher/ + defense/ + findings/hashes.csv) as a ZIP resource,
//  self-extracts it the first time to %LOCALAPPDATA%\HVGuard\<buildid>, and launches the already
//  validated PowerShell+WPF GUI (HVGuard.ps1). The .exe is asInvoker: elevation (and the degrade
//  to read-only if UAC is cancelled) is handled by HVGuard.ps1. 100% defensive: runs nothing from
//  the crack.
//
//  Compile with the .NET Framework csc (see tools/build-exe.ps1). Requires .NET Framework 4.x
//  (preinstalled on Win10/11). Nothing needs to be installed on the user's machine.
// =====================================================================================================
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("HVGuard")]
[assembly: AssemblyProduct("HVGuard")]
[assembly: AssemblyCompany("HVGuard")]
[assembly: AssemblyDescription("Defensive assistant against the hypervisor-based DRM bypass (blue team). Wraps the validated suite.")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

static class HVGuardLauncher
{
    // Injected by build-exe.ps1 (changes per compilation -> fresh extraction per build).
    const string BuildId = "__BUILDID__";
    const string ResourceName = "HVGuard.payload.zip";

    [DllImport("kernel32.dll")]
    static extern bool AttachConsole(int dwProcessId);

    [STAThread]
    static int Main(string[] args)
    {
        try
        {
            string root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "HVGuard", BuildId);
            string ready = Path.Combine(root, ".ready");

            if (!File.Exists(ready))
            {
                if (Directory.Exists(root)) { try { Directory.Delete(root, true); } catch { } }
                Directory.CreateDirectory(root);
                var asm = Assembly.GetExecutingAssembly();
                using (Stream s = asm.GetManifestResourceStream(ResourceName))
                {
                    if (s == null) throw new Exception("Embedded resource not found: " + ResourceName);
                    using (var zip = new ZipArchive(s, ZipArchiveMode.Read))
                        zip.ExtractToDirectory(root);
                }
                File.WriteAllText(ready, DateTime.UtcNow.ToString("o"));
            }

            string ps1 = Path.Combine(root, "launcher", "HVGuard.ps1");
            if (!File.Exists(ps1)) throw new Exception("HVGuard.ps1 not found at " + ps1);

            string host = FindHost();
            string passthrough = string.Join(" ", args.Select(Quote).ToArray());
            string psArgs = "-NoProfile -ExecutionPolicy Bypass -STA -File \"" + ps1 + "\" " + passthrough;

            bool selfTest = args.Any(a => string.Equals(a, "-SelfTest", StringComparison.OrdinalIgnoreCase));

            var psi = new ProcessStartInfo(host, psArgs)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = root
            };

            if (selfTest)
            {
                // Validation mode: waits for and forwards the child's output (to a file and, if there is a parent console, to it).
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                var p = Process.Start(psi);
                string outp = p.StandardOutput.ReadToEnd();
                string errp = p.StandardError.ReadToEnd();
                p.WaitForExit();
                try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "hvguard-selftest.out"), outp + errp); } catch { }
                try { AttachConsole(-1); Console.Out.Write(outp); if (!string.IsNullOrEmpty(errp)) Console.Error.Write(errp); Console.Out.Flush(); } catch { }
                return p.ExitCode;
            }
            else
            {
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(psi);
                return 0;
            }
        }
        catch (Exception ex)
        {
            try { System.Windows.Forms.MessageBox.Show("HVGuard could not start:\n" + ex.Message, "HVGuard"); }
            catch { }
            return 2;
        }
    }

    static string Quote(string a)
    {
        if (string.IsNullOrEmpty(a)) return "\"\"";
        if (a.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return a;
        return "\"" + a.Replace("\"", "\\\"") + "\"";
    }

    static string FindHost()
    {
        string pf = Environment.GetEnvironmentVariable("ProgramFiles");
        string[] cands =
        {
            pf == null ? null : Path.Combine(pf, "PowerShell", "7", "pwsh.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe")
        };
        foreach (var c in cands)
            if (c != null && File.Exists(c)) return c;
        return "powershell.exe";
    }
}
