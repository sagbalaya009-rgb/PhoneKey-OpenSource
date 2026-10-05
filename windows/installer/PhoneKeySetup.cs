using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;

// Small self-contained launcher. Installation logic stays in the auditable
// PowerShell source packaged as an embedded resource.
internal static class PhoneKeySetup
{
    private static bool IsAdministrator()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    private static int RunElevatedCopy()
    {
        ProcessStartInfo start = new ProcessStartInfo();
        start.FileName = Assembly.GetExecutingAssembly().Location;
        start.Arguments = "--elevated";
        start.UseShellExecute = true;
        start.Verb = "runas";
        using (Process process = Process.Start(start))
        {
            process.WaitForExit();
            return process.ExitCode;
        }
    }

    private static DirectorySecurity ProtectedDirectory()
    {
        DirectorySecurity security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    private static void ExtractPayload(string target)
    {
        using (Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("PhoneKey.Payload"))
        {
            if (resource == null) throw new InvalidDataException("PhoneKey setup payload is missing.");
            using (ZipArchive archive = new ZipArchive(resource, ZipArchiveMode.Read))
            {
                if (archive.Entries.Count > 12) throw new InvalidDataException("Too many PhoneKey setup entries.");
                long total = 0;
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string name = entry.FullName;
                    if (name.Length == 0 || name == "." || name == ".." ||
                        name.IndexOfAny(new char[] { '/', '\\', ':' }) >= 0)
                        throw new InvalidDataException("Unsafe PhoneKey setup entry.");
                    total += entry.Length;
                    if (entry.Length > 8000000 || total > 20000000)
                        throw new InvalidDataException("PhoneKey setup payload is too large.");
                    using (Stream input = entry.Open())
                    using (FileStream output = new FileStream(Path.Combine(target, name), FileMode.CreateNew))
                    {
                        input.CopyTo(output);
                    }
                }
            }
        }
        if (!File.Exists(Path.Combine(target, "Install-PhoneKeyPreview.ps1")))
            throw new InvalidDataException("PhoneKey setup script is missing.");
    }

    private static int RunInstaller(bool preflight)
    {
        string parent = preflight
            ? Path.Combine(Path.GetTempPath(), "PhoneKeyPreviewInstallerPreflight")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "PhoneKeyPreviewInstaller");
        Directory.CreateDirectory(parent);
        string stage = Path.Combine(parent, Guid.NewGuid().ToString("N"));
        if (preflight) Directory.CreateDirectory(stage);
        else Directory.CreateDirectory(stage, ProtectedDirectory());
        try
        {
            ExtractPayload(stage);
            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell\\v1.0\\powershell.exe");
            start.Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" +
                Path.Combine(stage, "Install-PhoneKeyPreview.ps1") + "\"" +
                (preflight ? " -PreflightOnly" : "");
            start.WorkingDirectory = stage;
            start.UseShellExecute = false;
            using (Process process = Process.Start(start))
            {
                process.WaitForExit();
                return process.ExitCode;
            }
        }
        finally
        {
            try
            {
                if (Directory.Exists(stage)) Directory.Delete(stage, true);
            }
            catch (IOException error)
            {
                Console.Error.WriteLine("PhoneKey temporary-file cleanup needs attention: " + error.Message);
            }
        }
    }

    private static int Main(string[] args)
    {
        bool preflight = args.Length == 1 && args[0] == "--preflight";
        bool elevated = args.Length == 1 && args[0] == "--elevated";
        if (args.Length > 0 && !preflight && !elevated)
        {
            Console.Error.WriteLine("Usage: PhoneKey-Windows-Setup-Preview.exe [--preflight]");
            return 2;
        }
        try
        {
            if (!preflight && !IsAdministrator()) return RunElevatedCopy();
            int result = RunInstaller(preflight);
            if (!preflight)
            {
                Console.WriteLine("Press Enter to close PhoneKey setup.");
                Console.ReadLine();
            }
            return result;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("PhoneKey setup failed: " + error.Message);
            if (!preflight)
            {
                Console.WriteLine("Press Enter to close PhoneKey setup.");
                Console.ReadLine();
            }
            return 1;
        }
    }
}
