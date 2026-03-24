using System;
using System.Diagnostics;
using System.IO;

namespace ArgusShieldDashboard
{
    public static class ServiceManager
    {
        private static string FindBinExe(string name)
        {
            var baseDir = AppContext.BaseDirectory;
            var candidates = new[]
            {
                Path.Combine(baseDir, name),
                Path.Combine(baseDir, "bin", name),
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "bin", name)),
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "ArgusShieldService", "x64", "Debug", name)),
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "ArgusShieldService", "x64", "Release", name)),
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "ArgusShieldAgent", "x64", "Debug", name)),
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "ArgusShieldAgent", "x64", "Release", name))
            };

            foreach (var path in candidates)
            {
                if (File.Exists(path)) return Path.GetFullPath(path);
            }
            return "";
        }

        private static (bool success, string output) RunCommand(string command)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                if (process == null) return (false, "Failed to start process");

                string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
                process.WaitForExit();

                return (process.ExitCode == 0, output.Trim());
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }

        public static (bool success, string message) InstallAll()
        {
            // 1. Install Service
            var svcPath = FindBinExe("ArgusShieldService.exe");
            if (string.IsNullOrEmpty(svcPath))
                return (false, "ArgusShieldService.exe not found.");

            var cmd = $"sc create ArgusShieldService binPath= \"{svcPath}\" start= auto DisplayName= \"ArgusShield Service\"";
            var (ok, outStr) = RunCommand(cmd);
            if (!ok && !outStr.ToUpper().Contains("SERVICE_EXISTS"))
                return (false, $"Failed to create service:\n{outStr}");

            var startRes = RunCommand("sc start ArgusShieldService");
            if (!startRes.success && !startRes.output.ToUpper().Contains("ALREADY_RUNNING"))
                return (false, $"Service created but failed to start:\n{startRes.output}");

            // 2. Install Agent
            var agentPath = FindBinExe("ArgusShieldAgent.exe");
            if (!string.IsNullOrEmpty(agentPath))
            {
                cmd = $"sc create ArgusShieldAgent binPath= \"{agentPath}\" start= auto depend= ArgusShieldService DisplayName= \"ArgusShield Agent\"";
                RunCommand(cmd);
                RunCommand("sc start ArgusShieldAgent");
            }

            // 3. Autostart Dashboard
            SetupDashboardAutostart();

            return (true, "");
        }

        public static (bool success, string message) UninstallAll()
        {
            RunCommand("sc stop ArgusShieldService");
            var delSvc = RunCommand("sc delete ArgusShieldService");
            if (!delSvc.success && !delSvc.output.ToUpper().Contains("SERVICE_DOES_NOT_EXIST"))
                return (false, $"Failed to delete service:\n{delSvc.output}");

            RunCommand("sc stop ArgusShieldAgent");
            RunCommand("sc delete ArgusShieldAgent");

            RemoveDashboardAutostart();

            return (true, "");
        }

        private static void SetupDashboardAutostart()
        {
            var exePath = Environment.ProcessPath;
            var cmd = $"schtasks /Create /F /TN \"ArgusShieldDashboard\" /TR \"\\\"{exePath}\\\"\" /SC ONLOGON /RL HIGHEST";
            RunCommand(cmd);
        }

        private static void RemoveDashboardAutostart()
        {
            RunCommand("schtasks /Delete /TN \"ArgusShieldDashboard\" /F");
        }
    }
}
