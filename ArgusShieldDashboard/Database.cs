using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Data.Sqlite;

namespace ArgusShieldDashboard
{ 
    public class EventDetection
    {
        public string Timestamp { get; set; } = "";
        public string Component { get; set; } = "";
        public string EventType { get; set; } = "";
        public int Pid { get; set; }
        public int TargetPid { get; set; }
        public string DllPath { get; set; } = "";
        public string Technique { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Action { get; set; } = "";
        public string Details { get; set; } = "";
    }

    public class DetectionStats
    {
        public int Total { get; set; }
        public int Blocked { get; set; }
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int Today { get; set; }
        public int DllInjection { get; set; }
        public int ManualMapping { get; set; }
        public int ProcessHollowing { get; set; }
    }

    public static class Database
    {
        private static string DbPath;
        private static string EventsLogPath;

        static Database()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var dbDir = Path.Combine(appData, "ArgusShield");
            Directory.CreateDirectory(dbDir);
            DbPath = Path.Combine(dbDir, "argusshield.db");

            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            EventsLogPath = Path.Combine(programData, "ArgusShield", "events.log");
        }

        private static SqliteConnection GetConnection()
        {
            var conn = new SqliteConnection($"Data Source={DbPath}");
            conn.Open();
            return conn;
        }

        public static void CreateDb()
        {
            try
            {
                using var conn = GetConnection();
                using var cmd = conn.CreateCommand();
                
                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS detections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        process_name TEXT,
                        pid INTEGER,
                        threat_level TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )";
                cmd.ExecuteNonQuery();

                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT
                    )";
                cmd.ExecuteNonQuery();

                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        component TEXT,
                        event_type TEXT,
                        pid INTEGER,
                        target_pid INTEGER,
                        dll_path TEXT,
                        technique TEXT,
                        severity TEXT,
                        action TEXT,
                        details TEXT,
                        raw_line TEXT UNIQUE
                    )";
                cmd.ExecuteNonQuery();

                EnsureSetting("installed", "0");
                EnsureSetting("last_event_offset", "0");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating db: {ex.Message}");
            }
        }

        private static void EnsureSetting(string key, string defaultValue)
        {
            if (GetSetting(key, null) == null)
            {
                SetSetting(key, defaultValue);
            }
        }

        public static bool GetInstallState()
        {
            return GetSetting("installed", "0") == "1";
        }

        public static void SetInstallState(bool state)
        {
            SetSetting("installed", state ? "1" : "0");
        }

        private static string? GetSetting(string key, string? defaultValue = "0")
        {
            try
            {
                using var conn = GetConnection();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT value FROM settings WHERE key = @key";
                cmd.Parameters.AddWithValue("@key", key);
                var result = cmd.ExecuteScalar();
                return result?.ToString() ?? defaultValue;
            }
            catch
            {
                return defaultValue;
            }
        }

        private static void SetSetting(string key, string value)
        {
            try
            {
                using var conn = GetConnection();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "INSERT OR REPLACE INTO settings (key, value) VALUES (@key, @value)";
                cmd.Parameters.AddWithValue("@key", key);
                cmd.Parameters.AddWithValue("@value", value);
                cmd.ExecuteNonQuery();
            }
            catch { }
        }

        public static int ImportEventsFromLog()
        {
            if (!File.Exists(EventsLogPath)) return 0;

            long offset = 0;
            if (long.TryParse(GetSetting("last_event_offset", "0"), out long parsed))
            {
                offset = parsed;
            }

            var newLines = new List<string>();
            long newOffset = offset;
            try
            {
                using var fs = new FileStream(EventsLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                if (offset > fs.Length) offset = 0; // File was truncated
                fs.Seek(offset, SeekOrigin.Begin);
                
                using var reader = new StreamReader(fs);
                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (!string.IsNullOrWhiteSpace(line))
                        newLines.Add(line);
                }
                newOffset = fs.Position;
            }
            catch
            {
                return 0;
            }

            if (newLines.Count == 0) return 0;

            int count = 0;
            try
            {
                using var conn = GetConnection();
                using var tx = conn.BeginTransaction();
                
                using var cmd = conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = @"
                    INSERT OR IGNORE INTO events
                    (timestamp, component, event_type, pid, target_pid, dll_path, technique, severity, action, details, raw_line)
                    VALUES (@t, @c, @e, @p, @tp, @d, @tech, @s, @a, @det, @raw)";
                
                // Add parameters once
                cmd.Parameters.Add("@t", SqliteType.Text);
                cmd.Parameters.Add("@c", SqliteType.Text);
                cmd.Parameters.Add("@e", SqliteType.Text);
                cmd.Parameters.Add("@p", SqliteType.Integer);
                cmd.Parameters.Add("@tp", SqliteType.Integer);
                cmd.Parameters.Add("@d", SqliteType.Text);
                cmd.Parameters.Add("@tech", SqliteType.Text);
                cmd.Parameters.Add("@s", SqliteType.Text);
                cmd.Parameters.Add("@a", SqliteType.Text);
                cmd.Parameters.Add("@det", SqliteType.Text);
                cmd.Parameters.Add("@raw", SqliteType.Text);

                foreach (var line in newLines)
                {
                    var parts = line.Split('|');
                    if (parts.Length < 10) continue;

                    cmd.Parameters["@t"].Value = parts[0];
                    cmd.Parameters["@c"].Value = parts[1];
                    cmd.Parameters["@e"].Value = parts[2];
                    
                    int.TryParse(parts[3], out int pid);
                    int.TryParse(parts[4], out int targetPid);
                    cmd.Parameters["@p"].Value = pid;
                    cmd.Parameters["@tp"].Value = targetPid;
                    
                    cmd.Parameters["@d"].Value = parts[5];
                    cmd.Parameters["@tech"].Value = parts[6];
                    cmd.Parameters["@s"].Value = parts[7];
                    cmd.Parameters["@a"].Value = parts[8];
                    cmd.Parameters["@det"].Value = parts[9];
                    cmd.Parameters["@raw"].Value = line;

                    if (cmd.ExecuteNonQuery() > 0)
                    {
                        count++;
                    }
                }

                tx.Commit();
                SetSetting("last_event_offset", newOffset.ToString());
            }
            catch
            {
                return 0;
            }

            return count;
        }

        public static List<EventDetection> GetRecentDetections(int limit = 20)
        {
            var list = new List<EventDetection>();
            try
            {
                using var conn = GetConnection();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    SELECT timestamp, component, event_type, pid, target_pid,
                           dll_path, technique, severity, action, details
                    FROM events
                    ORDER BY id DESC LIMIT @limit";
                cmd.Parameters.AddWithValue("@limit", limit);
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    list.Add(new EventDetection
                    {
                        Timestamp = reader.GetString(0),
                        Component = reader.GetString(1),
                        EventType = reader.GetString(2),
                        Pid = reader.GetInt32(3),
                        TargetPid = reader.GetInt32(4),
                        DllPath = reader.GetString(5),
                        Technique = reader.GetString(6),
                        Severity = reader.GetString(7),
                        Action = reader.GetString(8),
                        Details = reader.GetString(9)
                    });
                }
            }
            catch { }
            return list;
        }

        public static DetectionStats GetDetectionStats()
        {
            var stats = new DetectionStats();
            try
            {
                using var conn = GetConnection();
                using var cmd = conn.CreateCommand();

                cmd.CommandText = "SELECT COUNT(*) FROM events";
                stats.Total = Convert.ToInt32(cmd.ExecuteScalar() ?? 0);

                cmd.CommandText = "SELECT COUNT(*) FROM events WHERE action = 'Blocked'";
                stats.Blocked = Convert.ToInt32(cmd.ExecuteScalar() ?? 0);

                cmd.CommandText = "SELECT COUNT(*) FROM events WHERE severity = 'Critical'";
                stats.Critical = Convert.ToInt32(cmd.ExecuteScalar() ?? 0);

                cmd.CommandText = "SELECT COUNT(*) FROM events WHERE severity = 'High'";
                stats.High = Convert.ToInt32(cmd.ExecuteScalar() ?? 0);

                cmd.CommandText = "SELECT COUNT(*) FROM events WHERE severity = 'Medium'";
                stats.Medium = Convert.ToInt32(cmd.ExecuteScalar() ?? 0);

                cmd.CommandText = "SELECT COUNT(*) FROM events WHERE severity = 'Low'";
                stats.Low = Convert.ToInt32(cmd.ExecuteScalar() ?? 0);

                cmd.CommandText = "SELECT COUNT(*) FROM events WHERE timestamp LIKE @today";
                cmd.Parameters.AddWithValue("@today", $"{DateTime.Today.ToString("yyyy-MM-dd")}%");
                stats.Today = Convert.ToInt32(cmd.ExecuteScalar() ?? 0);

                cmd.CommandText = "SELECT COUNT(*) FROM events WHERE technique = 'LoadLibrary'";
                stats.DllInjection = Convert.ToInt32(cmd.ExecuteScalar() ?? 0);

                cmd.CommandText = "SELECT COUNT(*) FROM events WHERE technique = 'ManualMapping'";
                stats.ManualMapping = Convert.ToInt32(cmd.ExecuteScalar() ?? 0);

                cmd.CommandText = "SELECT COUNT(*) FROM events WHERE technique = 'ProcessHollowing'";
                stats.ProcessHollowing = Convert.ToInt32(cmd.ExecuteScalar() ?? 0);
            }
            catch { }
            return stats;
        }
    }
}
