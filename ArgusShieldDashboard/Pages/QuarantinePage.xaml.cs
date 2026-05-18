using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace ArgusShieldDashboard.Pages
{
    public partial class QuarantinePage : System.Windows.Controls.UserControl
    {
        public QuarantinePage()
        {
            InitializeComponent();
        }

        public void RefreshData()
        {
            // Only show BLOCKED attacks in the quarantine page
            var entries = Database.GetBlockedDetections(200);
            
            int critical = 0, high = 0, medium = 0;
            
            foreach (var e in entries)
            {
                if (e.Severity == "Critical") critical++;
                else if (e.Severity == "High") high++;
                else if (e.Severity == "Medium") medium++;
            }

            TxtTotal.Text = entries.Count.ToString();
            TxtBlocked.Text = entries.Count.ToString(); // All entries here are blocked
            TxtCritical.Text = critical.ToString();
            TxtHigh.Text = high.ToString();
            TxtMedium.Text = medium.ToString();

            QuarantineGrid.ItemsSource = entries;
        }

        private void ExportCSV_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var entries = Database.GetRecentDetections(50);

                if (entries.Count == 0)
                {
                    System.Windows.MessageBox.Show("No events to export.", "Export CSV",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var dialog = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
                    DefaultExt = ".csv",
                    FileName = $"ArgusShield_Quarantine_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
                };

                if (dialog.ShowDialog() == true)
                {
                    var sb = new StringBuilder();

                    // Header row
                    sb.AppendLine("Timestamp,Component,Event Type,Source PID,Target PID,DLL / Source,Technique,Severity,Action,Details");

                    // Data rows
                    foreach (var entry in entries)
                    {
                        sb.AppendLine(string.Join(",",
                            EscapeCsvField(entry.Timestamp),
                            EscapeCsvField(entry.Component),
                            EscapeCsvField(entry.EventType),
                            entry.Pid.ToString(),
                            entry.TargetPid.ToString(),
                            EscapeCsvField(entry.DllPath),
                            EscapeCsvField(entry.Technique),
                            EscapeCsvField(entry.Severity),
                            EscapeCsvField(entry.Action),
                            EscapeCsvField(entry.Details)
                        ));
                    }

                    File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);

                    System.Windows.MessageBox.Show(
                        $"Successfully exported {entries.Count} events to:\n{dialog.FileName}",
                        "Export CSV", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(
                    $"Failed to export CSV:\n{ex.Message}",
                    "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static string EscapeCsvField(string field)
        {
            if (string.IsNullOrEmpty(field))
                return "\"\"";

            if (field.Contains(",") || field.Contains("\"") || field.Contains("\n") || field.Contains("\r"))
            {
                return "\"" + field.Replace("\"", "\"\"") + "\"";
            }

            return field;
        }
    }
}

