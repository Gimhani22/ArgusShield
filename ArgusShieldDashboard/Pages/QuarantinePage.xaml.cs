using System.Collections.Generic;
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
            var entries = Database.GetRecentDetections(50);
            
            int critical = 0, high = 0, medium = 0, low = 0, blocked = 0;
            
            foreach (var e in entries)
            {
                if (e.Severity == "Critical") critical++;
                else if (e.Severity == "High") high++;
                else if (e.Severity == "Medium") medium++;
                else if (e.Severity == "Low") low++;

                if (e.Action == "Blocked") blocked++;
            }

            TxtTotal.Text = entries.Count.ToString();
            TxtBlocked.Text = blocked.ToString();
            TxtCritical.Text = critical.ToString();
            TxtHigh.Text = high.ToString();
            TxtMedium.Text = medium.ToString();

            QuarantineGrid.ItemsSource = entries;
        }

        private void ExportCSV_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.MessageBox.Show("Log exported to quarantine_log.csv (demo).", "Export", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
