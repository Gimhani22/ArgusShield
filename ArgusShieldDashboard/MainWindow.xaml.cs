using System;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using System.Windows.Forms;
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;

namespace ArgusShieldDashboard
{
    public partial class MainWindow : Window
    {
        private Pages.DashboardPage _dashboardPage;
        private Pages.QuarantinePage _quarantinePage;
        private Pages.AboutPage _aboutPage;

        private PipeListener _pipeListener;
        private DispatcherTimer _refreshTimer;
        private NotifyIcon? _trayIcon;

        private bool _installed;

        public MainWindow()
        {
            InitializeComponent();

            Database.CreateDb();
            _installed = Database.GetInstallState();
            SyncInstallButton();

            _dashboardPage = new Pages.DashboardPage();
            _quarantinePage = new Pages.QuarantinePage();
            _aboutPage = new Pages.AboutPage();

            MainContent.Content = _dashboardPage;

            SetupTrayIcon();

            _pipeListener = new PipeListener();
            _pipeListener.AlertReceived += OnAlertReceived;
            _pipeListener.ConnectionChanged += OnConnectionChanged;
            _pipeListener.Start();

            _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _refreshTimer.Tick += (s, e) => PeriodicRefresh();
            _refreshTimer.Start();
        }

        private void SetupTrayIcon()
        {
            // Use standard generic shield icon, or extract from exe
            _trayIcon = new NotifyIcon
            {
                Icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? ""),
                Visible = true,
                Text = "ArgusShield \u2014 Protection Active"
            };

            _trayIcon.DoubleClick += (s, e) => ShowFromTray();

            var menu = new ContextMenuStrip();
            menu.Items.Add("Show Dashboard", null, (s, e) => ShowFromTray());
            menu.Items.Add("Hide", null, (s, e) => Hide());
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Exit", null, (s, e) => QuitApp());

            _trayIcon.ContextMenuStrip = menu;
        }

        private void PeriodicRefresh()
        {
            int count = Database.ImportEventsFromLog();
            if (count > 0 || _dashboardPage.IsLoaded)
            {
                _dashboardPage.RefreshData();
                _quarantinePage.RefreshData();
            }
        }

        private void OnAlertReceived(System.Collections.Generic.Dictionary<string, string> data)
        {
            var dllPath = data.TryGetValue("dll_path", out var d) ? d : "Unknown DLL";
            var pid = data.TryGetValue("target_pid", out var p) ? p : "?";
            var severity = data.TryGetValue("severity", out var sev) ? sev : "High";
            var technique = data.TryGetValue("technique", out var t) ? t : "DLL Injection";
            var action = data.TryGetValue("action", out var a) ? a : "Blocked";
            var score = data.TryGetValue("score", out var s) ? s : "?";

            if (action == "Blocked" || action == "DetectedOnly")
            {
                Dispatcher.Invoke(() =>
                {
                    _trayIcon.ShowBalloonTip(5000,
                        "🛡 Blocked by ArgusShield",
                        $"{technique} injection blocked!\nTarget PID: {pid}\nDLL: {dllPath}\nSeverity: {severity} | Score: {score}",
                        ToolTipIcon.Error);
                });
            }

            // Immediate refresh
            Dispatcher.Invoke(() => PeriodicRefresh());
        }

        private void OnConnectionChanged(bool connected)
        {
            Dispatcher.Invoke(() =>
            {
                if (connected)
                    _trayIcon.Text = "ArgusShield \u2014 Protection Active (Agent Connected)";
                else
                    _trayIcon.Text = "ArgusShield \u2014 Agent Disconnected";
            });
        }

        private void Nav_Checked(object sender, RoutedEventArgs e)
        {
            if (MainContent == null) return;
            if (BtnDashboard.IsChecked == true) MainContent.Content = _dashboardPage;
            else if (BtnQuarantine.IsChecked == true) MainContent.Content = _quarantinePage;
            else if (BtnAbout.IsChecked == true) MainContent.Content = _aboutPage;
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            e.Cancel = true;
            Hide();
            _trayIcon.ShowBalloonTip(2000, "ArgusShield", "Running in the background. Right-click the tray icon for options.", ToolTipIcon.Info);
        }

        private void ShowFromTray()
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        }

        private void QuitApp()
        {
            _pipeListener.Stop();
            _refreshTimer.Stop();
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            Application.Current.Shutdown();
        }

        private void SyncInstallButton()
        {
            if (_installed)
            {
                BtnInstall.Content = "Uninstall Shield";
                BtnInstall.Background = (SolidColorBrush)FindResource("CriticalColor");
            }
            else
            {
                BtnInstall.Content = "Install Shield";
                BtnInstall.Background = (SolidColorBrush)FindResource("LowColor");
            }
        }

        private async void BtnInstall_Click(object sender, RoutedEventArgs e)
        {
            BtnInstall.IsEnabled = false;
            try
            {
                if (!_installed)
                {
                    BtnInstall.Content = "Installing...";
                    var (ok, msg) = await Task.Run(() => ServiceManager.InstallAll());
                    if (ok)
                    {
                        _installed = true;
                        Database.SetInstallState(true);
                        SyncInstallButton();
                        MessageBox.Show("ArgusShield Service + Agent installed and started.\nDashboard auto-start has been configured.", "ArgusShield", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                    {
                        SyncInstallButton();
                        MessageBox.Show(msg, "Installation Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                else
                {
                    BtnInstall.Content = "Uninstalling...";
                    var (ok, msg) = await Task.Run(() => ServiceManager.UninstallAll());
                    if (ok)
                    {
                        _installed = false;
                        Database.SetInstallState(false);
                        SyncInstallButton();
                        MessageBox.Show("ArgusShield Service + Agent uninstalled.\nDashboard auto-start has been removed.", "ArgusShield", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                    {
                        SyncInstallButton();
                        MessageBox.Show(msg, "Uninstall Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
            finally
            {
                BtnInstall.IsEnabled = true;
            }
        }
    }
}