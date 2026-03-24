using System.Windows;
using System.Threading;

namespace ArgusShieldDashboard
{
    public partial class App : System.Windows.Application
    {
        private static Mutex? _mutex;

        protected override void OnStartup(StartupEventArgs e)
        {
            const string appName = "ArgusShieldDashboardApp";
            bool createdNew;

            _mutex = new Mutex(true, appName, out createdNew);

            if (!createdNew)
            {
                System.Windows.Application.Current.Shutdown();
                return;
            }

            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            var mainWindow = new MainWindow();
            
            if (e.Args.Length > 0 && e.Args[0] == "/hidden")
            {
                // Starting hidden for background
            }
            else
            {
                mainWindow.Show();
            }

            base.OnStartup(e);
        }
    }
}
