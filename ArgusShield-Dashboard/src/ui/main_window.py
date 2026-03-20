import os
import sys
import subprocess

from PyQt5.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QStackedWidget,
    QSizePolicy,
    QApplication,
    QMessageBox,
    QSystemTrayIcon,
    QMenu,
    QAction,
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon, QPixmap, QPainter, QColor, QFont
from ui.styles import (
    get_dark_palette,
    GLOBAL_STYLE,
    SIDEBAR_STYLE,
    NAV_BUTTON_STYLE,
    NAV_BUTTON_ACTIVE_STYLE,
    INSTALL_BUTTON_STYLE,
    UNINSTALL_BUTTON_STYLE,
)
from ui.pages import DashboardPage, QuarantinePage, SettingsPage, AboutPage
from database import (
    create_db, get_install_state, set_install_state,
    import_events_from_log,
)
from pipe_listener import PipeListenerThread


def _create_shield_icon():
    """Generate a simple shield icon programmatically."""
    pix = QPixmap(64, 64)
    pix.fill(QColor(0, 0, 0, 0))

    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)

    from PyQt5.QtGui import QPainterPath
    path = QPainterPath()
    path.moveTo(32, 4)
    path.lineTo(8, 16)
    path.lineTo(8, 36)
    path.cubicTo(8, 52, 32, 60, 32, 60)
    path.cubicTo(32, 60, 56, 52, 56, 36)
    path.lineTo(56, 16)
    path.closeSubpath()

    p.setBrush(QColor('#2d8cff'))
    p.setPen(Qt.NoPen)
    p.drawPath(path)

    p.setPen(QColor('#ffffff'))
    font = QFont('Segoe UI', 22, QFont.Bold)
    p.setFont(font)
    p.drawText(pix.rect(), Qt.AlignCenter, 'A')
    p.end()
    return QIcon(pix)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('ArgusShield')
        self.resize(1300, 800)
        self.center_on_screen()

        create_db()
        self.installed = get_install_state()

        self.setPalette(get_dark_palette())
        self.setStyleSheet(
            "QWidget { background-color: #181818; color: #fff; }\n" + GLOBAL_STYLE
        )

        self._icon = _create_shield_icon()
        self.setWindowIcon(self._icon)

        # ── System tray ──────────────────────────────────────────────────
        self.tray_icon = QSystemTrayIcon(self._icon, self)
        tray_menu = QMenu()

        show_action = QAction('Show Dashboard', self)
        show_action.triggered.connect(self._show_from_tray)
        tray_menu.addAction(show_action)

        hide_action = QAction('Hide', self)
        hide_action.triggered.connect(self.hide)
        tray_menu.addAction(hide_action)

        tray_menu.addSeparator()

        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self._quit_app)
        tray_menu.addAction(exit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.setToolTip('ArgusShield — Protection Active')
        self.tray_icon.show()

        # ── Central widget ───────────────────────────────────────────────
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        central_widget.setLayout(main_layout)

        # Sidebar
        sidebar_widget = QWidget()
        sidebar_layout = QVBoxLayout()
        sidebar_widget.setLayout(sidebar_layout)
        sidebar_widget.setFixedWidth(260)
        sidebar_widget.setStyleSheet(SIDEBAR_STYLE)

        self.nav_buttons = []
        nav_items = [('Dashboard', 0), ('Quarantine', 1), ('Settings', 2), ('About', 3)]

        sidebar_layout.addSpacing(20)
        for text, index in nav_items:
            btn = QPushButton(f"  {text}")
            btn.setFixedHeight(45)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet(NAV_BUTTON_STYLE)
            btn.clicked.connect(lambda checked, idx=index: self.switch_page(idx))
            sidebar_layout.addWidget(btn)
            sidebar_layout.addSpacing(10)
            self.nav_buttons.append(btn)

        sidebar_layout.addStretch()

        self.install_button = QPushButton('Install Shield')
        self.install_button.setCursor(Qt.PointingHandCursor)
        self.install_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.install_button.setStyleSheet(INSTALL_BUTTON_STYLE)
        self.install_button.clicked.connect(self.toggle_install)
        sidebar_layout.addWidget(self.install_button)

        main_layout.addWidget(sidebar_widget)

        # Stacked widget for pages
        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack)

        self.page_dashboard  = DashboardPage()
        self.page_quarantine = QuarantinePage()
        self.page_settings   = SettingsPage()
        self.page_about      = AboutPage()

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_quarantine)
        self.stack.addWidget(self.page_settings)
        self.stack.addWidget(self.page_about)

        self.sync_install_button()
        self.switch_page(0)

        # ── Pipe listener (real-time alerts from Agent) ──────────────────
        self._pipe_thread = PipeListenerThread(self)
        self._pipe_thread.alert_received.connect(self._on_injection_alert)
        self._pipe_thread.connection_changed.connect(self._on_agent_connection)
        self._pipe_thread.start()

        # ── Periodic data refresh timer ──────────────────────────────────
        # Reads events.log every 5 seconds and refreshes page data
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._periodic_refresh)
        self._refresh_timer.start(5000)

    # ──────────────────────────────────────────────────────────────────────
    #  Periodic data refresh (reads shared events.log → SQLite)
    # ──────────────────────────────────────────────────────────────────────

    def _periodic_refresh(self):
        count = import_events_from_log()
        if count > 0:
            self.page_dashboard.refresh_data()
            self.page_quarantine.refresh_data()

    # ──────────────────────────────────────────────────────────────────────
    #  System tray
    # ──────────────────────────────────────────────────────────────────────

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            'ArgusShield',
            'Running in the background. Right-click the tray icon for options.',
            QSystemTrayIcon.Information, 2000,
        )

    def _show_from_tray(self):
        self.showNormal()
        self.activateWindow()
        self.raise_()

    def _quit_app(self):
        self._pipe_thread.stop()
        self._pipe_thread.wait(2000)
        self._refresh_timer.stop()
        self.tray_icon.hide()
        QApplication.quit()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self._show_from_tray()

    # ──────────────────────────────────────────────────────────────────────
    #  Pipe listener callbacks
    # ──────────────────────────────────────────────────────────────────────

    def _on_injection_alert(self, data: dict):
        dll_path  = data.get('dll_path', 'Unknown DLL')
        pid       = data.get('target_pid', '?')
        severity  = data.get('severity', 'High')
        technique = data.get('technique', 'DLL Injection')
        action    = data.get('action', 'Blocked')
        score     = data.get('score', '?')
        decision  = data.get('decision', '')

        # Only show tray notification for BLOCKED threats
        if action in ('Blocked', 'DetectedOnly'):
            self.tray_icon.showMessage(
                '🛡️ Blocked by ArgusShield',
                f'{technique} injection blocked!\n'
                f'Target PID: {pid}\n'
                f'DLL: {dll_path}\n'
                f'Severity: {severity} | Score: {score}',
                QSystemTrayIcon.Critical, 5000,
            )

        # Trigger an immediate data refresh for both Block and Alert
        import_events_from_log()
        self.page_dashboard.refresh_data()
        self.page_quarantine.refresh_data()

    def _on_agent_connection(self, connected: bool):
        if connected:
            self.tray_icon.setToolTip('ArgusShield — Protection Active (Agent Connected)')
        else:
            self.tray_icon.setToolTip('ArgusShield — Agent Disconnected')

    # ──────────────────────────────────────────────────────────────────────
    #  Window helpers
    # ──────────────────────────────────────────────────────────────────────

    def center_on_screen(self):
        screen_geo = QApplication.primaryScreen().availableGeometry()
        margin = 40
        max_w = max(320, screen_geo.width() - margin)
        max_h = max(240, screen_geo.height() - margin)
        new_w = min(self.width(), max_w)
        new_h = min(self.height(), max_h)
        if new_w != self.width() or new_h != self.height():
            self.resize(new_w, new_h)
        x = screen_geo.left() + (screen_geo.width() - self.width()) // 2
        y = screen_geo.top() + (screen_geo.height() - self.height()) // 2
        x = max(screen_geo.left(), min(x, screen_geo.left() + screen_geo.width() - self.width()))
        y = max(screen_geo.top(),  min(y, screen_geo.top()  + screen_geo.height() - self.height()))
        self.move(x, y)

    def toggle_install(self):
        if not self.installed:
            ok, message = self._install_all()
            if ok:
                self.installed = True
                set_install_state(True)
                self.sync_install_button()
                QMessageBox.information(
                    self, "ArgusShield",
                    "ArgusShield Service + Agent installed and started.\n"
                    "Dashboard auto-start has been configured.",
                )
            else:
                QMessageBox.critical(self, "Installation Failed", message)
        else:
            ok, message = self._uninstall_all()
            if ok:
                self.installed = False
                set_install_state(False)
                self.sync_install_button()
                QMessageBox.information(
                    self, "ArgusShield",
                    "ArgusShield Service + Agent uninstalled.\n"
                    "Dashboard auto-start has been removed.",
                )
            else:
                QMessageBox.critical(self, "Uninstall Failed", message)

    def sync_install_button(self):
        if self.installed:
            self.install_button.setText('Uninstall Shield')
            self.install_button.setStyleSheet(UNINSTALL_BUTTON_STYLE)
        else:
            self.install_button.setText('Install Shield')
            self.install_button.setStyleSheet(INSTALL_BUTTON_STYLE)

    # ──────────────────────────────────────────────────────────────────────
    #  Service + Agent + Dashboard installation (all-in-one)
    # ──────────────────────────────────────────────────────────────────────

    def _find_bin_exe(self, name: str) -> str:
        exe_dir = os.path.dirname(sys.executable)
        candidates = [os.path.join(exe_dir, 'bin', name)]

        here = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(here))
        candidates.extend([
            os.path.join(project_root, 'bin', name),
            os.path.join(project_root, '..', 'ArgusShieldService', 'x64', 'Debug', name),
            os.path.join(project_root, '..', 'ArgusShieldService', 'x64', 'Release', name),
            os.path.join(project_root, '..', 'ArgusShieldAgent', 'x64', 'Debug', name),
            os.path.join(project_root, '..', 'ArgusShieldAgent', 'x64', 'Release', name),
        ])

        for path in candidates:
            if os.path.exists(path):
                return os.path.abspath(path)
        return ''

    def _run_command(self, command: str):
        try:
            completed = subprocess.run(
                command, shell=True, capture_output=True, text=True,
            )
            output = (completed.stdout or '') + (completed.stderr or '')
            return completed.returncode == 0, output.strip()
        except Exception as exc:
            return False, str(exc)

    def _install_all(self):
        """Install both Windows services + configure Dashboard auto-start."""

        # ── 1. Install ArgusShieldService ────────────────────────────────
        svc_path = self._find_bin_exe('ArgusShieldService.exe')
        if not svc_path:
            return False, (
                "ArgusShieldService.exe not found.\n"
                "Build the project and copy to bin/ folder."
            )

        cmd = (f'sc create ArgusShieldService '
               f'binPath= "{svc_path}" start= auto '
               f'DisplayName= "ArgusShield Service"')
        ok, out = self._run_command(cmd)
        if not ok and 'SERVICE_EXISTS' not in out.upper():
            return False, f"Failed to create service:\n{out}"

        ok, out = self._run_command('sc start ArgusShieldService')
        if not ok and 'ALREADY_RUNNING' not in out.upper():
            return False, f"Service created but failed to start:\n{out}"

        # ── 2. Install ArgusShieldAgent ──────────────────────────────────
        agent_path = self._find_bin_exe('ArgusShieldAgent.exe')
        if agent_path:
            cmd = (f'sc create ArgusShieldAgent '
                   f'binPath= "{agent_path}" start= auto '
                   f'depend= ArgusShieldService '
                   f'DisplayName= "ArgusShield Agent"')
            ok, out = self._run_command(cmd)
            # Not fatal if agent install fails

            self._run_command('sc start ArgusShieldAgent')

        # ── 3. Configure Dashboard auto-start on login ───────────────────
        self._setup_dashboard_autostart()

        return True, ''

    def _uninstall_all(self):
        """Stop and remove both services + remove Dashboard auto-start."""

        # Stop and delete Service
        self._run_command('sc stop ArgusShieldService')
        ok, out = self._run_command('sc delete ArgusShieldService')
        if not ok and 'SERVICE_DOES_NOT_EXIST' not in out.upper():
            return False, f"Failed to delete service:\n{out}"

        # Stop and delete Agent
        self._run_command('sc stop ArgusShieldAgent')
        self._run_command('sc delete ArgusShieldAgent')

        # Remove Dashboard auto-start
        self._remove_dashboard_autostart()

        return True, ''

    # ── Dashboard auto-start (Task Scheduler) ────────────────────────────

    def _setup_dashboard_autostart(self):
        """Register a Task Scheduler task so the Dashboard starts on login."""
        exe_path = sys.executable
        if getattr(sys, 'frozen', False):
            # PyInstaller bundle — use the exe directly
            exe_path = sys.executable
        else:
            # Dev mode — run python script
            script = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), '..', 'ArgusShield.py'
            )
            exe_path = f'"{sys.executable}" "{os.path.abspath(script)}"'

        cmd = (
            f'schtasks /Create /F /TN "ArgusShieldDashboard" '
            f'/TR "{exe_path}" '
            f'/SC ONLOGON /RL HIGHEST'
        )
        self._run_command(cmd)

    def _remove_dashboard_autostart(self):
        self._run_command('schtasks /Delete /TN "ArgusShieldDashboard" /F')

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            if i == index:
                btn.setStyleSheet(NAV_BUTTON_STYLE + NAV_BUTTON_ACTIVE_STYLE)
            else:
                btn.setStyleSheet(NAV_BUTTON_STYLE)
