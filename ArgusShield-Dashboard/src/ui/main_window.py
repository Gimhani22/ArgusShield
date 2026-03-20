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
from database import create_db, get_install_state, set_install_state
from pipe_listener import PipeListenerThread


def _create_shield_icon():
    """Generate a simple shield icon programmatically (no file needed)."""
    pix = QPixmap(64, 64)
    pix.fill(QColor(0, 0, 0, 0))  # transparent

    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)

    # Shield body
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

    # "A" letter
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

        # Ensure database exists and read persisted install state
        create_db()
        self.installed = get_install_state()

        # Set theme
        self.setPalette(get_dark_palette())
        self.setStyleSheet(
            "QWidget { background-color: #181818; color: #fff; }\n" + GLOBAL_STYLE
        )

        # App icon
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

        # ── Central widget and main layout ───────────────────────────────
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

        # Navigation Buttons
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

        # Stacked widget for main content
        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack)

        # Pages (order must match sidebar nav_items indices)
        self.page_dashboard  = DashboardPage()
        self.page_quarantine = QuarantinePage()
        self.page_settings   = SettingsPage()
        self.page_about      = AboutPage()

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_quarantine)
        self.stack.addWidget(self.page_settings)
        self.stack.addWidget(self.page_about)

        # Sync install button with current state and show initial page
        self.sync_install_button()
        self.switch_page(0)

        # ── Pipe listener (receives alerts from the Agent) ───────────────
        self._pipe_thread = PipeListenerThread(self)
        self._pipe_thread.alert_received.connect(self._on_injection_alert)
        self._pipe_thread.connection_changed.connect(self._on_agent_connection)
        self._pipe_thread.start()

    # ──────────────────────────────────────────────────────────────────────
    #  System tray
    # ──────────────────────────────────────────────────────────────────────

    def closeEvent(self, event):
        """Minimize to tray instead of quitting."""
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            'ArgusShield',
            'Running in the background. Right-click the tray icon for options.',
            QSystemTrayIcon.Information,
            2000,
        )

    def _show_from_tray(self):
        self.showNormal()
        self.activateWindow()
        self.raise_()

    def _quit_app(self):
        self._pipe_thread.stop()
        self._pipe_thread.wait(2000)
        self.tray_icon.hide()
        QApplication.quit()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self._show_from_tray()

    # ──────────────────────────────────────────────────────────────────────
    #  Pipe listener callbacks
    # ──────────────────────────────────────────────────────────────────────

    def _on_injection_alert(self, data: dict):
        """Called when an injection alert arrives from the Agent pipe."""
        dll_path = data.get('dll_path', 'Unknown DLL')
        pid = data.get('target_pid', '?')
        severity = data.get('severity', 'High')
        technique = data.get('technique', 'DLL Injection')

        # Show a tray balloon notification
        self.tray_icon.showMessage(
            f'⚠ Injection Detected [{severity}]',
            f'{technique} blocked!\nPID: {pid}\nDLL: {dll_path}',
            QSystemTrayIcon.Critical,
            5000,
        )

        # Add to quarantine table
        import time
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        self.page_quarantine.add_detection(
            timestamp=timestamp,
            process=f'PID {pid}',
            source=dll_path,
            attack_type=technique,
            severity=severity,
            status='Blocked',
        )

    def _on_agent_connection(self, connected: bool):
        """Called when Agent pipe connects or disconnects."""
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
        """Handle Install/Uninstall button click."""
        if not self.installed:
            ok, message = self.install_service()
            if ok:
                self.installed = True
                set_install_state(True)
                self.sync_install_button()
                QMessageBox.information(
                    self,
                    "ArgusShield",
                    "ArgusShield background service has been installed and started.",
                )
            else:
                QMessageBox.critical(self, "Installation Failed", message)
        else:
            ok, message = self.uninstall_service()
            if ok:
                self.installed = False
                set_install_state(False)
                self.sync_install_button()
                QMessageBox.information(
                    self,
                    "ArgusShield",
                    "ArgusShield background service has been uninstalled.",
                )
            else:
                QMessageBox.critical(self, "Uninstall Failed", message)

    def sync_install_button(self):
        """Update button label and style from current install state."""
        if self.installed:
            self.install_button.setText('Uninstall Shield')
            self.install_button.setStyleSheet(UNINSTALL_BUTTON_STYLE)
        else:
            self.install_button.setText('Install Shield')
            self.install_button.setStyleSheet(INSTALL_BUTTON_STYLE)

    # ──────────────────────────────────────────────────────────────────────
    #  Service + Agent management helpers (Windows only)
    # ──────────────────────────────────────────────────────────────────────

    def _find_bin_exe(self, name: str) -> str:
        """Search standard locations for a binary (e.g. ArgusShieldService.exe)."""
        # 1. PyInstaller bundled path
        exe_dir = os.path.dirname(sys.executable)
        candidates = [
            os.path.join(exe_dir, 'bin', name),
        ]

        # 2. Development-time fallbacks
        here = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(here))  # ArgusShield-Dashboard
        candidates.extend([
            os.path.join(project_root, 'bin', name),
            # Direct build output fallbacks
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
        """Run a shell command and return (success, stdout+stderr)."""
        try:
            completed = subprocess.run(
                command, shell=True, capture_output=True, text=True,
            )
            output = (completed.stdout or '') + (completed.stderr or '')
            return completed.returncode == 0, output.strip()
        except Exception as exc:
            return False, str(exc)

    def install_service(self):
        """Create and start the Windows service + launch the Agent."""
        service_path = self._find_bin_exe('ArgusShieldService.exe')
        if not service_path:
            return False, (
                "ArgusShieldService.exe was not found.\n\n"
                "Build the service project (ArgusShieldService) first, "
                "or ensure bin/ArgusShieldService.exe exists."
            )

        # ── Install the Windows Service ──────────────────────────────────
        create_cmd = (
            f'sc create ArgusShieldService '
            f'binPath= "{service_path}" '
            f'start= auto '
            f'DisplayName= "ArgusShield Service"'
        )
        ok, output = self._run_command(create_cmd)
        if not ok and 'SERVICE_EXISTS' not in output.upper():
            return False, f"Failed to create service:\n{output}"

        start_cmd = 'sc start ArgusShieldService'
        ok, output = self._run_command(start_cmd)
        if not ok and 'ALREADY_RUNNING' not in output.upper():
            return False, f"Service created but failed to start:\n{output}"

        # ── Launch the Agent (hidden background process) ─────────────────
        self._start_agent()

        return True, ''

    def _start_agent(self):
        """Start ArgusShieldAgent.exe as a detached hidden process."""
        agent_path = self._find_bin_exe('ArgusShieldAgent.exe')
        if not agent_path:
            return  # Agent not found — not a fatal error

        try:
            # DETACHED_PROCESS = 0x08  — no console window, runs independently
            subprocess.Popen(
                [agent_path],
                creationflags=0x08,  # DETACHED_PROCESS
                close_fds=True,
            )
        except Exception:
            pass  # Best-effort — agent will auto-start on next login anyway

    def uninstall_service(self):
        """Stop and delete the Windows service + kill the Agent."""
        # ── Stop and delete the service ──────────────────────────────────
        self._run_command('sc stop ArgusShieldService')
        delete_cmd = 'sc delete ArgusShieldService'
        ok, output = self._run_command(delete_cmd)
        if not ok and 'SERVICE_DOES_NOT_EXIST' not in output.upper():
            return False, f"Failed to delete service:\n{output}"

        # ── Kill the Agent process ───────────────────────────────────────
        self._run_command('taskkill /IM ArgusShieldAgent.exe /F')

        # ── Remove Agent auto-start registry entry ───────────────────────
        self._run_command(
            'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
            '/v ArgusShieldAgent /f'
        )

        return True, ''

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            if i == index:
                btn.setStyleSheet(NAV_BUTTON_STYLE + NAV_BUTTON_ACTIVE_STYLE)
            else:
                btn.setStyleSheet(NAV_BUTTON_STYLE)

