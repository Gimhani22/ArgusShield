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
)
from PyQt5.QtCore import Qt
from ui.styles import (
    get_dark_palette,
    SIDEBAR_STYLE,
    NAV_BUTTON_STYLE,
    NAV_BUTTON_ACTIVE_STYLE,
    INSTALL_BUTTON_STYLE,
    UNINSTALL_BUTTON_STYLE,
)
from ui.pages import DashboardPage, QuarantinePage, SettingsPage, AboutPage
from database import create_db, get_install_state, set_install_state

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('ArgusShield')
        # Don't hard-lock the window size; on small VM screens a fixed 1300x800
        # pushes the title bar off-screen (appearing to remove minimize/close).
        self.resize(1300, 800)
        self.center_on_screen()

        # Ensure database exists and read persisted install state
        create_db()
        self.installed = get_install_state()

        # Set theme
        self.setPalette(get_dark_palette())
        self.setStyleSheet("QWidget { background-color: #181818; color: #fff; }")

        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout()
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

        # Pages  (order must match sidebar nav_items indices)
        self.page_dashboard  = DashboardPage()   # index 0
        self.page_quarantine = QuarantinePage()  # index 1
        self.page_settings   = SettingsPage()    # index 2
        self.page_about      = AboutPage()       # index 3

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_quarantine)
        self.stack.addWidget(self.page_settings)
        self.stack.addWidget(self.page_about)

        # Sync install button with current state and show initial page
        self.sync_install_button()
        self.switch_page(0)

    def center_on_screen(self):
        screen_geo = QApplication.primaryScreen().availableGeometry()

        # If the current window is bigger than the available screen area,
        # shrink it so the title bar stays visible.
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

    # ──────────────────────────────────────────────────────────────
    #  Service management helpers (Windows only)
    # ──────────────────────────────────────────────────────────────

    def _get_service_executable_path(self) -> str:
        """Return full path to ArgusShieldService.exe if found, else ''."""

        # If running from a PyInstaller bundle, the service is expected in
        # the installed app directory under bin/ArgusShieldService.exe
        exe_dir = os.path.dirname(sys.executable)
        candidates = [
            os.path.join(exe_dir, 'bin', 'ArgusShieldService.exe'),
        ]

        # Development-time fallbacks
        here = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(here))
        candidates.extend(
            [
                os.path.join(project_root, 'bin', 'ArgusShieldService.exe'),
                os.path.join(
                    project_root,
                    '..',
                    'ArgusShieldService',
                    'x64',
                    'Debug',
                    'ArgusShieldService.exe',
                ),
            ]
        )

        for path in candidates:
            if os.path.exists(path):
                return os.path.abspath(path)

        return ''

    def _run_command(self, command: str):
        """Run a shell command and return (success, stdout+stderr)."""

        try:
            completed = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
            )
            output = (completed.stdout or '') + (completed.stderr or '')
            return completed.returncode == 0, output.strip()
        except Exception as exc:
            return False, str(exc)

    def install_service(self):
        """Create and start the Windows service using sc.exe."""

        service_path = self._get_service_executable_path()
        if not service_path:
            return False, (
                "ArgusShieldService.exe was not found.\n\n"
                "Build the service project (ArgusShieldService) first, "
                "or ensure the installer deployed bin/ArgusShieldService.exe."
            )

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

        return True, ''

    def uninstall_service(self):
        """Stop and delete the Windows service using sc.exe."""

        # Try to stop; ignore failures (e.g., not running)
        self._run_command('sc stop ArgusShieldService')

        delete_cmd = 'sc delete ArgusShieldService'
        ok, output = self._run_command(delete_cmd)
        if not ok and 'SERVICE_DOES_NOT_EXIST' not in output.upper():
            return False, f"Failed to delete service:\n{output}"

        return True, ''

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            if i == index:
                btn.setStyleSheet(NAV_BUTTON_STYLE + NAV_BUTTON_ACTIVE_STYLE)
            else:
                btn.setStyleSheet(NAV_BUTTON_STYLE)
