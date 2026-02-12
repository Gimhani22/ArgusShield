import sys
import json
import os
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QPushButton,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QSystemTrayIcon,
    QMenu,
    QAction,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from database import create_db, get_install_state, set_install_state


def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


class DLLDetectorUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("ArgusShield - DLL Injection Detector")
        self.setGeometry(100, 100, 1000, 600)
        
        # Initialize database
        create_db()
        
        # Check installation status
        self.is_installed = get_install_state()
        
        # Setup system tray
        self.setup_system_tray()

        # Main horizontal layout: sidebar + main area
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Sidebar
        sidebar = QFrame(self)
        sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 20, 20, 20)

        self.logo_label = QLabel("ArgusShield")
        self.logo_label.setStyleSheet("font-size:20pt; font-weight:bold;")
        sidebar_layout.addWidget(self.logo_label)
        sidebar_layout.addSpacing(10)

        self.btn_dashboard = QPushButton("Dashboard")
        self.btn_monitor = QPushButton("Process Monitor")
        self.btn_dashboard.clicked.connect(self.show_dashboard)
        self.btn_monitor.clicked.connect(self.show_monitor)
        sidebar_layout.addWidget(self.btn_dashboard)
        sidebar_layout.addWidget(self.btn_monitor)

        sidebar_layout.addStretch()
        self.status_label = QLabel("System Status: Active")
        self.status_label.setStyleSheet("color: green;")
        sidebar_layout.addWidget(self.status_label)

        # Main content area
        self.main_frame = QFrame(self)
        main_frame_layout = QVBoxLayout(self.main_frame)
        main_frame_layout.setContentsMargins(20, 20, 20, 20)

        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.main_frame, 1)

        self.show_dashboard()
    
    def setup_system_tray(self):
        """Setup system tray icon and menu"""
        self.tray_icon = QSystemTrayIcon(self)
        
        # Try to load icon, use default if not found
        icon_path = get_resource_path("icon.ico")
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            # Use application default icon
            self.tray_icon.setIcon(self.style().standardIcon(self.style().SP_ComputerIcon))
        
        # Create tray menu
        tray_menu = QMenu()
        
        show_action = QAction("Show Dashboard", self)
        show_action.triggered.connect(self.show_window)
        tray_menu.addAction(show_action)
        
        tray_menu.addSeparator()
        
        quit_action = QAction("Exit", self)
        quit_action.triggered.connect(self.quit_application)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.setToolTip("ArgusShield - DLL Injection Detector")
        
        # Double-click to show window
        self.tray_icon.activated.connect(self.tray_icon_activated)
        
        self.tray_icon.show()
    
    def tray_icon_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_window()
    
    def show_window(self):
        """Show and bring window to front"""
        self.showNormal()
        self.activateWindow()
        self.raise_()
    
    def closeEvent(self, event):
        """Minimize to tray instead of closing"""
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "ArgusShield",
            "Application minimized to system tray. Right-click the tray icon for options.",
            QSystemTrayIcon.Information,
            2000
        )
    
    def quit_application(self):
        """Actually quit the application"""
        self.tray_icon.hide()
        QApplication.quit()
    
    def show_notification(self, title, message, icon=QSystemTrayIcon.Information):
        """Show a system tray notification"""
        self.tray_icon.showMessage(title, message, icon, 3000)

    def clear_main_frame(self):
        layout = self.main_frame.layout()
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def show_dashboard(self):
        self.clear_main_frame()
        layout = self.main_frame.layout()

        label = QLabel("Security Overview")
        label.setStyleSheet("font-size:24pt; font-weight:bold;")
        layout.addWidget(label)

        stats_frame = QFrame()
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.addWidget(QLabel("Scans: 0"))
        stats_layout.addWidget(QLabel("Threats: 0"))
        layout.addWidget(stats_frame)

        # Install/Uninstall button based on current status
        if self.is_installed:
            install_btn = QPushButton("Uninstall ArgusShield")
            install_btn.setStyleSheet("background-color: #d32f2f; color: white; padding:8px; font-weight:bold;")
            install_btn.clicked.connect(self.uninstall_application)
            status_label = QLabel("Status: Installed and Active")
            status_label.setStyleSheet("color: #4caf50; font-size:14pt; font-weight:bold;")
        else:
            install_btn = QPushButton("Install ArgusShield")
            install_btn.setStyleSheet("background-color: #4caf50; color: white; padding:8px; font-weight:bold;")
            install_btn.clicked.connect(self.install_application)
            status_label = QLabel("Status: Not Installed")
            status_label.setStyleSheet("color: #ff9800; font-size:14pt; font-weight:bold;")
        
        layout.addWidget(status_label)
        layout.addWidget(install_btn)

        scan_btn = QPushButton("Run Full System Scan")
        scan_btn.setStyleSheet("background-color: firebrick; color: white; padding:8px;")
        layout.addWidget(scan_btn)

    def show_monitor(self):
        self.clear_main_frame()
        layout = self.main_frame.layout()

        label = QLabel("Active Process Monitor")
        label.setStyleSheet("font-size:24pt; font-weight:bold;")
        layout.addWidget(label)

        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["PID", "Process Name", "Security Status", "DLLs Loaded"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Example data
        rows = [
            ("1024", "chrome.exe", "Safe", "42"),
            ("4096", "unknown.exe", "SUSPICIOUS", "12"),
        ]
        table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, value in enumerate(row):
                table.setItem(r, c, QTableWidgetItem(value))

        layout.addWidget(table)

    def install_application(self):
        """Handle the installation process"""
        reply = QMessageBox.question(
            self, 
            'Install ArgusShield ', 
            'Do you want to install ArgusShield DLL Injection Detector?',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Perform installation tasks here
            # For example: register services, create shortcuts, etc.
            set_install_state(True)
            self.is_installed = True
            QMessageBox.information(self, "Success", "ArgusShield has been installed successfully!")
            self.show_dashboard()  # Refresh the dashboard

    def uninstall_application(self):
        """Handle the uninstallation process"""
        reply = QMessageBox.question(
            self, 
            'Uninstall ArgusShield', 
            'Are you sure you want to uninstall ArgusShield DLL Injection Detector?',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Perform uninstallation tasks here
            # For example: unregister services, remove shortcuts, etc.
            set_install_state(False)
            self.is_installed = False
            QMessageBox.information(self, "Success", "ArgusShield has been uninstalled successfully!")
            self.show_dashboard()  # Refresh the dashboard


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Apply dark theme stylesheet
    app.setStyleSheet("""
        QWidget {
            background-color: #2b2b2b;
            color: #ffffff;
            font-family: Segoe UI, Arial, sans-serif;
        }
        QPushButton {
            background-color: #404040;
            color: #ffffff;
            border: 1px solid #555555;
            padding: 5px;
            border-radius: 3px;
        }
        QPushButton:hover {
            background-color: #505050;
        }
        QPushButton:pressed {
            background-color: #606060;
        }
        QTableWidget {
            background-color: #2b2b2b;
            color: #ffffff;
            gridline-color: #444444;
        }
        QLabel { color: #ffffff; }
    """)

    window = DLLDetectorUI()
    window.show()
    sys.exit(app.exec_())