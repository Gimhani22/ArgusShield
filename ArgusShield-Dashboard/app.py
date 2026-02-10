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
)
from PyQt5.QtCore import Qt


class DLLDetectorUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("SentriX - DLL Injection Detector")
        self.setGeometry(100, 100, 1000, 600)
        
        # Configuration file path
        self.config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        
        # Check installation status
        self.is_installed = self.check_installation_status()

        # Main horizontal layout: sidebar + main area
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Sidebar
        sidebar = QFrame(self)
        sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 20, 20, 20)

        self.logo_label = QLabel("SENTRIX")
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
            install_btn = QPushButton("Uninstall SentriX")
            install_btn.setStyleSheet("background-color: #d32f2f; color: white; padding:8px; font-weight:bold;")
            install_btn.clicked.connect(self.uninstall_application)
            status_label = QLabel("Status: Installed and Active")
            status_label.setStyleSheet("color: #4caf50; font-size:14pt; font-weight:bold;")
        else:
            install_btn = QPushButton("Install SentriX")
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

    def check_installation_status(self):
        """Check if the application is installed by reading the config file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    return config.get('installed', False)
        except Exception as e:
            print(f"Error reading config: {e}")
        return False

    def save_installation_status(self, installed):
        """Save the installation status to the config file"""
        try:
            config = {'installed': installed}
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
            self.is_installed = installed
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save configuration: {e}")

    def install_application(self):
        """Handle the installation process"""
        reply = QMessageBox.question(
            self, 
            'Install SentriX', 
            'Do you want to install SentriX DLL Injection Detector?',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Perform installation tasks here
            # For example: register services, create shortcuts, etc.
            self.save_installation_status(True)
            QMessageBox.information(self, "Success", "SentriX has been installed successfully!")
            self.show_dashboard()  # Refresh the dashboard

    def uninstall_application(self):
        """Handle the uninstallation process"""
        reply = QMessageBox.question(
            self, 
            'Uninstall SentriX', 
            'Are you sure you want to uninstall SentriX DLL Injection Detector?',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Perform uninstallation tasks here
            # For example: unregister services, remove shortcuts, etc.
            self.save_installation_status(False)
            QMessageBox.information(self, "Success", "SentriX has been uninstalled successfully!")
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