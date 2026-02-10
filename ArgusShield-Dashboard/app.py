import sys
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
)
from PyQt5.QtCore import Qt


class DLLDetectorUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("SentriX - DLL Injection Detector")
        self.setGeometry(100, 100, 1000, 600)

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