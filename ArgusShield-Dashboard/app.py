import sys
import json
import os
import random
import subprocess
import ctypes
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
    QScrollArea,
    QComboBox,
    QGridLayout,
    QSizePolicy,
    QSpacerItem,
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon, QFont, QPainter, QPen, QColor, QPainterPath
from database import create_db, get_install_state, set_install_state


def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


class ThreatActivityChart(QWidget):
    """Custom widget to draw the threat activity line chart"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(200)
        self.data = [1.5, 2.8, 4.0, 2.2, 3.5, 1.8, 1.2]  # Sample data for Mon-Sun
        self.days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        width = self.width()
        height = self.height()
        margin_left = 40
        margin_right = 20
        margin_top = 20
        margin_bottom = 40
        
        chart_width = width - margin_left - margin_right
        chart_height = height - margin_top - margin_bottom
        
        # Draw Y-axis labels
        painter.setPen(QPen(QColor('#6b7280'), 1))
        painter.setFont(QFont('Segoe UI', 8))
        for i in range(5):
            y = margin_top + (chart_height * i / 4)
            value = 4 - i
            painter.drawText(5, int(y + 5), str(value))
            # Draw horizontal grid line
            painter.setPen(QPen(QColor('#374151'), 1, Qt.DotLine))
            painter.drawLine(margin_left, int(y), width - margin_right, int(y))
            painter.setPen(QPen(QColor('#6b7280'), 1))
        
        # Draw X-axis labels
        for i, day in enumerate(self.days):
            x = margin_left + (chart_width * i / (len(self.days) - 1))
            painter.drawText(int(x - 15), height - 10, day)
        
        # Draw the line chart with gradient fill
        if len(self.data) > 1:
            # Create path for fill
            path = QPainterPath()
            points = []
            for i, value in enumerate(self.data):
                x = margin_left + (chart_width * i / (len(self.data) - 1))
                y = margin_top + chart_height - (value / 4.0 * chart_height)
                points.append((x, y))
            
            # Fill area under curve
            path.moveTo(points[0][0], margin_top + chart_height)
            for x, y in points:
                path.lineTo(x, y)
            path.lineTo(points[-1][0], margin_top + chart_height)
            path.closeSubpath()
            
            painter.setBrush(QColor(16, 185, 129, 30))  # Semi-transparent green
            painter.setPen(Qt.NoPen)
            painter.drawPath(path)
            
            # Draw the line
            painter.setPen(QPen(QColor('#10b981'), 3))
            for i in range(len(points) - 1):
                painter.drawLine(int(points[i][0]), int(points[i][1]), 
                               int(points[i+1][0]), int(points[i+1][1]))


class DLLDetectorUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("ArgusShield")
        self.setGeometry(100, 100, 1000, 650)
        self.setMinimumSize(900, 600)
        
        # Initialize database
        create_db()
        
        # Check installation status
        self.is_installed = get_install_state()
        
        # Protection status states
        self.protection_status = {
            'realtime': True,
            'firewall': True,
            'email': True,
            'ransomware': True,
            'web': False
        }
        
        # Setup system tray
        self.setup_system_tray()

        # Main horizontal layout: sidebar + main area
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Create sidebar
        self.sidebar = self.create_sidebar()
        main_layout.addWidget(self.sidebar)

        # Main content area
        self.main_frame = QFrame(self)
        self.main_frame.setObjectName("mainFrame")
        main_frame_layout = QVBoxLayout(self.main_frame)
        main_frame_layout.setContentsMargins(30, 20, 30, 20)
        main_frame_layout.setSpacing(20)

        main_layout.addWidget(self.main_frame, 1)
        
        # Track active nav button
        self.active_nav_button = None

        self.show_dashboard()
    
    def create_sidebar(self):
        """Create the sidebar with navigation"""
        sidebar = QFrame(self)
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(15, 20, 15, 20)
        sidebar_layout.setSpacing(5)

        # Logo section
        logo_frame = QFrame()
        logo_layout = QHBoxLayout(logo_frame)
        logo_layout.setContentsMargins(0, 0, 0, 20)
        logo_layout.setSpacing(10)
        
        # Shield icon (using text as placeholder)
        shield_label = QLabel("🛡")
        shield_label.setStyleSheet("font-size: 24px; color: #10b981;")
        logo_layout.addWidget(shield_label)
        
        logo_text = QLabel("ArgusShield")
        logo_text.setStyleSheet("font-size: 16px; font-weight: bold; color: #ffffff;")
        logo_layout.addWidget(logo_text)
        logo_layout.addStretch()
        
        sidebar_layout.addWidget(logo_frame)

        # Navigation buttons
        self.btn_dashboard = self.create_nav_button("📊", "Dashboard")
        self.btn_about = self.create_nav_button("ℹ", "About")
        self.btn_quarantine = self.create_nav_button("🗂", "Quarantine")
        self.btn_notifications = self.create_nav_button("🔔", "Notifications")
        
        self.btn_dashboard.clicked.connect(lambda: self.navigate_to('dashboard'))
        self.btn_about.clicked.connect(lambda: self.navigate_to('about'))
        self.btn_quarantine.clicked.connect(lambda: self.navigate_to('quarantine'))
        self.btn_notifications.clicked.connect(lambda: self.navigate_to('notifications'))
        
        sidebar_layout.addWidget(self.btn_dashboard)
        sidebar_layout.addWidget(self.btn_about)
        sidebar_layout.addWidget(self.btn_quarantine)
        sidebar_layout.addWidget(self.btn_notifications)
        
        sidebar_layout.addStretch()

        # Install Agent button
        self.install_btn = QPushButton("⬇  Install Agent")
        self.install_btn.setObjectName("installButton")
        self.install_btn.setCursor(Qt.PointingHandCursor)
        self.install_btn.clicked.connect(self.toggle_install)
        self.update_install_button()
        sidebar_layout.addWidget(self.install_btn)

        return sidebar
    
    def create_nav_button(self, icon, text):
        """Create a navigation button for the sidebar"""
        btn = QPushButton(f"  {icon}   {text}")
        btn.setObjectName("navButton")
        btn.setCursor(Qt.PointingHandCursor)
        btn.setCheckable(True)
        return btn
    
    def navigate_to(self, page):
        """Navigate to a specific page"""
        # Reset all nav buttons
        for btn in [self.btn_dashboard, self.btn_about, self.btn_quarantine, self.btn_notifications]:
            btn.setChecked(False)
        
        if page == 'dashboard':
            self.btn_dashboard.setChecked(True)
            self.show_dashboard()
        elif page == 'about':
            self.btn_about.setChecked(True)
            self.show_about()
        elif page == 'quarantine':
            self.btn_quarantine.setChecked(True)
            self.show_quarantine()
        elif page == 'notifications':
            self.btn_notifications.setChecked(True)
            self.show_notifications()
    
    def update_install_button(self):
        """Update install button text based on installation state"""
        if self.is_installed:
            self.install_btn.setText("⬆  Uninstall Agent")
            self.install_btn.setStyleSheet("""
                QPushButton {
                    background-color: #dc2626;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    padding: 12px 20px;
                    font-size: 13px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #b91c1c;
                }
            """)
        else:
            self.install_btn.setText("⬇  Install Agent")
            self.install_btn.setStyleSheet("""
                QPushButton {
                    background-color: #10b981;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    padding: 12px 20px;
                    font-size: 13px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #059669;
                }
            """)
    
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
        
        show_action = QAction("Show ArgusShield", self)
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

    def create_status_card(self, icon, title, subtitle, card_type="default"):
        """Create a status card widget"""
        card = QFrame()
        card.setObjectName(f"statusCard_{card_type}")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        card_layout.setSpacing(10)
        
        # Icon
        icon_label = QLabel(icon)
        icon_label.setStyleSheet(f"""
            font-size: 32px;
            color: {'#10b981' if card_type == 'secure' else '#9ca3af'};
        """)
        card_layout.addWidget(icon_label)
        
        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            font-size: 20px;
            font-weight: bold;
            color: {'#10b981' if card_type == 'secure' else '#ffffff'};
        """)
        card_layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel(subtitle)
        subtitle_label.setStyleSheet("font-size: 12px; color: #9ca3af;")
        subtitle_label.setWordWrap(True)
        card_layout.addWidget(subtitle_label)
        
        card_layout.addStretch()
        
        return card
    
    def create_protection_indicator(self, name, is_active):
        """Create a protection status indicator"""
        indicator_frame = QFrame()
        indicator_layout = QHBoxLayout(indicator_frame)
        indicator_layout.setContentsMargins(10, 8, 10, 8)
        indicator_layout.setSpacing(10)
        
        # Name label
        name_label = QLabel(name)
        name_label.setStyleSheet("font-size: 13px; color: #d1d5db;")
        indicator_layout.addWidget(name_label)
        
        indicator_layout.addStretch()
        
        # Status dot
        dot_label = QLabel("●")
        dot_label.setStyleSheet(f"""
            font-size: 12px;
            color: {'#10b981' if is_active else '#ef4444'};
        """)
        indicator_layout.addWidget(dot_label)
        
        return indicator_frame

    def show_dashboard(self):
        self.clear_main_frame()
        self.btn_dashboard.setChecked(True)
        layout = self.main_frame.layout()

        # Header section
        header_frame = QFrame()
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        # Status header
        status_section = QVBoxLayout()
        
        title_label = QLabel("System Status: Protected")
        title_label.setStyleSheet("font-size: 22px; font-weight: bold; color: #ffffff;")
        status_section.addWidget(title_label)
        
        status_indicator = QLabel("● Real-time protection is active")
        status_indicator.setStyleSheet("font-size: 13px; color: #10b981;")
        status_section.addWidget(status_indicator)
        
        header_layout.addLayout(status_section)
        header_layout.addStretch()
        
        # Notification bell
        bell_btn = QPushButton("🔔")
        bell_btn.setObjectName("iconButton")
        bell_btn.setFixedSize(40, 40)
        bell_btn.setCursor(Qt.PointingHandCursor)
        header_layout.addWidget(bell_btn)
        
        layout.addWidget(header_frame)

        # Cards section
        cards_frame = QFrame()
        cards_layout = QHBoxLayout(cards_frame)
        cards_layout.setSpacing(15)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        
        # Secure card
        secure_card = self.create_status_card(
            "✓",
            "Secure",
            "Your device is protected against all known threats.",
            "secure"
        )
        cards_layout.addWidget(secure_card)
        
        # Quick Scan card
        quick_scan_card = self.create_status_card(
            "⚡",
            "Quick Scan",
            "Scan critical system areas for active threats.",
            "default"
        )
        quick_scan_card.setCursor(Qt.PointingHandCursor)
        cards_layout.addWidget(quick_scan_card)
        
        # Last Scan card
        last_scan_card = self.create_status_card(
            "🕐",
            "Last Scan",
            "Completed 2 hours ago. No threats found.",
            "default"
        )
        cards_layout.addWidget(last_scan_card)
        
        layout.addWidget(cards_frame)

        # Bottom section: Chart + Protection Status
        bottom_frame = QFrame()
        bottom_layout = QHBoxLayout(bottom_frame)
        bottom_layout.setSpacing(20)
        bottom_layout.setContentsMargins(0, 0, 0, 0)

        # Threat Activity section
        threat_frame = QFrame()
        threat_frame.setObjectName("chartFrame")
        threat_layout = QVBoxLayout(threat_frame)
        threat_layout.setContentsMargins(20, 15, 20, 15)
        
        # Chart header
        chart_header = QHBoxLayout()
        chart_title = QLabel("⚠ Threat Activity")
        chart_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #ffffff;")
        chart_header.addWidget(chart_title)
        chart_header.addStretch()
        
        time_combo = QComboBox()
        time_combo.addItems(["This Week", "This Month", "This Year"])
        time_combo.setObjectName("timeCombo")
        chart_header.addWidget(time_combo)
        
        threat_layout.addLayout(chart_header)
        
        # Chart widget
        chart = ThreatActivityChart()
        threat_layout.addWidget(chart)
        
        bottom_layout.addWidget(threat_frame, 2)

        # Protection Status section
        protection_frame = QFrame()
        protection_frame.setObjectName("protectionFrame")
        protection_layout = QVBoxLayout(protection_frame)
        protection_layout.setContentsMargins(20, 15, 20, 15)
        
        protection_title = QLabel("Protection Status")
        protection_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #ffffff;")
        protection_layout.addWidget(protection_title)
        
        protection_layout.addSpacing(10)
        
        # Protection indicators
        protection_layout.addWidget(self.create_protection_indicator("Real-time Protection", self.protection_status['realtime']))
        protection_layout.addWidget(self.create_protection_indicator("Network Firewall", self.protection_status['firewall']))
        protection_layout.addWidget(self.create_protection_indicator("Email Shield", self.protection_status['email']))
        protection_layout.addWidget(self.create_protection_indicator("Ransomware Shield", self.protection_status['ransomware']))
        protection_layout.addWidget(self.create_protection_indicator("Web Protection", self.protection_status['web']))
        
        protection_layout.addStretch()
        
        # Manage Shields button
        manage_btn = QPushButton("Manage Shields")
        manage_btn.setObjectName("manageButton")
        manage_btn.setCursor(Qt.PointingHandCursor)
        protection_layout.addWidget(manage_btn)
        
        bottom_layout.addWidget(protection_frame, 1)

        layout.addWidget(bottom_frame, 1)

    def show_about(self):
        """Show about page"""
        self.clear_main_frame()
        layout = self.main_frame.layout()

        title = QLabel("About ArgusShield")
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)
        
        info_frame = QFrame()
        info_frame.setObjectName("infoFrame")
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(20, 20, 20, 20)
        info_layout.setSpacing(15)
        
        version_label = QLabel("Version: 1.0.0")
        version_label.setStyleSheet("font-size: 14px; color: #d1d5db;")
        info_layout.addWidget(version_label)
        
        desc_label = QLabel("ArgusShield is an advanced DLL injection detection system designed to protect your system from malicious software and security threats.")
        desc_label.setStyleSheet("font-size: 14px; color: #9ca3af;")
        desc_label.setWordWrap(True)
        info_layout.addWidget(desc_label)
        
        features_title = QLabel("Key Features:")
        features_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #ffffff; margin-top: 10px;")
        info_layout.addWidget(features_title)
        
        features = [
            "• Real-time DLL injection detection",
            "• Network firewall monitoring", 
            "• Email protection scanning",
            "• Ransomware shield",
            "• Web protection"
        ]
        
        for feature in features:
            feature_label = QLabel(feature)
            feature_label.setStyleSheet("font-size: 13px; color: #10b981;")
            info_layout.addWidget(feature_label)
        
        info_layout.addStretch()
        layout.addWidget(info_frame, 1)

    def show_quarantine(self):
        """Show quarantine page"""
        self.clear_main_frame()
        layout = self.main_frame.layout()

        title = QLabel("Quarantine")
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)
        
        subtitle = QLabel("Isolated threats are stored here for your review")
        subtitle.setStyleSheet("font-size: 13px; color: #9ca3af;")
        layout.addWidget(subtitle)
        
        layout.addSpacing(20)

        # Quarantine table
        table = QTableWidget()
        table.setObjectName("quarantineTable")
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Threat Name", "Type", "Date Quarantined", "Actions"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setRowCount(0)
        
        # Empty state
        empty_label = QLabel("🛡️ No threats in quarantine")
        empty_label.setStyleSheet("font-size: 16px; color: #6b7280; padding: 40px;")
        empty_label.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(table)
        layout.addWidget(empty_label)
        layout.addStretch()

    def show_notifications(self):
        """Show notifications page"""
        self.clear_main_frame()
        layout = self.main_frame.layout()

        title = QLabel("Notifications")
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)
        
        layout.addSpacing(20)
        
        # Sample notifications
        notifications = [
            {"icon": "✓", "title": "System scan completed", "time": "2 hours ago", "type": "success"},
            {"icon": "🛡", "title": "Real-time protection enabled", "time": "1 day ago", "type": "info"},
            {"icon": "⚠", "title": "Database updated successfully", "time": "2 days ago", "type": "warning"},
        ]
        
        for notif in notifications:
            notif_frame = QFrame()
            notif_frame.setObjectName("notificationItem")
            notif_layout = QHBoxLayout(notif_frame)
            notif_layout.setContentsMargins(15, 12, 15, 12)
            
            icon_label = QLabel(notif["icon"])
            icon_label.setStyleSheet("font-size: 20px;")
            notif_layout.addWidget(icon_label)
            
            text_layout = QVBoxLayout()
            title_label = QLabel(notif["title"])
            title_label.setStyleSheet("font-size: 14px; color: #ffffff; font-weight: bold;")
            text_layout.addWidget(title_label)
            
            time_label = QLabel(notif["time"])
            time_label.setStyleSheet("font-size: 12px; color: #6b7280;")
            text_layout.addWidget(time_label)
            
            notif_layout.addLayout(text_layout)
            notif_layout.addStretch()
            
            layout.addWidget(notif_frame)
        
        layout.addStretch()

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

    def toggle_install(self):
        """Toggle installation status"""
        if self.is_installed:
            self.uninstall_application()
        else:
            self.install_application()

    def is_admin(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def get_service_path(self):
        """Get the path to the ArgusShieldService.exe
        
        When installed via NSI, the service exe lives in the bin folder
        next to app.exe (e.g. C:\Program Files (x86)\ArgusShield\bin\).
        Fall back to PyInstaller's temp _MEIPASS folder for dev/testing.
        """
        # Prefer the permanent installed location next to the executable
        if hasattr(sys, '_MEIPASS'):
            app_dir = os.path.dirname(os.path.abspath(sys.executable))
        else:
            app_dir = os.path.dirname(os.path.abspath(__file__))
        
        service_path = os.path.join(app_dir, 'bin', 'ArgusShieldService.exe')
        if os.path.exists(service_path):
            return service_path
        
        # Fallback to PyInstaller bundled resource
        return os.path.join(get_resource_path('bin'), 'ArgusShieldService.exe')

    def install_application(self):
        """Handle the installation process - installs the background service"""
        # Check for admin privileges
        if not self.is_admin():
            QMessageBox.warning(
                self,
                'Administrator Required',
                'Installing the service requires administrator privileges.\n\nPlease run ArgusShield as Administrator.',
                QMessageBox.Ok
            )
            return

        reply = QMessageBox.question(
            self, 
            'Install ArgusShield', 
            'Do you want to install ArgusShield DLL Injection Detector?\n\nThis will install a background monitoring service.',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                service_path = self.get_service_path()
                
                if not os.path.exists(service_path):
                    QMessageBox.critical(
                        self,
                        'Error',
                        f'Service executable not found:\n{service_path}',
                        QMessageBox.Ok
                    )
                    return
                
                # Create the Windows service using sc command
                service_name = "ArgusShieldService"
                display_name = "ArgusShield Protection Service"
                
                # Create service
                create_cmd = [
                    'sc', 'create', service_name,
                    f'binPath={service_path}',
                    f'DisplayName={display_name}',
                    'start=auto'
                ]
                
                result = subprocess.run(
                    create_cmd,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode != 0 and 'exists' not in result.stderr.lower():
                    raise Exception(f'Failed to create service: {result.stderr}')
                
                # Set service description
                desc_cmd = [
                    'sc', 'description', service_name,
                    'ArgusShield DLL Injection Detection and Protection Service'
                ]
                subprocess.run(desc_cmd, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                
                # Start the service
                start_cmd = ['sc', 'start', service_name]
                subprocess.run(start_cmd, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                
                # Update state
                set_install_state(True)
                self.is_installed = True
                self.update_install_button()
                
                QMessageBox.information(
                    self, 
                    'Success', 
                    'ArgusShield has been installed and started successfully!\n\nThe protection service is now running in the background.'
                )
                self.show_dashboard()
                
            except Exception as e:
                QMessageBox.critical(
                    self,
                    'Installation Failed',
                    f'Failed to install the service:\n{str(e)}',
                    QMessageBox.Ok
                )

    def uninstall_application(self):
        """Handle the uninstallation process - removes the background service"""
        # Check for admin privileges
        if not self.is_admin():
            QMessageBox.warning(
                self,
                'Administrator Required',
                'Uninstalling the service requires administrator privileges.\n\nPlease run ArgusShield as Administrator.',
                QMessageBox.Ok
            )
            return

        reply = QMessageBox.question(
            self, 
            'Uninstall ArgusShield', 
            'Are you sure you want to uninstall ArgusShield DLL Injection Detector?\n\nThis will stop and remove the background monitoring service.',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                service_name = "ArgusShieldService"
                
                # Stop the service first
                stop_cmd = ['sc', 'stop', service_name]
                subprocess.run(
                    stop_cmd, 
                    capture_output=True, 
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Wait a moment for the service to stop
                import time
                time.sleep(2)
                
                # Delete the service
                delete_cmd = ['sc', 'delete', service_name]
                result = subprocess.run(
                    delete_cmd, 
                    capture_output=True, 
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode != 0 and 'does not exist' not in result.stderr.lower():
                    raise Exception(f'Failed to remove service: {result.stderr}')
                
                # Update state
                set_install_state(False)
                self.is_installed = False
                self.update_install_button()
                
                QMessageBox.information(
                    self, 
                    'Success', 
                    'ArgusShield has been uninstalled successfully!\n\nThe protection service has been stopped and removed.'
                )
                self.show_dashboard()
                
            except Exception as e:
                QMessageBox.critical(
                    self,
                    'Uninstallation Failed',
                    f'Failed to uninstall the service:\n{str(e)}',
                    QMessageBox.Ok
                )


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Apply dark theme stylesheet matching the design
    app.setStyleSheet("""
        QWidget {
            background-color: #111827;
            color: #ffffff;
            font-family: 'Segoe UI', Arial, sans-serif;
        }
        
        #sidebar {
            background-color: #1f2937;
            border-right: 1px solid #374151;
        }
        
        #mainFrame {
            background-color: #111827;
        }
        
        #navButton {
            background-color: transparent;
            color: #9ca3af;
            border: none;
            border-radius: 8px;
            padding: 12px 15px;
            font-size: 13px;
            text-align: left;
        }
        
        #navButton:hover {
            background-color: #374151;
            color: #ffffff;
        }
        
        #navButton:checked {
            background-color: #10b981;
            color: #ffffff;
        }
        
        #iconButton {
            background-color: #1f2937;
            border: 1px solid #374151;
            border-radius: 8px;
            font-size: 16px;
        }
        
        #iconButton:hover {
            background-color: #374151;
        }
        
        #statusCard_secure {
            background-color: rgba(16, 185, 129, 0.15);
            border: 1px solid #10b981;
            border-radius: 12px;
            min-height: 140px;
        }
        
        #statusCard_default {
            background-color: #1f2937;
            border: 1px solid #374151;
            border-radius: 12px;
            min-height: 140px;
        }
        
        #statusCard_default:hover {
            border-color: #4b5563;
        }
        
        #chartFrame {
            background-color: #1f2937;
            border: 1px solid #374151;
            border-radius: 12px;
        }
        
        #protectionFrame {
            background-color: #1f2937;
            border: 1px solid #374151;
            border-radius: 12px;
            min-width: 220px;
        }
        
        #infoFrame {
            background-color: #1f2937;
            border: 1px solid #374151;
            border-radius: 12px;
        }
        
        #timeCombo {
            background-color: #374151;
            border: 1px solid #4b5563;
            border-radius: 6px;
            padding: 5px 10px;
            color: #ffffff;
            min-width: 100px;
        }
        
        #timeCombo::drop-down {
            border: none;
            width: 20px;
        }
        
        #timeCombo QAbstractItemView {
            background-color: #374151;
            color: #ffffff;
            selection-background-color: #10b981;
        }
        
        #manageButton {
            background-color: #374151;
            color: #ffffff;
            border: none;
            border-radius: 8px;
            padding: 10px 20px;
            font-size: 13px;
        }
        
        #manageButton:hover {
            background-color: #4b5563;
        }
        
        #notificationItem {
            background-color: #1f2937;
            border: 1px solid #374151;
            border-radius: 8px;
            margin-bottom: 8px;
        }
        
        #notificationItem:hover {
            border-color: #4b5563;
        }
        
        #quarantineTable {
            background-color: #1f2937;
            border: 1px solid #374151;
            border-radius: 8px;
            gridline-color: #374151;
        }
        
        #quarantineTable::item {
            padding: 10px;
        }
        
        #quarantineTable QHeaderView::section {
            background-color: #374151;
            color: #ffffff;
            padding: 10px;
            border: none;
            font-weight: bold;
        }
        
        QTableWidget {
            background-color: #1f2937;
            color: #ffffff;
            gridline-color: #374151;
            border: 1px solid #374151;
            border-radius: 8px;
        }
        
        QTableWidget::item {
            padding: 8px;
        }
        
        QTableWidget QHeaderView::section {
            background-color: #374151;
            color: #ffffff;
            padding: 10px;
            border: none;
        }
        
        QScrollBar:vertical {
            background-color: #1f2937;
            width: 10px;
            border-radius: 5px;
        }
        
        QScrollBar::handle:vertical {
            background-color: #4b5563;
            border-radius: 5px;
            min-height: 20px;
        }
        
        QScrollBar::handle:vertical:hover {
            background-color: #6b7280;
        }
        
        QMessageBox {
            background-color: #1f2937;
        }
        
        QMessageBox QLabel {
            color: #ffffff;
        }
        
        QMessageBox QPushButton {
            background-color: #374151;
            color: #ffffff;
            border: none;
            border-radius: 6px;
            padding: 8px 20px;
            min-width: 80px;
        }
        
        QMessageBox QPushButton:hover {
            background-color: #4b5563;
        }
    """)

    window = DLLDetectorUI()
    window.show()
    sys.exit(app.exec_())