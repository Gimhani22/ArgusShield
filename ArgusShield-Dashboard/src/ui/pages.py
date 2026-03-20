from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QSizePolicy, QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QGridLayout, QScrollArea, QGroupBox, QCheckBox,
    QComboBox, QLineEdit
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont
from ui.styles import (
    CONTENT_BOX_STYLE, INNER_BOX_STYLE, TABLE_STYLE,
    STATUS_BANNER_PROTECTED, STATUS_BANNER_ALERT,
)
from database import get_detection_stats, get_recent_detections, get_quarantine_entries


# ──────────────────────────────────────────────────────────────────────────────
#  Shared inner-box style  (#1e1e1e background, used for all section panels)
# ──────────────────────────────────────────────────────────────────────────────

def make_inner_box(title=''):
    """Return a QGroupBox styled with the inner box theme."""
    box = QGroupBox(title)
    box.setStyleSheet(INNER_BOX_STYLE)
    lyt = QVBoxLayout()
    lyt.setContentsMargins(12, 20, 12, 12)
    lyt.setSpacing(6)
    box.setLayout(lyt)
    return box


# ──────────────────────────────────────────────────────────────────────────────
#  Stat card widget
# ──────────────────────────────────────────────────────────────────────────────

class StatCard(QWidget):
    def __init__(self, title, value, color='#2d8cff'):
        super().__init__()
        self.setStyleSheet(f"""
            StatCard {{
                background-color: #1e1e1e;
                border-radius: 8px;
                border-left: 3px solid {color};
            }}
        """)
        self.setMinimumHeight(85)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)

        title_lbl = QLabel(title.upper())
        title_lbl.setStyleSheet('font-size: 11px; color: #666; font-weight: bold; '
                                'letter-spacing: 1px; background: transparent; border: none;')

        self.value_lbl = QLabel(str(value))
        self.value_lbl.setStyleSheet(f'font-size: 26px; font-weight: bold; '
                                     f'color: {color}; background: transparent; border: none;')

        layout.addWidget(title_lbl)
        layout.addWidget(self.value_lbl)

    def set_value(self, v):
        self.value_lbl.setText(str(v))


# ──────────────────────────────────────────────────────────────────────────────
#  Feature card (for About page)
# ──────────────────────────────────────────────────────────────────────────────

class FeatureCard(QWidget):
    def __init__(self, title, desc, color='#2d8cff'):
        super().__init__()
        self.setStyleSheet(f"""
            FeatureCard {{
                background-color: #1e1e1e;
                border-radius: 8px;
                border-top: 3px solid {color};
            }}
        """)
        self.setMinimumHeight(100)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet('font-size: 14px; font-weight: bold; color: #eee; background: transparent;')

        desc_lbl = QLabel(desc)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet('font-size: 12px; color: #888; background: transparent;')

        layout.addWidget(title_lbl)
        layout.addWidget(desc_lbl)
        layout.addStretch()


SEVERITY_COLORS = {
    'Critical': '#e74c3c',
    'High':     '#e67e22',
    'Medium':   '#f1c40f',
    'Low':      '#27ae60',
}


# ──────────────────────────────────────────────────────────────────────────────
#  1. DASHBOARD PAGE
# ──────────────────────────────────────────────────────────────────────────────

class DashboardPage(QWidget):
    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        box = QWidget()
        box.setStyleSheet(CONTENT_BOX_STYLE)
        box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        outer.addWidget(box)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet('QScrollArea { border: none; background: transparent; }')
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(0, 0, 0, 0)
        box_layout.addWidget(scroll)

        container = QWidget()
        container.setStyleSheet('background: transparent;')
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setSpacing(14)
        layout.setContentsMargins(14, 14, 14, 14)

        # Header
        header = QLabel('Dashboard')
        header.setStyleSheet('font-size: 28px; font-weight: bold; color: #fff; background: transparent;')
        sub = QLabel('ArgusShield Security Overview')
        sub.setStyleSheet('font-size: 13px; color: #666; background: transparent;')
        layout.addWidget(header)
        layout.addWidget(sub)

        # Status banner
        self.status_banner = QLabel('Protection Active  -  System is Secure')
        self.status_banner.setAlignment(Qt.AlignCenter)
        self.status_banner.setStyleSheet(STATUS_BANNER_PROTECTED)
        layout.addWidget(self.status_banner)

        # Stat cards — initialized to 0, refresh_data fills from DB
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)
        self.card_total  = StatCard('Total Events',       '0', '#e74c3c')
        self.card_blocked = StatCard('Attacks Blocked',   '0', '#e67e22')
        self.card_today  = StatCard('Today',              '0', '#f39c12')
        self.card_dll    = StatCard('DLL Injections',     '0', '#9b59b6')
        for c in (self.card_total, self.card_blocked, self.card_today, self.card_dll):
            cards_row.addWidget(c)
        layout.addLayout(cards_row)

        # Recent activity table — populated from database
        recent_box = make_inner_box('Recent Activity')
        self.recent_table = QTableWidget(0, 6)
        self.recent_table.setHorizontalHeaderLabels(
            ['Time', 'Event', 'Source PID', 'Target PID', 'Technique', 'Action'])
        self.recent_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.recent_table.verticalHeader().setVisible(False)
        self.recent_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.recent_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.recent_table.setAlternatingRowColors(True)
        self.recent_table.setStyleSheet(TABLE_STYLE)
        recent_box.layout().addWidget(self.recent_table)
        layout.addWidget(recent_box)

        # System info
        info_box = make_inner_box('System Information')
        info_grid = QGridLayout()
        info_grid.setSpacing(10)
        infos = [
            ('Protection Mode',  'Real-time'),
            ('Detection Engine', 'Multi-Layer Scoring'),
            ('ETW Service',      'ArgusShieldService'),
            ('Agent Service',    'ArgusShieldAgent'),
        ]
        for row, (k, v) in enumerate(infos):
            k_lbl = QLabel(k + ':')
            k_lbl.setStyleSheet('color: #666; font-size: 13px; background: transparent;')
            v_lbl = QLabel(v)
            v_lbl.setStyleSheet('color: #ddd; font-size: 13px; font-weight: bold; background: transparent;')
            info_grid.addWidget(k_lbl, row, 0)
            info_grid.addWidget(v_lbl, row, 1)
        info_box.layout().addLayout(info_grid)
        layout.addWidget(info_box)

        layout.addStretch()

        # Load data from database
        self.refresh_data()

    def refresh_data(self):
        """Reload stat cards and recent table from the database."""
        stats = get_detection_stats()
        self.card_total.set_value(str(stats.get('total', 0)))
        self.card_blocked.set_value(str(stats.get('blocked', 0)))
        self.card_today.set_value(str(stats.get('today', 0)))
        self.card_dll.set_value(str(stats.get('dll_injection', 0)))

        # Update status banner
        blocked = stats.get('blocked', 0)
        if blocked > 0:
            self.status_banner.setText(
                f'Protection Active  -  {blocked} attacks blocked')
        else:
            self.status_banner.setText('Protection Active  -  System is Secure')

        # Refresh recent activity table from DB
        detections = get_recent_detections(10)
        self.recent_table.setRowCount(len(detections))
        for r, det in enumerate(detections):
            self.recent_table.setRowHeight(r, 36)
            vals = [
                det.get('timestamp', ''),
                det.get('event_type', ''),
                str(det.get('pid', '')),
                str(det.get('target_pid', '')),
                det.get('technique', ''),
                det.get('action', 'Detected'),
            ]
            for c, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                item.setTextAlignment(Qt.AlignCenter)
                if c == 5:
                    color = '#e74c3c' if val == 'Blocked' else '#f39c12'
                    item.setForeground(QColor(color))
                self.recent_table.setItem(r, c, item)


# ──────────────────────────────────────────────────────────────────────────────
#  2. QUARANTINE PAGE
# ──────────────────────────────────────────────────────────────────────────────

class QuarantinePage(QWidget):
    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        box = QWidget()
        box.setStyleSheet(CONTENT_BOX_STYLE)
        box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        outer.addWidget(box)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet('QScrollArea { border: none; background: transparent; }')
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(0, 0, 0, 0)
        box_layout.addWidget(scroll)

        container = QWidget()
        container.setStyleSheet('background: transparent;')
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setSpacing(14)
        layout.setContentsMargins(14, 14, 14, 14)

        # Header row
        h_row = QHBoxLayout()
        title_col = QVBoxLayout()
        header = QLabel('Quarantine')
        header.setStyleSheet('font-size: 28px; font-weight: bold; color: #fff; background: transparent;')
        sub = QLabel('Attacks detected and blocked by ArgusShield')
        sub.setStyleSheet('font-size: 13px; color: #666; background: transparent;')
        title_col.addWidget(header)
        title_col.addWidget(sub)
        h_row.addLayout(title_col)
        h_row.addStretch()

        export_btn = QPushButton('Export CSV')
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #2d8cff;
                border: 1px solid #2d8cff;
                border-radius: 5px;
                padding: 7px 16px;
                font-size: 13px;
            }
            QPushButton:hover { background-color: #2d8cff; color: #fff; }
        """)
        export_btn.clicked.connect(self.export_csv)
        h_row.addWidget(export_btn)
        layout.addLayout(h_row)

        # Summary stat cards — filled from DB
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)
        self.card_total    = StatCard('Total Events',    '0', '#e74c3c')
        self.card_blocked  = StatCard('Blocked',         '0', '#e67e22')
        self.card_critical = StatCard('Critical',        '0', '#e74c3c')
        self.card_high     = StatCard('High',            '0', '#e67e22')
        self.card_medium   = StatCard('Medium',          '0', '#f1c40f')
        for c in (self.card_total, self.card_blocked, self.card_critical,
                  self.card_high, self.card_medium):
            cards_row.addWidget(c)
        layout.addLayout(cards_row)

        # Attack log table — populated from database, no hardcoded data
        table_box = make_inner_box('Event Log')
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ['Timestamp', 'Source PID', 'Target PID', 'DLL / Source', 'Technique', 'Severity', 'Action'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(TABLE_STYLE)
        table_box.layout().addWidget(self.table)
        layout.addWidget(table_box)

        layout.addStretch()

        # Load data from database
        self.refresh_data()

    def refresh_data(self):
        """Reload the quarantine table and stat cards from the database."""
        entries = get_quarantine_entries(50)

        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        blocked_count = 0

        self.table.setRowCount(len(entries))
        for r, det in enumerate(entries):
            self.table.setRowHeight(r, 36)
            severity = det.get('severity', 'Medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            if det.get('action', '') == 'Blocked':
                blocked_count += 1

            vals = [
                det.get('timestamp', ''),
                str(det.get('pid', '')),
                str(det.get('target_pid', '')),
                det.get('dll_path', 'N/A'),
                det.get('technique', 'Unknown'),
                severity,
                det.get('action', 'Detected'),
            ]
            for c, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                item.setTextAlignment(Qt.AlignCenter)
                if c == 5:
                    item.setForeground(QColor(SEVERITY_COLORS.get(val, '#ddd')))
                if c == 6:
                    color = '#e74c3c' if val == 'Blocked' else '#f39c12'
                    item.setForeground(QColor(color))
                self.table.setItem(r, c, item)

        self.card_total.set_value(str(len(entries)))
        self.card_blocked.set_value(str(blocked_count))
        self.card_critical.set_value(str(severity_counts.get('Critical', 0)))
        self.card_high.set_value(str(severity_counts.get('High', 0)))
        self.card_medium.set_value(str(severity_counts.get('Medium', 0)))

    def export_csv(self):
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.information(self, 'Export', 'Log exported to quarantine_log.csv (demo).')


# ──────────────────────────────────────────────────────────────────────────────
#  3. SETTINGS PAGE
# ──────────────────────────────────────────────────────────────────────────────

class ToggleRow(QWidget):
    def __init__(self, label, description='', checked=True):
        super().__init__()
        self.setStyleSheet('background: transparent;')
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 6, 0, 6)

        text_col = QVBoxLayout()
        lbl = QLabel(label)
        lbl.setStyleSheet('font-size: 13px; color: #ddd; font-weight: bold; background: transparent;')
        text_col.addWidget(lbl)
        if description:
            desc = QLabel(description)
            desc.setStyleSheet('font-size: 11px; color: #555; background: transparent;')
            text_col.addWidget(desc)

        self.checkbox = QCheckBox()
        self.checkbox.setChecked(checked)
        self.checkbox.setStyleSheet("""
            QCheckBox::indicator {
                width: 40px; height: 22px;
                border-radius: 11px;
            }
            QCheckBox::indicator:unchecked {
                background-color: #2a2a2a;
                border: 2px solid #444;
                border-radius: 11px;
            }
            QCheckBox::indicator:checked {
                background-color: #2d8cff;
                border: 2px solid #2d8cff;
                border-radius: 11px;
            }
        """)

        row.addLayout(text_col)
        row.addStretch()
        row.addWidget(self.checkbox)


class SettingsPage(QWidget):
    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        box = QWidget()
        box.setStyleSheet(CONTENT_BOX_STYLE)
        box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        outer.addWidget(box)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet('QScrollArea { border: none; background: transparent; }')
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(0, 0, 0, 0)
        box_layout.addWidget(scroll)

        container = QWidget()
        container.setStyleSheet('background: transparent;')
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setSpacing(14)
        layout.setContentsMargins(14, 14, 14, 14)

        # Header
        header = QLabel('Settings')
        header.setStyleSheet('font-size: 28px; font-weight: bold; color: #fff; background: transparent;')
        sub = QLabel('Configure ArgusShield protection and behavior')
        sub.setStyleSheet('font-size: 13px; color: #666; background: transparent;')
        layout.addWidget(header)
        layout.addWidget(sub)

        # Protection
        prot_box = make_inner_box('Protection')
        pb = prot_box.layout()
        pb.addWidget(ToggleRow('Real-time DLL Injection Protection',
                               'Monitor and block DLL injections as they happen', True))
        pb.addWidget(self._divider())
        pb.addWidget(ToggleRow('Process Hooking Detection',
                               'Detect API and inline hooks in running processes', True))
        pb.addWidget(self._divider())
        pb.addWidget(ToggleRow('Kernel-level Exploit Guard',
                               'Block exploits targeting the Windows kernel', True))
        layout.addWidget(prot_box)

        # Notifications
        notif_box = make_inner_box('Notifications')
        nb = notif_box.layout()
        nb.addWidget(ToggleRow('Desktop Alerts',
                               'Show pop-up notifications for blocked threats', True))
        nb.addWidget(self._divider())
        nb.addWidget(ToggleRow('System Tray Alerts',
                               'Display alerts in the system tray', True))
        layout.addWidget(notif_box)

        # Logging
        log_box = make_inner_box('Logging')
        lb = log_box.layout()
        lb.addWidget(ToggleRow('Enable Detailed Logging',
                               'Record all security events to a log file', True))
        lb.addWidget(self._divider())

        log_path_row = QHBoxLayout()
        log_dir_lbl = QLabel('Log Directory')
        log_dir_lbl.setStyleSheet('font-size: 13px; color: #888; min-width: 90px; background: transparent;')
        self.log_path_edit = QLineEdit(r'C:\ProgramData\ArgusShield\Logs')
        self.log_path_edit.setStyleSheet("""
            QLineEdit {
                background-color: #181818;
                color: #ddd;
                border: 1px solid #2a2a2a;
                border-radius: 5px;
                padding: 6px 10px;
                font-size: 13px;
            }
        """)
        browse_btn = QPushButton('Browse')
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #2d8cff;
                border: 1px solid #2d8cff;
                border-radius: 5px;
                padding: 6px 14px;
                font-size: 13px;
            }
            QPushButton:hover { background-color: #2d8cff; color: #fff; }
        """)
        log_path_row.addWidget(log_dir_lbl)
        log_path_row.addWidget(self.log_path_edit)
        log_path_row.addWidget(browse_btn)
        lb.addLayout(log_path_row)
        layout.addWidget(log_box)

        # Save
        save_btn = QPushButton('Save Settings')
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #2d8cff;
                color: #fff;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
                padding: 10px 28px;
                border: none;
            }
            QPushButton:hover  { background-color: #1a5caf; }
            QPushButton:pressed { background-color: #0f3070; }
        """)
        save_btn.clicked.connect(self.save_settings)
        bottom_row = QHBoxLayout()
        bottom_row.addStretch()
        bottom_row.addWidget(save_btn)
        layout.addLayout(bottom_row)
        layout.addStretch()

    def _divider(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet('color: #2a2a2a; margin: 1px 0;')
        return line

    def save_settings(self):
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.information(self, 'Settings', 'Settings saved successfully.')

# ──────────────────────────────────────────────────────────────────────────────
#  4. ABOUT PAGE
# ──────────────────────────────────────────────────────────────────────────────

class AboutPage(QWidget):
    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        box = QWidget()
        box.setStyleSheet(CONTENT_BOX_STYLE)
        box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        outer.addWidget(box)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet('QScrollArea { border: none; background: transparent; }')
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(0, 0, 0, 0)
        box_layout.addWidget(scroll)

        container = QWidget()
        container.setStyleSheet('background: transparent;')
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setSpacing(16)
        layout.setContentsMargins(14, 14, 14, 14)

        # Hero section
        hero_box = make_inner_box()
        hero_lyt = hero_box.layout()
        hero_lyt.setAlignment(Qt.AlignCenter)

        title = QLabel('ArgusShield')
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet('font-size: 42px; font-weight: bold; color: #2d8cff; background: transparent;')
        hero_lyt.addWidget(title)

        version = QLabel('Version 1.0.0')
        version.setAlignment(Qt.AlignCenter)
        version.setStyleSheet('font-size: 18px; color: #555; background: transparent;')
        hero_lyt.addWidget(version)

        tagline = QLabel('Security Against Advanced Injection Attacks')
        tagline.setAlignment(Qt.AlignCenter)
        tagline.setWordWrap(True)
        tagline.setStyleSheet('font-size: 14px; color: #888; margin-top: 8px; background: transparent;')
        hero_lyt.addWidget(tagline)

        layout.addWidget(hero_box)

        # Feature cards grid
        features_label = QLabel('Key Features')
        features_label.setStyleSheet('font-size: 20px; font-weight: bold; color: #ddd; background: transparent;')
        layout.addWidget(features_label)

        features_row1 = QHBoxLayout()
        features_row1.setSpacing(12)
        features_row1.addWidget(FeatureCard(
            'Real-time DLL Protection',
            'Monitor and block DLL injection attacks as they happen using ETW tracing.',
            '#e74c3c'))
        features_row1.addWidget(FeatureCard(
            'Multi-Layer Scoring',
            'Context enrichment, code signing validation, and behavior analysis to reduce false positives.',
            '#f39c12'))
        features_row1.addWidget(FeatureCard(
            'Process Monitoring',
            'Parent-child relationship analysis and burst detection for injection attempts.',
            '#9b59b6'))
        layout.addLayout(features_row1)

        features_row2 = QHBoxLayout()
        features_row2.setSpacing(12)
        features_row2.addWidget(FeatureCard(
            'Code Signing Validation',
            'WinVerifyTrust checks to distinguish trusted publishers from unknown binaries.',
            '#2d8cff'))
        features_row2.addWidget(FeatureCard(
            'Lightweight Operation',
            'Background service with minimal CPU and memory footprint.',
            '#27ae60'))
        features_row2.addWidget(FeatureCard(
            'Threat Blocking',
            'Automatic termination of injector processes when score exceeds threshold.',
            '#e67e22'))
        layout.addLayout(features_row2)

        # Credits
        credits_box = make_inner_box('Credits')
        credits_lyt = credits_box.layout()
        credits_text = QLabel(
            'Developed as a Final Year Project.\n'
            'Built with ETW (Event Tracing for Windows), C++ Windows Services, and PyQt5.\n'
            'MITRE ATT&CK Framework: T1055.001 (Process Injection: DLL Injection)'
        )
        credits_text.setWordWrap(True)
        credits_text.setStyleSheet('font-size: 13px; color: #888; line-height: 1.6; background: transparent;')
        credits_lyt.addWidget(credits_text)
        layout.addWidget(credits_box)

        layout.addStretch()
