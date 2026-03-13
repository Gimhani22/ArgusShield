from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QSizePolicy, QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QGridLayout, QScrollArea, QGroupBox, QCheckBox,
    QComboBox, QLineEdit
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPainter, QColor, QPen, QFont
from ui.styles import CONTENT_BOX_STYLE, INNER_BOX_STYLE, TABLE_STYLE


# ──────────────────────────────────────────────────────────────────────────────
#  Shared inner-box style  (#1e1e1e background, used for all section panels)
# ──────────────────────────────────────────────────────────────────────────────

def make_inner_box(title=''):
    """Return a QGroupBox styled with the inner box theme."""
    box = QGroupBox(title)
    box.setStyleSheet(INNER_BOX_STYLE)
    lyt = QVBoxLayout()
    lyt.setContentsMargins(12, 16, 12, 12)
    lyt.setSpacing(6)
    box.setLayout(lyt)
    return box


# ──────────────────────────────────────────────────────────────────────────────
#  Bar-chart widget  (pure QPainter — no extra dependencies)
# ──────────────────────────────────────────────────────────────────────────────

class BarChartWidget(QWidget):
    """Simple bar chart rendered with QPainter."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(200)
        self._data = []
        self._title = ''
        self._bar_color = QColor('#2d8cff')

    def set_data(self, data, title='', bar_color='#2d8cff'):
        self._data = data
        self._title = title
        self._bar_color = QColor(bar_color)
        self.update()

    def paintEvent(self, event):
        if not self._data:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        pad_l, pad_r, pad_t, pad_b = 50, 20, 30, 40
        chart_w = w - pad_l - pad_r
        chart_h = h - pad_t - pad_b
        max_val  = max(v for _, v in self._data) or 1

        # Background matches inner box
        painter.fillRect(0, 0, w, h, QColor('#1e1e1e'))

        # Title
        if self._title:
            painter.setPen(QColor('#ccc'))
            f = QFont(); f.setPointSize(9); f.setBold(True)
            painter.setFont(f)
            painter.drawText(pad_l, 20, self._title)

        # Grid lines
        grid_pen = QPen(QColor('#2a2a2a'))
        grid_pen.setWidth(1)
        for i in range(5):
            y = pad_t + int(chart_h * i / 4)
            painter.setPen(grid_pen)
            painter.drawLine(pad_l, y, pad_l + chart_w, y)
            painter.setPen(QColor('#555'))
            f2 = QFont(); f2.setPointSize(8)
            painter.setFont(f2)
            painter.drawText(2, y + 5, 44, 14, Qt.AlignRight,
                             str(int(max_val * (4 - i) / 4)))

        # Bars
        n     = len(self._data)
        gap   = chart_w / n
        bar_w = max(8, int(gap * 0.55))

        for i, (lbl, val) in enumerate(self._data):
            bar_h = int(chart_h * val / max_val)
            x = pad_l + int(gap * i + gap / 2 - bar_w / 2)
            y = pad_t + chart_h - bar_h

            shadow = QColor(self._bar_color); shadow.setAlpha(50)
            painter.fillRect(x + 2, y + 2, bar_w, bar_h, shadow)
            painter.fillRect(x,     y,     bar_w, bar_h, self._bar_color)

            painter.setPen(QColor('#888'))
            f3 = QFont(); f3.setPointSize(8)
            painter.setFont(f3)
            painter.drawText(x - 10, pad_t + chart_h + 5, bar_w + 20, 30,
                             Qt.AlignHCenter, lbl)

        painter.end()


# ──────────────────────────────────────────────────────────────────────────────
#  Stat card widget
# ──────────────────────────────────────────────────────────────────────────────

class StatCard(QWidget):
    def __init__(self, title, value, color='#2d8cff'):
        super().__init__()
        self.setStyleSheet(f"""
            QWidget {{
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
                                'letter-spacing: 1px; border: none;')

        self.value_lbl = QLabel(str(value))
        self.value_lbl.setStyleSheet(f'font-size: 26px; font-weight: bold; '
                                     f'color: {color}; border: none;')

        layout.addWidget(title_lbl)
        layout.addWidget(self.value_lbl)

    def set_value(self, v):
        self.value_lbl.setText(str(v))


# ──────────────────────────────────────────────────────────────────────────────
#  1. DASHBOARD PAGE
# ──────────────────────────────────────────────────────────────────────────────

class DashboardPage(QWidget):
    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        # Outer content box  ← uses CONTENT_BOX_STYLE (#222)
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
        header.setStyleSheet('font-size: 28px; font-weight: bold; color: #fff;')
        sub = QLabel('ArgusShield Security Overview')
        sub.setStyleSheet('font-size: 13px; color: #666;')
        layout.addWidget(header)
        layout.addWidget(sub)

        # Status banner
        self.status_banner = QLabel('Protection Active  —  System is Secure')
        self.status_banner.setAlignment(Qt.AlignCenter)
        self.status_banner.setStyleSheet("""
            background-color: #152a1e;
            color: #27ae60;
            font-size: 14px;
            font-weight: bold;
            border: 1px solid #27ae60;
            border-radius: 6px;
            padding: 10px;
        """)
        layout.addWidget(self.status_banner)

        # Stat cards
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        self.card_total  = StatCard('Total Attacks Blocked', '1,284', '#e74c3c')
        self.card_today  = StatCard('Blocked Today',          '17',    '#f39c12')
        self.card_dll    = StatCard('DLL Injection Stopped',  '342',   '#9b59b6')
        self.card_uptime = StatCard('System Uptime',          '14 d',  '#2d8cff')
        for c in (self.card_total, self.card_today, self.card_dll, self.card_uptime):
            cards_row.addWidget(c)
        layout.addLayout(cards_row)

        # Charts row
        charts_row = QHBoxLayout()
        charts_row.setSpacing(10)

        weekly_chart = BarChartWidget()
        weekly_chart.setMinimumHeight(210)
        weekly_chart.set_data(
            [('Mon', 12), ('Tue', 8), ('Wed', 21), ('Thu', 5),
             ('Fri', 17), ('Sat', 3), ('Sun', 9)],
            'Attacks Blocked (Last 7 Days)', '#e74c3c')
        w_box = make_inner_box('Weekly Attack History')
        w_box.layout().addWidget(weekly_chart)
        charts_row.addWidget(w_box, 3)

        type_chart = BarChartWidget()
        type_chart.setMinimumHeight(210)
        type_chart.set_data(
            [('DLL', 342), ('Proc\nInject', 198), ('Hook', 97),
             ('Kernel', 44), ('Other', 31)],
            'Attack Breakdown by Type', '#9b59b6')
        t_box = make_inner_box('Attack Types')
        t_box.layout().addWidget(type_chart)
        charts_row.addWidget(t_box, 2)

        layout.addLayout(charts_row)

        # Recent activity table
        recent_box = make_inner_box('Recent Activity')
        recent_table = QTableWidget(0, 4)
        recent_table.setHorizontalHeaderLabels(['Time', 'Process', 'Attack Type', 'Status'])
        recent_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        recent_table.verticalHeader().setVisible(False)
        recent_table.setEditTriggers(QTableWidget.NoEditTriggers)
        recent_table.setSelectionBehavior(QTableWidget.SelectRows)
        recent_table.setAlternatingRowColors(True)
        recent_table.setMaximumHeight(175)
        recent_table.setStyleSheet(TABLE_STYLE)

        rows = [
            ('13:41:02', 'explorer.exe',  'DLL Injection',    'Blocked'),
            ('12:58:17', 'chrome.exe',    'Process Hooking',  'Blocked'),
            ('11:30:44', 'svchost.exe',   'Kernel Exploit',   'Blocked'),
            ('09:15:03', 'notepad.exe',   'DLL Sideloading',  'Blocked'),
            ('07:02:55', 'winlogon.exe',  'Injection Attempt','Blocked'),
        ]
        recent_table.setRowCount(len(rows))
        for r, (t, proc, atype, status) in enumerate(rows):
            for c, val in enumerate((t, proc, atype, status)):
                item = QTableWidgetItem(val)
                item.setTextAlignment(Qt.AlignCenter)
                if c == 3:
                    item.setForeground(QColor('#e74c3c'))
                recent_table.setItem(r, c, item)

        recent_box.layout().addWidget(recent_table)
        layout.addWidget(recent_box)

        # System info
        info_box = make_inner_box('System Information')
        info_grid = QGridLayout()
        info_grid.setSpacing(8)
        infos = [
            ('Driver Status',    'Loaded and Active'),
            ('Monitor Mode',     'Real-time'),
            ('Protection Level', 'Maximum'),
            ('Last Scan',        '2026-02-24   11:30 AM'),
            ('Threats Removed',  '1,284'),
            ('Engine Version',   'v3.7.1'),
        ]
        for row, (k, v) in enumerate(infos):
            k_lbl = QLabel(k + ':')
            k_lbl.setStyleSheet('color: #666; font-size: 13px;')
            v_lbl = QLabel(v)
            v_lbl.setStyleSheet('color: #ddd; font-size: 13px; font-weight: bold;')
            info_grid.addWidget(k_lbl, row, 0)
            info_grid.addWidget(v_lbl, row, 1)
        info_box.layout().addLayout(info_grid)
        layout.addWidget(info_box)

        layout.addStretch()


# ──────────────────────────────────────────────────────────────────────────────
#  2. QUARANTINE PAGE
# ──────────────────────────────────────────────────────────────────────────────

SAMPLE_ATTACKS = [
    ('2026-02-24 13:41', 'explorer.exe',   'C:\\Windows\\System32\\evil.dll', 'DLL Injection',    'High',    'Blocked'),
    ('2026-02-24 12:58', 'chrome.exe',     'N/A',                             'Process Hooking',  'Medium',  'Blocked'),
    ('2026-02-24 11:30', 'svchost.exe',    'C:\\Temp\\rootkit.sys',           'Kernel Exploit',   'Critical','Blocked'),
    ('2026-02-24 09:15', 'notepad.exe',    'C:\\Users\\User\\AppData\\x.dll', 'DLL Sideloading',  'Low',     'Blocked'),
    ('2026-02-24 07:02', 'winlogon.exe',   'N/A',                             'Code Injection',   'High',    'Blocked'),
    ('2026-02-23 22:14', 'powershell.exe', 'C:\\Temp\\inject.dll',            'DLL Injection',    'High',    'Blocked'),
    ('2026-02-23 18:05', 'cmd.exe',        'N/A',                             'Process Inject',   'Medium',  'Blocked'),
    ('2026-02-23 14:37', 'lsass.exe',      'C:\\Windows\\Temp\\spy.dll',      'Memory Scraping',  'Critical','Blocked'),
    ('2026-02-23 10:20', 'services.exe',   'N/A',                             'Token Impersonat.','Medium',  'Blocked'),
    ('2026-02-22 20:55', 'taskmgr.exe',    'C:\\Temp\\hook.dll',              'API Hooking',      'Low',     'Blocked'),
    ('2026-02-22 15:30', 'explorer.exe',   'C:\\Windows\\System32\\bad.dll',  'DLL Injection',    'High',    'Blocked'),
    ('2026-02-21 09:45', 'chrome.exe',     'N/A',                             'Sandbox Escape',   'Critical','Blocked'),
]

SEVERITY_COLORS = {
    'Critical': '#e74c3c',
    'High':     '#e67e22',
    'Medium':   '#f1c40f',
    'Low':      '#27ae60',
}


class QuarantinePage(QWidget):
    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        # Outer content box  ← uses CONTENT_BOX_STYLE (#222)
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
        header.setStyleSheet('font-size: 28px; font-weight: bold; color: #fff;')
        sub = QLabel('Attacks detected and blocked by ArgusShield')
        sub.setStyleSheet('font-size: 13px; color: #666;')
        title_col.addWidget(header)
        title_col.addWidget(sub)
        h_row.addLayout(title_col)
        h_row.addStretch()

        clear_btn = QPushButton('Clear Log')
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #e74c3c;
                border: 1px solid #e74c3c;
                border-radius: 5px;
                padding: 7px 16px;
                font-size: 13px;
            }
            QPushButton:hover { background-color: #e74c3c; color: #fff; }
        """)
        clear_btn.clicked.connect(self.clear_log)
        h_row.addWidget(clear_btn)

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

        # Summary stat cards
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        self.card_total    = StatCard('Total Quarantined', str(len(SAMPLE_ATTACKS)), '#e74c3c')
        self.card_critical = StatCard('Critical',          '3',  '#e74c3c')
        self.card_high     = StatCard('High',              '4',  '#e67e22')
        self.card_medium   = StatCard('Medium',            '3',  '#f1c40f')
        self.card_low      = StatCard('Low',               '2',  '#27ae60')
        for c in (self.card_total, self.card_critical, self.card_high,
                  self.card_medium, self.card_low):
            cards_row.addWidget(c)
        layout.addLayout(cards_row)

        # Charts
        charts_row = QHBoxLayout()
        charts_row.setSpacing(10)

        weekly_chart = BarChartWidget()
        weekly_chart.set_data(
            [('Mon', 12), ('Tue', 8), ('Wed', 21), ('Thu', 5),
             ('Fri', 17), ('Sat', 3), ('Sun', 9)],
            'Attacks per Day', '#e74c3c')
        wc_box = make_inner_box('Weekly Attack History')
        wc_box.layout().addWidget(weekly_chart)
        charts_row.addWidget(wc_box, 3)

        type_chart = BarChartWidget()
        type_chart.set_data(
            [('DLL\nInject', 5), ('Hooking', 3), ('Kernel', 2),
             ('Code\nInject', 1), ('Other', 1)],
            'Attack Types', '#9b59b6')
        tc_box = make_inner_box('Attack Type Breakdown')
        tc_box.layout().addWidget(type_chart)
        charts_row.addWidget(tc_box, 2)

        layout.addLayout(charts_row)

        # Attack log table
        table_box = make_inner_box('Quarantined Attacks Log')
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ['Timestamp', 'Process', 'File / Source', 'Attack Type', 'Severity', 'Status'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(TABLE_STYLE)
        self._populate_table(SAMPLE_ATTACKS)
        table_box.layout().addWidget(self.table)
        layout.addWidget(table_box)

        layout.addStretch()

    def _populate_table(self, data):
        self.table.setRowCount(len(data))
        for row, cols in enumerate(data):
            for col, val in enumerate(cols):
                item = QTableWidgetItem(val)
                item.setTextAlignment(Qt.AlignCenter)
                if col == 4:
                    item.setForeground(QColor(SEVERITY_COLORS.get(val, '#ddd')))
                if col == 5:
                    item.setForeground(QColor('#e74c3c'))
                self.table.setItem(row, col, item)

    def clear_log(self):
        self.table.setRowCount(0)
        for c in (self.card_total, self.card_critical, self.card_high,
                  self.card_medium, self.card_low):
            c.set_value('0')

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
        lbl.setStyleSheet('font-size: 13px; color: #ddd; font-weight: bold;')
        text_col.addWidget(lbl)
        if description:
            desc = QLabel(description)
            desc.setStyleSheet('font-size: 11px; color: #555;')
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

        # Outer content box  ← uses CONTENT_BOX_STYLE (#222)
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
        header.setStyleSheet('font-size: 28px; font-weight: bold; color: #fff;')
        sub = QLabel('Configure ArgusShield protection and behavior')
        sub.setStyleSheet('font-size: 13px; color: #666;')
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
        pb.addWidget(self._divider())
        pb.addWidget(ToggleRow('Stealth Operation Mode',
                               'Run ArgusShield without visible process indicators', False))
        layout.addWidget(prot_box)

        # Scan Settings
        scan_box = make_inner_box('Scan Settings')
        sb = scan_box.layout()

        sched_lbl = QLabel('Scan Schedule')
        sched_lbl.setStyleSheet('font-size: 13px; color: #888;')
        sb.addWidget(sched_lbl)

        sched_combo = QComboBox()
        sched_combo.addItems(['Every Hour', 'Every 4 Hours', 'Daily', 'Weekly', 'Manual Only'])
        sched_combo.setCurrentIndex(2)
        sched_combo.setStyleSheet("""
            QComboBox {
                background-color: #181818;
                color: #ddd;
                border: 1px solid #2a2a2a;
                border-radius: 5px;
                padding: 6px 10px;
                font-size: 13px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background-color: #1e1e1e;
                color: #ddd;
                selection-background-color: #2d8cff;
            }
        """)
        sb.addWidget(sched_combo)
        sb.addSpacing(6)
        sb.addWidget(self._divider())
        sb.addWidget(ToggleRow('Scan Compressed Archives',
                               'Include .zip, .rar and similar files in scan', True))
        sb.addWidget(self._divider())
        sb.addWidget(ToggleRow('Deep Memory Scan',
                               'Inspect process memory regions — higher CPU usage', False))
        layout.addWidget(scan_box)

        # Notifications
        notif_box = make_inner_box('Notifications')
        nb = notif_box.layout()
        nb.addWidget(ToggleRow('Desktop Alerts',
                               'Show pop-up notifications for detected threats', True))
        nb.addWidget(self._divider())
        nb.addWidget(ToggleRow('System Tray Alerts',
                               'Display alerts in the system tray', True))
        nb.addWidget(self._divider())
        nb.addWidget(ToggleRow('Email Reports',
                               'Send weekly summary to the administrator email address', False))
        layout.addWidget(notif_box)

        # Logging
        log_box = make_inner_box('Logging')
        lb = log_box.layout()
        lb.addWidget(ToggleRow('Enable Detailed Logging',
                               'Record all security events to a log file', True))
        lb.addWidget(self._divider())

        log_path_row = QHBoxLayout()
        log_dir_lbl = QLabel('Log Directory')
        log_dir_lbl.setStyleSheet('font-size: 13px; color: #888; min-width: 90px;')
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
#  5. ABOUT PAGE  (unchanged)
# ──────────────────────────────────────────────────────────────────────────────

class AboutPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        box = QWidget()
        box_layout = QVBoxLayout()
        box.setLayout(box_layout)
        box.setStyleSheet(CONTENT_BOX_STYLE)
        box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        label = QLabel('ArgusShield')
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet('font-size: 48px; font-weight: bold; color: #2d8cff;')
        box_layout.addWidget(label)

        version = QLabel('Version 1.0.0')
        version.setAlignment(Qt.AlignCenter)
        version.setStyleSheet('font-size: 22px; color: #555; margin-bottom: 30px;')
        box_layout.addWidget(version)

        about_text = QLabel(
            "ArgusShield is a professional-grade security solution designed to protect "
            "your system from advanced threats.\n\n"
            "Key Features:\n"
            "  Real-time DLL Injection Protection\n"
            "  Process Monitoring and Behavioral Analysis\n"
            "  Stealth Operation Mode\n"
            "  Minimal System Resource Usage\n\n"
            "Developed by ArgusShield."
        )
        about_text.setAlignment(Qt.AlignCenter)
        about_text.setWordWrap(True)
        about_text.setStyleSheet('font-size: 18px; line-height: 1.6; color: #ccc; padding: 20px;')
        box_layout.addWidget(about_text)

        box_layout.addStretch()
        layout.addWidget(box)
