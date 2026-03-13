from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QColor

def get_dark_palette():
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(20, 20, 20))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(30, 30, 30))
    palette.setColor(QPalette.AlternateBase, QColor(20, 20, 20))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(40, 40, 40))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Highlight, QColor(45, 140, 240))
    palette.setColor(QPalette.HighlightedText, Qt.black)
    return palette

SIDEBAR_STYLE = 'background-color: #1e1e1e; border-right: 1px solid #333; border-radius: 10px;'

NAV_BUTTON_STYLE = """
    QPushButton {
        background-color: transparent;
        color: #bbb;
        border: none;
        border-radius: 8px;
        text-align: left;
        font-size: 18px;
        font-weight: 500;
        margin: 0px 15px;
        padding-left: 10px;
    }
    QPushButton:hover {
        background-color: #2d8cff;
        color: white;
    }
    QPushButton:pressed {
        background-color: #1a5caf;
        padding-left: 12px;
    }
"""

NAV_BUTTON_ACTIVE_STYLE = "QPushButton { background-color: #2d8cff; color: white; font-weight: bold; }"

INSTALL_BUTTON_STYLE = """
    QPushButton {
        background-color: #27ae60; 
        color: #fff; 
        font-size: 18px; 
        padding: 12px; 
        margin: 20px 15px; 
        border-radius: 8px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #2ecc71;
    }
    QPushButton:pressed {
        background-color: #219150;
    }
"""

UNINSTALL_BUTTON_STYLE = """
    QPushButton {
        background-color: #e74c3c; 
        color: #fff; 
        font-size: 18px; 
        padding: 12px; 
        margin: 20px 15px; 
        border-radius: 8px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #c0392b;
    }
    QPushButton:pressed {
        background-color: #962d22;
    }
"""

CONTENT_BOX_STYLE = 'background-color: #222; border-radius: 10px; padding: 20px;'

INNER_BOX_STYLE = """
    QGroupBox {
        background-color: #1e1e1e;
        border-radius: 8px;
        border: 1px solid #2a2a2a;
        margin-top: 14px;
        font-size: 13px;
        font-weight: bold;
        color: #aaa;
        padding: 6px;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 12px;
        padding: 0 6px;
        color: #888;
    }
"""

TABLE_STYLE = """
    QTableWidget {
        background-color: #1e1e1e;
        alternate-background-color: #1a1a1a;
        color: #ddd;
        border: none;
        gridline-color: #2a2a2a;
        font-size: 13px;
    }
    QHeaderView::section {
        background-color: #181818;
        color: #2d8cff;
        font-weight: bold;
        border: none;
        padding: 6px;
    }
    QTableWidget::item:selected { background-color: #2a3a50; }
"""