from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QStackedWidget, QSizePolicy, QApplication
from PyQt5.QtCore import Qt
from ui.styles import (
    get_dark_palette, SIDEBAR_STYLE, NAV_BUTTON_STYLE, 
    NAV_BUTTON_ACTIVE_STYLE, INSTALL_BUTTON_STYLE, UNINSTALL_BUTTON_STYLE
)
from ui.pages import DashboardPage, QuarantinePage, SettingsPage, AboutPage

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('ArgusShield')
        self.setFixedSize(1300, 800)
        self.center_on_screen()

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

        # Initial page
        self.switch_page(0)

    def center_on_screen(self):
        geo = self.frameGeometry()
        screen = QApplication.primaryScreen().availableGeometry().center()
        geo.moveCenter(screen)
        self.move(geo.topLeft())

    def toggle_install(self):
        if self.install_button.text() == 'Install Shield':
            self.install_button.setText('Uninstall Shield')
            self.install_button.setStyleSheet(UNINSTALL_BUTTON_STYLE)
        else:
            self.install_button.setText('Install Shield')
            self.install_button.setStyleSheet(INSTALL_BUTTON_STYLE)

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            if i == index:
                btn.setStyleSheet(NAV_BUTTON_STYLE + NAV_BUTTON_ACTIVE_STYLE)
            else:
                btn.setStyleSheet(NAV_BUTTON_STYLE)
