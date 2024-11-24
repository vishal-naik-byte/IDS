import sys
from lll import follow_journal_logs
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, 
    QTabWidget, QWidget, QPushButton, QHBoxLayout
)

class HIDS_GUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Host-Based Intrusion Detection System")
        self.setGeometry(100, 100, 900, 600)
        self.initUI()

    def initUI(self):
        # Create main layout
        self.tabs = QTabWidget()
        
        # Add tabs
        self.tabs.addTab(self.create_dashboard_tab(), "Dashboard")
        self.tabs.addTab(self.create_logs_tab(), "Logs")
        self.tabs.addTab(self.create_settings_tab(), "Settings")
        self.tabs.addTab(self.create_alerts_tab(), "Alerts")
        
        # Set central widget
        self.setCentralWidget(self.tabs)
    
    def create_dashboard_tab(self):
        """Create the dashboard tab."""
        dashboard_tab = QWidget()
        layout = QVBoxLayout()
        
        # System status label
        self.status_label = QLabel("System Status: Monitoring...")
        layout.addWidget(self.status_label)
        
        # Table for recent logs
        self.recent_logs_table = QTableWidget(0, 3)
        self.recent_logs_table.setHorizontalHeaderLabels(["Time", "Event", "Details"])
        layout.addWidget(self.recent_logs_table)
        
        # Simulate alert button
        alert_button = QPushButton("Simulate Alert")
        alert_button.clicked.connect(self.simulate_alert)
        layout.addWidget(alert_button)
        
        dashboard_tab.setLayout(layout)
        return dashboard_tab
    
    def create_logs_tab(self):
        """Create the logs tab."""
        logs_tab = QWidget()
        layout = QVBoxLayout()
        
        # Logs table
        self.logs_table = QTableWidget(0, 3)
        self.logs_table.setHorizontalHeaderLabels(["Time", "Severity", "Message"])
        layout.addWidget(self.logs_table)
        
        logs_tab.setLayout(layout)
        return logs_tab
    
    def create_settings_tab(self):
        """Create the settings tab."""
        settings_tab = QWidget()
        layout = QVBoxLayout()
        
        # Placeholder for settings
        settings_label = QLabel("Settings will be configurable here.")
        layout.addWidget(settings_label)
        
        settings_tab.setLayout(layout)
        return settings_tab
    
    def create_alerts_tab(self):
        """Create the alerts tab."""
        alerts_tab = QWidget()
        layout = QVBoxLayout()
        
        # Placeholder for alerts
        self.alert_label = QLabel("No active alerts.")
        layout.addWidget(self.alert_label)
        
        alerts_tab.setLayout(layout)
        return alerts_tab

    def simulate_alert(self):
        """Simulate an alert in the dashboard."""
        self.status_label.setText("System Status: Threat Detected!")
        
        # Add alert to the recent logs table
        row_count = self.recent_logs_table.rowCount()
        self.recent_logs_table.insertRow(row_count)
        self.recent_logs_table.setItem(row_count, 0, QTableWidgetItem("12:30 PM"))
        self.recent_logs_table.setItem(row_count, 1, QTableWidgetItem("Unauthorized Access"))
        self.recent_logs_table.setItem(row_count, 2, QTableWidgetItem("Login attempt from IP 192.168.1.50"))
        
        # Add to logs tab
        row_count = self.logs_table.rowCount()
        self.logs_table.insertRow(row_count)
        self.logs_table.setItem(row_count, 0, QTableWidgetItem("12:30 PM"))
        self.logs_table.setItem(row_count, 1, QTableWidgetItem("High"))
        self.logs_table.setItem(row_count, 2, QTableWidgetItem("Unauthorized Access"))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HIDS_GUI()
    window.show()
    sys.exit(app.exec_())
