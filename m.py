import sys
from scapy.all import sniff, TCP, UDP, IP, Raw
import re
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QTabWidget, QWidget, QPushButton, QHBoxLayout
)
from PyQt5.QtCore import QThread, pyqtSignal

# Malicious signatures for detection
malicious_signatures = [
    {'type': 'IP', 'pattern': '192.168.1.100'},
    {'type': 'PORT', 'pattern': 80},
    {'type': 'PAYLOAD', 'pattern': r"select.*from.*users"},
]


class SniffThread(QThread):
    log_signal = pyqtSignal(str, str, str)  # Signal to send logs to the GUI

    def __init__(self, iface="wlan0"):
        super().__init__()
        self.iface = iface
        self.running = True

    def run(self):
        """Run the sniffing in a thread."""
        sniff(prn=self.packet_callback, store=0, iface=self.iface, stop_filter=self.stop_sniff)

    def packet_callback(self, packet):
        """Process each packet and emit log signals for malicious activity."""
        try:
            if IP in packet:
                is_malicious, message = self.match_signature(packet)
                if is_malicious:
                    time_now = time.strftime("%H:%M:%S")
                    self.log_signal.emit(time_now, "High", message)
        except Exception as e:
            print(f"Error processing packet: {e}")

    def match_signature(self, packet):
        """Check for malicious signatures."""
        for sig in malicious_signatures:
            if sig['type'] == 'IP' and (packet[IP].src == sig['pattern'] or packet[IP].dst == sig['pattern']):
                return True, f"Malicious IP match: {sig['pattern']}"
            elif sig['type'] == 'PORT' and (
                (TCP in packet and packet[TCP].dport == sig['pattern']) or
                (UDP in packet and packet[UDP].dport == sig['pattern'])
            ):
                return True, f"Malicious port match: {sig['pattern']}"
            elif sig['type'] == 'PAYLOAD' and packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors='ignore')
                if re.search(sig['pattern'], payload):
                    return True, f"Malicious payload match: {sig['pattern']}"
        return False, None

    def stop_sniff(self, packet):
        """Stop sniffing gracefully."""
        return not self.running

    def stop(self):
        """Stop the thread."""
        self.running = False
        self.quit()
        self.wait()


class HIDS_GUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Host-Based Intrusion Detection System")
        self.setGeometry(100, 100, 900, 600)
        self.initUI()

    def initUI(self):
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_dashboard_tab(), "Dashboard")
        self.tabs.addTab(self.create_logs_tab(), "Logs")
        self.setCentralWidget(self.tabs)

    def create_dashboard_tab(self):
        dashboard_tab = QWidget()
        layout = QVBoxLayout()

        self.status_label = QLabel("System Status: Idle")
        layout.addWidget(self.status_label)

        control_layout = QHBoxLayout()
        start_button = QPushButton("Start Sniffing")
        stop_button = QPushButton("Stop Sniffing")
        control_layout.addWidget(start_button)
        control_layout.addWidget(stop_button)
        layout.addLayout(control_layout)

        start_button.clicked.connect(self.start_sniffing)
        stop_button.clicked.connect(self.stop_sniffing)

        self.recent_logs_table = QTableWidget(0, 3)
        self.recent_logs_table.setHorizontalHeaderLabels(["Time", "Severity", "Message"])
        layout.addWidget(self.recent_logs_table)

        dashboard_tab.setLayout(layout)
        return dashboard_tab

    def create_logs_tab(self):
        logs_tab = QWidget()
        layout = QVBoxLayout()

        self.logs_table = QTableWidget(0, 3)
        self.logs_table.setHorizontalHeaderLabels(["Time", "Severity", "Message"])
        layout.addWidget(self.logs_table)

        logs_tab.setLayout(layout)
        return logs_tab

    def add_log_entry(self, time, severity, message):
        """Add a log entry to the logs table."""
        row_count = self.logs_table.rowCount()
        self.logs_table.insertRow(row_count)
        self.logs_table.setItem(row_count, 0, QTableWidgetItem(time))
        self.logs_table.setItem(row_count, 1, QTableWidgetItem(severity))
        self.logs_table.setItem(row_count, 2, QTableWidgetItem(message))

    def start_sniffing(self):
        self.sniff_thread = SniffThread("wlan0")
        self.sniff_thread.log_signal.connect(self.add_log_entry)
        self.sniff_thread.start()
        self.status_label.setText("System Status: Monitoring...")

    def stop_sniffing(self):
        if hasattr(self, 'sniff_thread') and self.sniff_thread.isRunning():
            self.sniff_thread.stop()
            self.status_label.setText("System Status: Stopped")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HIDS_GUI()
    window.show()
    sys.exit(app.exec_())
