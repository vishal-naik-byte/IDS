import sys
from scapy.all import sniff, TCP, UDP, IP, Raw
import re
import time
from lll import follow_journal_logs
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, 
    QTabWidget, QWidget, QPushButton, QHBoxLayout
)
from PyQt5.QtCore import QThread, pyqtSignal

# List of malicious signatures (for demonstration purposes)
# Format: {'signature_type': 'pattern'}
malicious_signatures = [
    {'type': 'IP', 'pattern': '192.168.1.100'},
    {'type': 'IP', 'pattern': '192.168.152.116'},
    {'type': 'IP', 'pattern': '64:ff9b::a29f:8a40'},  # Example malicious IP
    {'type': 'PORT', 'pattern': 80},             # Example malicious port
    {'type': 'PAYLOAD', 'pattern': r"select.*from.*users"},  # Example SQL Injection pattern
]
class SniffThread(QThread):
    # Signal to send data back to the GUI
    log_signal = pyqtSignal(str, str, str)
    alert_signal = pyqtSignal(str)

    def __init__(self, iface="wlan0"):
        super().__init__()
        self.iface = iface
        self.running = True  # To allow thread termination
        
    def add_log_entry(self, time, severity, message):
    	#print("jj::")
    	#row_count = self.logs_table.rowCount()
    	#self.logs_table.insertRow(row_count)
    	#self.logs_table.setItem(row_count, 0, QTableWidgetItem(time))
    	#self.logs_table.setItem(row_count, 1, QTableWidgetItem(severity))
    	#self.logs_table.setItem(row_count, 2, QTableWidgetItem(message))
    	#print("")
    	"""vv"""
    
    def run(self):
        """Start packet sniffing."""
        print("started")
        #main(self)
        sniff(prn=self.process_packet, store=0, iface=self.iface, stop_filter=self.stop_sniff)
        print("sniff")
        #sniff(prn=lambda packet: SniffThread.packet_callback1(packet), store=0, iface="wlan0")
        #sniff(prn=lambda packet: self.process_packet(packet), store=0, iface="wlan0")

    def process_packet(self, packet):
        """Callback to process each packet."""
        print("processing")
        #print(packet)
        time_now = time.strftime("%H:%M:%S")
        self.log_signal.emit(time_now, "High", "message")
        try:
            if IP in packet:
                is_malicious, message = match_signature(packet)
                if is_malicious:
                    time_now = time.strftime("%H:%M:%S")
                    self.log_signal.emit(time_now, "High", message)
                    self.alert_signal.emit(message)
        except Exception as e:
            print(f"Error processing packet: {e}")
            
    def packet_callback1(packet,gui_instance):
    	"""Callback function to process each packet."""
    	#gui_instance.add_log_entry("12:45 PM", "Medium", "Detected suspicious payload.")
    	#gui_instance.add_log_entry("1:00 PM", "High", "Malicious IP activity detected from 192.168.1.100.")
    	try:
    	    # Only process IP packets (skip non-IP packets like ARP, etc.)
    	    if IP in packet:
    	    	# Check packet against malicious signatures
    	    	is_malicious, message = match_signature(packet)
    	    	if is_malicious:
    	    		print(f"[ALERT] {message}")
    	    	else:
    	    		print(f"Packet OK: {packet[IP].src} -> {packet[IP].dst}")
    	except Exception as e:
    		print(f"Error processing packet: {e}")

    def stop_sniff(self, packet):
        """Stop sniffing if the thread is terminated."""
        return not self.running

    def stop(self):
        """Stop the thread gracefully."""
        self.running = False
        self.wait()

class HIDS_GUI(QMainWindow):
    def add_log_entry(self, time, severity, message):
    	print("jj::")
    	row_count = self.logs_table.rowCount()
    	self.logs_table.insertRow(row_count)
    	self.logs_table.setItem(row_count, 0, QTableWidgetItem(time))
    	self.logs_table.setItem(row_count, 1, QTableWidgetItem(severity))
    	self.logs_table.setItem(row_count, 2, QTableWidgetItem(message)) 
    	
    def update_alert_tab(self, alert_message):
	    """Update the Alerts tab with a new alert."""
	    self.alert_label.setText(f"Alert: {alert_message}")  # Update the alert label

	    # Add the alert to the logs tab as well
	    time_now = time.strftime("%H:%M:%S")
	    row_count = self.logs_table.rowCount()
	    self.logs_table.insertRow(row_count)
	    self.logs_table.setItem(row_count, 0, QTableWidgetItem(time_now))
	    self.logs_table.setItem(row_count, 1, QTableWidgetItem("High"))
	    self.logs_table.setItem(row_count, 2, QTableWidgetItem(alert_message))

	    # Optionally, you can also update the recent logs in the dashboard tab
	    row_count = self.recent_logs_table.rowCount()
	    self.recent_logs_table.insertRow(row_count)
	    self.recent_logs_table.setItem(row_count, 0, QTableWidgetItem(time_now))
	    self.recent_logs_table.setItem(row_count, 1, QTableWidgetItem("High"))
	    self.recent_logs_table.setItem(row_count, 2, QTableWidgetItem(alert_message))
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
    	self.status_label = QLabel("System Status: Idle")
    	layout.addWidget(self.status_label)

    	# Control buttons
    	control_layout = QHBoxLayout()
    	start_button = QPushButton("Start Sniffing")
    	stop_button = QPushButton("Stop Sniffing")
    	control_layout.addWidget(start_button)
    	control_layout.addWidget(stop_button)
    	layout.addLayout(control_layout)

    	# Connect buttons to methods
    	start_button.clicked.connect(self.start_sniffing)
    	stop_button.clicked.connect(self.stop_sniffing)

    	# Table for recent logs
    	self.recent_logs_table = QTableWidget(0, 3)
    	self.recent_logs_table.setHorizontalHeaderLabels(["Time", "Event", "Details"])
    	layout.addWidget(self.recent_logs_table)

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
        
    def start_sniffing(self):
    	"""Start the sniffing thread."""
    	self.sniff_thread = SniffThread("wlan0")
    	self.sniff_thread.log_signal.connect(self.add_log_entry)  # Connect signal to add log entry
    	self.sniff_thread.alert_signal.connect(self.update_alert_tab)  # Connect signal to update alert tab
    	self.sniff_thread.start()
    	self.status_label.setText("System Status: Monitoring...")
    	
    def stop_sniffing(self):
    	"""Stop the sniffing thread."""
    	if hasattr(self, 'sniff_thread') and self.sniff_thread.isRunning():
        	self.sniff_thread.stop()
        	self.status_label.setText("System Status: Stopped")

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
        main(self)    
    
  
def match_signature(packet):
    	"""Check if a packet matches any predefined malicious signature."""
    	for sig in malicious_signatures:
        	if sig['type'] == 'IP':
            		# Match based on source or destination IP address
            		if packet[IP].src == sig['pattern'] or packet[IP].dst == sig['pattern']:
                		return True, f"Malicious IP match: {sig['pattern']}"
        
        	elif sig['type'] == 'PORT':
            		# Match based on destination port (TCP/UDP)
            		if TCP in packet and packet[TCP].dport == sig['pattern']:
                		return True, f"Malicious port match: {sig['pattern']}"
            		elif UDP in packet and packet[UDP].dport == sig['pattern']:
                		return True, f"Malicious port match: {sig['pattern']}"

        	elif sig['type'] == 'PAYLOAD':
            	# Match based on payload content using regex (e.g., SQL injection patterns)
            		if packet.haslayer(Raw):
                		payload = packet[Raw].load.decode(errors='ignore')
                		if re.search(sig['pattern'], payload):
                    			return True, f"Malicious payload match: {sig['pattern']}"

    	return False, None
    	
def packet_callback(packet,gui_instance):
    """Callback function to process each packet."""
    #gui_instance.add_log_entry("12:45 PM", "Medium", "Detected suspicious payload.")
    #gui_instance.add_log_entry("1:00 PM", "High", "Malicious IP activity detected from 192.168.1.100.")
    try:
        # Only process IP packets (skip non-IP packets like ARP, etc.)
        if IP in packet:
            # Check packet against malicious signatures
            is_malicious, message = match_signature(packet)
            if is_malicious:
                print(f"[ALERT] {message}")
            else:
                print(f"Packet OK: {packet[IP].src} -> {packet[IP].dst}")

    except Exception as e:
        print(f"Error processing packet: {e}")
        
    
"""Capture packets on the network interface (e.g., eth0)"""
def main(gui_instance):
	print("Starting NIDS...")
	#sniff(prn=lambda packet: process_packet(packet,gui_instance), store=0, iface="wlan0")
	sniff(prn=lambda packet: packet_callback(packet,gui_instance), store=0, iface="wlan0")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HIDS_GUI()
    window.show()
    sys.exit(app.exec_())
