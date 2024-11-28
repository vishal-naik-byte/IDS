import sys
import time
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget
from pp import *

class WorkerThread(QThread):
    update_signal = pyqtSignal(int)  # Signal to update GUI with data

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        counter = 0
        while self.running:
            time.sleep(1)  # Simulate background work
            counter += 1
            self.update_signal.emit(counter)  # Emit updated data
            main(self)

    def stop(self):
        self.running = False
        self.wait()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyQt5 Background Thread Example")

        # UI Elements
        self.label = QLabel("Counter: 0", self)
        self.button = QPushButton("Click Me", self)
        self.button.clicked.connect(self.on_button_click)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.button)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Worker Thread
        self.worker = WorkerThread()
        self.worker.update_signal.connect(self.update_label)
        self.worker.start()

    def update_label(self, value):
        """Update label with the data from the thread."""
        self.label.setText(f"Counter: {value}")

    def on_button_click(self):
        """Handle button click."""
        print("Button clicked!")

    def closeEvent(self, event):
        """Ensure the thread stops when the window is closed."""
        self.worker.stop()
        event.accept()

def main(gui_instance):
	print("Starting NIDS...")
	#sniff(prn=lambda packet: process_packet(packet,gui_instance), store=0, iface="wlan0")
	sniff(prn=lambda packet: packet_callback(packet,gui_instance), store=0, iface="wlan0")
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
