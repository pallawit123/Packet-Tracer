import sys
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QHBoxLayout, QLabel, QComboBox, QLineEdit
)
from scapy.all import AsyncSniffer, get_if_list
from core.parser import packet_to_row


class PacketEmitter(QObject):
    packet_ready = Signal(dict)
    error = Signal(str)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer UI")
        self.resize(1100, 650)

        self.sniffer = None
        self.emitter = PacketEmitter()
        self.emitter.packet_ready.connect(self.add_row)
        self.emitter.error.connect(self.show_error)

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        controls = QHBoxLayout()
        self.btn_start = QPushButton("Start")
        self.btn_stop = QPushButton("Stop")
        self.btn_clear = QPushButton("Clear")
        self.btn_stop.setEnabled(False)

        self.iface_combo = QComboBox()
        self.iface_combo.addItems(get_if_list())

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Optional BPF filter (tcp / udp / port 53)")

        controls.addWidget(QLabel("Interface:"))
        controls.addWidget(self.iface_combo)
        controls.addWidget(QLabel("Filter:"))
        controls.addWidget(self.filter_input)
        controls.addWidget(self.btn_start)
        controls.addWidget(self.btn_stop)
        controls.addWidget(self.btn_clear)
        layout.addLayout(controls)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Src IP", "Dst IP", "Protocol", "Src Port", "Dst Port", "Length"]
        )
        layout.addWidget(self.table)

        self.statusBar().showMessage("Ready")

        self.btn_start.clicked.connect(self.start_sniffing)
        self.btn_stop.clicked.connect(self.stop_sniffing)
        self.btn_clear.clicked.connect(lambda: self.table.setRowCount(0))

    def on_packet(self, packet):
        try:
            self.emitter.packet_ready.emit(packet_to_row(packet))
        except Exception as e:
            self.emitter.error.emit(str(e))

    def start_sniffing(self):
        iface = self.iface_combo.currentText().strip()
        bpf = self.filter_input.text().strip() or None
        try:
            self.sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=self.on_packet, store=False)
            self.sniffer.start()
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
            self.statusBar().showMessage(f"Sniffing on {iface} (filter: {bpf or 'none'})")
        except Exception as e:
            self.statusBar().showMessage(f"Start failed: {e}")

    def stop_sniffing(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.statusBar().showMessage("Stopped")

    def add_row(self, row: dict):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(str(row.get("time", "-"))))
        self.table.setItem(r, 1, QTableWidgetItem(str(row.get("src_ip", "-"))))
        self.table.setItem(r, 2, QTableWidgetItem(str(row.get("dst_ip", "-"))))
        self.table.setItem(r, 3, QTableWidgetItem(str(row.get("protocol", "-"))))
        self.table.setItem(r, 4, QTableWidgetItem(str(row.get("src_port", "-"))))
        self.table.setItem(r, 5, QTableWidgetItem(str(row.get("dst_port", "-"))))
        self.table.setItem(r, 6, QTableWidgetItem(str(row.get("length", "-"))))
        self.table.scrollToBottom()

    def show_error(self, msg: str):
        self.statusBar().showMessage(f"Parse error: {msg}")

    def closeEvent(self, event):
        self.stop_sniffing()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()