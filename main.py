import sys
from PyQt6.QtWidgets import QApplication, QTabWidget
from system_monitor import SystemMonitorWidget
from analyzer_gui import AnalyzerWidget

def main():
    app = QApplication(sys.argv)
    tabs = QTabWidget()
    tabs.addTab(SystemMonitorWidget(), "System Status")
    tabs.addTab(AnalyzerWidget(), "Executable Analyzer")
    tabs.setMinimumSize(1000, 700)
    tabs.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
