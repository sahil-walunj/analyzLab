
import psutil
from collections import deque
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QHBoxLayout
from PyQt6.QtCore import QTimer
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

class SystemMonitorWidget(QWidget):
    def __init__(self, history_len=120):
        super().__init__()
        self.history_len = history_len

        self.cpu_history = deque([0.0]*history_len, maxlen=history_len)
        self.mem_history = deque([0.0]*history_len, maxlen=history_len)
        self.times = deque(range(-history_len+1, 1), maxlen=history_len)

        layout = QVBoxLayout()

        hl = QHBoxLayout()
        self.cpu_label = QLabel("CPU Usage: ")
        self.mem_label = QLabel("Memory Usage: ")
        hl.addWidget(self.cpu_label)
        hl.addWidget(self.mem_label)
        hl.addStretch()
        layout.addLayout(hl)

        self.fig = Figure(figsize=(8, 3))
        self.canvas = FigureCanvas(self.fig)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("CPU & Memory (recent)")
        self.ax.set_ylim(0, 100)
        self.cpu_line, = self.ax.plot([], [], label="CPU %")
        self.mem_line, = self.ax.plot([], [], label="Mem %")
        self.ax.legend(loc="upper right")
        layout.addWidget(self.canvas)

        self.proc_label = QLabel("Top processes (by CPU):")
        self.process_list = QTextEdit()
        self.process_list.setReadOnly(True)
        layout.addWidget(self.proc_label)
        layout.addWidget(self.process_list)

        self.setLayout(layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)

    def update_stats(self):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent

        
        self.cpu_history.append(cpu)
        self.mem_history.append(mem)
        
        self.cpu_label.setText(f"CPU Usage: {cpu:.1f}%")
        self.mem_label.setText(f"Memory Usage: {mem:.1f}%")

        
        xs = list(range(-len(self.cpu_history)+1, 1))
        self.cpu_line.set_data(xs, list(self.cpu_history))
        self.mem_line.set_data(xs, list(self.mem_history))
        self.ax.set_xlim(min(xs), 0)
        
        self.canvas.draw_idle()

        
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = p.info
                procs.append(info)
            except Exception:
                continue
        procs.sort(key=lambda x: x.get('cpu_percent') or 0.0, reverse=True)
        text_lines = []
        for info in procs[:30]:
            text_lines.append(f"{info['pid']:6d}  {info.get('name')[:30]:30s}  CPU:{info.get('cpu_percent',0):5.1f}%  MEM:{info.get('memory_percent',0):5.1f}%")
        self.process_list.setPlainText("\n".join(text_lines))
