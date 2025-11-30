
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLineEdit, QFileDialog,
    QHBoxLayout, QLabel, QTextEdit, QSpinBox, QMessageBox, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QPixmap

from analyzer_backend import (
    run_memory_analysis,
    run_syscall_analysis,
    run_network_syscall_analysis,
    run_file_access_analysis
)


class AnalyzerWorker(QThread):
    finished_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, exe, args, input_file, timeout, mode):
        super().__init__()
        self.exe = exe
        self.args = args
        self.input_file = input_file
        self.timeout = timeout
        self.mode = mode

    def run(self):
        import traceback
        try:
            exe_path = os.path.abspath(self.exe)
            if not os.path.isfile(exe_path):
                raise FileNotFoundError(f"Executable not found:\n{exe_path}")

            input_path = os.path.abspath(self.input_file) if self.input_file else None

            if self.mode == "memory":
                result = run_memory_analysis(exe_path, self.args, input_path, self.timeout)
            elif self.mode == "syscall":
                result = run_syscall_analysis(exe_path, self.args, input_path, self.timeout)
            elif self.mode == "network_syscalls":
                result = run_network_syscall_analysis(exe_path, self.args, input_path, self.timeout)
            elif self.mode == "files":
                result = run_file_access_analysis(exe_path, self.args, input_path, self.timeout)
            else:
                raise RuntimeError("Unknown mode: " + str(self.mode))

            self.finished_signal.emit(result)

        except Exception as e:
            self.error_signal.emit(str(e) + "\n" + traceback.format_exc())


class AnalyzerWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()


        h1 = QHBoxLayout()
        self.exe_edit = QLineEdit()
        btn_exe = QPushButton("Choose Executable")
        btn_exe.clicked.connect(self.pick_executable)
        h1.addWidget(QLabel("Executable:"))
        h1.addWidget(self.exe_edit)
        h1.addWidget(btn_exe)
        layout.addLayout(h1)


        layout.addWidget(QLabel("Arguments:"))
        self.args_edit = QLineEdit()
        layout.addWidget(self.args_edit)


        h2 = QHBoxLayout()
        self.input_edit = QLineEdit()
        btn_input = QPushButton("Choose Input File")
        btn_input.clicked.connect(self.pick_input)
        h2.addWidget(QLabel("Input File:"))
        h2.addWidget(self.input_edit)
        h2.addWidget(btn_input)
        layout.addLayout(h2)


        h3 = QHBoxLayout()
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 86400)
        self.timeout_spin.setValue(30)
        h3.addWidget(QLabel("Timeout (s):"))
        h3.addWidget(self.timeout_spin)
        layout.addLayout(h3)


        h4 = QHBoxLayout()
        self.mem_btn = QPushButton("Run Memory Analysis")
        self.mem_btn.clicked.connect(lambda: self.start_mode("memory"))
        self.sys_btn = QPushButton("Run Syscall Analysis")
        self.sys_btn.clicked.connect(lambda: self.start_mode("syscall"))
        self.net_btn = QPushButton("Run Network Syscall Analysis")
        self.net_btn.clicked.connect(lambda: self.start_mode("network_syscalls"))
        self.file_btn = QPushButton("Run File Access Analysis")
        self.file_btn.clicked.connect(lambda: self.start_mode("files"))

        h4.addWidget(self.mem_btn)
        h4.addWidget(self.sys_btn)
        h4.addWidget(self.net_btn)
        h4.addWidget(self.file_btn)
        layout.addLayout(h4)


        splitter = QSplitter(Qt.Orientation.Horizontal)

        left = QWidget()
        left_layout = QVBoxLayout()
        left.setLayout(left_layout)
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        left_layout.addWidget(QLabel("Execution Output / Metrics"))
        left_layout.addWidget(self.output_area)

        right = QWidget()
        right_layout = QVBoxLayout()
        right.setLayout(right_layout)
        self.image_label = QLabel("Graphs will appear here.")
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_layout.addWidget(self.image_label)

        splitter.addWidget(left)
        splitter.addWidget(right)
        layout.addWidget(splitter)

        self.setLayout(layout)
        self.current_result = None

    def pick_executable(self):
        file, _ = QFileDialog.getOpenFileName(self, "Choose Executable")
        if file:
            self.exe_edit.setText(file)

    def pick_input(self):
        file, _ = QFileDialog.getOpenFileName(self, "Choose Input File")
        if file:
            self.input_edit.setText(file)

    def start_mode(self, mode):
        exe = self.exe_edit.text().strip()
        args = self.args_edit.text().strip()
        inp = self.input_edit.text().strip() or None
        timeout = self.timeout_spin.value()

        if not exe:
            QMessageBox.warning(self, "Missing Executable", "Please select a binary to run.")
            return

        self.output_area.setPlainText(f"Starting {mode} analysis...")
        self.image_label.setText("")

        self.worker = AnalyzerWorker(exe, args, inp, timeout, mode)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.error_signal.connect(self.on_error)
        self.worker.start()

    def on_error(self, err):
        QMessageBox.critical(self, "Error", err)
        self.output_area.append("\nERROR:\n" + err)

    def on_finished(self, result):
        self.current_result = result
        mode = result.get("mode")

        text_lines = []
        text_lines.append(f"Mode: {mode}")
        text_lines.append(f"Return code: {result.get('returncode')}")
        text_lines.append(f"Elapsed: {result.get('elapsed')}")
        text_lines.append("\n=== METRICS ===")
        for k, v in result.get("metrics", {}).items():
            text_lines.append(f"{k}: {v}")

        text_lines.append("\n=== STDOUT ===")
        text_lines.append(result.get("stdout", "")[:20000])

        text_lines.append("\n=== STDERR ===")
        text_lines.append(result.get("stderr", "")[:20000])

        if mode == "syscall":
            if result.get("strace"):
                text_lines.append("\n=== SYSCALL SUMMARY ===\n")
                text_lines.append(result.get("strace")[:20000])
        if mode == "files":
            if result.get("file_access"):
                text_lines.append("\n=== FILE ACCESS LOG ===\n")
                text_lines.append(result.get("file_access")[:20000])
        if mode == "network_syscalls":
            if result.get("strace"):
                text_lines.append("\n=== NETWORK STRACE RAW (trimmed) ===\n")
                text_lines.append(result.get("strace")[:20000])

        self.output_area.setPlainText("\n".join(text_lines))


        graph_path = None
        if mode == "memory":
            graph_path = result.get("memory_png")
        elif mode == "syscall":
            graph_path = result.get("syscall_png")
        elif mode == "network_syscalls":
            graph_path = result.get("network_png")
        elif mode == "files":
            graph_path = None

        if graph_path and os.path.exists(graph_path):
            pix = QPixmap(graph_path)
            self.image_label.setPixmap(
                pix.scaled(
                    self.image_label.width(),
                    self.image_label.height(),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
            )
        else:
            if mode == "files":
                self.image_label.setText("File-access mode: no graphs produced.")
            else:
                self.image_label.setText("No graph produced for this run (or file missing).")
