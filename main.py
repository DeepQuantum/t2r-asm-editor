import re
import sys
import itertools
from typing import Any
from PyQt6.QtWidgets import QApplication, QMainWindow, QTextEdit
from ui.main_window import Ui_MainWindow
import subprocess

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.currentFile = "ss-assault-manager.bin"
        self.binary = self.read_main_file(self.currentFile)
        self.config = self.read_config()
        self.asm = self.get_disassembly()
        self.asmLines = self.asm.split("\n")

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.asmField.cursorPositionChanged.connect(self.asm_cursor_changed)
        #self.ui.hexField.cursorPositionChanged.connect(self.hex_cursor_changed)

        self.ui.hexField.setText(self.str_binary())
        self.ui.asmField.setText(self.asm)

    def read_main_file(self, path: str) -> list[bytearray]:
        with open(path, "rb") as f:
            return [bytearray(l) for l in itertools.batched(f.read(), 16)]
        
    def read_config(self, path: str = "t2r-asm-editor.cfg") -> dict[str, Any]:
        with open(path, "r") as f:
            lines = f.readlines()
            out = dict[str, Any]()
            for line in lines:
                split = line.split("=")
                out[split[0]] = split[1]
            return out
        
    def str_binary(self) -> str:
        out = list[str]()
        for i, line in enumerate(self.binary):
            txtline = f"0x{i*16:04X}  |  {" ".join(f"{x:02X}" for x in line)}"
            out.append(txtline)
        return "\n".join(out)
    
    def get_disassembly(self) -> str:
        exec_path = self.config.get("DISASM_PATH", "t2r-dc-disasm/x64/Release/t2r-dc-disasm.exe")
        subprocess.run([
            exec_path,
            self.currentFile
        ])
        new_file = self.currentFile.replace(".bin", ".bin.txt")
        with open(new_file, "r") as f:
            return f.read().replace("CODE: ", "").replace("DC::", "")
    
    def get_offset_from_asm_line(self, asm_line: str) -> int:
        offset_match = re.search(r"loc_\d* - (0x\d{8})", asm_line)
        if offset_match:
            return int(offset_match.group(1), 16)
        return -1

    def asm_cursor_changed(self):
        pos = self.ui.asmField.textCursor().position()
        line_idx = self.asm[:pos].count("\n")
        line = self.asmLines[line_idx]
        offset = self.get_offset_from_asm_line(line)
        if offset != -1:
            self.ui.hexField.verticalScrollBar().setValue(line_idx)


    # def eventFilter(self, source: Any, event: QEvent) -> bool:
    #     if source == self.ui.asmField and event.type() == QEvent.:
    #         print("Line edit got focus!")
    #     return super().eventFilter(source, event)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())