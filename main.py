from dataclasses import dataclass
from datetime import datetime, timedelta
import re
import sys
import itertools
from typing import Any
from PyQt6.QtWidgets import QApplication, QMainWindow, QMenu, QScrollBar
from PyQt6.QtGui import QTextCharFormat, QTextCursor, QColor, QAction
from PyQt6.QtCore import Qt, QPoint
from ui.main_window import Ui_MainWindow
import subprocess

@dataclass
class LineData:
    offset: int
    instruction: bytearray
    fnv_hashes: set[str]

def bytes_to_string(bytes: bytearray) -> str:
    return " ".join(f"{x:02X}" for x in bytes)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.currentFile = "ss-assault-manager.bin"
        self.binary = self.read_main_file(self.currentFile)
        self.config = self.read_config()
        self.asm = self.get_disassembly()
        self.asmLines = self.asm.split("\n")
        self.max_offset = len(self.binary)
        self.start_pos = 0
        self.end_pos = 0
        self.selection_delay_ms = timedelta(milliseconds=50)
        self.last_selection_time = datetime.now()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.hex_cursor = QTextCursor(self.ui.hexField.document())
        self.highlight_format = QTextCharFormat()
        self.highlight_format.setBackground(QColor("blue"))
        self.hash_format = QTextCharFormat()
        self.hash_format.setBackground(QColor("red"))
        self.reset_format = QTextCharFormat()
        self.reset_format.setBackground(QColor("transparent"))

        self.ui.asmField.cursorPositionChanged.connect(self.asm_cursor_changed)
        self.ui.asmField.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ui.asmField.customContextMenuRequested.connect(self.patch_instruction_menu)
        #self.ui.hexField.cursorPositionChanged.connect(self.hex_cursor_changed)

        self.ui.hexField.verticalScrollBar().valueChanged.connect(
            self.ui.offsetField.verticalScrollBar().setValue
        )
        
        self.ui.offsetField.verticalScrollBar().valueChanged.connect(
            self.ui.hexField.verticalScrollBar().setValue
        )
        self.ui.offsetField.verticalScrollBar().setVisible(False)

        self.ui.hexField.setText(self.str_binary())
        self.ui.offsetField.setText("\n".join(f"0x{i:06X}" for i in range(0, len(self.binary), 16)))
        self.ui.asmField.setText(self.asm)
        
    
    def read_main_file(self, path: str) -> bytearray:
        with open(path, "rb") as f:
            return bytearray(f.read())
        
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
        for bytes in itertools.batched(self.binary, 16):
            txtline = " ".join(f"{x:02X}" for x in bytes)
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
            return f.read().replace("CODE: ", "").replace("DC::", "").replace("( ", "(").replace(" )", ")").replace("hashid: ", "")
    
    # loc_24 - 0x00000218 0F 02 02 00 kLoadPointer/kLoadI64/kLoadU64: R2, R2
    def get_line_data(self, asm_line: str) -> LineData | None:
        line_regex = re.search(r"loc_\d+ - (0x[\da-fA-F]{8}) ((?:[\da-fA-F]{2} ){3}[\da-fA-F]{2})", asm_line)
        if line_regex:
            hash_matches: list[str] = re.findall(r"(?:0x|#)([\da-fA-F]{16})", asm_line)
            hashes = {' '.join([s[i:i+2] for i in range(0, len(s), 2)][::-1]) for s in hash_matches}
            offset =  int(line_regex.group(1), 16)
            instructions = bytearray(b"".join(int(i, 16).to_bytes() for i in line_regex.group(2).split()))
            return LineData(offset, instructions, hashes)
        return None

    def reset_hexfield(self):
        self.hex_cursor.setPosition(self.start_pos)
        self.hex_cursor.setPosition(self.end_pos, QTextCursor.MoveMode.KeepAnchor)
        self.hex_cursor.mergeCharFormat(self.reset_format)

    def asm_cursor_changed(self):

        self.reset_hexfield()
        cursor = self.ui.asmField.textCursor()
        selected_text = cursor.selectedText()
        if selected_text:
            start = cursor.selectionStart()
            if start > cursor.selectionEnd():
                start = cursor.selectionEnd()
        else:
            start = cursor.position()
        start_line_idx = self.asm[:start].count("\n")
        stop_line_idx = start_line_idx + selected_text.count("\u2029") if selected_text else start_line_idx
        lines = self.asmLines[start_line_idx:stop_line_idx + 1]
        linedata = [self.get_line_data(line) for line in lines]
        linedata = [l for l in linedata if l is not None]
        if linedata:
            first_line = linedata[0]
            scroll_percentage = first_line.offset / self.max_offset
            scroll_amount = round(self.ui.hexField.verticalScrollBar().maximum() * scroll_percentage + scroll_percentage * self.ui.hexField.height() - self.ui.hexField.height() // 2)
            self.ui.hexField.verticalScrollBar().setValue(scroll_amount)
            self.start_pos = min(self.start_pos, first_line.offset * 3)
            for line in linedata:
                idx = line.offset * 3
                self.hex_cursor.setPosition(idx)
                self.hex_cursor.setPosition(idx + 23, QTextCursor.MoveMode.KeepAnchor)
                self.hex_cursor.mergeCharFormat(self.highlight_format)
                for hash in line.fnv_hashes:
                    idx = self.ui.hexField.toPlainText().find(hash, idx)
                    if idx == -1:
                        continue
                    self.hex_cursor.setPosition(idx)
                    self.hex_cursor.setPosition(idx + 23, QTextCursor.MoveMode.KeepAnchor)
                    self.hex_cursor.mergeCharFormat(self.hash_format)
                    self.end_pos = max(self.end_pos, idx + 23)
        self.last_selection_time = datetime.now()

    def edit_binary(self, offset: int, new_bytes: bytearray):
        self.binary[offset:offset+8] = new_bytes + bytearray([0, 0, 0, 0])
        self.ui.hexField.setText(self.str_binary())

    def replace_instruction(self, new_instruction: bytearray):
        pos = self.ui.asmField.textCursor().position()
        idx = self.asm[:pos].count("\n")
        line = self.asmLines[idx]
        line_data = self.get_line_data(line)
        if not line_data:
            return
        old_instruction = " ".join(f"{x:02X}" for x in line_data.instruction)
        self.edit_binary(line_data.offset, new_instruction)
        self.asmLines[idx] = self.asmLines[idx].replace(old_instruction, bytes_to_string(new_instruction))
        self.ui.asmField.setText("\n".join(self.asmLines))

    def show_instruction_dropdown_menu(self, pos: QPoint):
        context_menu = QMenu(self)
        replace_action_0 = QAction("00 00 00 00", self)
        replace_action_1 = QAction("ff ff ff ff", self)
        replace_action_0.triggered.connect(lambda: self.replace_instruction(bytearray(b"\x00\x00\x00\x00")))
        replace_action_1.triggered.connect(lambda: self.replace_instruction(bytearray(b"\xFF\xFF\xFF\xFF")))
        context_menu.addAction(replace_action_0)
        context_menu.addAction(replace_action_1)
        context_menu.exec(self.mapToGlobal(pos))

  

    def patch_instruction_menu(self, pos: QPoint):
        asm_cursor_pos = self.ui.asmField.textCursor().position()
        asm_scroll_value = self.ui.asmField.verticalScrollBar().value()
        hex_cursor_pos = self.ui.hexField.textCursor().position()
        hex_scroll_value = self.ui.hexField.verticalScrollBar().value()

        context_menu = QMenu(self)
        patch_action = QAction('Patch Instruction', self)
        patch_action.triggered.connect(lambda: self.show_instruction_dropdown_menu(pos))
        context_menu.addAction(patch_action)
        context_menu.exec(self.mapToGlobal(pos))

        asm_cursor = self.ui.asmField.textCursor()
        asm_cursor.setPosition(asm_cursor_pos, QTextCursor.MoveMode.MoveAnchor)
        self.ui.asmField.setTextCursor(asm_cursor)
        hex_cursor = self.ui.asmField.textCursor()
        hex_cursor.setPosition(hex_cursor_pos, QTextCursor.MoveMode.MoveAnchor)
        self.ui.hexField.setTextCursor(hex_cursor)

        self.ui.asmField.verticalScrollBar().setValue(asm_scroll_value)
        self.ui.hexField.verticalScrollBar().setValue(hex_scroll_value)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())