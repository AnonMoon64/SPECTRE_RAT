# plugins/message.py
from PyQt6.QtWidgets import QDialog, QTextEdit, QLineEdit, QFormLayout, QPushButton, QHBoxLayout
from .base_plugin import BasePlugin
import json

class MessageDialog(QDialog):
    def __init__(self, parent=None, target="all", client=None, topic="/commands/"):
        super().__init__(parent)
        self.client = client
        self.topic = topic
        self.target = target
        self.setWindowTitle('Message')
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
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.message_input = QLineEdit()
        layout.addRow('Chat:', self.chat_area)
        layout.addRow('Message:', self.message_input)
        send_button = QPushButton('Send')
        send_button.clicked.connect(self.send_message)
        close_button = QPushButton('Close')
        close_button.clicked.connect(self.close_dialog)
        button_layout = QHBoxLayout()
        button_layout.addWidget(send_button)
        button_layout.addWidget(close_button)
        layout.addRow(button_layout)
        self.setLayout(layout)

    def send_message(self):
        message_text = self.message_input.text().strip()
        if message_text:
            cmd = {'type': 'command', 'target': self.target, 'action': 'message', 'message': message_text}
            print(f"MessageDialog sending command: {cmd}")
            self.client.publish(self.topic, json.dumps(cmd))
            self.chat_area.append(f"Sent: {message_text}")
            self.message_input.clear()

    def append_message(self, message):
        print(f"MessageDialog appending message: {message}")
        self.chat_area.append(f"Received: {message}")

    def close_dialog(self):
        # Send a close_message command to the bot
        cmd = {'type': 'command', 'target': self.target, 'action': 'close_message'}
        print(f"MessageDialog sending close command: {cmd}")
        self.client.publish(self.topic, json.dumps(cmd))
        self.accept()

class MessagePlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        self.name = "Send Message"
        self.menu_action = self.name
        self.priority = 60
        self.dialogs = {}
        self.message_buffers = {}  # Buffer messages for each target
        # Clear any old buffered messages at startup
        self.message_buffers.clear()
        print("MessagePlugin initialized, cleared message buffers")

    def execute(self, target):
        print(f"MessagePlugin execute: opening dialog for target={target}")
        dialog = MessageDialog(self.parent, target, client=self.parent.client, topic=self.parent.topic)
        self.dialogs[target] = dialog
        # Display any buffered messages for this target
        if target in self.message_buffers:
            print(f"MessagePlugin execute: displaying buffered messages for target={target}: {self.message_buffers[target]}")
            for message in self.message_buffers[target]:
                dialog.append_message(message)
            del self.message_buffers[target]
        dialog.exec()
        print(f"MessagePlugin execute: closing dialog for target={target}")
        del self.dialogs[target]

    def handle_response(self, data):
        if data.get('type') == 'message_response':
            ip = data['ip']
            bot_id = data['id']
            target = f"{ip}:{bot_id}"
            dialog = self.dialogs.get(target)
            message = data.get('message', '')
            # Ignore bot acknowledgment messages
            if message.startswith(f"Bot {bot_id} received:"):
                print(f"MessagePlugin handle_response: ignoring acknowledgment message for target={target}: {message}")
                return
            print(f"MessagePlugin handle_response: target={target}, dialog found={dialog is not None}, message={message}")
            if dialog:
                dialog.append_message(message)
            else:
                # Buffer the message if the dialog is closed
                if target not in self.message_buffers:
                    self.message_buffers[target] = []
                self.message_buffers[target].append(message)
                print(f"MessagePlugin buffered message for target={target}: {message}")