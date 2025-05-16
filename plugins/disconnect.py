# plugins/disconnect.py
from PyQt6.QtWidgets import QMessageBox
from .base_plugin import BasePlugin
import ujson as json

class DisconnectPlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        self.name = "Disconnect"
        self.menu_action = self.name
        self.category = "Bot"
        self.priority = 100  # Lowest priority, bottom of the menu

    def execute(self, target):
        # Confirmation for disconnecting all bots
        if target == 'all':
            reply = QMessageBox.question(self.parent, 'Confirm Disconnect', 
                                         'Are you sure you want to disconnect all bots?', 
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                         QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No:
                return

        command = {'type': 'command', 'target': target, 'action': 'disconnect'}
        message = json.dumps(command)
        self.parent.client.publish(self.parent.topic, message)
        self.parent.log_area.append(f"Sent command: {command}")
        if target != 'all':
            ip, bot_id = target.split(':')
            self.parent.remove_device_from_table(ip, bot_id)
        else:
            self.parent.device_table.setRowCount(0)
            self.parent.device_status.clear()
            self.parent.connected_bots_count = 0  # Reset connected count
            self.parent.status_bar.showMessage(f"{self.parent.connected_bots_count} connected")