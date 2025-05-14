# plugins/cleaner.py
from .base_plugin import BasePlugin
from PyQt6.QtWidgets import QMessageBox
from PyQt6.QtCore import QTimer
import ujson as json
import os

class CleanerPlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        self.name = "Clean Connections"
        self.menu_action = self.name
        self.priority = 80
        self.first_run = True  # Track if this is the first run
        self.pending_bots = {}  # Track bots waiting for a response
        self.timeout_ms = 5000  # 5 seconds timeout

    def execute(self, target):
        # On first run, show confirmation dialog
        if self.first_run:
            self.first_run = False
            reply = QMessageBox.question(self.parent, "Confirm Cleaning",
                                         "Are you sure you want to clean the connections.json file? This will remove unresponsive bots.",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                self.parent.log_area.append("Cleaning aborted by user")
                return

        # Load connections from JSON
        json_file = os.path.join(self.parent.data_dir, 'connections.json')
        if not os.path.exists(json_file):
            self.parent.log_area.append("Connections JSON file not found")
            return

        with open(json_file, 'r') as f:
            bots = json.load(f)

        if not bots:
            self.parent.log_area.append("No bots to clean")
            return

        # Ping each bot and set up a timeout
        self.pending_bots = {}
        for bot in bots:
            bot_id = bot['id']
            ip = bot.get('ip', 'Unknown')
            target = f"{ip}:{bot_id}"
            self.pending_bots[target] = True  # Mark as pending response
            self.parent.log_area.append(f"Pinging {target}...")
            cmd = {'type': 'command', 'target': target, 'action': 'ping'}
            self.parent.client.publish(self.parent.topic, json.dumps(cmd))

        # Set up a timer to check for timeouts
        QTimer.singleShot(self.timeout_ms, self.check_timeouts)

    def handle_response(self, data):
        if data.get('type') == 'connect':  # Presence response to ping
            ip = data['ip']
            bot_id = data['id']
            target = f"{ip}:{bot_id}"
            if target in self.pending_bots:
                self.parent.log_area.append(f"Bot {target} responded to ping")
                self.pending_bots[target] = False  # Mark as responded

    def check_timeouts(self):
        """Check for bots that didn't respond within the timeout period and remove them."""
        json_file = os.path.join(self.parent.data_dir, 'connections.json')
        if not os.path.exists(json_file):
            self.parent.log_area.append("Connections JSON file not found")
            return

        with open(json_file, 'r') as f:
            bots = json.load(f)

        # Filter out unresponsive bots
        remaining_bots = []
        for bot in bots:
            bot_id = bot['id']
            ip = bot.get('ip', 'Unknown')
            target = f"{ip}:{bot_id}"
            if target in self.pending_bots and self.pending_bots[target]:
                self.parent.log_area.append(f"Bot {target} did not respond, removing...")
                # Remove from device table
                self.parent.remove_device_from_table(ip, bot_id)
            else:
                remaining_bots.append(bot)

        # Save updated connections
        with open(json_file, 'w') as f:
            json.dump(remaining_bots, f, indent=4)
        self.parent.log_area.append(f"Cleaned connections.json, {len(remaining_bots)} bots remain")
        self.pending_bots.clear()