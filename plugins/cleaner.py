# plugins/cleaner.py
from .base_plugin import BasePlugin
from PyQt6.QtWidgets import QMessageBox
from PyQt6.QtCore import QTimer
import ujson as json
import os
import time

class CleanerPlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        self.name = "Clean"
        self.menu_action = self.name
        self.category = "Bot"
        self.priority = 3
        self.first_run = True  # Track if this is the first run
        self.pending_bots = {}  # Track bots waiting for a response
        self.timeout_ms = 10000  # 10 seconds timeout
        self.start_time = None  # Track when the ping commands are sent
        self.responses_processed = False  # Track if we're still processing responses

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
        self.responses_processed = False
        self.start_time = time.time()  # Record the start time
        self.parent.log_area.append(f"Starting ping process at {self.start_time}")
        for bot in bots:
            bot_id = bot['id']
            ip = bot.get('ip', 'Unknown')
            target = f"{ip}:{bot_id}"
            self.pending_bots[target] = False  # Initially mark as unresponsive
            self.parent.log_area.append(f"Pinging {target}...")
            cmd = {'type': 'command', 'target': target, 'action': 'ping'}
            cmd_json = json.dumps(cmd)
            encrypted_cmd = self.parent.encrypt_message(cmd_json)
            self.parent.client.publish(self.parent.topic, encrypted_cmd)

        # Set up a timer to check for timeouts
        QTimer.singleShot(self.timeout_ms, self.check_timeouts)

    def handle_response(self, data):
        if data.get('type') == 'connect':  # Presence response to ping
            ip = data['ip']
            bot_id = data['id']
            target = f"{ip}:{bot_id}"
            # Only process the response if we're actively pinging (start_time is set)
            if self.start_time is None:
                self.parent.log_area.append(f"Ignoring connect message from {target} - no active ping operation")
                return
            current_time = time.time()
            elapsed_time = current_time - self.start_time
            self.parent.log_area.append(f"Received connect message from {target} after {elapsed_time:.2f} seconds")
            if target in self.pending_bots:
                self.parent.log_area.append(f"Bot {target} responded to ping after {elapsed_time:.2f} seconds")
                self.pending_bots[target] = True  # Mark as responded
            else:
                self.parent.log_area.append(f"Received response from {target}, but it was not in pending_bots")

    def check_timeouts(self):
        """Check for bots that didn't respond within the timeout period and remove them."""
        current_time = time.time()
        elapsed_time = current_time - self.start_time
        self.responses_processed = True  # Mark that we're done processing responses
        self.parent.log_area.append(f"Checking timeouts after {elapsed_time:.2f} seconds")
        self.parent.log_area.append(f"Pending bots before check: {self.pending_bots}")
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
            self.parent.log_area.append(f"Checking bot {target}: responded={self.pending_bots.get(target, False)}")
            if target in self.pending_bots and not self.pending_bots[target]:
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