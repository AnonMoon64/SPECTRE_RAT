# plugins/ping.py
from .base_plugin import BasePlugin
import json

class PingPlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        self.name = "Ping Device"
        self.menu_action = self.name
        self.priority = 100  # Highest priority, top of the menu

    def execute(self, target):
        command = {'type': 'command', 'target': target, 'action': 'ping'}
        message = json.dumps(command)
        self.parent.client.publish(self.parent.topic, message)
        self.parent.log_area.append(f"Sent command: {command}")