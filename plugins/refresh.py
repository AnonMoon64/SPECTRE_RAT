# plugins/refresh.py
from .base_plugin import BasePlugin

class RefreshPlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        self.name = "Refresh Bots"
        self.menu_action = self.name
        self.priority = 90  # High priority, near the top of the menu

    def execute(self, target):
        try:
            # Clear the current device table
            self.parent.device_table.setRowCount(0)
            self.parent.device_status.clear()
            # Reload the JSON file
            self.parent.load_connections()  # Updated method name
            self.parent.log_area.append("Refreshed bot list from JSON")
        except Exception as e:
            self.parent.log_area.append(f"Error refreshing bot list: {e}")