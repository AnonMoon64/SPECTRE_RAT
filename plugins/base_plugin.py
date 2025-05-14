# plugins/base_plugin.py
class BasePlugin:
    def __init__(self, parent):
        self.parent = parent
        self.name = "Base Plugin"
        self.menu_action = None
        self.priority = 0  # Default priority, higher means higher in the menu

    def get_menu_action(self):
        return self.menu_action

    def execute(self, target):
        pass

    def handle_response(self, data):
        pass