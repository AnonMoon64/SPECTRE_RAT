# plugins/base_plugin.py
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BasePlugin:
    def __init__(self, parent):
        self.parent = parent
        self.name = "Base Plugin"
        self.menu_action = self.name
        self.priority = 100
        logger.info(f"BasePlugin initialized with name: {self.name}, menu_action: {self.menu_action}")

    def execute(self, target):
        raise NotImplementedError("execute method must be implemented by subclasses")

    def handle_response(self, data):
        pass

    def get_menu_action(self):
        logger.info(f"BasePlugin get_menu_action returning: {self.menu_action}")
        return self.menu_action