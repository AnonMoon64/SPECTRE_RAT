# SPECTRE_RAT
# (System for Persistent Execution, Control, and Targeted Remote Engagement)
SPECTRE Bot
SPECTRE (System for Persistent Execution, Control, and Targeted Remote Engagement) is a remote administration tool designed for managing and controlling bots over MQTT with end-to-end encryption. It provides a GUI for interacting with bots, including features like shell access, file transfer, screenshot capture, and connection cleaning.
Features

MQTT-Based Communication: Bots communicate with the GUI using MQTT, secured with AES encryption.
Shell Access: Navigate the bot's file system, execute commands, and transfer files.
Screenshot Capture: Capture screenshots from the bot's screen and save them on the GUI side.
Connection Cleaning: Automatically remove unresponsive bots from the connection list.
End-to-End Encryption: All MQTT messages are encrypted using a single AES key stored in settings.json.

Prerequisites

Python 3.8+ with the following packages:
PyQt6
paho-mqtt
ujson
pycryptodome


Go 1.16+ for building the bot stub.
Dependencies for Go:
github.com/eclipse/paho.mqtt.golang
github.com/kbinani/screenshot



Install Python dependencies:
pip install PyQt6 paho-mqtt ujson pycryptodome

Install Go dependencies (during bot generation):
go get github.com/eclipse/paho.mqtt.golang
go get github.com/kbinani/screenshot

Setup

Clone the Repository:
git clone <repository-url>
cd spectre-bot


Run the GUI:
python SPECTRE.py

The GUI will create a data folder with settings.json (containing the encryption key) and connections.json (for bot connections).

Create a Bot:

In the GUI, click "Create Server".
Fill in the bot details (name, broker URL, topic, etc.).
The encryption key from settings.json will be embedded into the bot stub.
The bot executable will be generated (e.g., server.exe).


Run the Bot:

Copy the generated bot executable to the target machine.
Run the bot:./server.exe


The bot will connect to the specified MQTT broker and start communicating with the GUI.



Usage

GUI Interface:

Device Table: Lists connected bots with their IP, hostname, OS, status, and last ping.
Context Menu: Right-click on a bot to access plugins (Shell Access, Take Screenshot, Keylogger, Clean Connections, etc.).
Settings: Configure the MQTT broker, topic, and encryption key under "Settings".


Plugins:

Shell Access: Navigate the bot's file system, execute commands, download/upload files, and execute files.
Take Screenshot: Capture a screenshot from the bot and save it to the downloads folder.
Keylogger: Display simulated keystrokes from the bot in a dialog.
Clean Connections: Remove unresponsive bots from connections.json after pinging them.



Security

Encryption: All MQTT communication is encrypted using AES-GCM with a single key stored in settings.json on the GUI side and hardcoded into each bot.
Topic-Based Access: The MQTT topic acts as a shared secret for access control.

Project Structure

SPECTRE.py: Main GUI application.
SPECTRE_Stub.go: Bot stub template, compiled into an executable for each bot.
plugins/:
shell_access.py: File explorer and shell command execution.
screenshot.py: Screenshot capture functionality.
cleaner.py: Removes unresponsive bots.


data/:
settings.json: Stores the encryption key and MQTT settings.
connections.json: Stores bot connection details.



Contributing
Contributions are welcome! Please submit a pull request or open an issue for bugs, feature requests, or improvements.
License
This project is licensed under the MIT License - see the LICENSE file for details.
Acknowledgments

Built with PyQt6 for the GUI.
Uses paho-mqtt for MQTT communication.
Encryption powered by pycryptodome and Go's crypto/aes.

