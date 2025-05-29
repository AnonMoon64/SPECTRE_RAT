### SPECTRE_RAT
**(System for Persistent Execution, Control, and Targeted Remote Engagement)**

SPECTRE is a remote administration tool that manages bots over MQTT with end-to-end encryption.  It features a GUI for interaction and allows shell access, file transfer, screenshot capture, and connection cleaning.

#### Features
- **MQTT-Based Communication:** Bots communicate with the GUI via MQTT, secured with AES encryption.
- **Shell Access:** Navigate the bot's file system, execute commands, and transfer files.
- **Screenshot Capture:** Capture screenshots from the bot's screen.
- **Connection Cleaning:** Automatically remove unresponsive bots from the connection list.
- **End-to-End Encryption:** All MQTT messages are encrypted using a single AES key stored in settings.json.

#### Prerequisites
- **Python 3.8+** with the packages: PyQt6, paho-mqtt, ujson, pycryptodome.
- **Go 1.16+** for building the bot stub with the dependencies: 
  - `github.com/eclipse/paho.mqtt.golang`
  - `github.com/kbinani/screenshot`

##### Installation Commands:
- Python dependencies: 
  ```bash
  pip install PyQt6 paho-mqtt Jason pycryptodome
  ```
- Go dependencies (during bot generation):
  ```bash
  go get github.com/eclipse/paho.mqtt.golang
  go get github.com/kbinani/screenshot
  ```

#### Setup
1. **Clone the Repository:** 
   ```bash
   git clone <repository-url>
   cd spectre-bot
   ```
2. **Run the GUI:** 
   ```bash
   python SPECTRE.py
   ```
   This will create a `data` folder with `settings.json` (encryption key) and `connections.json` (bot connections).

#### Create a Bot
1.  In the GUI, click "Create Server".
2.  Fill in the bot details (name, broker URL, topic, etc.).  The encryption key from `settings.json` will be embedded in the bot stub, generating an executable (e.g., `server.exe`).

#### Run the Bot
- Copy the generated executable to the target machine and run:
  ```bash
  ./server.exe
  ```
  The bot will connect to the specified MQTT broker.

#### Usage
- **GUI Interface:**
  - **Device Table:** Lists connected bots with their IP, hostname, OS, status, and last ping.
  - **Context Menu:** Right-click a bot for plugins (Shell Access, Take Screenshot, Clean Connections, etc.).
  - **Settings:** Configure the MQTT broker, topic, and encryption key.

- **Plugins:**
  - **Shell Access:** Explore the file system, execute commands, and upload/download files.
  - **Take a Screenshot:** Capture and save a screenshot from the bot.
  - **Clean Connections:** Remove unresponsive bots from `connections.json` after pinging.

#### Security
- **Encryption:** All MQTT communication uses AES-GCM with a single key from `settings.json` on the GUI side, which is hardcoded into each bot.
- **Topic-Based Access:** The MQTT topic is a shared secret for access control.

#### Project Structure
- **SPECTRE.py:** Main GUI application.
- **SPECTRE_Stub.go:** Bot stub template, compiled into an executable for each bot.
- **plugins/:**
  - **shell_access.py:** File explorer and command execution.
  - **screenshot.py:** Functionality for screenshot capture.
  - **cleaner.py:** Removes unresponsive bots.
- **data/:**
  - **settings.json:** Stores encryption key and MQTT settings.
  - **connections.json:** Stores bot connection details.

#### Contributing
Contributions are welcome!  Please submit a pull request or open issues for bugs, feature requests, or improvements.

#### License
This project is licensed under the MIT License.

#### Safety:
This tool is for educational purposes only.  Do not use it for malicious activities.

#### Acknowledgments
- Built with **PyQt6** for the GUI.
- Uses **paho-mqtt** for MQTT communication.
- **pycryptodome** and Go's **crypto/aes** handle encryption.
