package client

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/widget"
	"github.com/Gordon-Yeh/simple-vpn/crypto"
	"github.com/Gordon-Yeh/simple-vpn/remote"
)

const (
	defaultIPAddress = "127.0.0.1"
	defaultPort      = "8080"
	a                = 10
)

var (
	conn           net.Conn
	statusLabel    *widget.Label
	ipAddressField *widget.Entry
	portField      *widget.Entry
	secretField    *widget.Entry
	inputArea      *widget.Entry
	inputBtn       *widget.Button
	outputArea     *widget.Entry
	continueBtn    *widget.Button
	isConnected    bool = false
	nonce          int
)

func handleConnect() {
	var err error

	// TODO: form validation
	if conn, err = remote.Connect(ipAddressField.Text, portField.Text); err != nil {
		statusLabel.SetText(err.Error())
		return
	}
	statusLabel.SetText(fmt.Sprintf("Successfully connected to server at %s:%s", ipAddressField.Text, portField.Text))
	inputArea.SetReadOnly(false)
	inputArea.SetPlaceHolder("")
	inputBtn.Enable()
	isConnected = true

	authenticate()
}

func authenticate() {
	fmt.Println("Client authentication")
	var (
		err       error
		message   string
		reader    *bufio.Reader = bufio.NewReader(conn)
		challenge int
	)
	// Msg1: R_A -->
	nonce = crypto.NewChallenge()
	fmt.Println("send (R_A): " + strconv.Itoa(nonce))
	conn.Write([]byte(strconv.Itoa(nonce) + "\n"))

	// Msg2: <-- R_B, length of encryption
	//       <-- Encrypt(R_A, g^b%p, SHARED_SECRET_VALUE)
	if message, err = reader.ReadString('\n'); err != nil {
		statusLabel.SetText(err.Error())
	}
	message = message[:len(message)-1]
	fields := strings.SplitN(message, " ", 2)
	challenge, err = strconv.Atoi(fields[0])
	fmt.Println("received (R_B): " + fields[0])
	encryptedLen, err := strconv.Atoi(fields[1])
	encryptedBuf := make([]byte, encryptedLen)
	reader.Read(encryptedBuf)

	decrypted := crypto.Decrypt(encryptedBuf, []byte(secretField.Text))
	decryptedParts := strings.SplitN(string(decrypted), " ", 2)
	fmt.Println(decryptedParts)
	retNonce, err := strconv.Atoi(decryptedParts[0])
	theirKey, err := strconv.Atoi(decryptedParts[1])
	if retNonce != nonce {
		fmt.Println("Client challenge failed")
	}
	fmt.Println("Server's partial key:" + decryptedParts[1])

	// Msg3: Encrypt(R_B, g^a%p, SHARED_SECRET_VALUE) -->
	partialKey := crypto.GeneratePartialKey(a)
	fmt.Println("Partial key: " + strconv.Itoa(partialKey))
	encrypted := crypto.Encrypt(challenge, partialKey, secretField.Text)
	conn.Write([]byte(strconv.Itoa(len(encrypted)) + "\n"))
	conn.Write(encrypted)

	key := crypto.GenerateKey(theirKey, a)
	fmt.Println("Established Session key: " + strconv.Itoa(key))
}

func handleSend() {
	// TODO: make sure connection still alive
	conn.Write([]byte(inputArea.Text + "\n"))
}

func recvLoop() {

	var (
		err     error
		message string
		reader  *bufio.Reader
	)

	for {
		time.Sleep(1000 * time.Millisecond)
		if conn == nil {
			continue
		}
		if reader = bufio.NewReader(conn); reader == nil {
			continue
		}
		// TODO: we probably don't want to delimit on newlines
		if message, err = reader.ReadString('\n'); err != nil {
			statusLabel.SetText(err.Error())
			continue
		}
		outputArea.SetText(outputArea.Text + "\n" + message)
	}
}

func NewBoldedLabel(text string) *widget.Label {
	return widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
}

// Start initializes the client application
func Start(w fyne.Window, app fyne.App) {

	statusLabel = widget.NewLabel("")

	ipAddressField = widget.NewEntry()
	ipAddressField.SetText(defaultIPAddress)

	portField = widget.NewEntry()
	portField.SetText(defaultPort)

	secretField = widget.NewEntry()
	secretField.SetPlaceHolder("Shared Secret Value")

	inputArea = widget.NewMultiLineEntry()
	inputArea.SetReadOnly(true)
	inputArea.SetPlaceHolder("Connection must be established first")
	inputBtn = widget.NewButton("Send", handleSend)
	inputBtn.Disable()

	outputArea = widget.NewMultiLineEntry()
	outputArea.SetReadOnly(true)
	continueBtn = widget.NewButton("Continue", func() {
		fmt.Println("step")
	})

	form := widget.NewForm()
	form.Append("IP Address", ipAddressField)
	form.Append("Port", portField)
	form.Append("Secret", secretField)

	clientLayout := widget.NewVBox(
		form,
		widget.NewHBox(layout.NewSpacer(),
			widget.NewButton("Connect", handleConnect),
		),

		NewBoldedLabel("Data to be Sent"),
		inputArea,
		widget.NewHBox(layout.NewSpacer(), inputBtn),

		NewBoldedLabel("Data as Received"),
		outputArea,

		NewBoldedLabel("Status"),
		statusLabel,
		widget.NewHBox(layout.NewSpacer(), continueBtn),
	)

	w.SetContent(clientLayout)

	// run a receiver loop in parallel
	// go recvLoop()
}
