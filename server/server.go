package server

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
	defaultPort = "8080"
	b           = 12
)

var (
	conn        net.Conn
	statusLabel *widget.Label
	portField   *widget.Entry
	secretField *widget.Entry
	serveBtn    *widget.Button
	inputArea   *widget.Entry
	inputBtn    *widget.Button
	outputArea  *widget.Entry
	continueBtn *widget.Button
	nonce       int
)

func handleServe() {
	var err error

	statusLabel.SetText(fmt.Sprintf("Waiting for a connection on port %s...", portField.Text))
	serveBtn.Disable()

	// TODO: form validation
	if conn, err = remote.ServeAndAccept(portField.Text); err != nil {
		statusLabel.SetText(err.Error())
	}
	statusLabel.SetText("Successfully connected to client")

	//TODO wait for challenge
	authenticate()

	inputArea.SetReadOnly(false)
	inputArea.SetPlaceHolder("")
	inputBtn.Enable()
}

func handleSend() {
	// TODO: make sure connection still alive
	conn.Write([]byte(inputArea.Text + "\n"))
}

func authenticate() {
	fmt.Println("Server authentication")
	var (
		err       error
		message   string
		reader    *bufio.Reader = bufio.NewReader(conn)
		challenge int
	)
	// Msg1: <-- R_A
	if message, err = reader.ReadString('\n'); err != nil {
		statusLabel.SetText(err.Error())
	}
	message = message[:len(message)-1]
	challenge, err = strconv.Atoi(message)
	fmt.Println("received (R_A): " + message)

	// Msg2: R_B, Encrypt(R_A, g^b%p, SHARED_SECRET_VALUE) -->
	nonce = crypto.NewChallenge()
	fmt.Println("send (R_B): " + strconv.Itoa(nonce))
	partialKey := crypto.GeneratePartialKey(b)
	fmt.Println("Partial key: " + strconv.Itoa(partialKey))
	// TODO: ensure secretField has a value...
	encrypted := crypto.Encrypt(challenge, partialKey, secretField.Text)
	conn.Write([]byte(strconv.Itoa(nonce) + " "))
	conn.Write([]byte(strconv.Itoa(len(encrypted)) + "\n"))
	conn.Write(encrypted)

	// Msg3: <-- length of encryption
	//       <-- Encrypt(R_B, g^a%p, SHARED_SECRET_VALUE)
	if message, err = reader.ReadString('\n'); err != nil {
		statusLabel.SetText(err.Error())
	}
	message = message[:len(message)-1]
	encryptedLen, err := strconv.Atoi(message)
	encryptedBuf := make([]byte, encryptedLen)
	reader.Read(encryptedBuf)

	decrypted := crypto.Decrypt(encryptedBuf, []byte(secretField.Text))
	decryptedParts := strings.SplitN(string(decrypted), " ", 2)
	fmt.Println(decryptedParts)
	retNonce, err := strconv.Atoi(decryptedParts[0])
	theirKey, err := strconv.Atoi(decryptedParts[1])
	if retNonce != nonce {
		fmt.Println("Server challenge failed")
	}
	fmt.Println("Client's partial key:" + decryptedParts[1])

	
	key := crypto.GenerateKey(theirKey, b)
	fmt.Println("Established Session key: " + strconv.Itoa(key))
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

	portField = widget.NewEntry()
	portField.SetText(defaultPort)

	secretField = widget.NewEntry()
	secretField.SetPlaceHolder("Shared Secret Value")
	serveBtn = widget.NewButton("Serve", handleServe)

	inputArea = widget.NewMultiLineEntry()
	inputArea.SetReadOnly(true)
	inputArea.SetPlaceHolder("Connection must be established first")
	inputBtn = widget.NewButton("Send", handleSend)
	inputBtn.Disable()

	outputArea = widget.NewMultiLineEntry()
	outputArea.SetReadOnly(true)
	continueBtn = widget.NewButton("Continue", func() { fmt.Println("step") })

	form := widget.NewForm()
	form.Append("Port", portField)
	form.Append("Secret", secretField)

	clientLayout := widget.NewVBox(
		form,
		widget.NewHBox(layout.NewSpacer(), serveBtn),

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
