package client

import (
	"bufio"
	"fmt"
	"net"
	"time"

	"fyne.io/fyne"
	"fyne.io/fyne/widget"
	"fyne.io/fyne/layout"
	"github.com/Gordon-Yeh/simple-vpn/remote"
)

const (
	defaultIPAddress = "127.0.0.1"
	defaultPort      = "8080"
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
	inputBtn.Enable()
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
		time.Sleep(1000 * time.Millisecond)
	}
}

// Start initializes the client application
func Start(w fyne.Window, app fyne.App) {

	statusLabel = widget.NewLabel("")

	ipAddressField = widget.NewEntry()
	ipAddressField.SetText(defaultIPAddress)

	portField = widget.NewEntry()
	portField.SetText(defaultPort)

	secretField = widget.NewEntry()
	secretField.SetPlaceHolder("shared secret")

	inputArea = widget.NewMultiLineEntry()
	inputArea.SetReadOnly(true)
	inputBtn = widget.NewButton("Send Message", handleSend)
	inputBtn.Disable()

	outputArea = widget.NewMultiLineEntry()
	outputArea.SetReadOnly(true)
	continueBtn = widget.NewButton("Continue", func(){fmt.Println("step")})

	form := widget.NewForm()
	form.Append("IP Address", ipAddressField)
	form.Append("Port", portField)
	form.Append("Secret", secretField)

	clientLayout := widget.NewVBox(
		form,
		widget.NewHBox(layout.NewSpacer(),
			widget.NewButton("Connect", handleConnect),
		),

		widget.NewLabel("Message"),
		inputArea,
		widget.NewHBox(layout.NewSpacer(), inputBtn),

		widget.NewLabel("Received messages"),
		outputArea,
		widget.NewHBox(layout.NewSpacer(), continueBtn),

		widget.NewLabel("Status"),
		statusLabel,
	)

	w.SetContent(clientLayout)

	// run a receiver loop in parallel
	go recvLoop()
}
