package server

import (
	"bufio"
	"fmt"
	"net"

	"fyne.io/fyne"
	"fyne.io/fyne/widget"
	"github.com/Gordon-Yeh/simple-vpn/remote"
)

const (
	defaultPort = "8080"
)

var (
	conn        net.Conn
	statusLabel *widget.Label
	portField   *widget.Entry
	inputArea   *widget.Entry
	inputBtn    *widget.Button
	outputArea  *widget.Entry
)

func handleServe() {

	var (
		err error
	)

	statusLabel.SetText(fmt.Sprintf("Waiting for a connection on port %s...", portField.Text))

	// TODO: form validation
	if conn, err = remote.ServeAndAccept(portField.Text); err != nil {
		statusLabel.SetText(err.Error())
	}
	statusLabel.SetText("Successfully connected to client")
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
			return
		}
		outputArea.SetText(outputArea.Text + "\n" + message)
	}
}

// Start initializes the client application
func Start(w fyne.Window, app fyne.App) {

	statusLabel = widget.NewLabel("")

	portField = widget.NewEntry()
	portField.SetText(defaultPort)

	inputArea = widget.NewMultiLineEntry()
	inputArea.SetReadOnly(true)
	inputBtn = widget.NewButton("Send Message", handleSend)
	inputBtn.Disable()

	outputArea = widget.NewMultiLineEntry()
	outputArea.SetReadOnly(true)

	clientLayout := widget.NewVBox(
		widget.NewForm(
			&widget.FormItem{Text: "Port", Widget: portField}),
		widget.NewButton("Serve", handleServe),
		inputArea,
		inputBtn,
		widget.NewLabel("Received messages"),
		outputArea,
		statusLabel,
	)

	w.SetContent(clientLayout)

	// run a receiver loop in parallel
	go recvLoop()
}
