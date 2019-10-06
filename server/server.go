package server

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
	defaultPort = "8080"
)

var (
	conn        net.Conn
	statusLabel *widget.Label
	portField   *widget.Entry
	secretField *widget.Entry
	inputArea   *widget.Entry
	inputBtn    *widget.Button
	outputArea  *widget.Entry
	continueBtn *widget.Button
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
	inputArea.SetPlaceHolder("")
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

	inputArea = widget.NewMultiLineEntry()
	inputArea.SetReadOnly(true)
	inputArea.SetPlaceHolder("Connection must be established first")
	inputBtn = widget.NewButton("Send", handleSend)
	inputBtn.Disable()

	outputArea = widget.NewMultiLineEntry()
	outputArea.SetReadOnly(true)
	continueBtn = widget.NewButton("Continue", func(){fmt.Println("step")})

	form := widget.NewForm()
	form.Append("Port", portField)
	form.Append("Secret", secretField)

	clientLayout := widget.NewVBox(
		form,
		widget.NewHBox(layout.NewSpacer(), 
			widget.NewButton("Serve", handleServe),
		),

		NewBoldedLabel("Data to be Sent"),
		inputArea,
		widget.NewHBox(layout.NewSpacer(), inputBtn),

		NewBoldedLabel("Data as Received"),
		outputArea,
		widget.NewHBox(layout.NewSpacer(), continueBtn),

		NewBoldedLabel("Status"),
		statusLabel,
	)

	w.SetContent(clientLayout)

	// run a receiver loop in parallel
	go recvLoop()
}
