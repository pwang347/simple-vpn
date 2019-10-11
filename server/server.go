package server

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"fyne.io/fyne"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/widget"
	"github.com/Gordon-Yeh/simple-vpn/crypto"
	"github.com/Gordon-Yeh/simple-vpn/remote"
	"github.com/Gordon-Yeh/simple-vpn/ui"
)

var (
	conn              net.Conn
	portField         *widget.Entry
	secretField       *widget.Entry
	serveBtn          *widget.Button
	disconnectBtn     *widget.Button
	inputArea         *widget.Entry
	inputBtn          *widget.Button
	outputArea        *widget.Entry
	continueBtn       *widget.Button
	nonce             int
	sharedSecretValue string
	sessionKey        string
	isConnected       bool
)

func handleServe() {
	var err error

	ui.DisplayMessageStatus(fmt.Sprintf("Waiting for a connection on port %s...", portField.Text))
	serveBtn.Disable()
	portField.SetReadOnly(true)

	// TODO: form validation
	if conn, err = remote.ServeAndAccept(portField.Text); err != nil {
		ui.LogE(err)
		handleDisconnect()
		return
	}

	ui.Log("Accepted connection from " + conn.RemoteAddr().String())
	ui.DisplayMessageStatus("Established connection to client")

	if err = authenticate(); err != nil {
		ui.LogE(err)
		handleDisconnect()
		return
	}

	ui.DisplayMessageStatus("Successfully authenticated with client")

	inputArea.SetReadOnly(false)
	inputArea.SetPlaceHolder("")
	inputBtn.Enable()
	disconnectBtn.Enable()
	isConnected = true

	go recvLoop()
}

func authenticate() (err error) {

	ui.Step(func() {
		ui.Log("Starting client authentication")
	})

	// Msg1: <-- (R_A)
	var (
		msg1       crypto.AuthenticationPayloadBeginAB
		ok         bool
		nonceAB    [crypto.DefaultNonceLength]byte
		decrypted  []byte
		decodedMsg interface{}
	)

	if ui.Step(func() {
		ui.DisplayMessageStatus("Waiting for Msg1 from client...")
		if decodedMsg, err = remote.ReadMessageStruct(conn); err != nil {
			return
		}

		if msg1, ok = decodedMsg.(crypto.AuthenticationPayloadBeginAB); !ok {
			err = errors.New("Could not parse Msg1")
			return
		}

		nonceAB = msg1.ChallengeAB
		ui.LogI("Received R_A (msg1):\n" + ui.FormatBinary(nonceAB[:]))
	}); err != nil {
		return
	}

	// Msg2: (R_B, Encrypt(SRVR, R_A, g^b%p, SHARED_SECRET_VALUE)) -->
	var (
		b            uint64
		nonceBA      []byte
		encrypted    []byte
		partialKeyB  uint64
		decryptedMsg crypto.DecodedChallengePartialKey
	)

	ui.Step(func() {
		nonceBA = crypto.NewChallenge(crypto.DefaultNonceLength)
		ui.Log("Generated R_B =\n" + ui.FormatBinary(nonceBA))
	})

	if ui.Step(func() {
		b = crypto.GenerateRandomExponent()
		ui.Log("Generated b =\n" + fmt.Sprintf("%d", (b)))

		partialKeyB = crypto.GeneratePartialKey(b)
		ui.Log("Generated g^b%p =\n" + fmt.Sprintf("%d", partialKeyB))
	}); err != nil {
		return
	}

	if ui.Step(func() {
		partialKeyBBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(partialKeyBBytes, partialKeyB)
		if encrypted, err = crypto.EncryptBytes(append([]byte("SRVR"), append(nonceAB[:], partialKeyBBytes[:]...)...), sharedSecretValue); err != nil {
			return
		}
		ui.Log("Generated Encrypt(SRVR, R_A, g^b%p, SHARED_SECRET_VALUE)) =\n" + ui.FormatBinary(encrypted))

		msg2 := crypto.AuthenticationPayloadResponseBA{EncSrvrChallengeABPartialkeyB: encrypted}
		copy(msg2.ChallengeBA[:], nonceBA[:])

		ui.LogO("Sent R_A (msg2):\n" + ui.FormatBinary(nonceBA[:]))
		ui.LogO("Sent Encrypt(SRVR, R_A, g^b%p, SHARED_SECRET_VALUE)) (msg2):\n" + ui.FormatBinary(msg2.EncSrvrChallengeABPartialkeyB[:]))
		ui.DisplayMessageStatus("Waiting for client to read Msg2...")
		if err = remote.WriteMessageStruct(conn, msg2); err != nil {
			return
		}
	}); err != nil {
		return
	}

	// Msg3: <-- (Encrypt(R_B, g^a%p, SHARED_SECRET_VALUE))
	var (
		msg3        crypto.AuthenticationPayloadResponseAB
		partialKeyA uint64
	)

	if ui.Step(func() {
		ui.DisplayMessageStatus("Waiting for Msg3 from client...")
		if decodedMsg, err = remote.ReadMessageStruct(conn); err != nil {
			return
		}
		if msg3, ok = decodedMsg.(crypto.AuthenticationPayloadResponseAB); !ok {
			err = errors.New("Could not parse Msg3")
			return
		}
		ui.LogI("Received Encrypt(R_B, g^a%p, SHARED_SECRET_VALUE) (msg3):\n" + ui.FormatBinary(msg3.EncChallengeBAPartialKeyA[:]))
	}); err != nil {
		return
	}

	if ui.Step(func() {
		if decrypted, err = crypto.DecryptBytes(msg3.EncChallengeBAPartialKeyA[:], sharedSecretValue); err != nil {
			return
		}

		decryptedMsg = crypto.DecodedChallengePartialKey{}
		if err = binary.Read(bytes.NewReader(decrypted), binary.BigEndian, &decryptedMsg); err != nil {
			return
		}

		partialKeyA = binary.LittleEndian.Uint64(decryptedMsg.PartialKey[:])
		ui.Log("Decrypted Challenge (msg2):\n" + ui.FormatBinary(decryptedMsg.Challenge[:]))
		ui.Log("Decrypted PartialKey (msg2):\n" + fmt.Sprintf("%d", partialKeyA))
	}); err != nil {
		return
	}

	if ui.Step(func() {
		if !bytes.Equal(decryptedMsg.Challenge[:], nonceBA) {
			err = errors.New("Client failed authentication challenge")
			return
		}
	}); err != nil {
		return
	}

	ui.Step(func() {
		key := crypto.ConstructKey(partialKeyA, b)
		sessionKey = strconv.FormatUint(key, 10)
		ui.LogS("Established Session key:\n" + sessionKey)
	})
	return
}

func handleDisconnect() {
	if err := conn.Close(); err != nil {
		ui.LogE(err)
	}
	ui.DisplayMessageStatus("Disconnected")
	isConnected = false
	serveBtn.Enable()
	portField.SetReadOnly(false)
	disconnectBtn.Disable()
}

func handleSend() {
	var (
		err       error
		encrypted []byte
	)
	if encrypted, err = crypto.EncryptMessage(inputArea.Text, sessionKey); err != nil {
		ui.LogE(err)
		return
	}
	encrypted = append(encrypted, []byte("\n")...)
	ui.Log("Sent encrypted text: " + ui.FormatBinary(encrypted))
	if _, err := conn.Write(encrypted); err != nil {
		ui.LogE(err)
	}
}

func recvLoop() {
	var (
		err       error
		encrypted []byte
		message   string
		reader    *bufio.Reader
	)
	for {
		time.Sleep(1000 * time.Millisecond)
		if !isConnected {
			fmt.Println("Not connected..")
			return
		}
		if conn == nil {
			continue
		}
		if reader = bufio.NewReader(conn); reader == nil {
			continue
		}
		// TODO: we probably don't want to delimit on newlines
		if encrypted, err = reader.ReadBytes('\n'); err != nil {
			ui.LogE(err)
			continue
		}
		ui.Log("Received encrypted text: " + ui.FormatBinary(encrypted))
		encrypted = encrypted[:len(encrypted)-1]
		if message, err = crypto.DecryptMessage(encrypted, sessionKey); err != nil {
			ui.LogE(err)
			continue
		}
		outputArea.SetText(outputArea.Text + "\n" + message)
	}
}

// Start initializes the client application
func Start(w fyne.Window, app fyne.App) {

	w.Resize(fyne.NewSize(960, 400))

	portField = ui.NewEntry(remote.DefaultPort, "", false)

	secretField = ui.NewEntry("", "Shared Secret Value", false)
	secretField.OnChanged = func(newStr string) {
		sharedSecretValue = newStr
	}

	serveBtn = widget.NewButton("Serve", handleServe)
	disconnectBtn = ui.NewButton("Disconnect", handleDisconnect, true)

	inputArea = ui.NewMultiLineEntry("", "Connection must be established first", true)
	inputBtn = ui.NewButton("Send", handleSend, true)

	outputArea = ui.NewMultiLineEntry("", "", true)

	form := widget.NewForm()
	form.Append("Port", portField)
	form.Append("Secret", secretField)

	headings := fyne.NewContainerWithLayout(layout.NewGridLayout(1), ui.NewBoldedLabel("Event Log"))
	scrollLayout := fyne.NewContainerWithLayout(layout.NewBorderLayout(headings, nil, nil, nil), headings, ui.NewScrollingLogContainer())

	clientLayout := fyne.NewContainerWithLayout(layout.NewGridLayout(2),
		widget.NewVBox(
			form,
			widget.NewHBox(layout.NewSpacer(), serveBtn, disconnectBtn),

			ui.NewBoldedLabel("Data to be Sent"),
			inputArea,
			widget.NewHBox(layout.NewSpacer(), inputBtn),

			ui.NewBoldedLabel("Data as Received"),
			outputArea,

			ui.NewBoldedLabel("Status"),
			ui.NewStatusLabel(),
			widget.NewHBox(layout.NewSpacer(), ui.NewCheck("Auto", func(b bool) { ui.SetStepMode(!b) }, false), ui.NewStepperButton("Step")),
		),
		scrollLayout)

	w.SetContent(clientLayout)
	ui.Log("Initialized server")

	w.SetContent(clientLayout)
}
