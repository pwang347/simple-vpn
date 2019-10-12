package client

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	ipAddressField    *widget.Entry
	portField         *widget.Entry
	secretField       *widget.Entry
	connectBtn        *widget.Button
	disconnectBtn     *widget.Button
	inputArea         *widget.Entry
	inputBtn          *widget.Button
	outputArea        *widget.Entry
	nonce             int
	sharedSecretValue string
	sessionKey        string
)

func handleConnect() {
	var err error

	connectBtn.Disable()
	ipAddressField.SetReadOnly(true)
	portField.SetReadOnly(true)
	ui.DisplayMessageStatus(fmt.Sprintf("Waiting for a connection with %s on port %s...", ipAddressField.Text, portField.Text))

	// TODO: form validation
	if conn, err = remote.Connect(ipAddressField.Text, portField.Text); err != nil {
		ui.LogE(err)
		handleDisconnect()
		return
	}

	ui.Log("Connection accepted by " + conn.RemoteAddr().String())
	ui.DisplayMessageStatus("Established connection to server")

	if err = authenticate(); err != nil {
		ui.LogE(err)
		handleDisconnect()
		return
	}
	ui.DisplayMessageStatus("Successfully authenticated with server")

	inputArea.SetReadOnly(false)
	inputArea.SetPlaceHolder("")
	inputBtn.Enable()
	disconnectBtn.Enable()

	go recvLoop()
}

func authenticate() (err error) {

	ui.Step(func() {
		ui.Log("Starting client authentication")
	})

	// Msg1: (R_A) -->
	var (
		nonceAB []byte
	)

	ui.Step(func() {
		nonceAB = crypto.NewChallenge(crypto.DefaultNonceLength)
		ui.Log("Generated R_A =\n" + ui.FormatBinary(nonceAB))
	})

	if ui.Step(func() {
		msg1 := crypto.AuthenticationPayloadBeginAB{}
		copy(msg1.ChallengeAB[:], nonceAB[:])
		ui.LogO("Sent R_A (msg1) =\n" + ui.FormatBinary(nonceAB))
		ui.DisplayMessageStatus("Waiting for server to read Msg1...")
		err = remote.WriteMessageStruct(conn, msg1)
	}); err != nil {
		return
	}

	// Msg2: <-- (R_B, Encrypt(SRVR, R_A, g^b%p, K_AB))
	var (
		decodedMsg   interface{}
		msg2         crypto.AuthenticationPayloadResponseBA
		ok           bool
		nonceBA      [crypto.DefaultNonceLength]byte
		decrypted    []byte
		partialKeyB  uint64
		decryptedMsg crypto.DecodedSrvrChallengePartialKey
	)

	if ui.Step(func() {
		ui.DisplayMessageStatus("Waiting for Msg2 from server...")
		if decodedMsg, err = remote.ReadMessageStruct(conn); err != nil {
			return
		}
		if msg2, ok = decodedMsg.(crypto.AuthenticationPayloadResponseBA); !ok {
			err = errors.New("Could not parse Msg2")
			return
		}
		ui.LogI("Received R_B (msg2):\n" + ui.FormatBinary(msg2.ChallengeBA[:]))
		ui.LogI("Received Encrypt(SRVR, R_A, g^b%p, K_AB) (msg2):\n" + ui.FormatBinary(msg2.EncSrvrChallengeABPartialkeyB[:]))
	}); err != nil {
		return
	}

	if ui.Step(func() {
		nonceBA = msg2.ChallengeBA
		if decrypted, err = crypto.DecryptBytes(msg2.EncSrvrChallengeABPartialkeyB[:], sharedSecretValue); err != nil {
			return
		}

		decryptedMsg = crypto.DecodedSrvrChallengePartialKey{}
		if err = binary.Read(bytes.NewReader(decrypted), binary.BigEndian, &decryptedMsg); err != nil {
			return
		}

		partialKeyB = binary.LittleEndian.Uint64(decryptedMsg.PartialKey[:])
		ui.Log("Decrypted SRVR (msg2):\n" + string(decryptedMsg.SRVR[:]))
		ui.Log("Decrypted Challenge (msg2):\n" + ui.FormatBinary(decryptedMsg.Challenge[:]))
		ui.Log("Decrypted PartialKey (msg2):\n" + fmt.Sprintf("%d", partialKeyB))
	}); err != nil {
		return
	}

	if ui.Step(func() {
		if !bytes.Equal(decryptedMsg.Challenge[:], nonceAB) {
			err = errors.New("Server failed authentication challenge")
			return
		}
	}); err != nil {
		return
	}

	// Msg3: Encrypt(R_B, g^a%p, K_AB) -->
	var (
		a           uint64
		encrypted   []byte
		partialKeyA uint64
	)

	ui.Step(func() {
		a = crypto.GenerateRandomExponent()
		ui.Log("Generated a =\n" + fmt.Sprintf("%d", (a)))

		partialKeyA = crypto.GeneratePartialKey(a)
		ui.Log("Generated g^a%p =\n" + fmt.Sprintf("%d", partialKeyA))
	})

	if ui.Step(func() {
		partialKeyABytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(partialKeyABytes, partialKeyA)
		if encrypted, err = crypto.EncryptBytes(append(nonceBA[:], partialKeyABytes[:]...), sharedSecretValue); err != nil {
			return
		}
		ui.Log("Generated Encrypt(R_B, g^a%p, K_AB) =\n" + ui.FormatBinary(encrypted))

		msg3 := crypto.AuthenticationPayloadResponseAB{EncChallengeBAPartialKeyA: encrypted}

		ui.LogO("Sent Encrypt(R_B, g^a%p, K_AB) (msg3):\n" + ui.FormatBinary(msg3.EncChallengeBAPartialKeyA[:]))
		ui.DisplayMessageStatus("Waiting for server to read Msg3...")
		if err = remote.WriteMessageStruct(conn, msg3); err != nil {
			return
		}
	}); err != nil {
		return
	}

	ui.Step(func() {
		key := crypto.ConstructKey(partialKeyB, a)
		sessionKey = strconv.FormatUint(key, 10)
		ui.LogS("Established Session key:\n" + sessionKey)
	})
	return
}

func handleDisconnect() {
	if conn != nil {
		conn.Close()
	}
	ui.Log("Disconnected")
	ui.DisplayMessageStatus("Disconnected")
	connectBtn.Enable()
	ipAddressField.SetReadOnly(false)
	portField.SetReadOnly(false)
	disconnectBtn.Disable()
}

func handleSend() {
	var (
		err         error
		encrypted   []byte
		messageSize uint64
	)

	if encrypted, err = crypto.EncryptBytes([]byte(inputArea.Text), sessionKey); err != nil {
		ui.LogE(err)
		handleDisconnect()
		return
	}

	messageSize = uint64(len(encrypted))
	messageSizeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(messageSizeBytes, messageSize)
	encrypted = append(messageSizeBytes, encrypted...)
	ui.LogO("Sent E(len, message, K_session): " + ui.FormatBinary(encrypted))

	if _, err := conn.Write(encrypted); err != nil {
		ui.LogE(err)
		handleDisconnect()
	}
}

func recvLoop() {
	var (
		err       error
		decrypted []byte
		message   string
		reader    *bufio.Reader
	)
	for {
		time.Sleep(1000 * time.Millisecond)
		if conn == nil {
			continue
		}
		if reader = bufio.NewReader(conn); reader == nil {
			continue
		}

		messageSizeBytes := make([]byte, 8)
		if _, err := io.ReadFull(reader, messageSizeBytes); err != nil {
			ui.LogE(err)
			handleDisconnect()
			return
		}

		messageSize := binary.LittleEndian.Uint64(messageSizeBytes[:])
		ui.LogI("Received message of length: " + strconv.FormatUint(messageSize, 10))

		encrypted := make([]byte, messageSize)
		if _, err := io.ReadFull(reader, encrypted); err != nil {
			ui.LogE(err)
			handleDisconnect()
			return
		}

		ui.LogI("Received encrypted text: " + ui.FormatBinary(encrypted))
		if decrypted, err = crypto.DecryptBytes(encrypted, sessionKey); err != nil {
			ui.LogE(err)
			handleDisconnect()
			return
		}

		message = string(decrypted)
		ui.Log("Decrypted message: " + message)
		outputArea.SetText(outputArea.Text + "\n" + message)
	}
}

// Start initializes the client application
func Start(w fyne.Window, app fyne.App) {

	w.Resize(fyne.NewSize(960, 400))

	ipAddressField = ui.NewEntry(remote.DefaultIPAddress, "", false)
	portField = ui.NewEntry(remote.DefaultPort, "", false)

	secretField = ui.NewEntry("", "Shared Secret Value", false)
	secretField.OnChanged = func(newStr string) {
		sharedSecretValue = newStr
	}

	connectBtn = widget.NewButton("Connect", handleConnect)
	disconnectBtn = ui.NewButton("Disconnect", handleDisconnect, true)

	inputArea = ui.NewMultiLineEntry("", "Connection must be established first", true)
	inputBtn = ui.NewButton("Send", handleSend, true)

	outputArea = ui.NewMultiLineEntry("", "", true)

	form := widget.NewForm()
	form.Append("IP Address", ipAddressField)
	form.Append("Port", portField)
	form.Append("Secret", secretField)

	headings := fyne.NewContainerWithLayout(layout.NewGridLayout(1), ui.NewBoldedLabel("Event Log"))
	scrollLayout := fyne.NewContainerWithLayout(layout.NewBorderLayout(headings, nil, nil, nil), headings, ui.NewScrollingLogContainer())

	clientLayout := fyne.NewContainerWithLayout(layout.NewGridLayout(2),
		widget.NewVBox(
			form,
			widget.NewHBox(layout.NewSpacer(), connectBtn, disconnectBtn),

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
	ui.Log("Initialized client")
}
