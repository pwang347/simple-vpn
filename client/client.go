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
	"strings"
	"sync"
	"time"

	"fyne.io/fyne"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/widget"
	"github.com/pwang347/simple-vpn/crypto"
	"github.com/pwang347/simple-vpn/remote"
	"github.com/pwang347/simple-vpn/ui"
)

var (
	conn                 net.Conn
	ipAddressField       *widget.Entry
	portField            *widget.Entry
	secretField          *widget.Entry
	connectBtn           *widget.Button
	disconnectBtn        *widget.Button
	inputArea            *widget.Entry
	inputAreaPlaceholder = "Connection must be established first"
	inputBtn             *widget.Button
	outputArea           *widget.Entry
	continueBtn          *widget.Button
	nonce                int
	sessionKey           string
	window               fyne.Window
	mutex                sync.Mutex
)

func handleConnect() {
	var err error

	connectBtn.Disable()
	ipAddressField.SetReadOnly(true)
	portField.SetReadOnly(true)
	secretField.SetReadOnly(true)
	ui.Log("Trying to connect to " + ipAddressField.Text + " on port " + portField.Text)

	// TODO: form validation
	if conn, err = remote.Connect(ipAddressField.Text, portField.Text); err != nil {
		ui.LogE(err)
		handleDisconnect()
		return
	}

	ui.Log("Connection accepted by " + conn.RemoteAddr().String())
	disconnectBtn.Enable()

	if err = authenticate(); err != nil {
		ui.LogE(err)
		handleDisconnect()
		return
	}

	inputArea.SetReadOnly(false)
	inputArea.SetPlaceHolder("")
	inputBtn.Enable()

	go recvLoop()
}

func handleDisconnect() {
	if conn != nil {
		conn.Close()
	}
	mutex.Lock()
	if !disconnectBtn.Disabled() {
		ui.Log("Disconnected")
		disconnectBtn.Disable()
	}
	mutex.Unlock()
	connectBtn.Enable()
	ipAddressField.SetReadOnly(false)
	portField.SetReadOnly(false)
	secretField.SetReadOnly(false)

	inputArea.SetReadOnly(true)
	inputArea.SetPlaceHolder(inputAreaPlaceholder)
	inputBtn.Disable()
	outputArea.SetText("")
}

func authenticate() (err error) {

	ui.Step(func() {
		ui.Log("Starting authentication using secret " + secretField.Text)
	})

	// Msg1: (R_A) -->
	var (
		nonceAB []byte
	)

	ui.Step(func() {
		nonceAB = crypto.NewChallenge(crypto.DefaultNonceLength)
		ui.Log("Generated R_A =\n" + fmt.Sprintf("%x", nonceAB))
	})

	if ui.Step(func() {
		msg1 := crypto.AuthenticationPayloadBeginAB{}
		copy(msg1.ChallengeAB[:], nonceAB[:])
		ui.LogO("Sent R_A (msg1) =\n" + fmt.Sprintf("%x", nonceAB))
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
		partialKeyB  []byte
		decryptedMsg crypto.DecodedSrvrChallengePartialKey
	)

	if ui.Step(func() {
		ui.Log("Waiting for Msg2 from server...")
		if decodedMsg, err = remote.ReadMessageStruct(conn); err != nil {
			return
		}
		if msg2, ok = decodedMsg.(crypto.AuthenticationPayloadResponseBA); !ok {
			err = errors.New("Could not parse Msg2")
			return
		}
		ui.LogI("Received R_B (msg2):\n" + fmt.Sprintf("%x", msg2.ChallengeBA[:]))
		ui.LogI("Received Encrypt(SRVR, R_A, g^b%p, K_AB) (msg2):\n" + fmt.Sprintf("%x", msg2.EncSrvrChallengeABPartialkeyB[:]))
	}); err != nil {
		return
	}

	if ui.Step(func() {
		nonceBA = msg2.ChallengeBA
		if decrypted, err = crypto.DecryptBytes(msg2.EncSrvrChallengeABPartialkeyB[:], secretField.Text); err != nil {
			return
		}

		decryptedMsg = crypto.DecodedSrvrChallengePartialKey{}
		if err = binary.Read(bytes.NewReader(decrypted), binary.BigEndian, &decryptedMsg); err != nil {
			return
		}

		partialKeyB = decryptedMsg.PartialKey[:]
		ui.Log("Decrypted SRVR (msg2):\n" + string(decryptedMsg.SRVR[:]))
		ui.Log("Decrypted Challenge (msg2):\n" + fmt.Sprintf("%x", decryptedMsg.Challenge[:]))
		ui.Log("Decrypted PartialKey (msg2):\n" + crypto.BytesToBigNumString(partialKeyB))
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
		a           []byte
		encrypted   []byte
		partialKeyA []byte
	)

	ui.Step(func() {
		a = crypto.GenerateRandomExponent()
		ui.Log("Generated a =\n" + crypto.BytesToBigNumString(a))

		partialKeyA = crypto.GeneratePartialKey(a)
		ui.Log("Generated g^a%p =\n" + crypto.BytesToBigNumString(partialKeyA))
	})

	if ui.Step(func() {
		if encrypted, err = crypto.EncryptBytes(append(nonceBA[:], partialKeyA[:]...), secretField.Text); err != nil {
			return
		}
		ui.Log("Generated Encrypt(R_B, g^a%p, K_AB) =\n" + fmt.Sprintf("%x", encrypted))

		msg3 := crypto.AuthenticationPayloadResponseAB{EncChallengeBAPartialKeyA: encrypted}

		ui.LogO("Sent Encrypt(R_B, g^a%p, K_AB) (msg3):\n" + fmt.Sprintf("%x", msg3.EncChallengeBAPartialKeyA[:]))
		if err = remote.WriteMessageStruct(conn, msg3); err != nil {
			return
		}
	}); err != nil {
		return
	}

	ui.Step(func() {
		key := crypto.ConstructKey(partialKeyB, a)
		sessionKey = crypto.BytesToBigNumString(key)
		ui.LogS("Established Session key:\n" + sessionKey)
		// continueBtn.Disable()
	})
	return
}

func handleSend() {
	var (
		err         error
		encrypted   []byte
		messageSize uint64
	)

	if strings.TrimSpace(inputArea.Text) == "" {
		return
	}

	if encrypted, err = crypto.EncryptBytes([]byte(inputArea.Text), sessionKey); err != nil {
		ui.LogE(err)
		handleDisconnect()
		return
	}

	messageSize = uint64(len(encrypted))
	messageSizeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(messageSizeBytes, messageSize)
	encrypted = append(messageSizeBytes, encrypted...)
	ui.LogO("Sent E(len, message, K_session): " + fmt.Sprintf("%x", encrypted))

	if _, err := conn.Write(encrypted); err != nil {
		ui.LogE(err)
		handleDisconnect()
	}

	inputArea.SetText("")
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

		ui.LogI("Received encrypted text: " + fmt.Sprintf("%x", encrypted))
		if decrypted, err = crypto.DecryptBytes(encrypted, sessionKey); err != nil {
			ui.LogE(err)
			handleDisconnect()
			return
		}

		message = string(decrypted)
		ui.Log("Decrypted message: " + message)
		outputArea.SetText(ui.StringWrap(message+"\n"+outputArea.Text, ui.WrapWordLength))
		window.Resize(window.Canvas().Size())
	}
}

// Start initializes the client application
func Start(w fyne.Window, app fyne.App) {

	w.Resize(fyne.NewSize(960, 440))
	window = w

	ipAddressField = ui.NewEntry(remote.DefaultIPAddress, "", false, 42)
	portField = ui.NewEntry(remote.DefaultPort, "", false, 42)

	secretField = ui.NewEntry("", "Shared Secret Value", false, 42)

	connectBtn = widget.NewButton("Connect", handleConnect)
	disconnectBtn = ui.NewButton("Disconnect", handleDisconnect, true)

	inputArea = ui.NewEntry("", inputAreaPlaceholder, true, 51)
	inputBtn = ui.NewButton("Send", handleSend, true)

	outputArea = ui.NewMultiLineEntry("", "", true)
	continueBtn = ui.NewStepperButton("Step")

	form := widget.NewForm()
	form.Append("IP Address", ipAddressField)
	form.Append("Port", portField)
	form.Append("Secret", secretField)

	headings := fyne.NewContainerWithLayout(layout.NewGridLayout(1),
		widget.NewHBox(
			ui.NewBoldedLabel("Event Log"),
			layout.NewSpacer(),
			ui.NewCheck("Auto", func(b bool) { ui.SetStepMode(!b) }, false),
			continueBtn))
	rightCell := fyne.NewContainerWithLayout(layout.NewBorderLayout(headings, nil, nil, nil), headings, ui.NewScrollingLogContainer())

	leftTopCell := widget.NewVBox(
		form,
		widget.NewHBox(layout.NewSpacer(), connectBtn, disconnectBtn),
		ui.NewBoldedLabel("Data to be Sent"),
		inputArea,
		widget.NewHBox(layout.NewSpacer(), inputBtn),
		ui.NewBoldedLabel("Data as Received"),
	)
	leftMidCell := widget.NewScrollContainer(widget.NewVBox(outputArea))
	leftCell := fyne.NewContainerWithLayout(layout.NewBorderLayout(leftTopCell, nil, nil, nil), leftTopCell, leftMidCell)

	uiLayout := fyne.NewContainerWithLayout(layout.NewGridLayout(2), leftCell, rightCell)
	w.SetContent(uiLayout)
	ui.Log("Initialized client")
}
