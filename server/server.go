package server

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
	conn                 net.Conn
	portField            *widget.Entry
	secretField          *widget.Entry
	serveBtn             *widget.Button
	disconnectBtn        *widget.Button
	inputArea            *widget.Entry
	inputAreaPlaceholder = "Connection must be established first"
	inputBtn             *widget.Button
	outputArea           *widget.Entry
	continueBtn          *widget.Button
	nonce                int
	sharedSecretValue    string
	sessionKey           string
	isConnected          = false
)

func handleServe() {
	var err error

	ui.Log("Initialized server on port " + portField.Text)
	serveBtn.Disable()
	portField.SetReadOnly(true)
	secretField.SetReadOnly(true)

	// TODO: form validation
	if conn, err = remote.ServeAndAccept(portField.Text); err != nil {
		ui.LogE(err)
		handleDisconnect()
		return
	}

	isConnected = true
	ui.Log("Accepted connection from " + conn.RemoteAddr().String())
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
	if isConnected {
		ui.Log("Disconnected")
		isConnected = false
	}
	serveBtn.Enable()
	portField.SetReadOnly(false)
	secretField.SetReadOnly(false)
	disconnectBtn.Disable()

	inputArea.SetReadOnly(true)
	inputArea.SetPlaceHolder(inputAreaPlaceholder)
	inputBtn.Disable()
	outputArea.SetText("")
}

func authenticate() (err error) {

	ui.Step(func() {
		ui.Log("Starting authentication using secret " + sharedSecretValue)
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
		ui.Log("Waiting for Msg1 from client...")
		if decodedMsg, err = remote.ReadMessageStruct(conn); err != nil {
			return
		}

		if msg1, ok = decodedMsg.(crypto.AuthenticationPayloadBeginAB); !ok {
			err = errors.New("Could not parse Msg1")
			return
		}

		nonceAB = msg1.ChallengeAB
		ui.LogI("Received R_A (msg1):\n" + fmt.Sprintf("%x", nonceAB[:]))
	}); err != nil {
		return
	}

	// Msg2: (R_B, Encrypt(SRVR, R_A, g^b%p, K_AB)) -->
	var (
		b            []byte
		nonceBA      []byte
		encrypted    []byte
		partialKeyB  []byte
		decryptedMsg crypto.DecodedChallengePartialKey
	)

	ui.Step(func() {
		nonceBA = crypto.NewChallenge(crypto.DefaultNonceLength)
		ui.Log("Generated R_B =\n" + fmt.Sprintf("%x", nonceBA))
	})

	if ui.Step(func() {
		b = crypto.GenerateRandomExponent()
		ui.Log("Generated b =\n" + crypto.BytesToBigNumString(b))

		partialKeyB = crypto.GeneratePartialKey(b)
		ui.Log("Generated g^b%p =\n" + crypto.BytesToBigNumString(partialKeyB))
	}); err != nil {
		return
	}

	if ui.Step(func() {
		if encrypted, err = crypto.EncryptBytes(append([]byte("SRVR"), append(nonceAB[:], partialKeyB[:]...)...), sharedSecretValue); err != nil {
			return
		}
		ui.Log("Generated Encrypt(SRVR, R_A, g^b%p, K_AB)) =\n" + fmt.Sprintf("%x", encrypted))

		msg2 := crypto.AuthenticationPayloadResponseBA{EncSrvrChallengeABPartialkeyB: encrypted}
		copy(msg2.ChallengeBA[:], nonceBA[:])

		ui.LogO("Sent R_A (msg2):\n" + fmt.Sprintf("%x", nonceBA[:]))
		ui.LogO("Sent Encrypt(SRVR, R_A, g^b%p, K_AB)) (msg2):\n" + fmt.Sprintf("%x", msg2.EncSrvrChallengeABPartialkeyB[:]))
		if err = remote.WriteMessageStruct(conn, msg2); err != nil {
			return
		}
	}); err != nil {
		return
	}

	// Msg3: <-- (Encrypt(R_B, g^a%p, K_AB))
	var (
		msg3        crypto.AuthenticationPayloadResponseAB
		partialKeyA []byte
	)

	if ui.Step(func() {
		ui.Log("Waiting for Msg3 from client...")
		if decodedMsg, err = remote.ReadMessageStruct(conn); err != nil {
			return
		}
		if msg3, ok = decodedMsg.(crypto.AuthenticationPayloadResponseAB); !ok {
			err = errors.New("Could not parse Msg3")
			return
		}
		ui.LogI("Received Encrypt(R_B, g^a%p, K_AB) (msg3):\n" + fmt.Sprintf("%x", msg3.EncChallengeBAPartialKeyA[:]))
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

		partialKeyA = decryptedMsg.PartialKey[:]
		ui.Log("Decrypted Challenge (msg2):\n" + fmt.Sprintf("%x", decryptedMsg.Challenge[:]))
		ui.Log("Decrypted PartialKey (msg2):\n" + crypto.BytesToBigNumString(partialKeyA))
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
		outputArea.SetText(ui.StringWrap(message+"\n"+outputArea.Text, ui.WrapNumWords, ui.WrapWordLength))
	}
}

// Start initializes the client application
func Start(w fyne.Window, app fyne.App) {

	w.Resize(fyne.NewSize(960, 440))

	portField = ui.NewEntry(remote.DefaultPort, "", false)

	secretField = ui.NewEntry("", "Shared Secret Value", false)
	secretField.OnChanged = func(newStr string) {
		sharedSecretValue = newStr
	}

	serveBtn = widget.NewButton("Serve", handleServe)
	disconnectBtn = ui.NewButton("Disconnect", handleDisconnect, true)

	inputArea = ui.NewMultiLineEntry("", inputAreaPlaceholder, true)
	inputBtn = ui.NewButton("Send", handleSend, true)

	outputArea = ui.NewMultiLineEntry("", "", true)
	continueBtn = ui.NewStepperButton("Step")

	form := widget.NewForm()
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
		widget.NewHBox(layout.NewSpacer(), serveBtn, disconnectBtn),
		ui.NewBoldedLabel("Data to be Sent"),
		inputArea,
		widget.NewHBox(layout.NewSpacer(), inputBtn),
		ui.NewBoldedLabel("Data as Received"))
	leftMidCell := widget.NewScrollContainer(widget.NewVBox(outputArea))
	leftCell := fyne.NewContainerWithLayout(layout.NewBorderLayout(leftTopCell, nil, nil, nil), leftTopCell, leftMidCell)

	uiLayout := fyne.NewContainerWithLayout(layout.NewGridLayout(2), leftCell, rightCell)
	w.SetContent(uiLayout)
	ui.Log("Initialized server")
}
