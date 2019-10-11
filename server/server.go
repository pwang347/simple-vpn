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
	statusLabel       *widget.Label
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

	ui.DisplayMessage(fmt.Sprintf("Waiting for a connection on port %s...", portField.Text))
	serveBtn.Disable()
	// TODO: form validation
	if conn, err = remote.ServeAndAccept(portField.Text); err != nil {
		ui.DisplayError(err)
		return
	}
	ui.DisplayMessage("Established connection to client")

	if err = authenticate(); err != nil {
		ui.DisplayError(err)
		return
	}
	ui.DisplayMessage("Successfully authenticated with client")

	inputArea.SetReadOnly(false)
	inputArea.SetPlaceHolder("")
	inputBtn.Enable()
	disconnectBtn.Enable()
	isConnected = true

	go recvLoop()
}

func authenticate() (err error) {
	fmt.Println("Server authentication")
	ui.DisplayMessage("Start mutual authentication [Continue]")
	ui.Pause()

	// Msg1: <-- R_A
	var (
		decodedMsg interface{}
		msg1       crypto.AuthenticationPayloadBeginAB
		msg3       crypto.AuthenticationPayloadResponseAB
		msg3s      string
		ok         bool
		nonceAB    [crypto.DefaultNonceLength]byte
		encrypted  []byte
		decrypted  []byte
	)

	ui.DisplayMessage("Waiting for response from client [1]...")
	if decodedMsg, err = remote.ReadMessageStruct(conn); err != nil {
		return
	}

	if msg1, ok = decodedMsg.(crypto.AuthenticationPayloadBeginAB); !ok {
		err = errors.New("Cast for received message [1] failed")
		return
	}

	nonceAB = msg1.ChallengeAB
	fmt.Println("received (R_A): " + string(nonceAB[:]))
	ui.DisplayMessage("Received: <Msg1> [Continue]")
	ui.Pause()

	// Msg2: R_B, Encrypt(R_A, g^b%p, SHARED_SECRET_VALUE) -->
	nonceBA := crypto.NewChallenge(crypto.DefaultNonceLength)

	b := crypto.GenerateRandomExponent()
	fmt.Printf("Selected exponent: %d\n", b)

	partialKeyB := crypto.GeneratePartialKey(b)
	fmt.Printf("Generated partial key: %d\n", partialKeyB)

	partialKeyBBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(partialKeyBBytes, partialKeyB)
	if encrypted, err = crypto.EncryptBytes(append(nonceAB[:], partialKeyBBytes[:]...), sharedSecretValue); err != nil {
		return
	}

	msg2 := crypto.AuthenticationPayloadResponseBA{EncChallengeABPartialkeyB: encrypted}
	copy(msg2.ChallengeBA[:], nonceBA[:])

	ui.DisplayMessage("Sending: <Msg2> [Continue]")
	ui.Pause()
	if err = remote.WriteMessageStruct(conn, msg2); err != nil {
		return
	}
	ui.DisplayMessage("Waiting for read from client...")

	// Msg3: <-- length of encryption
	//       <-- Encrypt(R_B, g^a%p, SHARED_SECRET_VALUE)
	ui.DisplayMessage("Waiting for response from client [2]...")
	if decodedMsg, err = remote.ReadMessageStruct(conn); err != nil {
		return
	}

	if msg3, ok = decodedMsg.(crypto.AuthenticationPayloadResponseAB); !ok {
		err = errors.New("Cast for received message [3] failed")
		return
	}

	msg3s, err = remote.StructToString(msg3)
	fmt.Println("received (R_A): " + msg3s)
	ui.DisplayMessage("Received: <Msg3> [Continue]")
	ui.Pause()

	if decrypted, err = crypto.DecryptBytes(msg3.EncChallengeBAPartialKeyA[:], sharedSecretValue); err != nil {
		return
	}

	decryptedMsg := crypto.DecodedChallengePartialKey{}
	if err = binary.Read(bytes.NewReader(decrypted), binary.BigEndian, &decryptedMsg); err != nil {
		return
	}

	if !bytes.Equal(decryptedMsg.Challenge[:], nonceBA) {
		err = errors.New("Client failed challenge")
		return
	}

	var partialKeyA uint64 = binary.LittleEndian.Uint64(decryptedMsg.PartialKey[:])
	fmt.Printf("Client's partial key: %d\n", partialKeyA)

	key := crypto.ConstructKey(partialKeyA, b)
	sessionKey = strconv.FormatUint(key, 10)
	fmt.Println("Established Session key: " + sessionKey)
	ui.DisplayMessage("Established Session key: " + sessionKey + " [Continue]")
	ui.Pause()
	return
}

func handleDisconnect() {
	if err := conn.Close(); err != nil {
		ui.DisplayError(err)
	}
	ui.DisplayMessage("Disconnected")
	isConnected = false
	serveBtn.Enable()
	disconnectBtn.Disable()
}

func handleSend() {
	var (
		err       error
		encrypted []byte
	)
	if encrypted, err = crypto.EncryptMessage(inputArea.Text, sessionKey); err != nil {
		ui.DisplayError(err)
		return
	}
	encrypted = append(encrypted, []byte("\n")...)
	fmt.Printf("Sending encrypted text: %s\n", encrypted)
	if _, err := conn.Write(encrypted); err != nil {
		ui.DisplayError(err)
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
			ui.DisplayError(err)
			continue
		}
		fmt.Printf("Received encrypted text: %s\n", encrypted)
		encrypted = encrypted[:len(encrypted)-1]
		if message, err = crypto.DecryptMessage(encrypted, sessionKey); err != nil {
			ui.DisplayError(err)
			continue
		}
		outputArea.SetText(outputArea.Text + "\n" + message)
	}
}

// Start initializes the client application
func Start(w fyne.Window, app fyne.App) {

	statusLabel = widget.NewLabel("")
	ui.SetStatusLabel(statusLabel)

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
	continueBtn = widget.NewButton("Continue", func() {
		fmt.Println("Continue")
		go ui.Resume() // FIXME: is the `go` needed? it seems to work either way; I just assumed the Pause() would freeze things but I don't think it does because of sleep()
	})

	form := widget.NewForm()
	form.Append("Port", portField)
	form.Append("Secret", secretField)

	clientLayout := widget.NewVBox(
		form,
		widget.NewHBox(layout.NewSpacer(), serveBtn, disconnectBtn),

		ui.NewBoldedLabel("Data to be Sent"),
		inputArea,
		widget.NewHBox(layout.NewSpacer(), inputBtn),

		ui.NewBoldedLabel("Data as Received"),
		outputArea,

		ui.NewBoldedLabel("Status"),
		statusLabel,
		widget.NewHBox(layout.NewSpacer(), continueBtn),
	)

	w.SetContent(clientLayout)
}
