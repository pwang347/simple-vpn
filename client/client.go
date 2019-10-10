package client

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
	ipAddressField    *widget.Entry
	portField         *widget.Entry
	secretField       *widget.Entry
	inputArea         *widget.Entry
	inputBtn          *widget.Button
	outputArea        *widget.Entry
	continueBtn       *widget.Button
	nonce             int
	sharedSecretValue string
	sessionKey        string
)

func handleConnect() {
	var err error

	// TODO: form validation
	if conn, err = remote.Connect(ipAddressField.Text, portField.Text); err != nil {
		ui.DisplayError(err)
		return
	}
	ui.DisplayMessage(fmt.Sprintf("Successfully connected to server at %s:%s", ipAddressField.Text, portField.Text))
	if err = authenticate(); err != nil {
		ui.DisplayError(err)
		return
	}
	ui.DisplayMessage(fmt.Sprintf("Authenticated with server at %s:%s", ipAddressField.Text, portField.Text))
	inputArea.SetReadOnly(false)
	inputArea.SetPlaceHolder("")
	inputBtn.Enable()

	go recvLoop()
}

func authenticate() (err error) {

	fmt.Println("Client authentication")
	ui.DisplayMessage("Performing mutual authentication")

	// Msg1: R_A -->
	nonceAB := crypto.NewChallenge(crypto.DefaultNonceLength)
	msg1 := crypto.AuthenticationPayloadBeginAB{}
	copy(msg1.ChallengeAB[:], nonceAB[0:crypto.DefaultNonceLength])
	fmt.Println("send (R_A): " + string(nonceAB))

	ui.DisplayMessage("Waiting for read from server [1]...")
	if err = remote.WriteMessageStruct(conn, msg1); err != nil {
		return
	}

	// Msg2: <-- R_B, length of encryption
	//       <-- Encrypt(R_A, g^b%p, SHARED_SECRET_VALUE)
	var (
		decodedMsg interface{}
		msg2       crypto.AuthenticationPayloadResponseBA
		ok         bool
		nonceBA    [crypto.DefaultNonceLength]byte
		encrypted  []byte
		decrypted  []byte
	)

	ui.DisplayMessage("Waiting for response from server...")
	if decodedMsg, err = remote.ReadMessageStruct(conn); err != nil {
		return
	}

	if msg2, ok = decodedMsg.(crypto.AuthenticationPayloadResponseBA); !ok {
		err = errors.New("Cast for received message failed [2]")
		return
	}

	fmt.Println("received (R_B): " + string(msg2.ChallengeBA[:]))

	nonceBA = msg2.ChallengeBA
	if decrypted, err = crypto.DecryptBytes(msg2.EncChallengeABPartialkeyB[:], sharedSecretValue); err != nil {
		return
	}

	decryptedMsg := crypto.DecodedChallengePartialKey{}
	if err = binary.Read(bytes.NewReader(decrypted), binary.BigEndian, &decryptedMsg); err != nil {
		return
	}

	if !bytes.Equal(decryptedMsg.Challenge[:], nonceAB) {
		err = errors.New("Server failed challenge")
		return
	}

	var partialKeyB uint64 = binary.LittleEndian.Uint64(decryptedMsg.PartialKey[:])
	fmt.Printf("Server's partial key: %d\n", partialKeyB)

	// Msg3: Encrypt(R_B, g^a%p, SHARED_SECRET_VALUE) -->
	a := crypto.GenerateRandomExponent()
	fmt.Printf("Selected exponent: %d\n", a)

	partialKeyA := crypto.GeneratePartialKey(a)
	fmt.Printf("Generated partial key: %d\n", partialKeyA)
	partialKeyABytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(partialKeyABytes, partialKeyA)
	if encrypted, err = crypto.EncryptBytes(append(nonceBA[:], partialKeyABytes[:]...), sharedSecretValue); err != nil {
		return
	}

	msg3 := crypto.AuthenticationPayloadResponseAB{EncChallengeBAPartialKeyA: encrypted}

	ui.DisplayMessage("Waiting for read from server [2]...")
	if err = remote.WriteMessageStruct(conn, msg3); err != nil {
		return
	}

	key := crypto.ConstructKey(partialKeyB, a)
	sessionKey = strconv.FormatUint(key, 10)
	fmt.Println("Established Session key: " + sessionKey)
	return
}

func handleDisconnect() {
	if err := conn.Close(); err != nil {
		ui.DisplayError(err)
	}
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

	ipAddressField = ui.NewEntry(remote.DefaultIPAddress, "", false)
	portField = ui.NewEntry(remote.DefaultPort, "", false)

	secretField = ui.NewEntry("", "Shared Secret Value", false)
	secretField.OnChanged = func(newStr string) {
		sharedSecretValue = newStr
	}

	inputArea = ui.NewMultiLineEntry("", "Connection must be established first", true)
	inputBtn = ui.NewButton("Send", handleSend, true)

	outputArea = ui.NewMultiLineEntry("", "", true)
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
			ui.NewButton("Disconnect", handleDisconnect, true),
		),

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
