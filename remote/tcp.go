package remote

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net"
)

const (
	// DefaultIPAddress is the default server IP address
	DefaultIPAddress = "127.0.0.1"

	// DefaultPort is the default server port
	DefaultPort = "8080"
)

// Connect returns a connection to a server for a client
func Connect(ipAddress, port string) (conn net.Conn, err error) {
	conn, err = net.Dial("tcp", fmt.Sprintf("%s:%s", ipAddress, port))
	return
}

// ServeAndAccept returns a connection to a single client for a server
func ServeAndAccept(port string) (conn net.Conn, err error) {
	var (
		l net.Listener
	)

	if l, err = net.Listen("tcp", fmt.Sprintf(":%s", port)); err != nil {
		return
	}

	// note: this blocks until we get a connection
	if conn, err = l.Accept(); err != nil {
		return
	}

	return
}

// WriteMessageStruct writes a struct to the connection
func WriteMessageStruct(conn net.Conn, msg interface{}) (err error) {
	buffer := new(bytes.Buffer)
	gobenc := gob.NewEncoder(buffer)
	if err = gobenc.Encode(&msg); err != nil {
		return
	}
	_, err = conn.Write(buffer.Bytes())
	return
}

// ReadMessageStruct reads a struct from the connection; the struct needs to be casted
func ReadMessageStruct(conn net.Conn) (msg interface{}, err error) {
	gobdec := gob.NewDecoder(conn)
	msg = new(interface{})
	err = gobdec.Decode(&msg)
	return
}

// StructToString converts a struct to a string
func StructToString(s interface{}) (outs string, err error) {
	var out []byte
	if out, err = json.Marshal(s); err != nil {
		return
	}
	outs = string(out)
	return
}

// WriteString writes a string to the connection
func WriteString(conn net.Conn, s string) (err error) {
	_, err = conn.Write([]byte(s))
	return
}

// ReadString reads a string from the connection
func ReadString() (s string, err error) {
	var reader *bufio.Reader
	s, err = reader.ReadString('\n')
	return
}
