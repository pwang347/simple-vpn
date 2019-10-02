package remote

import (
	"fmt"
	"net"
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
