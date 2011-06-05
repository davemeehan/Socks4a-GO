package socks

import (
	"net"
	"encoding/binary"
	"os"
	"log"
	"bytes"
)

type socket struct {
	conn *net.TCPConn
}
// Request.Connect provides functionality to connect to a socks server
// returns a status byte from socks server and an error which will be nil if no error is returned
// socks response object. Byte order for resp is: 0x00(discard) 0xXX(status) 0xXX 0xXX(2 bytes to ignore) 0xXX 0xXX 0xXX 0xXX (4 bytes to ignore)
// socks status codes: 0x5a(90) == granted ; 0x5b(91) == rejected/failed ; 0x5c(92) == failed because missing identd ; 0x5d(93) == identd couldn't confirm identity from user ID
func Connect(conn *net.TCPConn, domain string) (bool, os.Error) {
	sock := new(socket)
	sock.conn = conn
	version := []byte{0x04} // socks version 4
	cmd := []byte{0x01}     // socks stream mode
	port := 80              // destination http port
	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, version)
	binary.Write(buffer, binary.BigEndian, cmd)
	binary.Write(buffer, binary.BigEndian, uint16(port))                   // pad port with 0x00
	binary.Write(buffer, binary.BigEndian, []byte{0x00, 0x00, 0x00, 0x01}) // fake ip address forces socks4a to resolve the domain below using the socks protocol
	binary.Write(buffer, binary.BigEndian, []byte{0x00})
	binary.Write(buffer, binary.BigEndian, []byte(domain))
	binary.Write(buffer, binary.BigEndian, []byte{0x00})
	binary.Write(sock.conn, binary.BigEndian, buffer.Bytes())
	if sock.read() == false {
		return false, os.NewError("Unable to connect to socks server.")
	}
	return true, nil
}
func (this *socket) read() (status bool) {
	data := make([]byte, 8) // socks responses are 8 bytes
	count, err := this.conn.Read(data)
	if err != nil {
		log.Printf("Unable to read bytes from data stream.\n")
	}
	if count == 0 {
		log.Printf("socks host closed connection.\n")
	}
	if data[1] == 0x5a { // success
		return true
	}
	return false
}
