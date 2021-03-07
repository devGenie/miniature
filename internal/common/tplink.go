package common

import (
	"bytes"
	"encoding/gob"
	"log"
	"net"
)

const (
	// HANDSHAKE Initiates handshake
	HANDSHAKE byte = 0x01
	// HANDSHAKE_ACCEPTED accepts handshake
	HANDSHAKE_ACCEPTED byte = 0x02
	// CLIENT_CONFIGURATION sends client configuration
	CLIENT_CONFIGURATION byte = 0x03
	// SESSION_REQUEST requests for session
	SESSION_REQUEST byte = 0x04
	// SESSION_ACCEPTED accepts a session
	SESSION_ACCEPTED byte = 0x05
	// HEARTBEAT sends heartbeat
	HEARTBEAT byte = 0x06
	// SESSION sends session data
	SESSION byte = 0x07
	// FRAGMENT_SIZE size of each fragmented packet
	FRAGMENT_SIZE int = 400
)

// Addr represents a HTTP address
type Addr struct {
	IPAddr  net.IP
	Network net.IPNet
	Gateway net.IP
}

// PacketHeader represents header data in a packet
type PacketHeader struct {
	Src   string
	Flag  byte
	Plen  uint16
	Nonce []byte
}

// Packet is a structure representing a packet
type Packet struct {
	PacketHeader
	Payload []byte
}

// TransmissionPacket holds information about a packet in transit
type TransmissionPacket struct {
	Data          []byte
	FragmentCount int
	Index         int
	ID            string
}

// TCP is a structure of a tcp datagram
type TCP struct {
	TCPSrc    string
	TCPDst    string
	TCPSeqNum int
	TCPackNum int
	TCPHdrLen int
	TCPFin    []byte
}

// Decode recieves data as a byte array and decodes it to the passed dataStructure
func Decode(dataStructure interface{}, data []byte) error {
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	err := decoder.Decode(dataStructure)

	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

// Encode recieves a dataStructure to encode and returns an encoded byte array
func Encode(dataStructure interface{}) (encoded []byte, err error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err = encoder.Encode(dataStructure)

	if err != nil {
		log.Printf("Error : %s", err)
		return nil, err
	}

	return buffer.Bytes(), nil
}

// Fragment fragments packets over 1472 bytes
func Fragment(data []byte) [][]byte {
	packets := make([][]byte, 0, len(data)/FRAGMENT_SIZE+1)
	var packet []byte
	if len(data) > 1400 {
		for len(data) >= FRAGMENT_SIZE {
			packet, data = data[:FRAGMENT_SIZE], data[FRAGMENT_SIZE:]
			packets = append(packets, packet)
		}
	} else {
		packets = append(packets, data)
	}
	return packets
}

// PackFragments packs fragments before transmission
func PackFragments(id string, packet []byte, sequence int, fragments int) TransmissionPacket {
	return TransmissionPacket{ID: id, Data: packet, FragmentCount: fragments, Index: sequence}

}
