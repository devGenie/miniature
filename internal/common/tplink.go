package common

import (
	"bytes"
	"encoding/gob"
	"log"
	"net"
)

const (
	HANDSHAKE            byte = 0x01
	HANDSHAKE_ACCEPTED   byte = 0x02
	CLIENT_CONFIGURATION byte = 0x03
	SESSION_ACCEPTED     byte = 0x04
	HEARTBEAT            byte = 0x05
	SESSION              byte = 0x06
)

type Addr struct {
	IpAddr  net.IP
	Network net.IPNet
	Gateway net.IP
}

type PacketHeader struct {
	Flag byte
	Plen uint16
}

type Packet struct {
	PacketHeader
	Payload []byte
}

type TCP struct {
	Tcp_src     string
	Tcp_dst     string
	Tcp_seq_num int
	Tcp_ack_num int
	Tcp_hdr_len int
	Tcp_fin     []byte
}

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
