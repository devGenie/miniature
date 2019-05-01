package main

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
	SESSION              byte = 0x4
)

type Addr struct {
	IpAddr  *net.IP
	Network *net.IPNet
	Gateway *net.IP
}

type PacketHeader struct {
	Flag byte
	Plen uint16
}

type Packet struct {
	PacketHeader
	Payload []byte
}

type Encoded interface {
}

func decode(dataStructure Encoded, data []byte) error {
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	err := decoder.Decode(dataStructure)

	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func encode(dataStructure Encoded) (encoded []byte, err error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err = encoder.Encode(dataStructure)

	if err != nil {
		log.Printf("Error : %s", err)
		return nil, err
	}

	return buffer.Bytes(), nil
}
