package miniature

import (
	"errors"
	"log"

	"github.com/pierrec/lz4"
)

// Compress compresses bytes passed to it and returns a compressed byte array
func Compress(data []byte) (compressed []byte, err error) {
	buff := make([]byte, 100*len(data))

	log.Println("Compress Buffer size", len(buff))
	log.Println("Data to compress size", len(data))
	n, err := lz4.CompressBlockHC(data, buff, 1)
	if err != nil {
		return nil, err
	}

	if n >= len(data) || n == 0 {
		err = errors.New("Data cannot be compressed")
		return nil, err
	}

	compressedData := buff[:n]
	return compressedData, nil
}

// Decompress decompresses bytes passed to it and returns a decompressed byte array
func Decompress(data []byte) (decompressedData []byte, err error) {
	buff := make([]byte, 100*len(data))
	log.Println("Decompress Buffer size", len(buff))
	log.Println("Data to decompress size", len(data))
	n, err := lz4.UncompressBlock(data, buff)
	if err != nil {
		return nil, err
	}

	if n == 0 {
		err = errors.New("Failed to decompress data")
		return nil, err
	}

	decompressedData = buff[:n]
	return decompressedData, nil
}
