package miniature

import (
	"errors"

	"github.com/pierrec/lz4"
)

// Compress compresses bytes passed to it and returns a compressed byte array
func Compress(data []byte) (compressed []byte, err error) {
	buff := make([]byte, len(data))
	n, err := lz4.CompressBlockHC(data, buff, 1)
	if err != nil {
		return nil, err
	}

	if n >= len(data) {
		err = errors.New("Data cannot be compressed")
		return nil, err
	}

	compressedData := buff[:n]
	return compressedData, nil
}

// Decompress decompresses bytes passed to it and returns a decompressed byte array
func Decompress([]byte) {

}
