package hash

import (
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
)

var (
	supportedHashes = map[string]HashFunc{
		"BLAKE2b": BLAKE2b,
	}
)

func FromString(name string) HashFunc {
	return supportedHashes[name]
}

type HashFunc interface {
	fmt.Stringer
	New() hash.Hash
	Hash(data []byte) []byte
	Size() int
	BlockSize() int
	HKDF(chainingKey, inputKeyMaterial []byte, numOutputs int) [][]byte
}

// BLAKE2b-512
var BLAKE2b HashFunc = &hfBlake2b{}

type hfBlake2b struct {
}

func (b2 *hfBlake2b) String() string {
	return "BLAKE2b"
}

func (b2 *hfBlake2b) New() hash.Hash {
	hash, _ := blake2b.New512(nil)
	return hash
}

func (b2 *hfBlake2b) Hash(data []byte) []byte {
	hash := b2.New()
	hash.Write(data)
	h := hash.Sum(nil)
	// TODO: check if the length of h is HASHLEN
	return h
}

func (b2 *hfBlake2b) Size() int {
	return blake2b.Size
}

func (b2 *hfBlake2b) BlockSize() int {
	return blake2b.BlockSize
}

func (b2 *hfBlake2b) HKDF(chainingKey, inputKeyMaterial []byte, numOutputs int) [][]byte {
	r := hkdf.New(b2.New, inputKeyMaterial, chainingKey, nil)

	var outputs [][]byte
	for i := 0; i < numOutputs; i++ {
		key := make([]byte, b2.Size())
		_, _ = io.ReadFull(r, key)
		if len(key) != b2.Size() {
			panic("noise/hash: key size is different from hash size")
		}
		outputs = append(outputs, key)
	}

	return outputs
}
