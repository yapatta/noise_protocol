package cipher

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	maxMessageSize int = 65535
	// keySize        int    = 32
	MaxNonce uint64 = math.MaxUint64

	ErrOpen error = errors.New("noise/cipher: decryption failure")
)

var ciphers = map[string]CipherFunc{
	"ChaChaPoly": ChaChaPoly,
}

func FromString(name string) CipherFunc {
	return ciphers[name]
}

type CipherFunc interface {
	fmt.Stringer

	NewAEAD(key []byte) (cipher.AEAD, error)

	encodeNonce(nonce uint64) []byte
	Encrypt(aead cipher.AEAD, n uint64, ad []byte, plaintext []byte) ([]byte, error)
	Decrypt(aead cipher.AEAD, n uint64, ad []byte, ciphertext []byte) ([]byte, error)
	Rekey(k []byte) ([]byte, error)
}

var ChaChaPoly CipherFunc = &chaChaPoly{}

type chaChaPoly struct{}

func (ci *chaChaPoly) String() string {
	return "ChaChaPoly"
}

func (ci *chaChaPoly) NewAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// The 96-bit nonce is formed by encoding 32 bits of zeros followed by little-endian encoding of n
func (ci *chaChaPoly) encodeNonce(nonce uint64) []byte {
	var encodedNonce [12]byte // 96 bits
	binary.LittleEndian.PutUint64(encodedNonce[4:], nonce)
	return encodedNonce[:]
}

func (ci *chaChaPoly) Encrypt(aead cipher.AEAD, n uint64, ad []byte, plaintext []byte) ([]byte, error) {
	// k should be 32
	// if len(k) != keySize {
	// 	return nil, errors.New("noise/cipher: incorrect key size")
	// }

	// an AEAD ciphertext that is less than or equal to 65535 bytes in length
	// and that consists of an encrypted payload plus 16 bytes of authentication data.
	if len(plaintext)+aead.Overhead() > maxMessageSize {
		return nil, errors.New("noise/cipher: oversized message")
	}

	nonce := ci.encodeNonce(n)
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("noise/cipher: incorrect nonce size")
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, ad)

	return ciphertext, nil
}

func (ci *chaChaPoly) Decrypt(aead cipher.AEAD, n uint64, ad []byte, ciphertext []byte) ([]byte, error) {
	// k should be 32
	// if len(k) != keySize {
	// 	return nil, errors.New("noise/cipher: incorrect k size")
	// }

	nonce := ci.encodeNonce(n)
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("noise/cipher: incorrect nonce size")
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, ErrOpen
	}

	return plaintext, nil
}

func (ci *chaChaPoly) Rekey(k []byte) ([]byte, error) {
	// TODO: Returns a new 32-byte cipher key as a pseudorandom function of k.
	// ENCRYPT(k, maxnonce, zerolen, zeros), where maxnonce equals 264-1,
	// zerolen is a zero-length byte sequence, and zeros is a sequence of 32 bytes filled with zeros.
	var zeros [32]byte

	aead, err := ci.NewAEAD(k)
	if err != nil {
		return nil, err
	}

	ciphertext, err := ci.Encrypt(aead, MaxNonce, []byte(""), zeros[:])
	if err != nil {
		return nil, err
	}
	return ciphertext[:32], nil
}
