package dh

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

var supportedDHs = map[string]DHFunc{
	"25519": X25519,
	// "448":   X448,
}

type Keypair struct {
	rawPrivateKey []byte
	publicKey     []byte
}

func (kp *Keypair) Public() []byte {
	// res := make([]byte, len(kp.publicKey))
	// copy(res, kp.publicKey)
	return kp.publicKey
}

func FromString(name string) DHFunc {
	return supportedDHs[name]
}

type DHFunc interface {
	fmt.Stringer
	GenerateKeypair() (*Keypair, error)
	DH(*Keypair, []byte) ([]byte, error)
	Size() int
}

type x25519 struct{}

var X25519 DHFunc = &x25519{}

func (dh *x25519) String() string {
	return "25519"
}

// Generates a new Diffie-Hellman key pair. A DH key pair consists of public_key
// and private_key elements. A public_key represents an encoding of a DH public
// key into a byte sequence of length DHLEN. The public_key encoding details are
// specific to each set of DH functions.
func (dh *x25519) GenerateKeypair() (*Keypair, error) {
	rawPrivateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(rawPrivateKey); err != nil {
		return nil, err
	}
	publicKey := make([]byte, curve25519.PointSize)
	curve25519.ScalarBaseMult((*[32]byte)(publicKey), (*[32]byte)(rawPrivateKey))

	return &Keypair{rawPrivateKey: rawPrivateKey, publicKey: publicKey}, nil
}

// Performs a Diffie-Hellman calculation between the private key in key_pair
// and the public_key and returns an output sequence of bytes of length DHLEN.
func (dh *x25519) DH(keypair *Keypair, publicKey []byte) ([]byte, error) {
	return curve25519.X25519(keypair.rawPrivateKey, publicKey)
}

// A constant specifying the size in bytes of public keys and DH outputs.
// For security reasons, DHLEN must be 32 or greater.
// The size of scalar * point in x25519
func (dh *x25519) Size() int {
	return curve25519.PointSize
}
