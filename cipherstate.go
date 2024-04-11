package noise

import (
	"errors"

	goCipher "crypto/cipher"

	"github.com/yapatta/noise/cipher"
)

var (
	errInvalidKeySize = errors.New("noise/CipherState: invalid key size")
	ErrNonceExhausted = errors.New("noise/CipherState: nonce exhausted")
	ErrMessageSize    = errors.New("noise/CipherState: oversized message")
)

const (
	CipherKeySize = 32
)

type CipherState struct {
	cipher cipher.CipherFunc
	k      []byte // 32 bytes cipher key
	aead   goCipher.AEAD
	n      uint64 // nonce
}

// NOTE: this function has to be called when a new key is set
func (cs *CipherState) SetKey(key []byte) error {
	cs.k = make([]byte, CipherKeySize)
	copy(cs.k, key)

	var err error
	cs.aead, err = cs.cipher.NewAEAD(cs.k)
	if err != nil {
		panic("noise/CipherState: InitializeKey error: " + err.Error())
	}

	return nil
}

func (cs *CipherState) InitializeKey(key []byte) {
	if len(key) == 0 {
		return
	}

	if len(key) != CipherKeySize {
		panic("noise/CipherState: InitializeKey error: " + errInvalidKeySize.Error())
	}

	if err := cs.SetKey(key); err != nil {
		panic("noise/CipherState: InitializeKey error: " + err.Error())
	}

	cs.n = 0
}

func (cs *CipherState) HasKey() bool {
	return cs.k != nil && cs.aead != nil
}

func (cs *CipherState) SetNonce(nonce uint64) {
	cs.n = nonce
}

// EncryptWithAd encrypts and authenticates the additional data and plaintext
// and increments the nonce iff the CipherState is keyed, and otherwise returns
// the plaintext.
func (cs *CipherState) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	if !cs.HasKey() {
		return plaintext, nil
	}

	ciphertext, err := cs.cipher.Encrypt(cs.aead, cs.n, ad, plaintext)
	if err != nil {
		return nil, err
	}

	cs.n++
	if cs.n == cipher.MaxNonce {
		return nil, ErrNonceExhausted
	}

	return ciphertext, nil
}

// DecryptWithAd decrypts and authenticates the additional data and ciphertext
// and increments the nonce iff the CipherState is keyed, and otherwise returns
// the ciphertext.
func (cs *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if !cs.HasKey() {
		return ciphertext, nil
	}

	plaintext, err := cs.cipher.Decrypt(cs.aead, cs.n, ad, ciphertext)
	if err != nil {
		return nil, err
	}

	cs.n++
	if cs.n == cipher.MaxNonce {
		return nil, ErrNonceExhausted
	}

	return plaintext, nil
}

func (cs *CipherState) Rekey() error {
	k, err := cs.cipher.Rekey(cs.k)
	if err != nil {
		return err
	}

	return cs.SetKey(k)
}

func (cs *CipherState) Key() []byte {
	return cs.k
}

func (cs *CipherState) AEAD() goCipher.AEAD {
	return cs.aead
}

func (cs *CipherState) Overhead() int {
	return cs.aead.Overhead()
}

// NOTE: call InitializeKey after this constructor
func NewCipherState(cipher cipher.CipherFunc) *CipherState {
	return &CipherState{
		cipher: cipher,
	}
}
