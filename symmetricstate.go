package noise

import (
	"github.com/yapatta/noise/cipher"
	"github.com/yapatta/noise/hash"
)

// During the handshake phase each party has a single SymmetricState, which can be deleted once the handshake is finished.
type SymmetricState struct {
	cs     *CipherState
	ck     []byte // chaining key of HASHLEN bytes as a salt for HKDF function
	h      []byte // the hashed value of HASHLEN bytes for all data sent/received in handshake
	hash   hash.HashFunc
	cipher cipher.CipherFunc
}

func (ss *SymmetricState) InitializeSymmetric(protocolName []byte) {
	// if protocol_name is less than or equal to HASHLEN bytes in length
	hashLen := ss.hash.Size()
	if len(protocolName) <= hashLen {
		ss.h = make([]byte, hashLen)
		copy(ss.h, protocolName)
	} else {
		ss.h = ss.hash.Hash(protocolName)
	}

	ss.ck = make([]byte, 0, hashLen)
	ss.ck = append(ss.ck, ss.h...)
	ss.cs.InitializeKey(nil)
}

func (ss *SymmetricState) MixKey(inputKeyMaterial []byte) {
	hkdfOutputs := ss.hash.HKDF(ss.ck, inputKeyMaterial, 2)
	ss.ck = hkdfOutputs[0]
	tempK := hkdfOutputs[1]

	// If HASHLEN is 64, then truncates temp_k to 32 bytes.
	if ss.hash.Size() == 64 {
		tempK = tempK[:32]
	}

	ss.cs.InitializeKey(tempK)
}

func (ss *SymmetricState) MixHash(data []byte) {
	ss.h = append(ss.h, data...)
	ss.h = ss.hash.Hash(ss.h)
}

// This function is used for handling pre-shared symmetric keys, as described in Section 9.
func (ss *SymmetricState) MixKeyAndHash(inputKeyMaterial []byte) {
	hkdfOutputs := ss.hash.HKDF(ss.ck, inputKeyMaterial, 3)
	ss.ck = hkdfOutputs[0]
	tempH := hkdfOutputs[1]
	tempK := hkdfOutputs[2]

	ss.MixHash(tempH)

	if ss.hash.Size() == 64 {
		tempK = tempK[:32]
	}

	ss.cs.InitializeKey(tempK)
}

func (ss *SymmetricState) GetHandshakeHash() []byte {
	return ss.h
}

func (ss *SymmetricState) EncryptAndHash(plaintext []byte) []byte {
	ciphertext, err := ss.cs.EncryptWithAd(ss.h, plaintext)
	if err != nil {
		panic("noise/SymmetricState: EncryptWithAd error: " + err.Error())
	}

	ss.MixHash(ciphertext)
	return ciphertext
}

func (ss *SymmetricState) DecryptAndHash(ciphertext []byte) []byte {
	plaintext, err := ss.cs.DecryptWithAd(ss.h, ciphertext)
	if err != nil {
		panic("noise/SymmetricState: DecryptWithAd error: " + err.Error())
	}

	ss.MixHash(ciphertext)
	return plaintext
}

func (ss *SymmetricState) Split() []*CipherState {
	hkdfOutputs := ss.hash.HKDF(ss.ck, []byte(""), 2)

	var css []*CipherState
	for i := 0; i < len(hkdfOutputs); i++ {
		if len(hkdfOutputs[i]) == 64 {
			hkdfOutputs[i] = hkdfOutputs[i][:32]
		}
		cs := NewCipherState(ss.cipher)
		cs.InitializeKey(hkdfOutputs[i])
		css = append(css, cs)
	}
	return css
}

// NOTE: InitializeSymmetric should be called after NewSymmetricState
func NewSymmetricState(cipher cipher.CipherFunc, hash hash.HashFunc) *SymmetricState {
	return &SymmetricState{
		cs:     NewCipherState(cipher),
		hash:   hash,
		cipher: cipher,
	}
}

// for testing
func (ss *SymmetricState) HashValue() []byte {
	return ss.h
}
