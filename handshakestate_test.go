package noise

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yapatta/noise/cipher"
	"github.com/yapatta/noise/dh"
	"github.com/yapatta/noise/hash"
	"github.com/yapatta/noise/pattern"
)

func init() {
	pattern.InitializePatterns()
}

func TestHandshakeStateN(t *testing.T) {
	require := require.New(t)
	protocolName := "Noise_N_25519_ChaChaPoly_BLAKE2b"
	protocol := InitializeProtocol(protocolName)
	expectedProtocol := &Protocol{
		pattern: pattern.N,
		dh:      dh.X25519,
		cipher:  cipher.ChaChaPoly,
		hash:    hash.BLAKE2b,
	}

	fmt.Printf("Protocol Name: %v\n", protocolName)
	fmt.Printf("protocol: %v", protocol)
	require.Equal(expectedProtocol, protocol)

	bobS, err := protocol.dh.GenerateKeypair()
	require.NoError(err)

	aliceCfg := &HandshakeConfig{
		protocol:     protocol,
		isInitiator:  true,
		prologue:     []byte("yapatta_noise"),
		remoteStatic: bobS.Public(),
	}
	aliceHS := NewHandshakeState(aliceCfg)

	bobCfg := &HandshakeConfig{
		protocol:    protocol,
		prologue:    []byte("yapatta_noise"),
		localStatic: bobS,
	}
	bobHS := NewHandshakeState(bobCfg)

	plaintext := []byte("alice test") // 10 bytes
	// N:(alice) -> e, es
	// MEMO: plaintext will not be encrypted
	fmt.Printf("\nalice WriteMessage(1): -> e, es\n")
	aliceMsg, aliceSSS, err := aliceHS.WriteMessage(plaintext, nil)
	require.NoError(err, "aliceHS.WriteMessage(1)")
	fmt.Printf("bob ReadMessage(1): -> e, es\n")
	bobRecv, bobSSS, err := bobHS.ReadMessage(aliceMsg, nil)
	require.NoError(err, "bobHS.ReadMessage(1)")
	require.Equal(plaintext, bobRecv)

	// symmetric key for transport message
	aliceTx := aliceSSS[0]
	bobRx := bobSSS[0]

	alicePlaintext := []byte("alice's transport plaintext")
	fmt.Printf("alice encrypts a plaintext: \"%v\"\n", string(alicePlaintext))
	aliceMsg2, err := aliceTx.EncryptWithAd(nil, alicePlaintext)
	require.NoError(err)

	bobRecv2, err := bobRx.DecryptWithAd(nil, aliceMsg2)
	require.NoError(err)
	require.Equal(alicePlaintext, bobRecv2)
	fmt.Printf("bob decrypts a ciphertext: %v\n			into \"%v\"\n\n", aliceMsg2, string(bobRecv2))
}

func TestHandshakeStateXX(t *testing.T) {
	require := require.New(t)
	protocolName := "Noise_XX_25519_ChaChaPoly_BLAKE2b"
	protocol := InitializeProtocol(protocolName)
	expectedProtocol := &Protocol{
		pattern: pattern.XX,
		dh:      dh.X25519,
		cipher:  cipher.ChaChaPoly,
		hash:    hash.BLAKE2b,
	}

	require.Equal(expectedProtocol, protocol)

	aliceStatic, err := protocol.dh.GenerateKeypair()
	require.NoError(err, "GenerateKeypair()")
	aliceCfg := &HandshakeConfig{
		protocol:    protocol,
		isInitiator: true,
		prologue:    []byte("yapatta_noise"),
		localStatic: aliceStatic,
	}
	aliceHS := NewHandshakeState(aliceCfg)

	bobStatic, err := protocol.dh.GenerateKeypair()
	require.NoError(err, "GenerateKeypair()")
	bobCfg := &HandshakeConfig{
		protocol:    protocol,
		prologue:    []byte("yapatta_noise"),
		localStatic: bobStatic,
	}
	bobHS := NewHandshakeState(bobCfg)

	plaintext := []byte("alice test") // 10 bytes
	// XX:(alice) -> e
	// MEMO: plaintext will not be encrypted
	fmt.Printf("\nalice WriteMessage(1): -> e\n")
	aliceMsg, _, err := aliceHS.WriteMessage(plaintext, nil)
	require.NoError(err, "aliceHS.WriteMessage(1)")
	fmt.Printf("bob ReadMessage(1): -> e\n")
	bobRecv, _, err := bobHS.ReadMessage(aliceMsg, nil)
	require.NoError(err, "bobHS.ReadMessage(1)")
	require.Equal(plaintext, bobRecv)

	// XX: <- e, ee, s, es
	fmt.Printf("bob WriteMessage(1): <- e, ee, s, es\n")
	bobMsg, _, err := bobHS.WriteMessage(nil, nil)
	require.NoError(err, "bobHS.WriteMessage(2)")
	fmt.Printf("alice ReadMessage(1): <- e, ee, s, es\n")
	_, _, err = aliceHS.ReadMessage(bobMsg, nil)
	require.NoError(err, "aliceHS.ReadMessage(2)")

	fmt.Printf("alice's aead: %v\n", aliceHS.ss.cs.AEAD())
	fmt.Printf("bob's aead: %v\n", bobHS.ss.cs.AEAD())

	// XX: -> s, se
	fmt.Printf("alice WriteMessage(2): -> s, se\n")
	aliceMsg2, aliceSSS, err := aliceHS.WriteMessage(nil, nil)
	require.NoError(err, "aliceHS.WriteMessage(2)")
	fmt.Printf("bob ReadMessage(2): -> s, se\n")

	_, bobSSS, err := bobHS.ReadMessage(aliceMsg2, nil)
	require.NoError(err, "bobHS.ReadMessage(2)")

	// symmetric key for transport message
	aliceTx, aliceRx := aliceSSS[0], aliceSSS[1]
	bobRx, bobTx := bobSSS[0], bobSSS[1]

	fmt.Printf("\nhandshake done with \n- alice's cipher key: %v\n- bob's cipher key: %v\n\n", aliceTx.k, bobTx.k)

	alicePlaintext := []byte("alice's transport plaintext")
	fmt.Printf("alice encrypts a plaintext: \"%v\"\n", string(alicePlaintext))
	aliceMsg3, err := aliceTx.EncryptWithAd(nil, alicePlaintext)
	require.NoError(err)

	bobRecv3, err := bobRx.DecryptWithAd(nil, aliceMsg3)
	require.NoError(err)
	require.Equal(alicePlaintext, bobRecv3)
	fmt.Printf("bob decrypts a ciphertext: %v\n			into \"%v\"\n\n", aliceMsg2, string(bobRecv3))

	bobPlaintext := []byte("bob's transport plaintext")
	fmt.Printf("bob encrypts a plaintext: \"%v\"\n", string(bobPlaintext))
	bobMsg3, err := bobTx.EncryptWithAd(nil, bobPlaintext)
	require.NoError(err)

	aliceRecv3, err := aliceRx.DecryptWithAd(nil, bobMsg3)
	require.NoError(err)
	require.Equal(bobPlaintext, aliceRecv3)
	fmt.Printf("alice decrypts a ciphertext: %v\n			into \"%v\"\n", bobMsg3, string(aliceRecv3))
}

func TestHandshakeStateNN(t *testing.T) {
	require := require.New(t)
	protocolName := "Noise_NN_25519_ChaChaPoly_BLAKE2b"
	protocol := InitializeProtocol(protocolName)
	expectedProtocol := &Protocol{
		pattern: pattern.NN,
		dh:      dh.X25519,
		cipher:  cipher.ChaChaPoly,
		hash:    hash.BLAKE2b,
	}

	fmt.Printf("Protocol Name: %v\n", protocolName)
	fmt.Printf("protocol: %v", protocol)
	require.Equal(expectedProtocol, protocol)

	aliceCfg := &HandshakeConfig{
		protocol:    protocol,
		isInitiator: true,
		prologue:    []byte("yapatta_noise"),
	}
	aliceHS := NewHandshakeState(aliceCfg)

	bobCfg := &HandshakeConfig{
		protocol: protocol,
		prologue: []byte("yapatta_noise"),
	}
	bobHS := NewHandshakeState(bobCfg)

	plaintext := []byte("alice test") // 10 bytes
	// NN:(alice) -> e
	// MEMO: plaintext will not be encrypted
	fmt.Printf("\nalice WriteMessage(1): -> e\n")
	aliceMsg, _, err := aliceHS.WriteMessage(plaintext, nil)
	require.NoError(err, "aliceHS.WriteMessage(1)")
	fmt.Printf("bob ReadMessage(1): -> e\n")
	bobRecv, _, err := bobHS.ReadMessage(aliceMsg, nil)
	require.NoError(err, "bobHS.ReadMessage(1)")
	require.Equal(plaintext, bobRecv)

	// NN: <- (bob) e, ee
	fmt.Printf("bob WriteMessage(2): <- e, ee\n")
	bobMsg, bobSSS, err := bobHS.WriteMessage(nil, nil)
	require.NoError(err, "bobHS.WriteMessage(2)")
	fmt.Printf("alice ReadMessage(2): <- e, ee\n")
	_, aliceSSS, err := aliceHS.ReadMessage(bobMsg, nil)
	require.NoError(err, "aliceHS.ReadMessage(2)")

	// symmetric key for transport message
	aliceTx, aliceRx := aliceSSS[0], aliceSSS[1]
	bobRx, bobTx := bobSSS[0], bobSSS[1]

	fmt.Printf("\nhandshake done with \n- alice's cipher key: %v\n- bob's cipher key: %v\n\n", aliceTx.k, bobTx.k)

	alicePlaintext := []byte("alice's transport plaintext")
	fmt.Printf("alice encrypts a plaintext: \"%v\"\n", string(alicePlaintext))
	aliceMsg2, err := aliceTx.EncryptWithAd(nil, alicePlaintext)
	require.NoError(err)

	bobRecv2, err := bobRx.DecryptWithAd(nil, aliceMsg2)
	require.NoError(err)
	require.Equal(alicePlaintext, bobRecv2)
	fmt.Printf("bob decrypts a ciphertext: %v\n			into \"%v\"\n\n", aliceMsg2, string(bobRecv2))

	bobPlaintext := []byte("bob's transport plaintext")
	fmt.Printf("bob encrypts a plaintext: \"%v\"\n", string(bobPlaintext))
	bobMsg2, err := bobTx.EncryptWithAd(nil, bobPlaintext)
	require.NoError(err)

	aliceRecv2, err := aliceRx.DecryptWithAd(nil, bobMsg2)
	require.NoError(err)
	require.Equal(bobPlaintext, aliceRecv2)
	fmt.Printf("alice decrypts a ciphertext: %v\n			into \"%v\"\n", bobMsg2, string(aliceRecv2))
}

func TestHandshakeStateKN(t *testing.T) {
	require := require.New(t)
	protocolName := "Noise_KN_25519_ChaChaPoly_BLAKE2b"
	protocol := InitializeProtocol(protocolName)
	expectedProtocol := &Protocol{
		pattern: pattern.KN,
		dh:      dh.X25519,
		cipher:  cipher.ChaChaPoly,
		hash:    hash.BLAKE2b,
	}

	fmt.Printf("Protocol Name: %v\n", protocolName)
	fmt.Printf("protocol: %v", protocol)
	require.Equal(expectedProtocol, protocol)

	aliceS, err := protocol.dh.GenerateKeypair()
	require.NoError(err)
	aliceCfg := &HandshakeConfig{
		protocol:    protocol,
		isInitiator: true,
		prologue:    []byte("yapatta_noise"),
		localStatic: aliceS,
	}
	aliceHS := NewHandshakeState(aliceCfg)

	bobCfg := &HandshakeConfig{
		protocol:     protocol,
		prologue:     []byte("yapatta_noise"),
		remoteStatic: aliceS.Public(),
	}
	bobHS := NewHandshakeState(bobCfg)

	plaintext := []byte("alice test") // 10 bytes
	// NN:(alice) -> e
	// MEMO: plaintext will not be encrypted
	fmt.Printf("\nalice WriteMessage(1): -> e\n")
	aliceMsg, _, err := aliceHS.WriteMessage(plaintext, nil)
	require.NoError(err, "aliceHS.WriteMessage(1)")
	fmt.Printf("bob ReadMessage(1): -> e\n")
	bobRecv, _, err := bobHS.ReadMessage(aliceMsg, nil)
	require.NoError(err, "bobHS.ReadMessage(1)")
	require.Equal(plaintext, bobRecv)

	// NN: <- (bob) e, ee
	fmt.Printf("bob WriteMessage(2): <- e, ee, es\n")
	bobMsg, bobSSS, err := bobHS.WriteMessage(nil, nil)
	require.NoError(err, "bobHS.WriteMessage(2)")
	fmt.Printf("alice ReadMessage(2): <- e, ee, es\n")
	_, aliceSSS, err := aliceHS.ReadMessage(bobMsg, nil)
	require.NoError(err, "aliceHS.ReadMessage(2)")

	// symmetric key for transport message
	aliceTx, aliceRx := aliceSSS[0], aliceSSS[1]
	bobRx, bobTx := bobSSS[0], bobSSS[1]

	fmt.Printf("\nhandshake done with \n- alice's cipher key: %v\n- bob's cipher key: %v\n\n", aliceTx.k, bobTx.k)

	alicePlaintext := []byte("alice's transport plaintext")
	fmt.Printf("alice encrypts a plaintext: \"%v\"\n", string(alicePlaintext))
	aliceMsg2, err := aliceTx.EncryptWithAd(nil, alicePlaintext)
	require.NoError(err)

	bobRecv2, err := bobRx.DecryptWithAd(nil, aliceMsg2)
	require.NoError(err)
	require.Equal(alicePlaintext, bobRecv2)
	fmt.Printf("bob decrypts a ciphertext: %v\n			into \"%v\"\n\n", aliceMsg2, string(bobRecv2))

	bobPlaintext := []byte("bob's transport plaintext")
	fmt.Printf("bob encrypts a plaintext: \"%v\"\n", string(bobPlaintext))
	bobMsg2, err := bobTx.EncryptWithAd(nil, bobPlaintext)
	require.NoError(err)

	aliceRecv2, err := aliceRx.DecryptWithAd(nil, bobMsg2)
	require.NoError(err)
	require.Equal(bobPlaintext, aliceRecv2)
	fmt.Printf("alice decrypts a ciphertext: %v\n			into \"%v\"\n", bobMsg2, string(aliceRecv2))
}

func TestHandshakeStateIX(t *testing.T) {
	require := require.New(t)
	protocolName := "Noise_IX_25519_ChaChaPoly_BLAKE2b"
	protocol := InitializeProtocol(protocolName)
	expectedProtocol := &Protocol{
		pattern: pattern.IX,
		dh:      dh.X25519,
		cipher:  cipher.ChaChaPoly,
		hash:    hash.BLAKE2b,
	}

	fmt.Printf("Protocol Name: %v\n", protocolName)
	fmt.Printf("protocol: %v", protocol)
	require.Equal(expectedProtocol, protocol)

	aliceS, err := protocol.dh.GenerateKeypair()
	require.NoError(err)
	bobS, err := protocol.dh.GenerateKeypair()
	require.NoError(err)

	aliceCfg := &HandshakeConfig{
		protocol:    protocol,
		isInitiator: true,
		prologue:    []byte("yapatta_noise"),
		localStatic: aliceS,
	}
	aliceHS := NewHandshakeState(aliceCfg)

	bobCfg := &HandshakeConfig{
		protocol:    protocol,
		prologue:    []byte("yapatta_noise"),
		localStatic: bobS,
	}
	bobHS := NewHandshakeState(bobCfg)

	plaintext := []byte("alice test") // 10 bytes
	// NN:(alice) -> e
	// MEMO: plaintext will not be encrypted
	fmt.Printf("\nalice WriteMessage(1): -> e, s\n")
	aliceMsg, _, err := aliceHS.WriteMessage(plaintext, nil)
	require.NoError(err, "aliceHS.WriteMessage(1)")
	fmt.Printf("bob ReadMessage(1): -> e, s\n")
	bobRecv, _, err := bobHS.ReadMessage(aliceMsg, nil)
	require.NoError(err, "bobHS.ReadMessage(1)")
	require.Equal(plaintext, bobRecv)

	// NN: <- (bob) e, ee
	fmt.Printf("bob WriteMessage(2): <- e, ee, se, s, se\n")
	bobMsg, bobSSS, err := bobHS.WriteMessage(nil, nil)
	require.NoError(err, "bobHS.WriteMessage(2)")
	fmt.Printf("alice ReadMessage(2): <- e, ee, se, s, se\n")
	_, aliceSSS, err := aliceHS.ReadMessage(bobMsg, nil)
	require.NoError(err, "aliceHS.ReadMessage(2)")

	// symmetric key for transport message
	aliceTx, aliceRx := aliceSSS[0], aliceSSS[1]
	bobRx, bobTx := bobSSS[0], bobSSS[1]

	fmt.Printf("\nhandshake done with \n- alice's cipher key: %v\n- bob's cipher key: %v\n\n", aliceTx.k, bobTx.k)

	alicePlaintext := []byte("alice's transport plaintext")
	fmt.Printf("alice encrypts a plaintext: \"%v\"\n", string(alicePlaintext))
	aliceMsg2, err := aliceTx.EncryptWithAd(nil, alicePlaintext)
	require.NoError(err)

	bobRecv2, err := bobRx.DecryptWithAd(nil, aliceMsg2)
	require.NoError(err)
	require.Equal(alicePlaintext, bobRecv2)
	fmt.Printf("bob decrypts a ciphertext: %v\n			into \"%v\"\n\n", aliceMsg2, string(bobRecv2))

	bobPlaintext := []byte("bob's transport plaintext")
	fmt.Printf("bob encrypts a plaintext: \"%v\"\n", string(bobPlaintext))
	bobMsg2, err := bobTx.EncryptWithAd(nil, bobPlaintext)
	require.NoError(err)

	aliceRecv2, err := aliceRx.DecryptWithAd(nil, bobMsg2)
	require.NoError(err)
	require.Equal(bobPlaintext, aliceRecv2)
	fmt.Printf("alice decrypts a ciphertext: %v\n			into \"%v\"\n", bobMsg2, string(aliceRecv2))
}

func TestHandshakeStateNK1(t *testing.T) {
	require := require.New(t)
	protocolName := "Noise_NK1_25519_ChaChaPoly_BLAKE2b"
	protocol := InitializeProtocol(protocolName)
	expectedProtocol := &Protocol{
		pattern: pattern.NK1,
		dh:      dh.X25519,
		cipher:  cipher.ChaChaPoly,
		hash:    hash.BLAKE2b,
	}

	fmt.Printf("Protocol Name: %v\n", protocolName)
	fmt.Printf("protocol: %v", protocol)
	require.Equal(expectedProtocol, protocol)

	bobS, err := protocol.dh.GenerateKeypair()
	require.NoError(err)

	aliceCfg := &HandshakeConfig{
		protocol:     protocol,
		isInitiator:  true,
		prologue:     []byte("yapatta_noise"),
		remoteStatic: bobS.Public(),
	}
	aliceHS := NewHandshakeState(aliceCfg)

	bobCfg := &HandshakeConfig{
		protocol:    protocol,
		prologue:    []byte("yapatta_noise"),
		localStatic: bobS,
	}
	bobHS := NewHandshakeState(bobCfg)

	plaintext := []byte("alice test") // 10 bytes
	// NN:(alice) -> e
	// MEMO: plaintext will not be encrypted
	fmt.Printf("\nalice WriteMessage(1): -> e\n")
	aliceMsg, _, err := aliceHS.WriteMessage(plaintext, nil)
	require.NoError(err, "aliceHS.WriteMessage(1)")
	fmt.Printf("bob ReadMessage(1): -> e\n")
	bobRecv, _, err := bobHS.ReadMessage(aliceMsg, nil)
	require.NoError(err, "bobHS.ReadMessage(1)")
	require.Equal(plaintext, bobRecv)

	// NN: <- (bob) e, ee
	fmt.Printf("bob WriteMessage(2): <- e, ee, es\n")
	bobMsg, bobSSS, err := bobHS.WriteMessage(nil, nil)
	require.NoError(err, "bobHS.WriteMessage(2)")
	fmt.Printf("alice ReadMessage(2): <- e, ee, es\n")
	_, aliceSSS, err := aliceHS.ReadMessage(bobMsg, nil)
	require.NoError(err, "aliceHS.ReadMessage(2)")

	// symmetric key for transport message
	aliceTx, aliceRx := aliceSSS[0], aliceSSS[1]
	bobRx, bobTx := bobSSS[0], bobSSS[1]

	fmt.Printf("\nhandshake done with \n- alice's cipher key: %v\n- bob's cipher key: %v\n\n", aliceTx.k, bobTx.k)

	alicePlaintext := []byte("alice's transport plaintext")
	fmt.Printf("alice encrypts a plaintext: \"%v\"\n", string(alicePlaintext))
	aliceMsg2, err := aliceTx.EncryptWithAd(nil, alicePlaintext)
	require.NoError(err)

	bobRecv2, err := bobRx.DecryptWithAd(nil, aliceMsg2)
	require.NoError(err)
	require.Equal(alicePlaintext, bobRecv2)
	fmt.Printf("bob decrypts a ciphertext: %v\n			into \"%v\"\n\n", aliceMsg2, string(bobRecv2))

	bobPlaintext := []byte("bob's transport plaintext")
	fmt.Printf("bob encrypts a plaintext: \"%v\"\n", string(bobPlaintext))
	bobMsg2, err := bobTx.EncryptWithAd(nil, bobPlaintext)
	require.NoError(err)

	aliceRecv2, err := aliceRx.DecryptWithAd(nil, bobMsg2)
	require.NoError(err)
	require.Equal(bobPlaintext, aliceRecv2)
	fmt.Printf("alice decrypts a ciphertext: %v\n			into \"%v\"\n", bobMsg2, string(aliceRecv2))
}

func TestHandshakeStateXKpsk3(t *testing.T) {
	require := require.New(t)
	protocolName := "Noise_XKpsk3_25519_ChaChaPoly_BLAKE2b"
	protocol := InitializeProtocol(protocolName)
	expectedProtocol := &Protocol{
		pattern: pattern.XKpsk3,
		dh:      dh.X25519,
		cipher:  cipher.ChaChaPoly,
		hash:    hash.BLAKE2b,
	}

	fmt.Printf("Protocol Name: %v\n", protocolName)
	fmt.Printf("protocol: %v", protocol)
	require.Equal(expectedProtocol, protocol)

	psk := make([]byte, 32)
	rand.Read(psk)

	aliceS, err := protocol.dh.GenerateKeypair()
	require.NoError(err)
	bobS, err := protocol.dh.GenerateKeypair()
	require.NoError(err)

	aliceCfg := &HandshakeConfig{
		protocol:     protocol,
		isInitiator:  true,
		prologue:     []byte("yapatta_noise"),
		localStatic:  aliceS,
		remoteStatic: bobS.Public(),
		psk:          psk,
	}
	aliceHS := NewHandshakeState(aliceCfg)

	bobCfg := &HandshakeConfig{
		protocol:    protocol,
		prologue:    []byte("yapatta_noise"),
		localStatic: bobS,
		psk:         psk,
	}
	bobHS := NewHandshakeState(bobCfg)

	plaintext := []byte("alice test") // 10 bytes
	// XKpsk3:(alice) -> e
	// MEMO: plaintext will not be encrypted
	fmt.Printf("\nalice WriteMessage(1): -> e, es\n")
	aliceMsg, _, err := aliceHS.WriteMessage(plaintext, nil)
	require.NoError(err, "aliceHS.WriteMessage(1)")
	fmt.Printf("bob ReadMessage(1): -> e, es\n")
	bobRecv, _, err := bobHS.ReadMessage(aliceMsg, nil)
	require.NoError(err, "bobHS.ReadMessage(1)")
	require.Equal(plaintext, bobRecv)

	// XKpsk3: <- (bob) e, ee
	fmt.Printf("bob WriteMessage(2): <- e, ee\n")
	bobMsg, _, err := bobHS.WriteMessage(nil, nil)
	require.NoError(err, "bobHS.WriteMessage(2)")
	fmt.Printf("alice ReadMessage(2): <- e, ee\n")
	_, _, err = aliceHS.ReadMessage(bobMsg, nil)
	require.NoError(err, "aliceHS.ReadMessage(2)")

	// XKpsk3: (alice) -> s, se, psk
	fmt.Printf("alice WriteMessage(2): -> s, se, psk\n")
	aliceMsg2, aliceSSS, err := aliceHS.WriteMessage(nil, nil)
	require.NoError(err, "aliceHS.WriteMessage(2)")
	fmt.Printf("bob ReadMessage(2): -> s, se, psk\n")
	_, bobSSS, err := bobHS.ReadMessage(aliceMsg2, nil)
	require.NoError(err, "bobHS.ReadMessage(2)")

	// symmetric key for transport message
	aliceTx, aliceRx := aliceSSS[0], aliceSSS[1]
	bobRx, bobTx := bobSSS[0], bobSSS[1]

	fmt.Printf("\nhandshake done with \n- alice's cipher key: %v\n- bob's cipher key: %v\n\n", aliceTx.k, bobTx.k)

	alicePlaintext := []byte("alice's transport plaintext")
	fmt.Printf("alice encrypts a plaintext: \"%v\"\n", string(alicePlaintext))
	aliceMsg3, err := aliceTx.EncryptWithAd(nil, alicePlaintext)
	require.NoError(err)

	bobRecv2, err := bobRx.DecryptWithAd(nil, aliceMsg3)
	require.NoError(err)
	require.Equal(alicePlaintext, bobRecv2)
	fmt.Printf("bob decrypts a ciphertext: %v\n			into \"%v\"\n\n", aliceMsg2, string(bobRecv2))

	bobPlaintext := []byte("bob's transport plaintext")
	fmt.Printf("bob encrypts a plaintext: \"%v\"\n", string(bobPlaintext))
	bobMsg2, err := bobTx.EncryptWithAd(nil, bobPlaintext)
	require.NoError(err)

	aliceRecv2, err := aliceRx.DecryptWithAd(nil, bobMsg2)
	require.NoError(err)
	require.Equal(bobPlaintext, aliceRecv2)
	fmt.Printf("alice decrypts a ciphertext: %v\n			into \"%v\"\n", bobMsg2, string(aliceRecv2))
}
