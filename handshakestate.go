package noise

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yapatta/noise/cipher"
	"github.com/yapatta/noise/dh"
	"github.com/yapatta/noise/hash"
	"github.com/yapatta/noise/pattern"
)

const MaxMessageSize int = 65535

var (
	ProtocolPrefix              = "Noise"
	errInvalidProtocolName      = errors.New("noise: invalid protocol name")
	errUnsupportedToken         = errors.New("noise: unsupported token")
	errMessagePatternOutOfRange = errors.New("noise: index out of range in message patterns")
	errNotImplemented           = errors.New("noise: not implemented")
	errExceededMaxMessageSize   = errors.New("noise: exceeded max message size")
	errPSKEncryption            = errors.New("noise: encryption only with PSK is not supported")
)

type Protocol struct {
	fmt.Stringer
	pattern *pattern.MessagePattern
	dh      dh.DHFunc
	cipher  cipher.CipherFunc
	hash    hash.HashFunc
}

func (p *Protocol) String() string {
	return fmt.Sprintf("Protocol{pattern: %v, dh: %v, cipher: %v, hash: %v}\n", p.pattern, p.dh, p.cipher, p.hash)
}

func InitializeProtocol(protocolName string) *Protocol {
	parts := strings.Split(protocolName, "_")
	if len(parts) != 5 {
		panic(errInvalidProtocolName.Error())
	}
	if parts[0] != ProtocolPrefix {
		panic(errInvalidProtocolName.Error())
	}

	pattern := pattern.FromString(parts[1])
	dh := dh.FromString(parts[2])
	cipher := cipher.FromString(parts[3])
	hash := hash.FromString(parts[4])

	if pattern == nil || dh == nil || cipher == nil || hash == nil {
		panic(errInvalidProtocolName.Error())
	}

	return &Protocol{
		pattern: pattern,
		dh:      dh,
		cipher:  cipher,
		hash:    hash,
	}
}

// During the handshake phase each party has a single HandshakeState, which can be deleted once the handshake is finished.
type HandshakeState struct {
	ss              *SymmetricState
	localEphemeral  *dh.Keypair // e
	localStatic     *dh.Keypair // s
	remoteEphemeral []byte      // re
	remoteStatic    []byte      // rs

	isInitiator bool
	protocol    *Protocol

	patternIndex int // message pattern index

	// for PSK
	hasPSK           bool
	psk              [32]byte
	IsEphemeralKeyed bool
}

type HandshakeConfig struct {
	protocol                      *Protocol
	isInitiator                   bool
	prologue                      []byte
	localStatic, localEphemeral   *dh.Keypair
	remoteStatic, remoteEphemeral []byte
	psk                           []byte
}

func NewHandshakeState(cfg *HandshakeConfig) *HandshakeState {
	hs := &HandshakeState{
		ss:              NewSymmetricState(cfg.protocol.cipher, cfg.protocol.hash),
		protocol:        cfg.protocol,
		isInitiator:     cfg.isInitiator,
		localStatic:     cfg.localStatic,
		localEphemeral:  cfg.localEphemeral,
		remoteStatic:    cfg.remoteStatic,
		remoteEphemeral: cfg.remoteEphemeral,
	}

	// MEMO: Public keys are only passed in if the handshake_pattern uses pre-messages (see Section 7).
	// The ephemeral values (e, re) are typically left empty, since they are created and exchanged
	// during the handshake; but there are exceptions (see Section 10)

	// Derives a protocol_name byte sequence by combining the names for the handshake pattern and crypto functions,
	// as specified in Section 8. Calls InitializeSymmetric(protocol_name)

	var parts []string
	parts = append(parts, ProtocolPrefix)
	parts = append(parts, hs.protocol.pattern.String())
	parts = append(parts, hs.protocol.dh.String())
	parts = append(parts, hs.protocol.cipher.String())
	parts = append(parts, hs.protocol.hash.String())
	protocolName := strings.Join(parts, "_")

	hs.ss.InitializeSymmetric([]byte(protocolName))

	// Calls MixHash(prologue).
	hs.ss.MixHash(cfg.prologue)

	if cfg.psk != nil {
		hs.hasPSK = true
		// TODO: check if cfg.psk is 32 bytes...
		hs.psk = [32]byte(cfg.psk)
	}

	// Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern,
	// with the specified public key as input (see Section 7 for an explanation of pre-messages).
	// If both initiator and responder have pre-messages, the initiator's public keys are hashed first.
	// If multiple public keys are listed in either party's pre-message, the public keys are hashed in the order that they are listed.
	preMessages := hs.protocol.pattern.PreMessages()

	// for initiator
	for i := 0; i < len(preMessages); i += 2 {
		tokens := preMessages[i]
		for _, t := range tokens {
			switch t {
			case pattern.TokenE:
				if hs.isInitiator {
					hs.ss.MixHash(hs.localEphemeral.Public())
				} else {
					hs.ss.MixHash(hs.remoteEphemeral)
				}
			case pattern.TokenS:
				if hs.isInitiator {
					hs.ss.MixHash(hs.localStatic.Public())
				} else {
					hs.ss.MixHash(hs.remoteStatic)
				}
			default:
				panic(errUnsupportedToken.Error())
			}
		}
	}

	// for responder
	for i := 1; i < len(preMessages); i += 2 {
		tokens := preMessages[i]
		for _, t := range tokens {
			switch t {
			case pattern.TokenE:
				if hs.isInitiator {
					hs.ss.MixHash(hs.remoteEphemeral)
				} else {
					hs.ss.MixHash(hs.localEphemeral.Public())
				}
			case pattern.TokenS:
				if hs.isInitiator {
					hs.ss.MixHash(hs.remoteStatic)
				} else {
					hs.ss.MixHash(hs.localStatic.Public())
				}
			default:
				panic(errUnsupportedToken.Error())
			}
		}
	}

	return hs
}

func (hs *HandshakeState) WriteMessage(payload, messageBuffer []byte) ([]byte, []*CipherState, error) {
	// Fetches and deletes the next message pattern from message_patterns,
	// then sequentially processes each token from the message pattern:
	baseLen := len(messageBuffer)

	// MEMO: patternIndex must be divided by two when hs is an initiator
	if !(hs.isInitiator == (hs.patternIndex%2 == 0)) {
		return nil, nil, errMessagePatternOutOfRange
	}
	messages := hs.protocol.pattern.Messages()
	for _, token := range messages[hs.patternIndex] {
		switch token {
		case pattern.TokenE:
			// For "e": Sets e (which must be empty) to GENERATE_KEYPAIR().
			// Appends e.public_key to the buffer. Calls MixHash(e.public_key).
			var err error
			if hs.localEphemeral, err = hs.protocol.dh.GenerateKeypair(); err != nil {
				return nil, nil, err
			}
			messageBuffer = append(messageBuffer, hs.localEphemeral.Public()...)

			if hs.hasPSK {
				hs.ss.MixKey(hs.localEphemeral.Public())
				hs.IsEphemeralKeyed = true
			}

			hs.ss.MixHash(hs.localEphemeral.Public())
		case pattern.TokenS:
			// For "s": Appends EncryptAndHash(s.public_key) to the buffer.
			encryptedS := hs.ss.EncryptAndHash(hs.localStatic.Public())
			messageBuffer = append(messageBuffer, encryptedS...)
		case pattern.TokenEE:
			ee, err := hs.protocol.dh.DH(hs.localEphemeral, hs.remoteEphemeral)
			if err != nil {
				return nil, nil, err
			}
			hs.ss.MixKey(ee)
		case pattern.TokenES:
			// Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
			var es []byte
			var err error
			if hs.isInitiator {
				es, err = hs.protocol.dh.DH(hs.localEphemeral, hs.remoteStatic)
			} else {
				es, err = hs.protocol.dh.DH(hs.localStatic, hs.remoteEphemeral)
			}
			if err != nil {
				return nil, nil, err
			}

			hs.ss.MixKey(es)
		case pattern.TokenSE:
			// For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
			var se []byte
			var err error
			if hs.isInitiator {
				se, err = hs.protocol.dh.DH(hs.localStatic, hs.remoteEphemeral)
			} else {
				se, err = hs.protocol.dh.DH(hs.localEphemeral, hs.remoteStatic)
			}
			if err != nil {
				return nil, nil, err
			}
			hs.ss.MixKey(se)
		case pattern.TokenSS:
			// Calls MixKey(DH(s, rs)).
			ss, err := hs.protocol.dh.DH(hs.localStatic, hs.remoteStatic)
			if err != nil {
				return nil, nil, err
			}
			hs.ss.MixKey(ss)
		case pattern.TokenPSK:
			hs.ss.MixKeyAndHash(hs.psk[:])
		default:
			return nil, nil, errNotImplemented
		}
	}

	// A party may not send any encrypted data after it processes a "psk" token
	// unless it has previously sent an ephemeral public key (an "e" token),
	// either before or after the "psk" token.
	if hs.hasPSK && !hs.IsEphemeralKeyed {
		return nil, nil, errPSKEncryption
	}

	messageBuffer = append(messageBuffer, hs.ss.EncryptAndHash(payload)...)
	// TODO: check if the length of message buffer is less than max message size
	if len(messageBuffer)-baseLen > MaxMessageSize {
		return nil, nil, errExceededMaxMessageSize
	}
	// If there are no more message patterns returns two new CipherState objects by calling Split().
	hs.patternIndex += 1
	if hs.patternIndex < len(hs.protocol.pattern.Messages()) {
		return messageBuffer, nil, nil
	}

	return messageBuffer, hs.ss.Split(), nil
}

func (hs *HandshakeState) ReadMessage(message, payloadBuffer []byte) ([]byte, []*CipherState, error) {
	// Takes a byte sequence containing a Noise handshake message, and a payload_buffer to write the message's plaintext payload into.
	// Performs the following steps, aborting if any DecryptAndHash() call returns an error:

	// MEMO: patternIndex must be divided by two when hs is an initiator
	if hs.isInitiator == (hs.patternIndex%2 == 0) {
		return nil, nil, errMessagePatternOutOfRange
	}

	remainingIndex := 0
	messages := hs.protocol.pattern.Messages()
	for _, token := range messages[hs.patternIndex] {
		prevIndex := remainingIndex

		switch token {
		case pattern.TokenE:
			// Sets re (which must be empty) to the next DHLEN bytes from the message. Calls MixHash(re.public_key).
			remainingIndex += hs.protocol.dh.Size()
			hs.remoteEphemeral = message[prevIndex:remainingIndex]

			if hs.hasPSK {
				hs.ss.MixKey(hs.remoteEphemeral)
				hs.IsEphemeralKeyed = true
			}

			hs.ss.MixHash(hs.remoteEphemeral)
		case pattern.TokenS:
			// Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True,
			// or to the next DHLEN bytes otherwise. Sets rs (which must be empty) to DecryptAndHash(temp).
			var temp []byte
			if hs.ss.cs.HasKey() {
				remainingIndex += (hs.protocol.dh.Size() + hs.ss.cs.Overhead())
				temp = message[prevIndex:remainingIndex]
			} else {
				remainingIndex += hs.protocol.dh.Size()
				temp = message[prevIndex:remainingIndex]
			}
			fmt.Printf("aead before S: %v\n", hs.ss.cs.AEAD())
			hs.remoteStatic = hs.ss.DecryptAndHash(temp)
			fmt.Printf("aead after S: %v\n", hs.ss.cs.AEAD())
		case pattern.TokenEE:
			ee, err := hs.protocol.dh.DH(hs.localEphemeral, hs.remoteEphemeral)
			if err != nil {
				return nil, nil, err
			}
			hs.ss.MixKey(ee)
		case pattern.TokenES:
			// Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
			var es []byte
			var err error
			if hs.isInitiator {
				es, err = hs.protocol.dh.DH(hs.localEphemeral, hs.remoteStatic)
			} else {
				es, err = hs.protocol.dh.DH(hs.localStatic, hs.remoteEphemeral)
			}
			if err != nil {
				return nil, nil, err
			}

			hs.ss.MixKey(es)
		case pattern.TokenSE:
			// Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
			var se []byte
			var err error
			if hs.isInitiator {
				se, err = hs.protocol.dh.DH(hs.localStatic, hs.remoteEphemeral)
			} else {
				se, err = hs.protocol.dh.DH(hs.localEphemeral, hs.remoteStatic)
			}
			if err != nil {
				return nil, nil, err
			}
			hs.ss.MixKey(se)
		case pattern.TokenSS:
			// MixKey(DH(s, rs)).
			ss, err := hs.protocol.dh.DH(hs.localStatic, hs.remoteStatic)
			if err != nil {
				return nil, nil, err
			}
			hs.ss.MixKey(ss)
		case pattern.TokenPSK:
			hs.ss.MixKeyAndHash(hs.psk[:])
		default:
			return nil, nil, errNotImplemented
		}
	}

	payloadBuffer = append(payloadBuffer, hs.ss.DecryptAndHash(message[remainingIndex:])...)

	// If there are no more message patterns returns two new CipherState objects by calling Split().
	hs.patternIndex += 1
	if hs.patternIndex < len(hs.protocol.pattern.Messages()) {
		return payloadBuffer, nil, nil
	}

	return payloadBuffer, hs.ss.Split(), nil
}
