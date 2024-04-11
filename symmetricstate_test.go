package noise_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yapatta/noise"
	"github.com/yapatta/noise/cipher"
	"github.com/yapatta/noise/hash"
)

func TestSymmetricState(t *testing.T) {
	require := require.New(t)
	protocolName := []byte("Noise_NN_25519_ChaChaPoly_BLAKE2s")
	ss0 := noise.NewSymmetricState(cipher.ChaChaPoly, hash.BLAKE2b)
	ss0.InitializeSymmetric(protocolName)

	ss1 := noise.NewSymmetricState(cipher.ChaChaPoly, hash.BLAKE2b)
	ss1.InitializeSymmetric(protocolName)

	testPlaintext := []byte("test plaintext")

	ciphertext := ss0.EncryptAndHash(testPlaintext)
	plaintext := ss1.DecryptAndHash(ciphertext)

	require.Equal(testPlaintext, plaintext)
	require.Equal(ss0.HashValue(), ss1.HashValue())
}
