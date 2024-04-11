package noise_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yapatta/noise"
	"github.com/yapatta/noise/cipher"
)

func TestCipherState(t *testing.T) {
	require := require.New(t)
	cs := noise.NewCipherState(cipher.ChaChaPoly)

	testPlaintext := []byte("test plaintext")

	var testKey [32]byte
	cs.InitializeKey(testKey[:])

	ciphertext, err := cs.EncryptWithAd(nil, testPlaintext)
	require.NoError(err, "cs.EncryptWithAd()")

	cs.SetNonce(0)
	_, err = cs.DecryptWithAd([]byte("bogus ad"), ciphertext)
	require.Equal(cipher.ErrOpen, err, "cs.DecryptWithAd(bogus ad)")

	ciphertext[0] = ^ciphertext[0]
	_, err = cs.DecryptWithAd(nil, ciphertext)
	require.Equal(cipher.ErrOpen, err)

	ciphertext[0] = ^ciphertext[0]
	plaintext, err := cs.DecryptWithAd(nil, ciphertext)
	require.NoError(err, "cs.DecryptWithAd()")
	require.Equal(testPlaintext, plaintext)
}
