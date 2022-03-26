package rsakeygenerator

import (
	"bytes"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GenerateKeys_Happy(t *testing.T) {
	// given: test subject
	k := NewKeyPair()

	// when: calling function
	err := k.GenerateKeys()

	// then: no error returned
	assert.NoError(t, err)
}

func Test_GenerateKeys_GenerateKey_Error(t *testing.T) {
	// given: test function
	tmp := generateKey
	generateKey = func(random io.Reader, bits int) (*rsa.PrivateKey, error) {
		return nil, errors.New("test error")
	}

	// and: test subject
	k := NewKeyPair()

	// when: calling function
	err := k.GenerateKeys()

	// then: error returned
	assert.Error(t, err)

	generateKey = tmp
}

func Test_GenerateKeys_MarshalPublicKey_Error(t *testing.T) {
	// given: test function
	tmp := marshalPublicKey
	marshalPublicKey = func(pub any) ([]byte, error) {
		return nil, errors.New("test error")
	}

	// and: test subject
	k := NewKeyPair()

	// when: calling function
	err := k.GenerateKeys()

	// then: error returned
	assert.Error(t, err)

	marshalPublicKey = tmp
}

func Test_GenerateKeys_EncodePrivateKey_Error(t *testing.T) {
	// given: test function
	tmp := encodePrivateKey
	encodePrivateKey = func(out io.Writer, b *pem.Block) error {
		return errors.New("test error")
	}

	// and: test subject
	k := NewKeyPair()

	// when: calling function
	err := k.GenerateKeys()

	// then: error returned
	assert.Error(t, err)

	encodePrivateKey = tmp
}

func Test_GenerateKeys_EncodePublicKey_Error(t *testing.T) {
	// given: test function
	tmp := encodePublicKey
	encodePublicKey = func(out io.Writer, b *pem.Block) error {
		return errors.New("test error")
	}

	// and: test subject
	k := NewKeyPair()

	// when: calling function
	err := k.GenerateKeys()

	// then: error returned
	assert.Error(t, err)

	encodePublicKey = tmp
}

func Test_PublicKeyToString(t *testing.T) {
	// given: test public key
	s := `
-----BEGIN PUBLIC KEY-----
test-public-
string-content
-----END PUBLIC KEY-----
`

	// and: test subject
	k := NewKeyPair()

	k.Public = bytes.NewBuffer([]byte(s))

	// when: calling function
	res := k.PublicKeyToString()

	// then: string has been normalized
	assert.Equal(t, "test-public-string-content", res)
}
