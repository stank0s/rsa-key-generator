package rsakeygenerator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"strings"
)

var encodePublicKey func(out io.Writer, b *pem.Block) error = pem.Encode
var encodePrivateKey func(out io.Writer, b *pem.Block) error = pem.Encode
var marshalPublicKey func(pub any) ([]byte, error) = x509.MarshalPKIXPublicKey
var generateKey func(random io.Reader, bits int) (*rsa.PrivateKey, error) = rsa.GenerateKey

type KeyPair struct {
	Private *bytes.Buffer
	Public  *bytes.Buffer
}

func NewKeyPair() *KeyPair {
	return &KeyPair{
		Private: &bytes.Buffer{},
		Public:  &bytes.Buffer{},
	}
}

func (k *KeyPair) GenerateKeys() error {
	k.Private, k.Public = &bytes.Buffer{}, &bytes.Buffer{}

	key, err := generateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	err = encodePrivateKey(k.Private, privateKeyBlock)
	if err != nil {
		return err
	}

	publicKeyBytes, err := marshalPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	err = encodePublicKey(k.Public, publicKeyBlock)
	if err != nil {
		return err
	}

	return nil
}

func (k *KeyPair) PublicKeyToString() (pKey string) {
	pKey = strings.ReplaceAll(k.Public.String(), "\n", "")
	pKey = strings.ReplaceAll(pKey, "-----BEGIN PUBLIC KEY-----", "")
	pKey = strings.ReplaceAll(pKey, "-----END PUBLIC KEY-----", "")

	return
}
