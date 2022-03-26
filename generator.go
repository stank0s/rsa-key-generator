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

func GenerateKeys() (privateKey, publicKey bytes.Buffer, err error) {
	key, err := generateKey(rand.Reader, 2048)
	if err != nil {
		return privateKey, publicKey, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	err = encodePrivateKey(&privateKey, privateKeyBlock)
	if err != nil {
		return privateKey, publicKey, err
	}

	publicKeyBytes, err := marshalPublicKey(&key.PublicKey)
	if err != nil {
		return privateKey, publicKey, err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	err = encodePublicKey(&publicKey, publicKeyBlock)
	if err != nil {
		return privateKey, publicKey, err
	}

	return privateKey, publicKey, nil
}

// NormalizePublicKeyString creates one line string without comments and line breaks
func NormalizePublicKeyString(publicKey string) (pKey string) {
	pKey = strings.ReplaceAll(publicKey, "\n", "")
	pKey = strings.ReplaceAll(pKey, "-----BEGIN PUBLIC KEY-----", "")
	pKey = strings.ReplaceAll(pKey, "-----END PUBLIC KEY-----", "")

	return
}
