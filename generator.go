package generator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

type Generator struct {
	bitSize int
}

func NewGenerator(bitSize int) *Generator {
	return &Generator{bitSize: bitSize}
}

func (g *Generator) GenerateKeyPair() (Keys, error) {
	privateKey, err := g.generatePrivateKey()
	if err != nil {
		return Keys{}, err
	}

	publicKeyBytes, err := g.generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		return Keys{}, err
	}

	privateKeyBytes := g.encodePrivateKeyToPEM(privateKey)

	return Keys{
		Public:  *bytes.NewBuffer(publicKeyBytes),
		Private: *bytes.NewBuffer(privateKeyBytes),
	}, nil
}

func (g *Generator) generatePrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, g.bitSize)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (g *Generator) encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey),
	}

	return pem.EncodeToMemory(&privBlock)
}

func (g *Generator) generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	return ssh.MarshalAuthorizedKey(publicRsaKey), nil
}

func (g *Generator) WriteKeyToFile(keyBytes []byte, filename string) error {
	return ioutil.WriteFile(filename, keyBytes, 0600)
}
