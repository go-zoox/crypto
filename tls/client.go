package tls

import (
	"fmt"
	"time"

	"github.com/go-zoox/crypto/aes"
	"github.com/go-zoox/crypto/rsa"
	"github.com/go-zoox/random"
)

// TLSClient is a client for TLS.
type TLSClient struct {
	// public key
	publicKey string
	// secret
	secret string
	// algorithms
	asymmetric *rsa.RSAEncryptor
	symmetric  *aes.CFB
}

// NewClient creates a new TLS client.
func NewClient(publicKey string) *TLSClient {
	asymmetric, _ := rsa.NewEncryptor(publicKey)
	return &TLSClient{
		publicKey:  publicKey,
		asymmetric: asymmetric,
	}
}

// NegotiateGenerate generates a secret and encrypts it with the public key.
//	The secret is used to encrypt the data.
//	The hash is used to negotiate the secret.
func (t *TLSClient) NegotiateGenerate() string {
	// @TODO milliseconds, length: 13
	timestamp := fmt.Sprintf("%d", time.Now().UnixNano()/int64(time.Millisecond))
	// length = 32 - 13 = 19
	random := random.String(19)
	t.secret = fmt.Sprintf("%s%s", timestamp, random)
	// fmt.Println("client secret:", t.secret)
	t.symmetric, _ = aes.NewCFB(len(t.secret)*8, &aes.Base64Encoding{}, nil)

	hash, _ := t.asymmetric.Encrypt([]byte(t.secret))
	return string(hash)
}

// Encrypt encrypts the plaintext with the secret.
func (t *TLSClient) Encrypt(plainbytes []byte) (cipherbytes []byte, err error) {
	cipherbytes, err = t.symmetric.Encrypt(plainbytes, []byte(t.secret))
	return
}

// Decrypt decrypts the ciphertext with the secret.
func (t *TLSClient) Decrypt(cipherbytes []byte) (plainbytes []byte, err error) {
	plainbytes, err = t.symmetric.Decrypt(cipherbytes, []byte(t.secret))
	return
}

// GetSecret returns the secret.
func (t *TLSClient) GetSecret() string {
	return t.secret
}

// GetPublicKey returns the public key.
func (t *TLSClient) GetPublicKey() string {
	return t.publicKey
}
