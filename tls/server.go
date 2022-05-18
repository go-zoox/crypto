package tls

import (
	"github.com/go-zoox/crypto/aes"
	"github.com/go-zoox/crypto/rsa"
)

type TLSServer struct {
	// private key
	privateKey string
	// secret
	secret string
	// algorithms
	asymmetric *rsa.RSA
	symmetric  *aes.CFB
}

func NewServer(privateKey string) *TLSServer {
	asymmetric, _ := rsa.New(privateKey)
	return &TLSServer{
		privateKey: privateKey,
		asymmetric: asymmetric,
	}
}

func (t *TLSServer) NegotiateVerify(hash string) (bool, error) {
	secret, err := t.asymmetric.Decrypt([]byte(hash))
	if err != nil {
		return false, err
	}

	t.secret = string(secret)
	t.symmetric, _ = aes.NewCFB(len(secret)*8, &aes.Base64Encoding{}, nil)
	// fmt.Println("server secret:", t.secret)
	return true, nil
}

func (t *TLSServer) Encrypt(plainbytes []byte) (cipherbytes []byte, err error) {
	cipherbytes, err = t.symmetric.Encrypt(plainbytes, []byte(t.secret))
	return
}

func (t *TLSServer) Decrypt(cipherbytes []byte) (plainbytes []byte, err error) {
	plainbytes, err = t.symmetric.Decrypt(cipherbytes, []byte(t.secret))
	return
}

func (t *TLSServer) GetSecret() string {
	return t.secret
}

func (t *TLSServer) GetPrivateKey() string {
	return t.privateKey
}

func (t *TLSServer) GetPublicKey() string {
	return t.asymmetric.GetPublickKey()
}
