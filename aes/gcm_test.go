package aes

import (
	"testing"

	"github.com/go-zoox/crypto/test"
)

func Test_AES_GCM(t *testing.T) {
	testdata := "helloworld"
	testcases := map[string]string{
		// aes-128-gcm
		"mysecretmysecret": "cBQPqJx7vzvlDCa2geDRe91OvQgd8dzIseQ=",
		// aes-192-gcm
		"mysecretmysecretmysecret": "FY+J+wtDOmnHa/mrZHW3TCFZNsr/wm7RTkg=",
		// aes-256-gcm
		"mysecretmysecretmysecretmysecret": "W3cKXCGLFSomeRTwy+4e3FUM+jpUk1ThO30=",

		// short
		// aes-128-gcm
		"mysecretmy": "RB0kqWPC6vYGxyK0DSGhoItiOj+8QJGxv9c=",
		// aes-192-gcm
		"mysecretmysecretmy": "44ZyVed0yaEcOF2QugOtWlbjLjRZVccKSVA=",
		// aes-256-gcm
		"mysecretmysecretmysecretmy": "6WwoIOZJACazB/21fpzIMIEsbjsqO3hnFyE=",
	}

	for secret, encrypted := range testcases {
		aes, err := NewGCM(len(secret)*8, &Base64Encoding{}, nil)
		if err != nil {
			t.Fatalf("AES New failed: %s", err.Error())
		}

		ts := test.TestSuit{T: t}

		enc, err := aes.EncryptString(testdata, secret)
		if err != nil {
			t.Fatalf("AES Encrypt failed: %s", err.Error())
		}
		dec, _ := aes.DecryptString(enc, secret)

		// ts.Expect(base64.StdEncoding.EncodeToString(enc)).ToEqual(data.expected)
		ts.Expect(enc).ToEqual(encrypted)
		ts.Expect(dec).ToEqual(testdata)
	}
}
