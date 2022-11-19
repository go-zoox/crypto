package aes

import (
	"testing"

	"github.com/go-zoox/crypto/test"
)

func Test_Chacha20Poly1305(t *testing.T) {
	testdata := "helloworld"
	testcases := map[string]string{
		// chacha20-poly1305
		"mysecretmysecretmysecretmysecret": "3AuCGEQotoyxpZBhETLaICZJUXSf+TUyYho=",
		// short
		"mysecretmysecretmysecretmy": "mEGjOqHqZEwfCR45cC9iySM4K3Za0xRPQY0=",
	}

	for secret, encrypted := range testcases {
		aes, err := NewChacha20Poly1305(&Base64Encoding{}, nil)
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
