package aes

import (
	"testing"

	"github.com/go-zoox/crypto/test"
)

func Test_AES_CBC(t *testing.T) {
	testdata := "helloworld"
	testcases := map[string]string{
		// aes-128-cbc
		"mysecretmysecret": "2q17PNG+ARHvwWJEqTQ3xw==",
		// aes-192-cbc
		"mysecretmysecretmysecret": "GinncdmEkjOYqSadyEYLbQ==",
		// aes-256-cbc
		"mysecretmysecretmysecretmysecret": "Kl64DBtxfmcCXCf31xALqw==",

		// short
		// aes-128-cbc
		"mysecretmy": "6NEXL46lJZFnsbPsgS5/1g==",
		// aes-192-cbc
		"mysecretmysecretmy": "hk+d5hAUILO+x2zM+sZySA==",
		// aes-256-cbc
		"mysecretmysecretmysecretm": "rccdrZUSN6k3YavV0hv/Ag==",
	}

	for secret, encrypted := range testcases {
		aes, err := NewCBC(len(secret)*8, nil, &Base64Encoding{}, nil)
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
