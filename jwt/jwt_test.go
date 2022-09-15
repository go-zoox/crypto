package jwt

import (
	"testing"

	"github.com/go-zoox/testify"
)

func TestJWT(t *testing.T) {
	j := New("secret", &Options{
		IssuedAt: 1663218578,
	})

	token, err := j.Sign(map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	})
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdmF0YXIiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvNzQ2MzY4Nz92PTQiLCJpYXQiOjE2NjMyMTg1NzgsImlkIjoxLCJpc3MiOiJnby16b294Iiwibmlja25hbWUiOiJaZXJvIn0.fcJD66GgF-k2JgfuKgKW5PvqMEOhXqMQbJyMRrIdbfs", token)

	payload, err := j.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, payload["id"].(float64), 1)
	testify.Equal(t, payload["nickname"].(string), "Zero")
	testify.Equal(t, payload["avatar"].(string), "https://avatars.githubusercontent.com/u/7463687?v=4")
}

func TestGoZooxJWTSign(t *testing.T) {
	secret := "secret"
	jwt := New(secret, &Options{
		IssuedAt: 1648268173,
	})
	payload := map[string]interface{}{
		"name": "zero",
		"id":   "abcd",
	}

	_token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NDgyNjgxNzMsImlkIjoiYWJjZCIsImlzcyI6ImdvLXpvb3giLCJuYW1lIjoiemVybyJ9.6InYxP1hzY-FZHzo8-ehJX_sbWi1qCF_VLoajoTj7do"

	token, err := jwt.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	if token != _token {
		t.Fatalf("expect: %s, but %s", token, _token)
	}
}

// func TestGoZooxJWTVerify(t *testing.T) {
// 	token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiIiLCJleHAiOjAsImlhdCI6MTY0ODI2ODE3MywiaWQiOiJhYmNkIiwiaXNzIjoiIiwianRpIjoiIiwibmFtZSI6Inplcm8iLCJuYmYiOjAsInN1YiI6IiJ9.QSV-slPLFCZECmID-fRzEyZXFpP8WHqUhIt-6vmth7g"
// 	secret := "secret"
// 	jwt := New(secret)

// 	if payload, err := jwt.Verify(token); err != nil {
// 		t.Fatal(err)
// 	}

// 	if jwt.Get("name").String() != "zero" {
// 		t.Fatal("name mismatch")
// 	}

// 	if jwt.Get("id").String() != "abcd" {
// 		t.Fatal("id mismatch")
// 	}

// 	if jwt.GetIssuedAt() == 0 {
// 		t.Fatal("issuedAt mismatch")
// 	}

// 	if jwt.GetExpiresAt() != 0 {
// 		t.Fatal("expiresAt mismatch")
// 	}

// 	if jwt.GetNotBefore() != 0 {
// 		t.Fatal("notBefore mismatch")
// 	}

// 	if jwt.GetIssuer() != "" {
// 		t.Fatal("issuer mismatch")
// 	}

// 	if jwt.GetAudience() != "" {
// 		t.Fatal("audience mismatch")
// 	}

// 	if jwt.GetSubject() != "" {
// 		t.Fatal("subject mismatch")
// 	}

// 	if jwt.GetJwtID() != "" {
// 		t.Fatal("jwtID mismatch")
// 	}
// }

// func TestGoZooxJWTVerify2(t *testing.T) {
// 	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NDgyNjkyNzZ9.H_MAA3Xau6z3-4VWOUk8ojGiaV2gCfVyqRUdhS8d0xE"
// 	secret := "secret"
// 	jwt := New(secret)

// 	if err := jwt.Verify(token); err != nil {
// 		t.Fatal(err)
// 	}

// 	if jwt.GetIssuedAt() == 0 {
// 		t.Fatal("issuedAt mismatch")
// 	}

// 	if jwt.GetExpiresAt() != 0 {
// 		t.Fatal("expiresAt mismatch")
// 	}

// 	if jwt.GetNotBefore() != 0 {
// 		t.Fatal("notBefore mismatch")
// 	}

// 	if jwt.GetIssuer() != "" {
// 		t.Fatal("issuer mismatch")
// 	}

// 	if jwt.GetAudience() != "" {
// 		t.Fatal("audience mismatch")
// 	}

// 	if jwt.GetSubject() != "" {
// 		t.Fatal("subject mismatch")
// 	}

// 	if jwt.GetJwtID() != "" {
// 		t.Fatal("jwtID mismatch")
// 	}

// 	if jwt.GetIssuedAt() != 1648269276 {
// 		t.Fatal("issuedAt mismatch")
// 	}
// }
