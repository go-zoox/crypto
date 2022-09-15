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
