package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-zoox/crypto/hmac"
)

// VerifyOptions is the options for Verify
type VerifyOptions struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti"`
}

// Verify verifies data with secret
func Verify(secret string, token string, options ...*VerifyOptions) (map[string]interface{}, error) {
	var opt *VerifyOptions = nil
	if len(options) > 0 && options[0] != nil {
		opt = options[0]
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token")
	}

	headerBase64, payloadBase64, signatureX := parts[0], parts[1], parts[2]

	header, err := base64.RawURLEncoding.DecodeString(headerBase64)
	if err != nil {
		return nil, err
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, err
	}

	headerX := Header{}
	err = json.Unmarshal(header, &headerX)
	if err != nil {
		return nil, err
	}

	payloadX := map[string]interface{}{}
	err = json.Unmarshal(payload, &payloadX)
	if err != nil {
		return nil, err
	}

	var signature string
	switch headerX.Algorithm {
	case "HS256":
		signature = hmac.Sha256(secret, headerBase64+"."+payloadBase64, "base64")
	case "HS384":
		signature = hmac.Sha384(secret, headerBase64+"."+payloadBase64, "base64")
	case "HS512":
		signature = hmac.Sha512(secret, headerBase64+"."+payloadBase64, "base64")
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", headerX.Algorithm)
	}

	if signature != signatureX {
		return nil, errors.New("invalid signature")
	}

	if opt != nil {
		if opt.Issuer != "" && payloadX["iss"] != opt.Issuer {
			return nil, fmt.Errorf("invalid issuer: %s", payloadX["iss"])
		}

		if opt.Subject != "" && payloadX["sub"] != opt.Subject {
			return nil, fmt.Errorf("invalid subject: %s", payloadX["sub"])
		}

		if opt.Audience != "" && payloadX["aud"] != opt.Audience {
			return nil, fmt.Errorf("invalid audience: %s", payloadX["aud"])
		}
	}

	if payloadX["exp"] != nil {
		if payloadX["exp"].(float64) < float64(time.Now().Unix()) {
			return nil, errors.New("token expired")
		}
	}

	return payloadX, nil
}
