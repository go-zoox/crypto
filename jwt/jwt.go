package jwt

import typ "github.com/go-zoox/core-utils/type"

// Header is the header of JWT
type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

// Payload is the payload of JWT
type Payload struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti"`
}

// Options is the options for jwt
type Options struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti"`
	Algorithm string
}

// Jwt is the jwt
type Jwt interface {
	Sign(payload map[string]interface{}) (string, error)
	Verify(token string) (*typ.Value, error)
}

type jwt struct {
	secret  string
	options *Options
	//
	payload *typ.Value
}

// New creates a new JWT
func New(secret string, options ...*Options) Jwt {
	opt := &Options{}
	if len(options) > 0 && options[0] != nil {
		opt = options[0]
	}

	return &jwt{
		secret:  secret,
		options: opt,
	}
}

// Sign signs data with secret
func (j *jwt) Sign(payload map[string]interface{}) (string, error) {
	return Sign(j.secret, payload, &SignOptions{
		Issuer:    j.options.Issuer,
		Subject:   j.options.Subject,
		Audience:  j.options.Audience,
		ExpiresAt: j.options.ExpiresAt,
		NotBefore: j.options.NotBefore,
		IssuedAt:  j.options.IssuedAt,
		JWTID:     j.options.JWTID,
		Algorithm: j.options.Algorithm,
	})
}

// Verify verifies data with secret
func (j *jwt) Verify(token string) (*typ.Value, error) {
	payload, err := Verify(j.secret, token, &VerifyOptions{
		Issuer:    j.options.Issuer,
		Subject:   j.options.Subject,
		Audience:  j.options.Audience,
		ExpiresAt: j.options.ExpiresAt,
		NotBefore: j.options.NotBefore,
		IssuedAt:  j.options.IssuedAt,
		JWTID:     j.options.JWTID,
	})
	if err != nil {
		return nil, err
	}

	j.payload = payload

	return j.payload, nil
}

// SetIssuer sets issuer
func (j *jwt) SetIssuer(iss string) {
	j.options.Issuer = iss
}

// SetSubject sets subject
func (j *jwt) SetSubject(sub string) {
	j.options.Subject = sub
}

// SetAudience sets audience
func (j *jwt) SetAudience(aud string) {
	j.options.Audience = aud
}

// SetNotBefore sets not before
func (j *jwt) SetNotBefore(nbf int64) {
	j.options.NotBefore = nbf
}

// SetExpiresAt sets expires at
func (j *jwt) SetExpiresAt(exp int64) {
	j.options.ExpiresAt = exp
}

// SetIssuedAt sets issued at
func (j *jwt) SetIssuedAt(iat int64) {
	j.options.IssuedAt = iat
}

// SetJWTID sets jwt id
func (j *jwt) SetJWTID(jti string) {
	j.options.JWTID = jti
}

// SetAlgorithm sets algorithm
func (j *jwt) SetAlgorithm(alg string) {
	j.options.Algorithm = alg
}
