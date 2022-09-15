package jwt

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

type jwt struct {
	secret  string
	options *Options
}

// New creates a new JWT
func New(secret string, options ...*Options) *jwt {
	var opt *Options = nil
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
func (j *jwt) Verify(token string) (map[string]interface{}, error) {
	return Verify(j.secret, token, &VerifyOptions{
		Issuer:    j.options.Issuer,
		Subject:   j.options.Subject,
		Audience:  j.options.Audience,
		ExpiresAt: j.options.ExpiresAt,
		NotBefore: j.options.NotBefore,
		IssuedAt:  j.options.IssuedAt,
		JWTID:     j.options.JWTID,
	})
}
