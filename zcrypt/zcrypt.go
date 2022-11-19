// inspired by bcrypt: https://zhuanlan.zhihu.com/p/400196101
// zcrypt algorithm: random_id.timestamp.hmacSha256(password, timestamp)
package zcrypt

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-zoox/crypto/hmac"
	"github.com/go-zoox/random"
)

// Generate a hash from password
func Generate(password string) string {
	randomID := random.String(10)
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	return fmt.Sprintf("%s.%s.%s", randomID, timestamp, hmac.Sha256(password, timestamp+randomID))
}

// Compare a hash with password
func Compare(password, hash string) bool {
	parts := strings.Split(hash, ".")

	// invalid hash
	if len(parts) != 3 {
		return false
	}

	randomID, timestamp, hash := parts[0], parts[1], parts[2]
	return hash == hmac.Sha256(password, timestamp+randomID)
}
