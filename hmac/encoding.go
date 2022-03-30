package hmac

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
)

const DEFAULT_ENCODING = "hex"

func encode(h hash.Hash, encoding ...string) string {
	encodingX := DEFAULT_ENCODING
	if len(encoding) > 0 {
		encodingX = encoding[0]
	}

	switch encodingX {
	case "hex":
		// return fmt.Sprintf("%x", h.Sum(nil))
		return hex.EncodeToString(h.Sum(nil))
	case "base64":
		return base64.StdEncoding.EncodeToString(h.Sum(nil))
	case "binary":
		return string(h.Sum(nil))
	default:
		panic(fmt.Sprintf("encoding(%s) not supported, current availables: hex,base64,binary", encodingX))
	}
}
