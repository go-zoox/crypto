package hash

import (
	_md5 "crypto/md5"
	_sha1 "crypto/sha1"
	_sha256 "crypto/sha256"
	_sha512 "crypto/sha512"
	"io"

	"github.com/go-zoox/crypto/base62"
	"github.com/spaolacci/murmur3"
)

func Md5(text string, encoding ...string) string {
	h := _md5.New()
	io.WriteString(h, text)

	return encode(h, encoding...)
}

func Sha256(text string, encoding ...string) string {
	h := _sha256.New()
	io.WriteString(h, text)
	return encode(h, encoding...)
}

func Sha512(text string, encoding ...string) string {
	h := _sha512.New()
	io.WriteString(h, text)
	return encode(h, encoding...)
}

func Sha1(text string, encoding ...string) string {
	h := _sha1.New()
	io.WriteString(h, text)
	return encode(h, encoding...)
}

func Sha224(text string, encoding ...string) string {
	h := _sha256.New224()
	io.WriteString(h, text)
	return encode(h, encoding...)
}

func Sha384(text string, encoding ...string) string {
	h := _sha512.New384()
	io.WriteString(h, text)
	return encode(h, encoding...)
}

func MurmurHash(text string) string {
	m := murmur3.Sum32([]byte(text))
	return base62.Encode(int(m))
}
