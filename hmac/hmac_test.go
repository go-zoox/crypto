package hmac

import (
	"encoding/base64"
	"testing"
)

func TestMd5(t *testing.T) {
	if Md5("secret", "test") != "63d6baf65df6bdee8f32b332e0930669" {
		t.Errorf("Md5(test), expect %s, but got %s", "63d6baf65df6bdee8f32b332e0930669", Md5("secret", "test"))
	}

	if Md5("secret", "test", "hex") != "63d6baf65df6bdee8f32b332e0930669" {
		t.Errorf("Md5(test, \"hex\"), expect %s, but got %s", "63d6baf65df6bdee8f32b332e0930669", Md5("secret", "test", "hex"))
	}

	if Md5("secret", "test", "base64") != "Y9a69l32ve6PMrMy4JMGaQ" {
		t.Errorf("Md5(test, \"base64\"), expect %s, but got %s", "Y9a69l32ve6PMrMy4JMGaQ", Md5("secret", "test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Md5("secret", "test", "binary"))) != "Y9a69l32ve6PMrMy4JMGaQ==" {
		t.Errorf("Md5(test, \"binary\"), expect %s, but got %s", "Y9a69l32ve6PMrMy4JMGaQ==", base64.StdEncoding.EncodeToString([]byte(Md5("secret", "test", "binary"))))
	}
}

func TestSha256(t *testing.T) {
	if Sha256("secret", "test") != "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914" {
		t.Errorf("Sha256(test), expect %s, but got %s", "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914", Sha256("secret", "test"))
	}

	if Sha256("secret", "test", "hex") != "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914" {
		t.Errorf("Sha256(test, \"hex\"), expect %s, but got %s", "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914", Sha256("secret", "test", "hex"))
	}

	if Sha256("secret", "test", "base64") != "Aymga2LNFrM-tnkr6MYLFY2Jou46h2_Omogeu0iMCRQ" {
		t.Errorf("Sha256(test, \"base64\"), expect %s, but got %s", "Aymga2LNFrM-tnkr6MYLFY2Jou46h2_Omogeu0iMCRQ", Sha256("secret", "test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Sha256("secret", "test", "binary"))) != "Aymga2LNFrM+tnkr6MYLFY2Jou46h2/Omogeu0iMCRQ=" {
		t.Errorf("Sha256(test, \"binary\"), expect %s, but got %s", "Aymga2LNFrM+tnkr6MYLFY2Jou46h2/Omogeu0iMCRQ=", base64.StdEncoding.EncodeToString([]byte(Sha256("secret", "test", "binary"))))
	}
}

func TestSha512(t *testing.T) {
	if Sha512("secret", "test") != "f8a4f0a209167bc192a1bffaa01ecdb09e06c57f96530d92ec9ccea0090d290e55071306d6b654f26ae0c8721f7e48a2d7130b881151f2cec8d61d941a6be88a" {
		t.Errorf("Sha512(test), expect %s, but got %s", "f8a4f0a209167bc192a1bffaa01ecdb09e06c57f96530d92ec9ccea0090d290e55071306d6b654f26ae0c8721f7e48a2d7130b881151f2cec8d61d941a6be88a", Sha512("secret", "test"))
	}

	if Sha512("secret", "test", "hex") != "f8a4f0a209167bc192a1bffaa01ecdb09e06c57f96530d92ec9ccea0090d290e55071306d6b654f26ae0c8721f7e48a2d7130b881151f2cec8d61d941a6be88a" {
		t.Errorf("Sha512(test, \"hex\"), expect %s, but got %s", "f8a4f0a209167bc192a1bffaa01ecdb09e06c57f96530d92ec9ccea0090d290e55071306d6b654f26ae0c8721f7e48a2d7130b881151f2cec8d61d941a6be88a", Sha512("secret", "test", "hex"))
	}

	if Sha512("secret", "test", "base64") != "-KTwogkWe8GSob_6oB7NsJ4GxX-WUw2S7JzOoAkNKQ5VBxMG1rZU8mrgyHIffkii1xMLiBFR8s7I1h2UGmvoig" {
		t.Errorf("Sha512(test, \"base64\"), expect %s, but got %s", "-KTwogkWe8GSob_6oB7NsJ4GxX-WUw2S7JzOoAkNKQ5VBxMG1rZU8mrgyHIffkii1xMLiBFR8s7I1h2UGmvoig", Sha512("secret", "test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Sha512("secret", "test", "binary"))) != "+KTwogkWe8GSob/6oB7NsJ4GxX+WUw2S7JzOoAkNKQ5VBxMG1rZU8mrgyHIffkii1xMLiBFR8s7I1h2UGmvoig==" {
		t.Errorf("Sha512(test, \"binary\"), expect %s, but got %s", "+KTwogkWe8GSob/6oB7NsJ4GxX+WUw2S7JzOoAkNKQ5VBxMG1rZU8mrgyHIffkii1xMLiBFR8s7I1h2UGmvoig==", base64.StdEncoding.EncodeToString([]byte(Sha512("secret", "test", "binary"))))
	}
}

func TestSha1(t *testing.T) {
	if Sha1("secret", "test") != "1aa349585ed7ecbd3b9c486a30067e395ca4b356" {
		t.Errorf("Sha1(test), expect %s, but got %s", "1aa349585ed7ecbd3b9c486a30067e395ca4b356", Sha1("secret", "test"))
	}

	if Sha1("secret", "test", "hex") != "1aa349585ed7ecbd3b9c486a30067e395ca4b356" {
		t.Errorf("Sha1(test, \"hex\"), expect %s, but got %s", "1aa349585ed7ecbd3b9c486a30067e395ca4b356", Sha1("secret", "test", "hex"))
	}

	if Sha1("secret", "test", "base64") != "GqNJWF7X7L07nEhqMAZ-OVyks1Y" {
		t.Errorf("Sha1(test, \"base64\"), expect %s, but got %s", "GqNJWF7X7L07nEhqMAZ-OVyks1Y", Sha1("secret", "test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Sha1("secret", "test", "binary"))) != "GqNJWF7X7L07nEhqMAZ+OVyks1Y=" {
		t.Errorf("Sha1(test, \"binary\"), expect %s, but got %s", "GqNJWF7X7L07nEhqMAZ+OVyks1Y=", base64.StdEncoding.EncodeToString([]byte(Sha1("secret", "test", "binary"))))
	}
}

func TestSha224(t *testing.T) {
	if Sha224("secret", "test") != "a6252fa6169c5c89311eecd3a012127e0d9f5da86cbd61bfc10261ca" {
		t.Errorf("Sha224(test), expect %s, but got %s", "a6252fa6169c5c89311eecd3a012127e0d9f5da86cbd61bfc10261ca", Sha224("secret", "test"))
	}

	if Sha224("secret", "test", "hex") != "a6252fa6169c5c89311eecd3a012127e0d9f5da86cbd61bfc10261ca" {
		t.Errorf("Sha224(test, \"hex\"), expect %s, but got %s", "a6252fa6169c5c89311eecd3a012127e0d9f5da86cbd61bfc10261ca", Sha224("secret", "test", "hex"))
	}

	if Sha224("secret", "test", "base64") != "piUvphacXIkxHuzToBISfg2fXahsvWG_wQJhyg" {
		t.Errorf("Sha224(test, \"base64\"), expect %s, but got %s", "piUvphacXIkxHuzToBISfg2fXahsvWG_wQJhyg", Sha224("secret", "test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Sha224("secret", "test", "binary"))) != "piUvphacXIkxHuzToBISfg2fXahsvWG/wQJhyg==" {
		t.Errorf("Sha224(test, \"binary\"), expect %s, but got %s", "piUvphacXIkxHuzToBISfg2fXahsvWG/wQJhyg==", base64.StdEncoding.EncodeToString([]byte(Sha224("secret", "test", "binary"))))
	}
}

func TestSha384(t *testing.T) {
	if Sha384("secret", "test") != "4e54a97be947e471e89cdd22c25b8ff704f458fdfcebd8a79a366ff0e52b607fe3f1e52bd1a839f89396d1a4b2cbe570" {
		t.Errorf("Sha384(test), expect %s, but got %s", "4e54a97be947e471e89cdd22c25b8ff704f458fdfcebd8a79a366ff0e52b607fe3f1e52bd1a839f89396d1a4b2cbe570", Sha384("secret", "test"))
	}

	if Sha384("secret", "test", "hex") != "4e54a97be947e471e89cdd22c25b8ff704f458fdfcebd8a79a366ff0e52b607fe3f1e52bd1a839f89396d1a4b2cbe570" {
		t.Errorf("Sha384(test, \"hex\"), expect %s, but got %s", "4e54a97be947e471e89cdd22c25b8ff704f458fdfcebd8a79a366ff0e52b607fe3f1e52bd1a839f89396d1a4b2cbe570", Sha384("secret", "test", "hex"))
	}

	if Sha384("secret", "test", "base64") != "TlSpe-lH5HHonN0iwluP9wT0WP3869inmjZv8OUrYH_j8eUr0ag5-JOW0aSyy-Vw" {
		t.Errorf("Sha384(test, \"base64\"), expect %s, but got %s", "TlSpe-lH5HHonN0iwluP9wT0WP3869inmjZv8OUrYH_j8eUr0ag5-JOW0aSyy-Vw", Sha384("secret", "test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Sha384("secret", "test", "binary"))) != "TlSpe+lH5HHonN0iwluP9wT0WP3869inmjZv8OUrYH/j8eUr0ag5+JOW0aSyy+Vw" {
		t.Errorf("Sha384(test, \"binary\"), expect %s, but got %s", "TlSpe+lH5HHonN0iwluP9wT0WP3869inmjZv8OUrYH/j8eUr0ag5+JOW0aSyy+Vw", base64.StdEncoding.EncodeToString([]byte(Sha384("secret", "test", "binary"))))
	}
}
