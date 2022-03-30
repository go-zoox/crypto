package hash

import (
	"encoding/base64"
	"testing"
)

func TestMd5(t *testing.T) {
	if Md5("test") != "098f6bcd4621d373cade4e832627b4f6" {
		t.Errorf("Md5(test), expect %s, but got %s", "098f6bcd4621d373cade4e832627b4f6", Md5("test"))
	}

	if Md5("test", "hex") != "098f6bcd4621d373cade4e832627b4f6" {
		t.Errorf("Md5(test, \"hex\"), expect %s, but got %s", "098f6bcd4621d373cade4e832627b4f6", Md5("test", "hex"))
	}

	if Md5("test", "base64") != "CY9rzUYh03PK3k6DJie09g==" {
		t.Errorf("Md5(test, \"base64\"), expect %s, but got %s", "CY9rzUYh03PK3k6DJie09g==", Md5("test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Md5("test", "binary"))) != "CY9rzUYh03PK3k6DJie09g==" {
		t.Errorf("Md5(test, \"binary\"), expect %s, but got %s", "CY9rzUYh03PK3k6DJie09g==", base64.StdEncoding.EncodeToString([]byte(Md5("test", "binary"))))
	}
}

func TestSha256(t *testing.T) {
	if Sha256("test") != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Errorf("Sha256(test), expect %s, but got %s", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", Sha256("test"))
	}

	if Sha256("test", "hex") != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Errorf("Sha256(test, \"hex\"), expect %s, but got %s", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", Sha256("test", "hex"))
	}

	if Sha256("test", "base64") != "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" {
		t.Errorf("Sha256(test, \"base64\"), expect %s, but got %s", "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=", Sha256("test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Sha256("test", "binary"))) != "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" {
		t.Errorf("Sha256(test, \"binary\"), expect %s, but got %s", "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=", base64.StdEncoding.EncodeToString([]byte(Sha256("test", "binary"))))
	}
}

func TestSha512(t *testing.T) {
	if Sha512("test") != "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff" {
		t.Errorf("Sha512(test), expect %s, but got %s", "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", Sha512("test"))
	}

	if Sha512("test", "hex") != "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff" {
		t.Errorf("Sha512(test, \"hex\"), expect %s, but got %s", "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", Sha512("test", "hex"))
	}

	if Sha512("test", "base64") != "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==" {
		t.Errorf("Sha512(test, \"base64\"), expect %s, but got %s", "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==", Sha512("test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Sha512("test", "binary"))) != "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==" {
		t.Errorf("Sha512(test, \"binary\"), expect %s, but got %s", "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==", base64.StdEncoding.EncodeToString([]byte(Sha512("test", "binary"))))
	}
}

func TestSha1(t *testing.T) {
	if Sha1("test") != "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" {
		t.Errorf("Sha1(test), expect %s, but got %s", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", Sha1("test"))
	}

	if Sha1("test", "hex") != "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" {
		t.Errorf("Sha1(test, \"hex\"), expect %s, but got %s", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", Sha1("test", "hex"))
	}

	if Sha1("test", "base64") != "qUqP5cyxm6YcTAhz05Hph5gvu9M=" {
		t.Errorf("Sha1(test, \"base64\"), expect %s, but got %s", "qUqP5cyxm6YcTAhz05Hph5gvu9M=", Sha1("test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Sha1("test", "binary"))) != "qUqP5cyxm6YcTAhz05Hph5gvu9M=" {
		t.Errorf("Sha1(test, \"binary\"), expect %s, but got %s", "qUqP5cyxm6YcTAhz05Hph5gvu9M=", base64.StdEncoding.EncodeToString([]byte(Sha1("test", "binary"))))
	}
}

func TestSha224(t *testing.T) {
	if Sha224("test") != "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809" {
		t.Errorf("Sha224(test), expect %s, but got %s", "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809", Sha224("test"))
	}

	if Sha224("test", "hex") != "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809" {
		t.Errorf("Sha224(test, \"hex\"), expect %s, but got %s", "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809", Sha224("test", "hex"))
	}

	if Sha224("test", "base64") != "kKPtnjKyqvTGHEEOuSVCYRnhqdxT1Chq3pmoCQ==" {
		t.Errorf("Sha224(test, \"base64\"), expect %s, but got %s", "kKPtnjKyqvTGHEEOuSVCYRnhqdxT1Chq3pmoCQ==", Sha224("test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Sha224("test", "binary"))) != "kKPtnjKyqvTGHEEOuSVCYRnhqdxT1Chq3pmoCQ==" {
		t.Errorf("Sha224(test, \"binary\"), expect %s, but got %s", "kKPtnjKyqvTGHEEOuSVCYRnhqdxT1Chq3pmoCQ==", base64.StdEncoding.EncodeToString([]byte(Sha224("test", "binary"))))
	}
}

func TestSha384(t *testing.T) {
	if Sha384("test") != "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9" {
		t.Errorf("Sha384(test), expect %s, but got %s", "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9", Sha384("test"))
	}

	if Sha384("test", "hex") != "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9" {
		t.Errorf("Sha384(test, \"hex\"), expect %s, but got %s", "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9", Sha384("test", "hex"))
	}

	if Sha384("test", "base64") != "doQSMg97CqWBL85CjcRwazyuUOAqZMqhangiSb/o78S37xzLEmJV0ZYEff7fF6Cp" {
		t.Errorf("Sha384(test, \"base64\"), expect %s, but got %s", "doQSMg97CqWBL85CjcRwazyuUOAqZMqhangiSb/o78S37xzLEmJV0ZYEff7fF6Cp", Sha384("test", "base64"))
	}

	if base64.StdEncoding.EncodeToString([]byte(Sha384("test", "binary"))) != "doQSMg97CqWBL85CjcRwazyuUOAqZMqhangiSb/o78S37xzLEmJV0ZYEff7fF6Cp" {
		t.Errorf("Sha384(test, \"binary\"), expect %s, but got %s", "doQSMg97CqWBL85CjcRwazyuUOAqZMqhangiSb/o78S37xzLEmJV0ZYEff7fF6Cp", base64.StdEncoding.EncodeToString([]byte(Sha384("test", "binary"))))
	}
}
