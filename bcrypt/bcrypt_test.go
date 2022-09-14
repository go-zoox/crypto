package bcrypt

import (
	"testing"
)

func TestBcryptGenerate(t *testing.T) {
	password := "password"
	hash, err := Generate(password)
	if err != nil {
		t.Fatal(err)
	}

	if !Compare(password, hash) {
		t.Fatal("password and hash do not match")
	}
}

func TestBcryptCompare(t *testing.T) {
	if !Compare("password", "$2a$10$cX6uTzBUb/XFd82pDBwgWup/paZo0LtiY4Mvi0s8qbOr3TiX9BnFG") {
		t.Fatal("password and hash do not match (1)")
	}

	if !Compare("password", "$2a$10$lNNRsehZ5RXk8Um8Kh7/meKB6qrj7KcWUbfSEtknUTILrEt/Zfsoe") {
		t.Fatal("password and hash do not match (2)")
	}

	if !Compare("password", "$2a$10$PTpEN42VtP5LPOMicBS32OGXK76Wubb7ItPs3zCFb1YEQ.kuRR2Pa") {
		t.Fatal("password and hash do not match (3)")
	}

	if !Compare("password", "$2a$10$4DQNqNje7cvkkBO7MQs/0.ausAepoexkBpN1F38ELO5f3/RcqqLDC") {
		t.Fatal("password and hash do not match (3)")
	}
}
