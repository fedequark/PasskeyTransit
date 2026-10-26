// Exercise independently maintained jwx/v4 JOSE HPKE code against Python.
// This is a JWE crypto test, not a credential-provider import.
package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
)

type request struct {
	Mode    string `json:"mode"`
	Key     string `json:"key"`
	Payload string `json:"payload"`
}

type response struct {
	Status  string `json:"status"`
	Payload string `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
}

func run(input request) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(input.Key)
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid X25519 key")
	}
	switch input.Mode {
	case "encrypt":
		key, err := ecdh.X25519().NewPublicKey(raw)
		if err != nil {
			return "", err
		}
		plaintext, err := base64.RawURLEncoding.DecodeString(input.Payload)
		if err != nil || len(plaintext) == 0 || len(plaintext) > 256*1024 {
			return "", errors.New("invalid plaintext")
		}
		compact, err := jwe.Encrypt(plaintext,
			jwe.WithKey(jwa.HPKE_3_KE(), key),
			jwe.WithContentEncryption(jwa.A128GCM()),
		)
		return string(compact), err
	case "decrypt":
		key, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return "", err
		}
		if len(input.Payload) > 512*1024 {
			return "", errors.New("JWE exceeds limit")
		}
		plaintext, err := jwe.Decrypt([]byte(input.Payload), jwe.WithKey(jwa.HPKE_3_KE(), key))
		return base64.RawURLEncoding.EncodeToString(plaintext), err
	default:
		return "", errors.New("unknown mode")
	}
}

func main() {
	var input request
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 1024*1024+1))
	if err == nil && len(data) <= 1024*1024 {
		err = json.Unmarshal(data, &input)
	} else if err == nil {
		err = errors.New("input exceeds limit")
	}
	if err == nil {
		var payload string
		payload, err = run(input)
		if err == nil {
			json.NewEncoder(os.Stdout).Encode(response{Status: "PASS", Payload: payload})
			return
		}
	}
	json.NewEncoder(os.Stdout).Encode(response{Status: "FAIL", Error: err.Error()})
	os.Exit(1)
}
