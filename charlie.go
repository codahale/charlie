// Package charlie provides a fast, safe, stateless mechanism for adding CSRF
// protection to web applications.
//
// Charlie generates per-request tokens (Unix timestamps encrypted with AES-GCM),
// which resist modern web attacks like BEAST, BREACH, CRIME, TIME, and Lucky 13.
// Tokens are checked for integrity, decrypted, and their timestamps checked for
// freshness. Generation and validation each take ~2us on modern hardware.
package charlie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

var (
	// ErrInvalidToken is returned when the provided token is invalid.
	ErrInvalidToken = errors.New("charlie: invalid token")
)

// TokenParams are the parameters used for generating and validating tokens.
type TokenParams struct {
	aead   cipher.AEAD
	MaxAge time.Duration // MaxAge is the maximum age of tokens.
}

// New returns a new set of parameters given a valid AES key. The key must be
// 128, 192, or 256 bits long.
func New(key []byte) (*TokenParams, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, _ := cipher.NewGCM(block) // AES-GCM works just fine, ignoring this.
	return &TokenParams{
		aead:   aead,
		MaxAge: 10 * time.Minute,
	}, nil
}

// Generate returns a new token for the given user.
func (p *TokenParams) Generate(id string) (string, error) {
	nonce := make([]byte, p.aead.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}
	data := make([]byte, dataSize)
	binary.BigEndian.PutUint32(data, uint32(timer().Unix()))
	token := p.aead.Seal(nonce, nonce, data, []byte(id))
	return base64.URLEncoding.EncodeToString(token), nil
}

// Validate validates the given token for the given user.
func (p *TokenParams) Validate(id, token string) error {
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return ErrInvalidToken
	}

	nonce := data[0:p.aead.NonceSize()]
	data = data[p.aead.NonceSize():]
	b, err := p.aead.Open(nil, nonce, data, []byte(id))
	if err != nil {
		return ErrInvalidToken
	}

	t := time.Unix(int64(binary.BigEndian.Uint32(b)), 0)
	if timer().Sub(t) > p.MaxAge {
		return ErrInvalidToken
	}
	return nil
}

var (
	timer = time.Now // used by tests
)

const (
	dataSize = 4 // 32-bit timestamps
)
