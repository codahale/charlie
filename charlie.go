// Package charlie provides a fast, safe, stateless mechanism for adding CSRF
// protection to web applications.
//
// Charlie generates per-request tokens, which resist modern web attacks like
// BEAST, BREACH, CRIME, TIME, and Lucky 13, as well as web attacks of the
// future, like CONDOR, BEETLEBUTT, NINJAFACE, and TacoTacoPopNLock
// Quasi-Chunking. In addition, the fact that Charlie tokens are stateless means
// their usage is dramatically simpler than most CSRF countermeasures--simply
// return a token with each response and require a token with each authenticated
// request.
//
// A token is a 32-bit Unix epoch timestamp, concatenated with the
// HMAC-SHA256-128 MAC of both the timestamp and the user's identity (or session
// ID). This is a rapidly changing value, making tokens indistinguishable from
// random data to an attacker performing an online attack.
//
// Generation and validation each take ~4us on modern hardware, and the tokens
// themselves are only 28 bytes long.
package charlie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

var (
	// ErrInvalidToken is returned when the provided token is invalid.
	ErrInvalidToken = errors.New("invalid token")
)

// Params are the parameters used for generating and validating tokens.
type Params struct {
	key   []byte
	timer func() time.Time

	MaxAge time.Duration // MaxAge is the maximum age of tokens.
}

// New returns a new set of parameters given a key.
func New(key []byte) *Params {
	k := make([]byte, len(key))
	copy(k, key)
	return &Params{
		key:    k,
		timer:  time.Now,
		MaxAge: 10 * time.Minute,
	}
}

// Generate returns a new token for the given user.
func (p *Params) Generate(id string) string {
	buf := make([]byte, dataSize, dataSize+macSize)
	binary.BigEndian.PutUint32(buf, uint32(p.timer().Unix()))
	token := append(buf, hmacSHA256(p.key, buf, id)...)
	return base64.URLEncoding.EncodeToString(token)
}

// Validate validates the given token for the given user.
func (p *Params) Validate(id, token string) error {
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return ErrInvalidToken
	}

	mac := data[dataSize:][:macSize]
	data = data[:dataSize]
	if !hmac.Equal(hmacSHA256(p.key, data, id), mac) {
		return ErrInvalidToken
	}

	t := time.Unix(int64(binary.BigEndian.Uint32(data)), 0)
	if p.timer().Sub(t) > p.MaxAge {
		return ErrInvalidToken
	}

	return nil
}

const (
	dataSize = 4 // 32-bit timestamps
	macSize  = 16
)

func hmacSHA256(key, data []byte, id string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	_, _ = h.Write([]byte(id))
	return h.Sum(nil)[:macSize]
}
