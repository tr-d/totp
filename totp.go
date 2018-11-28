// Package totp is an implementation of Time-Based One-Time Passwords as
// described in IETF RFC 6238. See https://tools.ietf.org/html/rfc6238
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"time"
)

// Generator holds the state to calculate Time-Based One-Time Passwords as
// described in IETF RFC 6238. See https://tools.ietf.org/html/rfc6238
type Generator struct {
	key []byte
	t0  time.Time
	tx  time.Duration
	f   func() hash.Hash
}

// NewSha1 returns a Generator using the provided key, Sha1 hashes, a start time
// at the Unix epoch and a time step of 30 seconds.
func NewSha1(key []byte) Generator {
	return Totp{
		key: key,
		t0:  time.Unix(0, 0),
		tx:  30 * time.Second,
		f:   sha1.New,
	}
}

// NewSha256 returns a Generator using the provided key, Sha256 hashes, a start
// time at the Unix epoch and a time step of 30 seconds.
func NewSha256(key []byte) Generator {
	return Totp{
		key: key,
		t0:  time.Unix(0, 0),
		tx:  30 * time.Second,
		f:   sha256.New,
	}
}

// NewSha512 returns a Generator using the provided key, Sha512 hashes, a start
// time at the Unix epoch and a time step of 30 seconds.
func NewSha512(key []byte) Generator {
	return Totp{
		key: key,
		t0:  time.Unix(0, 0),
		tx:  30 * time.Second,
		f:   sha512.New,
	}
}

// At returns the value of the one-time password at the time t.
func (g Generator) At(t time.Time) string {
	// calculate the time step
	ct := t.Sub(g.t0).Nanoseconds() / g.tx.Nanoseconds()
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(ct))

	// calculate the hash
	h := hmac.New(g.f, g.key)
	h.Write(b)
	c := h.Sum(nil)

	// apply a window to select 4 bytes
	i := c[len(c)-1] & 0xf
	u := binary.BigEndian.Uint32(c[i : i+5])

	// calculate the final value
	p := (u & 0x7fffffff) % 1e6

	return fmt.Sprintf("%06d", p)
}

// In returns the value of the one-time password after the duration d.
func (g Generator) In(d time.Duration) string {
	return g.At(time.Now().Add(d))
}

// Now returns the value of the one-time password at the time of calling.
func (g Generator) Now() string {
	return g.At(time.Now())
}
