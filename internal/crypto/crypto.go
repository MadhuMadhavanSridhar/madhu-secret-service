// Package crypto holds every key-handling primitive of the service.
//
// Key material layout (see DESIGN.md):
//
//	share token  = 32 random bytes, base64url, lives only in the URL
//	lookup id    = HKDF(token, info="lookup")           -> Redis key, one-way
//	content key  = HKDF(ikm=token, salt=KEK, info="key") -> AES-256-GCM, used once
//	KEK          = 32 random bytes generated in process memory at start
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	TokenBytes  = 32
	LookupBytes = 16
	KeyBytes    = 32
	SaltBytes   = 16
	nonceBytes  = 12

	// Argon2id parameters for passphrase verification. 16 MiB, two passes.
	argonTime    = 2
	argonMemory  = 16 * 1024
	argonThreads = 1
)

var (
	enc = base64.RawURLEncoding

	// ErrBadCiphertext is returned when decryption fails (wrong key or tampering).
	ErrBadCiphertext = errors.New("ciphertext authentication failed")

	// DummySalt keeps the not-found path doing the same Argon2 work as a real
	// passphrase check, so request shape alone decides latency.
	DummySalt = []byte("ots-dummy-salt-0")
)

// KEK is the in-process key-encryption key. It is never serialised.
type KEK struct {
	b  [KeyBytes]byte
	fp string
}

// NewKEK generates a fresh random KEK. crypto/rand never fails on supported
// platforms; the runtime aborts the process if the OS source is unavailable.
func NewKEK() *KEK {
	k := &KEK{}
	rand.Read(k.b[:])
	k.fp = k.fingerprint()
	return k
}

// KEKFromBytes builds a KEK from caller-supplied bytes (tests only).
func KEKFromBytes(b []byte) *KEK {
	k := &KEK{}
	copy(k.b[:], b)
	k.fp = k.fingerprint()
	return k
}

func (k *KEK) fingerprint() string {
	sum := sha256.Sum256(append([]byte("ots/kek-fp/v1"), k.b[:]...))
	return hex.EncodeToString(sum[:4])
}

// Fingerprint is a short public identifier for this KEK, used to namespace
// records so a restarted process never tries to open records it cannot.
func (k *KEK) Fingerprint() string { return k.fp }

// NewToken returns a fresh share token (43 base64url characters, 256 bits).
func NewToken() string { return randomB64(TokenBytes) }

// NewDeletionToken returns a fresh deletion token (43 base64url characters).
func NewDeletionToken() string { return randomB64(TokenBytes) }

func randomB64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return enc.EncodeToString(b)
}

// HashDeletionToken returns the hex SHA-256 of a deletion token. Only the hash
// is stored.
func HashDeletionToken(t string) string {
	sum := sha256.Sum256([]byte("ots/deletion/v1" + t))
	return hex.EncodeToString(sum[:])
}

// Derive maps an id string from the URL to its lookup id (hex) and content key.
//
// Any string is accepted: a well-formed token is decoded to its 32 bytes, and
// anything else is used as raw bytes. That keeps the work identical for
// malformed, unknown and real ids, which matters for the timing requirement.
func Derive(kek *KEK, id string) (lookupHex string, key []byte) {
	ikm := []byte(id)
	if len(id) == 43 {
		if raw, err := enc.DecodeString(id); err == nil && len(raw) == TokenBytes {
			ikm = raw
		}
	}
	lookup, err := hkdf.Key(sha256.New, ikm, nil, "ots/lookup/v1", LookupBytes)
	if err != nil {
		panic(err) // fixed-size outputs from SHA-256 HKDF cannot fail
	}
	key, err = hkdf.Key(sha256.New, ikm, kek.b[:], "ots/key/v1", KeyBytes)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(lookup), key
}

// Seal encrypts plaintext under key with AES-256-GCM. The lookup id is bound
// as associated data so a ciphertext cannot be moved between records.
// Output is nonce || ciphertext.
func Seal(key []byte, lookupHex string, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, nonceBytes, nonceBytes+len(plaintext)+aead.Overhead())
	rand.Read(out)
	return aead.Seal(out, out[:nonceBytes], plaintext, []byte(lookupHex)), nil
}

// Open decrypts nonce || ciphertext produced by Seal.
func Open(key []byte, lookupHex string, blob []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < nonceBytes {
		return nil, ErrBadCiphertext
	}
	pt, err := aead.Open(nil, blob[:nonceBytes], blob[nonceBytes:], []byte(lookupHex))
	if err != nil {
		return nil, ErrBadCiphertext
	}
	return pt, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewSalt returns a random per-secret passphrase salt.
func NewSalt() []byte {
	s := make([]byte, SaltBytes)
	rand.Read(s)
	return s
}

// PassVerifier derives the stored passphrase verifier:
// HMAC-SHA256(contentKey, Argon2id(passphrase, salt)).
//
// The HMAC key only exists in the URL, so a dump of salt and verifier gives an
// attacker nothing to crack offline.
func PassVerifier(key, salt, passphrase []byte) []byte {
	stretched := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, KeyBytes)
	mac := hmac.New(sha256.New, key)
	mac.Write(stretched)
	clear(stretched)
	return mac.Sum(nil)
}

// Equal is a constant-time comparison.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Zero overwrites a buffer. Best effort in a garbage-collected language.
func Zero(b []byte) { clear(b) }
