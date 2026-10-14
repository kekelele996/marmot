package auth

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// scrambleSize is the length of a mysql_native_password auth response and of
// the server salt.
const scrambleSize = 20

// PasswordStage2 returns the password digest MySQL stores for
// mysql_native_password accounts: SHA1(SHA1(password)).
func PasswordStage2(password string) []byte {
	stage1 := sha1.Sum([]byte(password))
	stage2 := sha1.Sum(stage1[:])
	return stage2[:]
}

// MySQLPasswordHash renders a stored digest as MySQL's PASSWORD() string:
// "*" followed by 40 uppercase hex chars.
func MySQLPasswordHash(password string) string {
	return "*" + strings.ToUpper(hex.EncodeToString(PasswordStage2(password)))
}

// ParsePasswordHash decodes a configured password hash. Both the MySQL
// PASSWORD() form ("*" + 40 hex chars) and bare 40-char hex are accepted,
// case-insensitively.
func ParsePasswordHash(encoded string) ([]byte, error) {
	s := encoded
	if strings.HasPrefix(s, "*") {
		s = s[1:]
	}
	if len(s) != sha1.Size*2 {
		return nil, fmt.Errorf("password_hash must be %d hex chars optionally prefixed with '*' (got %d chars)", sha1.Size*2, len(s))
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("password_hash is not valid hexadecimal: %w", err)
	}
	return raw, nil
}

// GenerateSalt returns 20 random, non-zero bytes for the
// mysql_native_password handshake challenge. The scramble is null terminated
// on the wire, so a zero byte inside it would truncate it.
func GenerateSalt() [scrambleSize]byte {
	var salt [scrambleSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		// crypto/rand failing is not recoverable; every handshake would be
		// unsafe without it.
		panic(fmt.Sprintf("failed to generate MySQL auth salt: %v", err))
	}
	for i := range salt {
		for salt[i] == 0 {
			b := make([]byte, 1)
			_, _ = rand.Read(b)
			salt[i] = b[0]
		}
	}
	return salt
}

// VerifyNativePassword validates a client's mysql_native_password scramble
// against the stored SHA1(SHA1(password)) digest.
//
// The client sends:
//
//	scramble = SHA1(password) XOR SHA1(salt || SHA1(SHA1(password)))
//
// so the server recovers SHA1(password) by XORing the second term back and
// confirms its SHA1 equals the stored digest. Empty responses never match:
// accounts always carry a password.
func VerifyNativePassword(scramble, salt, stage2 []byte) bool {
	if len(scramble) != scrambleSize || len(salt) < scrambleSize || len(stage2) != sha1.Size {
		return false
	}

	hashed := sha1.New()
	hashed.Write(salt[:scrambleSize])
	hashed.Write(stage2)
	saltDigest := hashed.Sum(nil)

	candidate := make([]byte, scrambleSize)
	for i := 0; i < scrambleSize; i++ {
		candidate[i] = scramble[i] ^ saltDigest[i]
	}
	candidateDigest := sha1.Sum(candidate)
	return subtle.ConstantTimeCompare(candidateDigest[:], stage2) == 1
}
