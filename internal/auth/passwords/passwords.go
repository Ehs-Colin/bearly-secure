package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength = 128

	currentArgon2Version = argon2.Version
	argon2Memory         = 19 * 1024
	iterations           = 2
	threads              = 1
	saltLength           = 16
	argon2KeyLength      = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		argon2Memory,
		threads,
		argon2KeyLength,
	)

	return encodeArgon2idHash(argon2idHash{
		version:     currentArgon2Version,
		memoryKiB:   argon2Memory,
		iterations:  iterations,
		parallelism: threads,
		salt:        salt,
		derivedKey:  derivedKey,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	legacyHash, ok := decodeLegacyHash(encodedHash)
	if ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], legacyHash) == 1
	}
	storedHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	if storedHash.version != currentArgon2Version {
		return false
	}
	candidateHash := argon2.IDKey(
		[]byte(password),
		storedHash.salt,
		storedHash.iterations,
		storedHash.memoryKiB,
		storedHash.parallelism,
		uint32(len(storedHash.derivedKey)),
	)
	return subtle.ConstantTimeCompare(candidateHash, storedHash.derivedKey) == 1
}

func NeedsRehash(string) bool {
	return false
}
