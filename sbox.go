package cryptoutil

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// used to generate nonces for secretbox
func genNonce() (*[NonceLen]byte, error) {
	nonce := new([NonceLen]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

func Encrypt(key *[KeyLen]byte, data []byte) ([]byte, error) {
	nonce, err := genNonce()
	if err != nil {
		return nil, errors.New("encryption failed")
	}
	out := make([]byte, len(nonce))
	copy(out, nonce[:])
	out = secretbox.Seal(out, data, nonce, key)
	return out, nil
}

// panics if key is nil
func Decrypt(key *[KeyLen]byte, data []byte) ([]byte, error) {
	if len(data) < (NonceLen + secretbox.Overhead) {
		return nil, errors.New("decryption failed")
	}
	var nonce [NonceLen]byte
	copy(nonce[:], data[:NonceLen])
	out, ok := secretbox.Open(nil, data[NonceLen:], &nonce, key)
	if !ok {
		return nil, errors.New("decryption failed")
	}
	return out, nil
}


func (config ScryptConfig) Decrypt(password string, data []byte) ([]byte, error) {
	if len(data) < (SaltLen + NonceLen + secretbox.Overhead) {
		return nil, errors.New("decryption failed")
	}
	salt := data[:SaltLen]
	data = data[SaltLen:]

	key, err := config.Derive(salt, password)
	if err != nil {
		return nil, err
	}

	return Decrypt(key, data)
}

func (config ScryptConfig) Encrypt(password string, data []byte) ([]byte, error) {

	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	key, err := config.Derive(salt, password)
	if err != nil {
		return nil, err
	}

	encryptedData, err := Encrypt(key, data)
	if err != nil {
		return nil, err
	}

	return append(salt, encryptedData...), nil
}