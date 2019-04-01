package cryptoutil

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/scrypt"
	"io"
	"strconv"
	"time"
)

const (
	SaltLen   = 32
	KeyLen    = 32
	NonceLen  = 24
	ScryptLen = 24
)

func (config ScryptConfig) String() string {
	return "N=" + strconv.FormatUint(config.N, 10) + " R=" + strconv.FormatUint(config.R, 10) + " P=" + strconv.FormatUint(config.P, 10) + " (" + strconv.Itoa(config.MemoryRequiredMB()) + "MB required)"
}

// ScryptConfigRealtime requires 32MB RAM for under a second (i7).
var ScryptConfigRealtime = ScryptConfig{
	N: 1 << uint64(15),
	R: 8,
	P: 1,
}

// ScryptConfigLow requires 128MB RAM for about a second (i7).
var ScryptConfigLow = ScryptConfig{
	N: 1 << uint64(17),
	R: 8,
	P: 1,
}

// ScryptConfigMid requires 256MB RAM for less than 5 seconds (i7).
var ScryptConfigMid = ScryptConfig{
	N: 1 << uint64(18),
	R: 8,
	P: 1,
}

// ScryptConfigHigh requires 512MB RAM for less than 5 seconds (i7).
var ScryptConfigHigh = ScryptConfig{
	N: 1 << uint64(19),
	R: 8,
	P: 1,
}

// ScryptConfigParanoid requires 1GB RAM for about 5 seconds (i7).
var ScryptConfigParanoid = ScryptConfig{
	N: 1 << uint64(20),
	R: 8,
	P: 1,
}

type ScryptConfig struct {
	// CPU/memory cost parameter (logN)
	N uint64 `json:"n"`

	// block size parameter (octets)
	R uint64 `json:"r"`

	// parallelisation parameter (positive int)
	P uint64 `json:"p"`
}

type configAndSalt struct {
	config ScryptConfig
	salt   []byte
}

func DecodeScryptConfig(data []byte) (ScryptConfig, error) {
	if len(data) != ScryptLen {
		return ScryptConfig{}, errors.New("wrong scrypt config length")
	}
	return ScryptConfig{
		N: binary.LittleEndian.Uint64(data[0:8]),
		R: binary.LittleEndian.Uint64(data[8:16]),
		P: binary.LittleEndian.Uint64(data[16:24]),
	}, nil
}

func (config ScryptConfig) Encode() []byte {
	var data [ScryptLen]byte
	binary.LittleEndian.PutUint64(data[0:8], config.N)
	binary.LittleEndian.PutUint64(data[8:16], config.R)
	binary.LittleEndian.PutUint64(data[16:24], config.P)
	return data[:]
}

func (config ScryptConfig) MemoryRequiredMB() int {
	return (int(config.N) * int(config.R) * 128) / 1024 / 1024
}

func (config ScryptConfig) TimeRequiredMS() (int, error) {
	t := time.Now()
	salt, err := GenerateSalt()
	if err != nil {
		return -1, err
	}
	_, err = config.Derive(salt, "selftest")
	if err != nil {
		return -1, err
	}
	return int(time.Now().Sub(t) / time.Millisecond), nil
}

func (config ScryptConfig) Derive(salt []byte, password string) (*[KeyLen]byte, error) {
	b, err := scrypt.Key([]byte(password), salt, int(config.N), int(config.R), int(config.P), KeyLen)
	if err != nil {
		return nil, err
	}
	if len(b) != KeyLen {
		return nil, errors.New("derived key has wrong length")
	}

	var key [KeyLen]byte
	for i := range key {
		key[i] = b[i]
		b[i] = 0
	}

	return &key, nil
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	_, err := io.ReadFull(rand.Reader, salt[:])
	if err != nil {
		return nil, errors.New("error creating salt")
	}
	return salt[:], nil
}
