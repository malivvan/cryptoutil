package cryptoutil

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

var testSecret = [32]byte{170, 122, 87, 46, 32, 152, 236, 67, 199, 193, 53, 73, 208, 63, 68, 64, 15, 95, 106, 70, 171, 226, 53, 86, 80, 97, 73, 75, 22, 187, 253, 114}


func TestNonce(t *testing.T) {
	nonce, err := genNonce()
	if err != nil {
		t.Fatal(err)
	}
	var zero [NonceLen]byte
	if bytes.Equal(zero[:], nonce[:]) {
		t.Fatal("nonce is zero after creation")
	}
}

func BenchmarkNonce(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		genNonce()
	}
}

func BenchmarkSboxEncrypt(b *testing.B) {
	var plain [64]byte
	_, err := io.ReadFull(rand.Reader, plain[:])
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(&testSecret, plain[:])
	}
}

func BenchmarkSboxDecrypt(b *testing.B) {
	var plain [64]byte
	_, err := io.ReadFull(rand.Reader, plain[:])
	if err != nil {
		b.Fatal(err)
	}
	data, err := Encrypt(&testSecret, plain[:])
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(&testSecret, data)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	var secret [32]byte
	_, err := io.ReadFull(rand.Reader, secret[:])
	if err != nil {
		t.Fatal(err)
	}
	var message [256]byte
	_, err = io.ReadFull(rand.Reader, message[:])
	if err != nil {
		t.Fatal(err)
	}
	enc, err := Encrypt(&secret, message[:])
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decrypt(&secret, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message[:], dec) {
		t.Fatal("decrypted message does not match original message")
	}
}
