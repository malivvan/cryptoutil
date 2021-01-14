package cryptoutil

import (
	"bytes"
	"crypto"
	"errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"io"
)

var pgpConfig = &packet.Config{
	DefaultHash:   crypto.SHA256,
	DefaultCipher: packet.CipherAES256,
	CompressionConfig: &packet.CompressionConfig{
		Level: packet.BestCompression,
	},
	RSABits:                4096,
	DefaultCompressionAlgo: packet.CompressionZIP,
}

type Entity struct {
	entity *openpgp.Entity
}

func (e *Entity) PGP() *openpgp.Entity{
	return e.entity
}

func CreateEntity(name, comment, email string) (*Entity, error) {
	entity, err := openpgp.NewEntity(name, comment, email, pgpConfig)
	if err != nil {
		return nil, err
	}
	for _, id := range entity.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, pgpConfig)
		if err != nil {
			return nil, err
		}
	}
	return &Entity{entity: entity}, nil
}

func LoadEntity(b []byte) (*Entity, error) {
	r, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	if len(r) != 1 {
		return nil, errors.New("only entities with a single identity are supported")
	}
	return &Entity{entity: r[0]}, nil
}

func (e *Entity) PrivateKey() ([]byte, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	err = e.entity.SerializePrivate(w, pgpConfig)
	if err != nil {
		return nil, err
	}
	w.Close()
	return buf.Bytes(), nil
}

func (e *Entity) UserID() *packet.UserId {
	for _, id := range e.entity.Identities {
		return id.UserId
	}
	return nil
}

func (e *Entity) PublicKey() ([]byte, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	err = e.entity.Serialize(w)
	if err != nil {
		return nil, err
	}
	w.Close()
	return buf.Bytes(), nil
}

func (e *Entity) Sign(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	err := openpgp.ArmoredDetachSign(&buf, e.entity, r, pgpConfig)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *Entity) Encrypt(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	err := openpgp.ArmoredDetachSign(&buf, e.entity, r, pgpConfig)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *Entity) Verify(r io.Reader, signature []byte) error {
	sig, err := decodeSignature(signature)
	if err != nil {
		return err
	}
	hash := sig.Hash.New()
	_, err = io.Copy(hash, r)
	if err != nil {
		return err
	}
	err = e.entity.PrimaryKey.VerifySignature(hash, sig)
	if err != nil {
		return err
	}
	return nil
}

type PublicKey struct {
	key *packet.PublicKey
}

func LoadPublicKey(b []byte) (*PublicKey, error) {
	block, err := armor.Decode(bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	if block.Type != openpgp.PublicKeyType {
		return nil, errors.New("Invalid private key file")
	}
	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, err
	}
	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, errors.New("Invalid public key")
	}
	return &PublicKey{key: key}, nil
}

func (pub *PublicKey) Verify(r io.Reader, signature []byte) error {
	sig, err := decodeSignature(signature)
	if err != nil {
		return err
	}
	hash := sig.Hash.New()
	_, err = io.Copy(hash, r)
	if err != nil {
		return err
	}
	err = pub.key.VerifySignature(hash, sig)
	if err != nil {
		return err
	}
	return nil
}

func decodeSignature(signature []byte) (*packet.Signature, error) {

	buf := bytes.NewBuffer(signature)
	block, err := armor.Decode(buf)
	if err != nil {
		return nil, err
	}
	if block.Type != openpgp.SignatureType {
		return nil, errors.New("Invalid signature file")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, err
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		return nil, errors.New("Invalid signature")
	}
	return sig, nil
}
