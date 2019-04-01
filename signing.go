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

type Identity struct {
	Entity *openpgp.Entity
}

func LoadIdentity(b []byte) (*Identity, error) {
	r, err := openpgp.ReadKeyRing(bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	if len(r) != 1 {
		return nil, errors.New("only identities with a single Entity are supported")
	}

	return &Identity{Entity: r[0]}, nil
}

func CreateIdentity(name, comment, email string) (*Identity, error) {

	e, err := openpgp.NewEntity(name, comment, email, pgpConfig)
	if err != nil {
		return nil, err
	}

	for _, id := range e.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, pgpConfig)
		if err != nil {
			return nil, err
		}
	}

	return &Identity{Entity: e}, nil
}


func (i *Identity) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := i.Entity.SerializePrivate(buf, pgpConfig)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (i *Identity) UserID() *packet.UserId {
	for _, id := range i.Entity.Identities {
		return id.UserId
	}
	return nil
}

func (i *Identity) PublicKey() ([]byte, error) {
	var buf bytes.Buffer

	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}
	defer w.Close()

	err = i.Entity.Serialize(w)
	if err != nil {
		return nil, err
	}

	w.Close()
	return  buf.Bytes(), nil
}

func (i *Identity) Sign(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	err := openpgp.ArmoredDetachSign(&buf, i.Entity, r, pgpConfig)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (i *Identity) Verify(r io.Reader, signature []byte) error {
	sig, err := decodeSignature(signature)
	if err != nil {
		return err
	}

	hash := sig.Hash.New()
	_, err = io.Copy(hash, r)
	if err != nil {
		return err
	}

	err = i.Entity.PrimaryKey.VerifySignature(hash, sig)
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
