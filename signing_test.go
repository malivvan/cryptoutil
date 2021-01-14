package cryptoutil

import (
	"bytes"
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp/packet"
	"testing"
)

func TestIntegrity(t *testing.T) {

	// create identity, save and load
	e, err := CreateEntity("name", "comment", "name@example.org")
	assert.NoError(t, err)
	savedI, err := e.PrivateKey()
	assert.NoError(t, err)
	loadedI, err := LoadEntity(savedI)
	assert.NoError(t, err)

	// assert equal private key
	priv := e.PGP.PrivateKey.PrivateKey.(*rsa.PrivateKey)
	loadedPriv := loadedI.PGP.PrivateKey.PrivateKey.(*rsa.PrivateKey)
	assert.True(t, equalRSAPrivateKey(priv, loadedPriv))

	// get identitiy
	key := "name (comment) <name@example.org>"
	identity := e.PGP.Identities[key]
	loadedIdentity := loadedI.PGP.Identities[key]

	// compare basic fields
	assert.Equal(t, identity.Name, loadedIdentity.Name)
	assert.Equal(t, identity.UserId, loadedIdentity.UserId)

	// compare self signature
	assert.Equal(t, identity.SelfSignature.SigType, loadedIdentity.SelfSignature.SigType)
	assert.Equal(t, packet.SignatureType(packet.SigTypePositiveCert), identity.SelfSignature.SigType)
	assert.Equal(t, identity.SelfSignature.PubKeyAlgo, loadedIdentity.SelfSignature.PubKeyAlgo)
	assert.Equal(t, packet.PublicKeyAlgorithm(packet.PubKeyAlgoRSA), identity.SelfSignature.PubKeyAlgo)

	assert.Equal(t, identity.SelfSignature.Hash, loadedIdentity.SelfSignature.Hash)
	assert.Equal(t, identity.SelfSignature.HashSuffix, loadedIdentity.SelfSignature.HashSuffix)
	assert.Equal(t, identity.SelfSignature.HashTag, loadedIdentity.SelfSignature.HashTag)

	assert.Equal(t, identity.SelfSignature.RSASignature, loadedIdentity.SelfSignature.RSASignature)
	assert.Equal(t, identity.SelfSignature.DSASigR, loadedIdentity.SelfSignature.DSASigR)
	assert.Equal(t, identity.SelfSignature.DSASigS, loadedIdentity.SelfSignature.DSASigS)
	assert.Equal(t, identity.SelfSignature.ECDSASigR, loadedIdentity.SelfSignature.ECDSASigR)
	assert.Equal(t, identity.SelfSignature.ECDSASigS, loadedIdentity.SelfSignature.ECDSASigS)

	assert.Equal(t, identity.SelfSignature.SigLifetimeSecs, loadedIdentity.SelfSignature.SigLifetimeSecs)
	assert.Nil(t, loadedIdentity.SelfSignature.SigLifetimeSecs)
	assert.Equal(t, identity.SelfSignature.KeyLifetimeSecs, loadedIdentity.SelfSignature.KeyLifetimeSecs)
	assert.Nil(t, loadedIdentity.SelfSignature.KeyLifetimeSecs)
	assert.Equal(t, identity.SelfSignature.PreferredSymmetric, loadedIdentity.SelfSignature.PreferredSymmetric)
	assert.Equal(t, []uint8([]byte{0x09}), loadedIdentity.SelfSignature.PreferredSymmetric) // AES with 256-bit key
	assert.Equal(t, identity.SelfSignature.PreferredHash, loadedIdentity.SelfSignature.PreferredHash)
	assert.Equal(t, []uint8([]byte{0x08}), loadedIdentity.SelfSignature.PreferredHash) // SHA256
	assert.Equal(t, identity.SelfSignature.PreferredCompression, loadedIdentity.SelfSignature.PreferredCompression)
	assert.Nil(t, loadedIdentity.SelfSignature.PreferredCompression)
	assert.Equal(t, identity.SelfSignature.IssuerKeyId, loadedIdentity.SelfSignature.IssuerKeyId)
	assert.Equal(t, identity.SelfSignature.IsPrimaryId, loadedIdentity.SelfSignature.IsPrimaryId)

	assert.Equal(t, identity.SelfSignature.FlagCertify, loadedIdentity.SelfSignature.FlagCertify)
	assert.Equal(t, identity.SelfSignature.FlagEncryptStorage, loadedIdentity.SelfSignature.FlagEncryptStorage)
	assert.Equal(t, identity.SelfSignature.FlagEncryptCommunications, loadedIdentity.SelfSignature.FlagEncryptCommunications)
	assert.Equal(t, identity.SelfSignature.FlagSign, loadedIdentity.SelfSignature.FlagSign)
	assert.Equal(t, identity.SelfSignature.FlagsValid, loadedIdentity.SelfSignature.FlagsValid)

	assert.Equal(t, identity.SelfSignature.RevocationReason, loadedIdentity.SelfSignature.RevocationReason)
	assert.Nil(t, loadedIdentity.SelfSignature.RevocationReason)
	assert.Equal(t, identity.SelfSignature.RevocationReasonText, loadedIdentity.SelfSignature.RevocationReasonText)
	assert.Equal(t, "", loadedIdentity.SelfSignature.RevocationReasonText)

	assert.Equal(t, identity.SelfSignature.MDC, loadedIdentity.SelfSignature.MDC)

	assert.Equal(t, identity.SelfSignature.EmbeddedSignature, loadedIdentity.SelfSignature.EmbeddedSignature)
	assert.Nil(t, loadedIdentity.SelfSignature.EmbeddedSignature)
}

func equalRSAPrivateKey(priv *rsa.PrivateKey, priv2 *rsa.PrivateKey) bool {
	if !priv.PublicKey.Equal(&priv2.PublicKey) || priv.D.Cmp(priv2.D) != 0 {
		return false
	}
	if len(priv.Primes) != len(priv2.Primes) {
		return false
	}
	pcnt := len(priv.Primes)
	for _, prime1 := range priv.Primes {
		for _, prime2 := range priv2.Primes {
			if prime1.Cmp(prime2) == 0 {
				pcnt--
				break
			}
		}
	}
	if pcnt != 0 {
		return false
	}
	return true
}


func TestSignVerify(t *testing.T) {
	e, err := CreateEntity("name", "comment", "name@example.org")
	assert.NoError(t, err)

	s, err := e.Sign(bytes.NewBufferString("hello world"))
	assert.NoError(t, err)

	pubBytes, err := e.PublicKey()
	assert.NoError(t, err)
	pub, err := LoadPublicKey(pubBytes)
	assert.NoError(t, err)

	assert.NoError(t, e.Verify(bytes.NewBufferString("hello world"), s))
	assert.NoError(t, pub.Verify(bytes.NewBufferString("hello world"), s))

	assert.Error(t, e.Verify(bytes.NewBufferString("hello world!"), s))
	assert.Error(t, pub.Verify(bytes.NewBufferString("hello world!"), s))
}