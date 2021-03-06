package cryptoplus

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
)

type Crypter struct {
	privateKey *rsa.PrivateKey
	bitSize    int
}

func (c *Crypter) GenerateKeys() error {
	c.bitSize = 2048
	privkey, err := rsa.GenerateKey(rand.Reader, c.bitSize)
	if err != nil {
		return err
	}
	c.privateKey = privkey
	return nil
}

func (c *Crypter) GetPublicKey() []byte {
	return x509.MarshalPKCS1PublicKey(&c.privateKey.PublicKey)
}

func (c *Crypter) Encrypt(publicKeyByte []byte, data []byte) ([]byte, error) {
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyByte)

	if err != nil {
		return nil, err
	}

	sha := sha256.New()
	sha.Write(data)
	aesKey := sha.Sum(nil)
	encryptedAesKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		aesKey,
		nil)

	if err != nil {
		return nil, err
	}

	ci, err := aes.NewCipher(aesKey)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(ci)

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encryptedData := gcm.Seal(nonce, nonce, data, nil)

	allEncyptedData := append(encryptedAesKey, encryptedData...)

	return allEncyptedData, nil
}

func (c *Crypter) Decrypt(data []byte) ([]byte, error) {
	if len(data) < c.bitSize/8 {
		return nil, errors.New("can not split data")
	}
	encryptedAesKey := data[:c.bitSize/8]
	encryptedData := data[c.bitSize/8:]

	aesKey, err := c.privateKey.Decrypt(nil, encryptedAesKey, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}

	ci, err := aes.NewCipher(aesKey)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(ci)

	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	if len(encryptedData) < nonceSize {
		return nil, errors.New("len(encryptedData) < nonceSize")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return nil, err
	}

	sha := sha256.New()
	sha.Write(decryptedData)
	dataSha := sha.Sum(nil)

	for i := 0; i < 32; i += 1 {
		if aesKey[i] != dataSha[i] {
			return []byte{}, errors.New("incorrect data")
		}
	}

	return decryptedData, nil
}
