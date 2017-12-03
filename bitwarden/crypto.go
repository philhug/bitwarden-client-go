package bitwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/andreburgaud/crypt2go/padding"
	"golang.org/x/crypto/pbkdf2"
)

type CipherString struct {
	encryptedString      string
	encryptionType       int
	decryptedValue       string
	cipherText           string
	initializationVector string
	mac                  string
}

type CryptoKey struct {
	EncKey         []byte
	MacKey         []byte
	EncryptionType int
}

const (
	AesCbc256_B64                     = iota
	AesCbc128_HmacSha256_B64          = iota
	AesCbc256_HmacSha256_B64          = iota
	Rsa2048_OaepSha256_B64            = iota
	Rsa2048_OaepSha1_B64              = iota
	Rsa2048_OaepSha256_HmacSha256_B64 = iota
	Rsa2048_OaepSha1_HmacSha256_B64   = iota
)

func NewCryptoKey(key []byte, encryptionType int) (CryptoKey, error) {
	c := CryptoKey{EncryptionType: encryptionType}

	switch encryptionType {
	case AesCbc256_B64:
		c.EncKey = key
	case AesCbc256_HmacSha256_B64:
		c.EncKey = key[:32]
		c.MacKey = key[32:]
	default:
		return c, fmt.Errorf("Invalid encryption type: %d", encryptionType)
	}

	if len(key) != (len(c.EncKey) + len(c.MacKey)) {
		return c, fmt.Errorf("Invalid key size: %d", len(key))
	}

	return c, nil
}

func NewCipherString(encryptedString string) (*CipherString, error) {
	cs := CipherString{}
	cs.encryptedString = encryptedString
	if encryptedString == "" {
		return nil, errors.New("empty key")
	}
	headerPieces := strings.Split(cs.encryptedString, ".")
	var encPieces []string
	if len(headerPieces) == 2 {
		cs.encryptionType, _ = strconv.Atoi(headerPieces[0])
		encPieces = strings.Split(headerPieces[1], "|")
	} else {
		return nil, errors.New("invalid key header")
	}

	switch cs.encryptionType {
	case AesCbc256_B64:
		if len(encPieces) != 2 {
			return nil, fmt.Errorf("invalid key body len %d", len(encPieces))
		}
		cs.initializationVector = encPieces[0]
		cs.cipherText = encPieces[1]
	case AesCbc256_HmacSha256_B64:
		if len(encPieces) != 3 {
			return nil, fmt.Errorf("invalid key body len %d", len(encPieces))
		}
		cs.initializationVector = encPieces[0]
		cs.cipherText = encPieces[1]
		cs.mac = encPieces[2]
	default:
		return nil, errors.New("unknown algorithm")
	}
	return &cs, nil
}

func NewCipherStringRaw(encryptionType int, ct string, iv string, mac string) (*CipherString, error) {
	cs := CipherString{encryptionType: encryptionType, cipherText: ct, initializationVector: iv, mac: mac}
	return &cs, nil
}

func (cs *CipherString) ToString() string {
	s := cs.initializationVector + "|" + cs.cipherText
	if cs.mac != "" {
		s = s + "|" + cs.mac
	}
	return fmt.Sprintf("%d.%s", cs.encryptionType, s)
}

func (cs *CipherString) DecryptKey(key CryptoKey, encryptionType int) (CryptoKey, error) {
	kb, err := cs.Decrypt(key)
	if err != nil {
		return CryptoKey{}, err
	}
	k, err := NewCryptoKey(kb, encryptionType)
	return k, err
}

func (cs *CipherString) Decrypt(key CryptoKey) ([]byte, error) {
	iv, err := base64.StdEncoding.DecodeString(cs.initializationVector)
	if err != nil {
		return nil, err
	}

	ct, err := base64.StdEncoding.DecodeString(cs.cipherText)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key.EncKey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	if cs.mac != "" {
		mac := hmac.New(sha256.New, key.MacKey)
		mac.Write(iv)
		mac.Write(ct)
		ms := mac.Sum(nil)
		if base64.StdEncoding.EncodeToString(ms) != cs.mac {
			return ct, fmt.Errorf("MAC doesn't match %s %s", cs.mac, base64.StdEncoding.EncodeToString(ms))
		}
	}

	mode.CryptBlocks(ct, ct)

	ct, err = padding.NewPkcs7Padding(16).Unpad(ct) //TODO, configurable size
	return ct, err
}

func Encrypt(pt []byte, key CryptoKey) (*CipherString, error) {
	block, err := aes.NewCipher(key.EncKey)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure.
	iv := make([]byte, aes.BlockSize)

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	pt, _ = padding.NewPkcs7Padding(16).Pad(pt) //TODO, configurable size
	ct := make([]byte, len(pt))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, pt)

	cs := CipherString{encryptionType: key.EncryptionType, cipherText: base64.StdEncoding.EncodeToString(ct), initializationVector: base64.StdEncoding.EncodeToString(iv)}

	if len(key.MacKey) > 0 {
		mac := hmac.New(sha256.New, key.MacKey)
		mac.Write(iv)
		mac.Write(ct)
		cs.mac = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	return &cs, nil
}

func MakeEncKey(key []byte) (*CipherString, error) {
	b := make([]byte, 512/8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	k, err := NewCryptoKey(key, AesCbc256_HmacSha256_B64)
	if err != nil {
		return nil, err
	}
	return Encrypt(b, k)

}

func MakeKey(password string, salt string) CryptoKey {
	dk := pbkdf2.Key([]byte(password), []byte(salt), 5000, 256/8, sha256.New)
	k := CryptoKey{EncKey: dk, EncryptionType: AesCbc256_B64}
	return k
}

func HashPassword(password string, key CryptoKey) string {
	hash := pbkdf2.Key(key.EncKey, []byte(password), 1, 256/8, sha256.New)
	return base64.StdEncoding.EncodeToString(hash)
}
