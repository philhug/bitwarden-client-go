package bitwarden

import (
	"fmt"
	"log"
	"reflect"
)

func internalDecrypt(v reflect.Value, mk CryptoKey) error {

	switch v.Kind() {
	case reflect.Ptr:
		v := v.Elem()

		// Check if the pointer is nil
		if !v.IsValid() {
			return nil
		}
		err := internalDecrypt(v, mk)
		if err != nil {
			v.SetPointer(nil)
		}

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			err := internalDecrypt(v.Field(i), mk)
			if err != nil {
				return err
			}
		}
	case reflect.Int:
		return nil
	case reflect.String:
		s, err := DecryptString(v.String(), mk)
		if err != nil {
			return err
		}
		v.SetString(s)
	case reflect.Slice:
		for i := 0; i < v.Len(); i += 1 {
			err := internalDecrypt(v.Index(i), mk)
			if err != nil {
				return err
			}
		}
	default:
		log.Fatalf("Error, unknown type: %d", v.Kind())
	}
	return nil
}

func internalEncrypt(v reflect.Value, mk CryptoKey) error {

	switch v.Kind() {
	case reflect.Ptr:
		nv := v.Elem()

		// Check if the pointer is nil
		if !nv.IsValid() {
			return nil
		}
		err := internalEncrypt(nv, mk)
		if err != nil {
			invalid := (*string)(nil)
			t := reflect.TypeOf(invalid)

			v.Set(reflect.Indirect(reflect.New(t)))
		}
		return nil
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			err := internalEncrypt(v.Field(i), mk)
			if err != nil {
				return err
			}
		}
	case reflect.Int:
		return nil
	case reflect.String:
		s, err := EncryptString(v.String(), mk)
		if err != nil {
			return err
		}
		v.SetString(s)
	case reflect.Slice:
		for i := 0; i < v.Len(); i += 1 {
			err := internalEncrypt(v.Index(i), mk)
			if err != nil {
				return err
			}
		}
	default:
		log.Fatalf("Error, unknown type: %d", v.Kind())
	}
	return nil
}

func decrypt(data interface{}, mk CryptoKey) error {
	return internalDecrypt(reflect.ValueOf(data), mk)
}

func encrypt(data interface{}, mk CryptoKey) error {
	return internalEncrypt(reflect.ValueOf(data), mk)
}

func (c *Cipher) Decrypt(mk CryptoKey) error {
	var err error

	switch c.Type {
	case CipherType_Login:
		err = decrypt(&c.Login, mk)
	case CipherType_Card:
		err = decrypt(&c.Card, mk)
	case CipherType_Identity:
		err = decrypt(&c.Identity, mk)
	case CipherType_SecureNote:
		err = decrypt(&c.SecureNote, mk)
	default:
		log.Fatal("invalid cipher type")
	}
	return err
}

func (c *Cipher) Encrypt(mk CryptoKey) error {
	var err error

	switch c.Type {
	case CipherType_Login:
		err = encrypt(&c.Login, mk)
	case CipherType_Card:
		err = encrypt(&c.Card, mk)
	case CipherType_Identity:
		err = encrypt(&c.Identity, mk)
	case CipherType_SecureNote:
		err = encrypt(&c.SecureNote, mk)
	default:
		log.Fatal("invalid cipher type")
	}
	return err
}

func (f *Folder) Decrypt(mk CryptoKey) error {
	var err error
	f.Name, err = DecryptString(f.Name, mk)
	return err
}

func (f *Folder) Encrypt(mk CryptoKey) error {
	var err error
	f.Name, err = EncryptString(f.Name, mk)
	return err
}

func (l List) Decrypt(mk []byte) error {
	x, ok := (l.Data).([]Decryptable)
	if !ok {
		log.Fatal("object doesn't implement Decryptable")
	}
	for i, d := range x {
		err := d.Decrypt(mk)
		x[i] = d
		if err != nil {
			log.Fatal(err)
		}
	}
	return nil
}

type Decryptable interface {
	Decrypt(mk []byte) error
}

func DecryptString(s string, mk CryptoKey) (string, error) {
	rv, err := DecryptValue(s, mk)
	return string(rv), err
}

func EncryptString(s string, mk CryptoKey) (string, error) {
	if s == "" {
		return "", fmt.Errorf("Empty string canot be encrypted")
	}

	rv, err := EncryptValue([]byte(s), mk)
	return rv, err
}

func DecryptValue(s string, mk CryptoKey) ([]byte, error) {
	if s == "" {
		return []byte(""), nil
	}

	var rv []byte
	ck, err := NewCipherString(s)
	if err != nil {
		return rv, err
	}
	rv, err = ck.Decrypt(mk)
	return rv, err
}

func EncryptValue(v []byte, mk CryptoKey) (string, error) {
	cs, err := Encrypt(v, mk)

	if err != nil {
		return "", err
	}
	r := cs.ToString()
	return r, err
}
