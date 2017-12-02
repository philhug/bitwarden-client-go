package bitwarden

import (
	"log"
	"reflect"
)

func internalDecrypt(v reflect.Value, mk []byte) error {

	switch v.Kind() {
	case reflect.Ptr:
		v := v.Elem()

		// Check if the pointer is nil
		if !v.IsValid() {
			return nil
		}
		return internalDecrypt(v, mk)

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			err := internalDecrypt(v.Field(i), mk)
			if err != nil {
				return err
			}
		}
	case reflect.String:
		s, err := DecryptString(v.String(), mk)
		if err != nil {
			return err
		}
		v.SetString(s)
	case reflect.Slice:
		for i := 0; i < v.Len(); i += 1 {
			internalDecrypt(v.Index(i), mk)
		}
	default:
		log.Fatal("eerrror")
	}
	return nil
}

func decrypt(data interface{}, mk []byte) error {
	return internalDecrypt(reflect.ValueOf(data), mk)
}

func (c *Cipher) Decrypt(mk []byte) error {
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

func (f *Folder) Decrypt(mk []byte) error {
	var err error
	f.Name, err = DecryptString(f.Name, mk)
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

func DecryptString(s string, mk []byte) (string, error) {
	rv, err := DecryptValue(s, mk)
	return string(rv), err
}

func DecryptValue(s string, mk []byte) ([]byte, error) {
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
