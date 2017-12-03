package bitwarden

import (
	"testing"
)

func TestCrypto(t *testing.T) {
	var email = "test@example.com"
	var password = "password"
	var passwordHash = "Q4zw5LmXHMJDJYBPfeFYtW8+dxbcCHTFmzE04OXS6Ic="

	var enckey = "0.yMeH5ypzRLcyJX69HAt6mQ==|H0mdMpoX1aguKIaCXOreL93JyCpo9ORiX8ZbK+taLXlGZfCb5TOs0eriKa7u1ocBp9gDHwYm5EUyobnbVfZ3uiP2suYWAXKmC4IO67b7ozc="

	var encdata = "2.eWiu5v/7OWt5EiuypCP9nQ==|8vxfq3AsARNjPE8rWcDLSg==|TKN0DmdhK8qjIqLe7WPpjVcAoUghGDxnpWUb4WS0jHQ="
	var encdata_decrypted = "test"

	var encTest = "TESTING ENCRYPTN"

	cs, err := NewCipherString(enckey)
	if err != nil {
		t.Error(err)
	}

	dk := MakeKey(password, email)

	// MasterPasswordHash
	hash := HashPassword(password, dk)
	if hash != passwordHash {
		t.Errorf("Expected %v got %v", passwordHash, hash)
	}

	ct, err := Encrypt([]byte(encTest), dk)
	if err != nil {
		t.Error(err)
	}

	pt, err := ct.Decrypt(dk)
	if err != nil {
		t.Error(err)
	}

	if string(pt) != encTest {
		t.Errorf("Expected %v got %v", encTest, string(pt))
	}

	cs, err = NewCipherString(enckey)
	if err != nil {
		t.Error(err)
	}

	if cs.ToString() != enckey {
		t.Errorf("Expected %v got %v", cs.ToString(), enckey)

	}

	mkb, err := cs.Decrypt(dk)
	if err != nil {
		t.Error(err)
	}

	mk, err := NewCryptoKey(mkb, AesCbc256_HmacSha256_B64)
	if err != nil {
		t.Error(err)
	}

	if mk.EncryptionType != AesCbc256_HmacSha256_B64 {
		t.Errorf("NewCryptoKey: invalid EncryptionType")
	}

	ds, err := NewCipherString(encdata)
	if err != nil {
		t.Error(err)
	}

	if ds.ToString() != encdata {
		t.Errorf("Expected %v got %v", ds.ToString(), encdata)

	}

	d, err := ds.Decrypt(mk)
	if err != nil {
		t.Error(err)
	}

	if string(d) != encdata_decrypted {
		t.Errorf("Expected %v got %v", string(d), encdata_decrypted)
	}

}
