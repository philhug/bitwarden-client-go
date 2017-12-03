package main

import (
	"fmt"

	"github.com/philhug/bitwarden-client-go/bitwarden"
	"log"
)

func main() {

	var username = "user@example.com"
	var password = "password"

	client, err := bitwarden.NewUserPasswordAuthClient(username, password)
	if err != nil {
		log.Fatal(err)
	}
	var profile bitwarden.Account
	profile, err = client.Account.GetProfile()
	if err != nil {
		log.Fatal(err)
	}

	dk := bitwarden.MakeKey(password, username)

	cs, err := bitwarden.NewCipherString(profile.Key)
	if err != nil {
		log.Fatal(err)
	}

	mk, err := cs.DecryptKey(dk, bitwarden.AesCbc256_HmacSha256_B64)
	if err != nil {
		log.Fatal(err)
	}

	s := "Test"
	c := bitwarden.Cipher{Type: 1, Login: &bitwarden.LoginData{CipherData: bitwarden.CipherData{Name: &s}}}
	err = c.Encrypt(mk)
	if err != nil {
		log.Fatal(err)
	}

	cipher, err := client.Cipher.AddCipher(&c)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cipher)

	ciphers, err := client.Cipher.ListCiphers()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ciphers)
	fmt.Println(cipher)
	fmt.Println(cipher.Login)

	cipher.Decrypt(mk)
	pass := "bla"
	cipher.Login.Password = &pass
	cipher.Encrypt(mk)
	cipher, err = client.Cipher.UpdateCipher(cipher)
	if err != nil {
		log.Fatal(err)
	}

	ciphers, err = client.Cipher.ListCiphers()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(ciphers)

}
