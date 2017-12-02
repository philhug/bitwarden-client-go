package main

import (
	"fmt"

	"github.com/philhug/bitwarden-client-go/bitwarden"
	"log"
)

func main() {

	var username = "test@example.com"
	var password = "password"

	client, err := bitwarden.NewUserPasswordAuthClient(username, password)
	if err != nil {
		log.Fatal(err)
	}

	c := bitwarden.Cipher{Type: 1, Data: bitwarden.CipherData{Name: "Test"}}
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

	cipher.Login.Password = "bla"
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
