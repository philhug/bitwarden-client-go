package bitwarden

import (
	"encoding/json"
	"net/http"
	"net/url"
)

type CipherService struct {
	client *Client
}

func (c *CipherService) ListCiphers() ([]Cipher, error) {
	rel := &url.URL{Path: "ciphers"}
	u := c.client.APIBaseURL.ResolveReference(rel)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.client.UserAgent)

	resp, err := c.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var ciphers []Cipher
	err = json.NewDecoder(resp.Body).Decode(&ciphers)
	return ciphers, err
}

func (c *CipherService) AddCipher(cipher *Cipher) (*Cipher, error) {
	req, err := c.client.newRequest("POST", "ciphers", cipher)

	ci := Cipher{}
	_, err = c.client.do(req, &ci)
	if err != nil {
		return nil, err
	}

	return &ci, err
}

func (c *CipherService) UpdateCipher(cipher *Cipher) (*Cipher, error) {
	req, err := c.client.newRequest("PUT", "ciphers/"+cipher.Id, cipher)

	ci := Cipher{}
	_, err = c.client.do(req, &ci)
	if err != nil {
		return nil, err
	}

	return &ci, nil
}

func (c *CipherService) DeleteCipher(cipher *Cipher) (*Cipher, error) {
	req, err := c.client.newRequest("DELETE", "ciphers/"+cipher.Id, cipher)

	ci := Cipher{}
	_, err = c.client.do(req, &ci)
	if err != nil {
		return nil, err
	}

	return &ci, nil
}
