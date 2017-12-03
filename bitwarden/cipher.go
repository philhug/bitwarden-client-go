package bitwarden

type CipherService struct {
	client *Client
}

func (c *CipherService) ListCiphers() ([]Cipher, error) {
	req, err := c.client.newRequest("GET", "ciphers", nil)

	cir := make([]CipherDetailsResponse, 0)
	data := List{Data: &cir}
	_, err = c.client.do(req, &data)
	if err != nil {
		return nil, err
	}

	ci := make([]Cipher, len(cir))
	for i, c := range cir {
		ci[i] = c.ToCipher()
	}
	return ci, err
}

func (c *CipherService) AddCipher(cipher *Cipher) (*Cipher, error) {
	creq := CipherRequest{}
	err := creq.FromCipher(*cipher)
	if err != nil {
		return nil, err
	}
	req, err := c.client.newRequest("POST", "ciphers", creq)

	cres := CipherResponse{}
	_, err = c.client.do(req, &cres)
	if err != nil {
		return nil, err
	}
	ci := cres.ToCipher()
	return &ci, err
}

func (c *CipherService) UpdateCipher(cipher *Cipher) (*Cipher, error) {
	creq := CipherRequest{}
	err := creq.FromCipher(*cipher)
	if err != nil {
		return nil, err
	}
	req, err := c.client.newRequest("PUT", "ciphers/"+cipher.Id, creq)

	cres := CipherResponse{}
	_, err = c.client.do(req, &cres)
	if err != nil {
		return nil, err
	}
	ci := cres.ToCipher()
	return &ci, nil
}

func (c *CipherService) DeleteCipher(cipher *Cipher) (*Cipher, error) {
	creq := CipherRequest{}
	err := creq.FromCipher(*cipher)
	if err != nil {
		return nil, err
	}
	req, err := c.client.newRequest("DELETE", "ciphers/"+cipher.Id, creq)

	cres := CipherResponse{}
	_, err = c.client.do(req, &cres)
	if err != nil {
		return nil, err
	}
	ci := cres.ToCipher()
	return &ci, nil
}
