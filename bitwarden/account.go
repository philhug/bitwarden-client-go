package bitwarden

type AccountService struct {
	client *Client
}

func (c *AccountService) GetProfile() (Account, error) {
	req, err := c.client.newRequest("GET", "accounts/profile", nil)

	var account Account
	_, err = c.client.do(req, &account)
	if err != nil {
		return account, err
	}

	return account, err
}
