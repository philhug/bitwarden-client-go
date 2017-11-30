package bitwarden

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

func NewUserPasswordAuthClient(username string, password string) (*Client, error) {
	c := NewClient(nil)

	dk := MakeKey(password, username)
	password_hash := HashPassword(password, dk)

	ctx := context.Background()
	rel := &url.URL{Path: "connect/token"}
	u := c.IdentityBaseURL.ResolveReference(rel).String()

	config := &oauth2.Config{ClientID: "browser", Endpoint: oauth2.Endpoint{TokenURL: u}}

	tok, err := config.PasswordCredentialsToken(ctx, username, password_hash)
	if err != nil {
		return nil, err
	}
	ts := config.TokenSource(ctx, tok)
	c.httpClient = oauth2.NewClient(ctx, ts)

	return c, nil
}
