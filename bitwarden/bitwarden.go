package bitwarden

import (
	/*
		"bytes"
		"encoding/json"
		"fmt"
		"io"
		"log"
		"strings"
	*/
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

const (
	defaultAPIBaseURL      = "http://localhost:8080/api/"
	defaultIdentityBaseURL = "http://localhost:8080/identity/"
	defaultWebVaultBaseURL = "http://localhost:4001/"
	defaultIconsBaseURL    = "http://localhost:8080/icons/"
	apiVersion             = "0.0.1"
	defaultUserAgent       = "go-bitwarden/" + apiVersion
)

type Client struct {
	// BaseURL for API requests.
	APIBaseURL      *url.URL
	IdentityBaseURL *url.URL
	WebVaultBaseURL *url.URL
	IconsBaseURL    *url.URL

	// UserAgent used when communicating with the Bitwarden API.
	UserAgent string

	// HttpClient is the underlying HTTP client
	// used to communicate with the API.
	httpClient *http.Client

	common service // Reuse a single struct instead of allocating one for each service on the heap.

	// Services
	Cipher *CipherService

	// Set to true to output debugging logs during API calls
	Debug bool
}

type service struct {
	client *Client
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	apiBaseURL, _ := url.Parse(defaultAPIBaseURL)
	identityBaseURL, _ := url.Parse(defaultIdentityBaseURL)
	webVaultBaseURL, _ := url.Parse(defaultWebVaultBaseURL)
	iconsBaseURL, _ := url.Parse(defaultIconsBaseURL)

	c := &Client{httpClient: httpClient,
		APIBaseURL:      apiBaseURL,
		IdentityBaseURL: identityBaseURL,
		WebVaultBaseURL: webVaultBaseURL,
		IconsBaseURL:    iconsBaseURL,
	}
	c.common.client = c
	c.Cipher = (*CipherService)(&c.common)

	return c
}

func (c *Client) newRequest(method, path string, body interface{}) (*http.Request, error) {
	rel := &url.URL{Path: path}
	u := c.APIBaseURL.ResolveReference(rel)
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	return req, nil
}

func (c *Client) do(req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(v)
	return resp, err
}
