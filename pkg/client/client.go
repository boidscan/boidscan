// Package client is a Go client for the boidscan search API.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func New(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: http.DefaultClient}
}

// APIError is returned for non-2xx responses.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("boidscan api: %d %s", e.StatusCode, e.Message)
}

func (c *Client) get(ctx context.Context, path string, params url.Values, out any) error {
	u := c.BaseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var body struct {
			Error string `json:"error"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(b, &body) != nil || body.Error == "" {
			body.Error = strings.TrimSpace(string(b))
		}
		return &APIError{StatusCode: resp.StatusCode, Message: body.Error}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) Host(ctx context.Context, ip string) (Host, error) {
	var h Host
	err := c.get(ctx, "/api/v1/host/"+url.PathEscape(ip), nil, &h)
	return h, err
}

func (c *Client) Search(ctx context.Context, q Query) (Page, error) {
	v := url.Values{}
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	set("cidr", q.CIDR)
	set("q", q.Text)
	set("cert", q.Cert)
	if q.Port != 0 {
		v.Set("port", strconv.Itoa(q.Port))
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Before != 0 {
		v.Set("before", strconv.FormatInt(q.Before, 10))
	}
	var p Page
	err := c.get(ctx, "/api/v1/search", v, &p)
	return p, err
}

// SearchAll follows pagination and calls fn for each result until fn returns false.
func (c *Client) SearchAll(ctx context.Context, q Query, fn func(Observation) bool) error {
	for {
		p, err := c.Search(ctx, q)
		if err != nil {
			return err
		}
		for _, o := range p.Results {
			if !fn(o) {
				return nil
			}
		}
		if p.Next == 0 {
			return nil
		}
		q.Before = p.Next
	}
}

func (c *Client) OptOuts(ctx context.Context) ([]OptOut, error) {
	var list []OptOut
	err := c.get(ctx, "/api/v1/optouts", nil, &list)
	return list, err
}
