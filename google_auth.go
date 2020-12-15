package google_auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/applicaset/user-svc"
	"github.com/pkg/errors"
	"net/http"
)

const Name = "google"

type googleAuth struct {
	clientID string
}

type response struct {
	id string
}

func (rsp response) Validated() bool {
	return rsp.id != ""
}

func (rsp response) ID() string {
	return rsp.id
}

type claims struct {
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
}

func (ga *googleAuth) Validate(ctx context.Context, args map[string]interface{}) (user.ValidateResponse, error) {
	rsp := new(response)
	iIDToken, ok := args["id_token"]
	if !ok {
		return rsp, nil
	}

	idToken, ok := iIDToken.(string)
	if !ok {
		return rsp, nil
	}

	u := fmt.Sprintf("https://oauth2.googleapis.com/tokeninfo?id_token=%s", idToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error on create new http request")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error on http get request to google")
	}

	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return rsp, nil
	}

	var c claims
	err = json.NewDecoder(res.Body).Decode(&c)
	if err != nil {
		return nil, errors.Wrap(err, "error on decode response body")
	}

	if c.Audience != ga.clientID {
		return rsp, nil
	}

	rsp.id = c.Subject

	return rsp, nil
}

func NewAuthProvider(clientID string) user.AuthProvider {
	ga := googleAuth{
		clientID: clientID,
	}

	return &ga
}

func New(clientID string) user.Option {
	return user.WithAuthProvider(Name, NewAuthProvider(clientID))
}
