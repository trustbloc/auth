/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type rawAuthRequest struct {
	AccessToken json.RawMessage  `json:"access_token,omitempty"`
	Client      *RequestClient   `json:"client,omitempty"`
	Interact    *RequestInteract `json:"interact,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler..
func (a *AuthRequest) UnmarshalJSON(data []byte) error {
	raw := &rawAuthRequest{}

	err := json.Unmarshal(data, raw)
	if err != nil {
		return fmt.Errorf("parsing request: %w", err)
	}

	a.Interact = raw.Interact
	a.Client = raw.Client

	tokList, err := unmarshalTokenList(raw.AccessToken)
	if err != nil {
		return fmt.Errorf("parsing request.access_token: %w", err)
	}

	a.AccessToken = tokList

	return nil
}

func unmarshalTokenList(data []byte) ([]*TokenRequest, error) {
	dec := json.NewDecoder(bytes.NewReader(data))

	tok, err := dec.Token()
	if errors.Is(err, io.EOF) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	delim, ok := tok.(json.Delim)
	if !ok {
		return nil, fmt.Errorf("expected to be either an object or array")
	}

	switch delim {
	case '{':
		tokRequest := &TokenRequest{}

		err = json.Unmarshal(data, tokRequest)
		if err != nil {
			return nil, fmt.Errorf("parsing as object: %w", err)
		}

		return []*TokenRequest{tokRequest}, nil
	case '[':
		tokList := []*TokenRequest{}

		err = json.Unmarshal(data, &tokList)
		if err != nil {
			return nil, fmt.Errorf("parsing as array: %w", err)
		}

		return tokList, nil
	}

	return nil, fmt.Errorf("expected to be either an object or array")
}

// MarshalJSON implements json.Marshaler.
func (a *AuthRequest) MarshalJSON() ([]byte, error) {
	var rawTok json.RawMessage

	var err error

	if len(a.AccessToken) == 1 {
		rawTok, err = json.Marshal(a.AccessToken[0])
		if err != nil {
			return nil, fmt.Errorf("marshaling single access_token: %w", err)
		}
	} else if len(a.AccessToken) != 0 {
		rawTok, err = json.Marshal(a.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("marshaling access_token array: %w", err)
		}
	}

	raw := &rawAuthRequest{
		AccessToken: rawTok,
		Client:      a.Client,
		Interact:    a.Interact,
	}

	return json.Marshal(raw)
}

type rawRequestClient struct {
	Key *ClientKey `json:"key"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *RequestClient) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("parsing request.client: %w", err)
	}

	switch val := tok.(type) {
	case string:
		r.Key = nil
		r.Ref = val
		r.IsReference = true

		return nil
	case json.Delim:
		if val != '{' {
			break
		}

		raw := &rawRequestClient{}

		err = json.Unmarshal(data, raw)
		if err != nil {
			return fmt.Errorf("parsing request.client as object: %w", err)
		}

		r.IsReference = false
		r.Ref = ""
		r.Key = raw.Key

		return nil
	}

	return fmt.Errorf("parsing request.client expected either string or object, got '%v'", tok)
}

// MarshalJSON implements json.Marshaler.
func (r *RequestClient) MarshalJSON() ([]byte, error) {
	if r.IsReference {
		return json.Marshal(r.Ref)
	}

	raw := &rawRequestClient{
		Key: r.Key,
	}

	return json.Marshal(raw)
}

type rawTokenAccess struct {
	Type string `json:"type"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *TokenAccess) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("parsing token access descriptor: %w", err)
	}

	switch val := tok.(type) {
	case string:
		t.Ref = val
		t.Type = ""
		t.Raw = nil
		t.IsReference = true

		return nil
	case json.Delim:
		if val.String() != "{" {
			break
		}

		raw := &rawTokenAccess{}

		err = json.Unmarshal(data, raw)
		if err != nil {
			return fmt.Errorf("parsing token access descriptor as object: %w", err)
		}

		t.IsReference = false
		t.Ref = ""
		t.Type = raw.Type
		t.Raw = data

		return nil
	}

	return fmt.Errorf("parsing token access descriptor expected either string or object, got '%v'", tok)
}

// MarshalJSON implements json.Marshaler.
func (t *TokenAccess) MarshalJSON() ([]byte, error) {
	if t.IsReference {
		return json.Marshal(t.Ref)
	}

	return t.Raw, nil
}
