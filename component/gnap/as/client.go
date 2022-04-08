/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// package as is the Authentication Server client that requests GNAP tokens from the Authorization Server.

package as

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"

	gnaprest "github.com/trustbloc/auth/pkg/restapi/gnap"
	"github.com/trustbloc/auth/spi/gnap"
)

//nolint:gochecknoglobals
var logger = log.New("auth-server-client")

const contentType = "application/json"

// Client requesting Gnap tokens from the Authorization Server.
type Client struct {
	signer            gnap.Signer
	httpClient        *http.Client
	gnapAuthServerURL string
}

// NewClient creates a new GNAP authorization client. It requires a signer for HTTP Signature header, an HTTP client
// and a base URL of the authorization server.
func NewClient(signer gnap.Signer, httpClient *http.Client, gnapAuthServerURL string) (*Client, error) {
	if signer == nil {
		return nil, fmt.Errorf("gnap auth client: missing signer")
	}

	if httpClient == nil {
		return nil, fmt.Errorf("gnap auth client: missing http client")
	}

	if gnapAuthServerURL == "" {
		return nil, fmt.Errorf("gnap auth client: missing Authorization Server URL")
	}

	return &Client{
		signer:            signer,
		httpClient:        httpClient,
		gnapAuthServerURL: gnapAuthServerURL,
	}, nil
}

// RequestAccess creates a GNAP grant access req then submit it to the server to receive a response with an
// interact_ref value.
func (c *Client) RequestAccess(req *gnap.AuthRequest) (*gnap.AuthResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("requestAccess: empty request")
	}

	mReq, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("requestAccess: marshal access token error: %w", err)
	}

	var sig []byte

	sig, err = c.signer.Sign(mReq)
	if err != nil {
		return nil, fmt.Errorf("requestAccess: signature error: %w", err)
	}

	requestReader := bytes.NewReader(mReq)

	url := c.gnapAuthServerURL + gnaprest.AuthRequestPath

	httpReq, err := http.NewRequest(http.MethodPost, url, requestReader)
	if err != nil {
		return nil, fmt.Errorf("requestAccess: failed to build http request: %w", err)
	}

	httpReq.Header.Add("Content-Type", contentType)
	// httpReq.Header.Add("Signature-Input", "TODO") // TODO update signature input
	httpReq.Header.Add("Signature", base64.URLEncoding.EncodeToString(sig))

	r, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("requestAccess: failed to post HTTP request to [%s]: %w", gnaprest.AuthRequestPath, err)
	}

	defer func() {
		err = r.Body.Close()
		if err != nil {
			logger.Warnf("failed to close http request but it has been processed: %w", err)
		}
	}()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("requestAccess: Auth server replied with invalid Status [%s]: %v",
			gnaprest.AuthRequestPath, r.Status)
	}

	respBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("requestAccess: read response failed [%s]: %w", gnaprest.AuthRequestPath, err)
	}

	gnapResp := &gnap.AuthResponse{}

	err = json.Unmarshal(respBody, gnapResp)
	if err != nil {
		return nil, fmt.Errorf("requestAccess: read response not properly formatted [%s, %w]",
			gnaprest.AuthRequestPath, err)
	}

	return gnapResp, nil
}

// Continue gnap auth request containing interact_ref.
func (c *Client) Continue(req *gnap.ContinueRequest) (*gnap.AuthResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("continue: empty request")
	}

	mReq, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("continue: marshal access token error: %w", err)
	}

	var sig []byte

	sig, err = c.signer.Sign(mReq)
	if err != nil {
		return nil, fmt.Errorf("continue: signature error: %w", err)
	}

	requestReader := bytes.NewReader(mReq)

	//nolint:noctx // TODO add context if needed.
	httpReq, err := http.NewRequest(http.MethodPost, c.gnapAuthServerURL+gnaprest.AuthContinuePath, requestReader)
	if err != nil {
		return nil, fmt.Errorf("continue: failed to build http request: %w", err)
	}

	httpReq.Header.Add("Content-Type", contentType)
	// httpReq.Header.Add("Signature-Input", "TODO") // TODO update signature input
	httpReq.Header.Add("Signature", base64.URLEncoding.EncodeToString(sig))

	r, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("continue: failed to post HTTP request to [%s]: %w", gnaprest.AuthContinuePath, err)
	}

	defer func() {
		err = r.Body.Close()
		if err != nil {
			logger.Warnf("failed to close http request but it has been processed: %w", err)
		}
	}()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("continue: Auth server replied with invalid Status [%s]: %v",
			gnaprest.AuthContinuePath, r.Status)
	}

	respBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("continue: read response failed [%s, %w]", gnaprest.AuthContinuePath, err)
	}

	gnapResp := &gnap.AuthResponse{}

	err = json.Unmarshal(respBody, gnapResp)
	if err != nil {
		return nil, fmt.Errorf("continue: read response not properly formatted [%s, %w]",
			gnaprest.AuthContinuePath, err)
	}

	return gnapResp, nil
}
