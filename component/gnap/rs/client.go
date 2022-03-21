/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// rs package contains the Resource Server client to validate GNAP tokens.

package rs

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
var logger = log.New("resource-server-client")

const contentType = "application/json"

// Client is a GNAP client for creating and verify GNAP requests.
type Client struct {
	signer                gnap.Signer
	httpClient            *http.Client
	gnapResourceServerURL string
}

// NewClient creates a new GNAP introspection client. It requires a signer for HTTP Signature header, an HTTP client
// and a base URL of the resource server.
func NewClient(signer gnap.Signer, httpClient *http.Client, gnapResourceServerURL string) (*Client, error) {
	if signer == nil {
		return nil, fmt.Errorf("gnap introspect client: missing signer")
	}

	if httpClient == nil {
		return nil, fmt.Errorf("gnap introspect client: missing http client")
	}

	if gnapResourceServerURL == "" {
		return nil, fmt.Errorf("gnap introspect client: missing Resource Server URL")
	}

	return &Client{
		signer:                signer,
		httpClient:            httpClient,
		gnapResourceServerURL: gnapResourceServerURL,
	}, nil
}

// Introspect verifies a GNAP auth grant request.
func (c *Client) Introspect(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("introspect: empty request")
	}

	mReq, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("introspect: signature error: %w", err)
	}

	var sig []byte

	sig, err = c.signer.Sign(mReq)
	if err != nil {
		return nil, fmt.Errorf("introspect: signature error: %w", err)
	}

	requestReader := bytes.NewReader(mReq)

	//nolint:noctx // TODO add context if needed.
	httpReq, err := http.NewRequest(http.MethodPost, c.gnapResourceServerURL+gnaprest.AuthIntrospectPath, requestReader)
	if err != nil {
		return nil, fmt.Errorf("introspect: failed to build http request: %w", err)
	}

	httpReq.Header.Add("Content-Type", contentType)
	// httpReq.Header.Add("Signature-Input", "TODO") // TODO update signature input
	httpReq.Header.Add("Signature", base64.URLEncoding.EncodeToString(sig))

	r, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("introspect: failed to post HTTP request to [%s]: %w", gnaprest.AuthIntrospectPath,
			err)
	}

	defer func() {
		err = r.Body.Close()
		if err != nil {
			logger.Warnf("failed to close http request but it has been processed: %w", err)
		}
	}()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspect: Resource server replied with invalid Status [%s]: %v",
			gnaprest.AuthIntrospectPath, r.Status)
	}

	respBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("introspect: read response failed [%s, %w]", gnaprest.AuthIntrospectPath, err)
	}

	gnapResp := &gnap.IntrospectResponse{}

	err = json.Unmarshal(respBody, gnapResp)
	if err != nil {
		return nil, fmt.Errorf("introspect: read response not properly formatted [%s, %w]",
			gnaprest.AuthIntrospectPath, err)
	}

	return gnapResp, nil
}
