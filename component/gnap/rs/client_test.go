/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gnaprest "github.com/trustbloc/auth/pkg/restapi/gnap"
	"github.com/trustbloc/auth/spi/gnap"
)

const (
	certPrefix    = "../testdata/crypto/"
	clientTimeout = 5 * time.Second
)

func TestGNAPIntrospectClient(t *testing.T) {
	c, err := NewClient(nil, nil, "")
	require.EqualError(t, err, "gnap introspect client: missing signer")
	require.Empty(t, c)

	c, err = NewClient(&mockSigner{}, nil, "")
	require.EqualError(t, err, "gnap introspect client: missing http client")
	require.Empty(t, c)

	c, err = NewClient(&mockSigner{}, &http.Client{}, "")
	require.EqualError(t, err, "gnap introspect client: missing Resource Server URL")
	require.Empty(t, c)

	c, err = NewClient(&mockSigner{}, &http.Client{}, "https://resource/server/url")
	require.NoError(t, err)
	require.NotEmpty(t, c)
}

func TestRequestAccess(t *testing.T) {
	tests := []struct {
		name      string
		signer    gnap.Signer
		tokenRef  string
		grantReq  *gnap.IntrospectRequest
		grantResp *gnap.IntrospectResponse
		errMsg    string
	}{
		{
			name:     "success gnap introspecting access",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			tokenRef: "test Success Value",
			grantReq: &gnap.IntrospectRequest{
				AccessToken: "",
			},
			grantResp: &gnap.IntrospectResponse{
				Active: true,
				Access: []gnap.TokenAccess{{
					IsReference: true,
					Ref:         "test Success Value",
					Type:        "",
					Raw:         nil,
				}},
				Key: &gnap.ClientKey{
					Proof: "",
					JWK:   nil,
				},
				Flags: []string{},
			},
		},
		{
			name:     "error gnap introspecting access with invalid server URL",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			tokenRef: "test Success Value",
			grantReq: &gnap.IntrospectRequest{
				AccessToken: "",
			},
			errMsg: "introspect: failed to build http request: parse \"\\u007fbad url/gnap/introspect\": net/url: " +
				"invalid control character in URL",
		},
		{
			name:     "error gnap introspecting with empty request",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			tokenRef: "test Success Value",
			grantReq: nil,
			errMsg:   "introspect: empty request",
		},
		{
			name:     "error gnap introspecting with invalid signer",
			signer:   &mockSigner{SignatureErr: fmt.Errorf("signing error")},
			tokenRef: "test Success Value",
			grantReq: &gnap.IntrospectRequest{
				AccessToken:    "",
				Proof:          "",
				Access:         nil,
				ResourceServer: nil,
			},
			errMsg: "introspect: signature error: signing error",
		},
		{
			name:   "error gnap introspecting with http server returning 501 error",
			signer: &mockSigner{SignatureVal: []byte("signature")},
			grantReq: &gnap.IntrospectRequest{
				AccessToken:    "",
				Proof:          "",
				Access:         nil,
				ResourceServer: nil,
			},
			errMsg: "introspect: Resource server replied with invalid Status [/gnap/introspect]: 501 Not Implemented",
		},
		{
			name:   "error gnap introspecting access with bad http client error",
			signer: &mockSigner{SignatureVal: []byte("signature")},
			grantReq: &gnap.IntrospectRequest{
				AccessToken:    "",
				Proof:          "",
				Access:         nil,
				ResourceServer: nil,
			},
			errMsg: "introspect: failed to post HTTP request to [/gnap/introspect]: Post \"%s\": x509:" +
				" certificate signed by unknown authority",
		},
		{
			name:   "error gnap introspecting with bad response unmarshall",
			signer: &mockSigner{SignatureVal: []byte("signature")},
			grantReq: &gnap.IntrospectRequest{
				AccessToken:    "",
				Proof:          "",
				Access:         nil,
				ResourceServer: nil,
			},
			errMsg: "introspect: read response not properly formatted [/gnap/introspect, unexpected end of JSON input]",
			grantResp: &gnap.IntrospectResponse{
				Active: false,
				Access: nil,
				Key:    nil,
				Flags:  []string{"mocking empty response"},
			},
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := processPOSTRequest(w, r, tc.grantResp)
				require.NoError(t, err)
			})

			server, url, httpClient := CreateMockHTTPServerAndClient(t, hf)

			switch tc.name {
			case "error gnap introspecting with http server returning 501 error":
				server, url, httpClient = CreateMockHTTPServerAndClientNotOKStatusCode(t, http.StatusNotImplemented)
			case "error gnap introspecting access with bad http client error":
				httpClient = &http.Client{}
			case "error gnap introspecting access with invalid server URL":
				url = string(byte(0x7f)) + "bad url"
			}

			defer func() {
				e := server.Close()
				require.NoError(t, e)
			}()

			c, err := NewClient(tc.signer, httpClient, url)
			require.NoError(t, err)

			response, err := c.Introspect(tc.grantReq)
			if tc.errMsg != "" {
				if tc.name == "error gnap introspecting access with bad http client error" {
					require.EqualError(t, err, fmt.Sprintf(tc.errMsg, url+gnaprest.AuthIntrospectPath))
				} else {
					require.EqualError(t, err, tc.errMsg)
				}
				require.Empty(t, response)

				return
			}

			require.NoError(t, err)
			require.EqualValues(t, tc.tokenRef, response.Access[0].Ref)
		})
	}
}

func processPOSTRequest(w http.ResponseWriter, r *http.Request, expectedGnapResp *gnap.IntrospectResponse) error {
	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	if strings.LastIndex(r.URL.Path, gnaprest.AuthIntrospectPath) == len(r.URL.Path)-len(gnaprest.AuthIntrospectPath) {
		err = handleIntrospectRequest(w, reqBody, expectedGnapResp)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateHTTPMethod validate HTTP method and content-type.
func validateHTTPMethod(w http.ResponseWriter, r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodGet:
	default:
		http.Error(w, "HTTP Method not allowed", http.StatusMethodNotAllowed)

		return false
	}

	ct := r.Header.Get("Content-type")
	if ct != contentType && r.Method == http.MethodPost {
		http.Error(w, fmt.Sprintf("Unsupported Content-type \"%s\"", ct), http.StatusUnsupportedMediaType)

		return false
	}

	return true
}

// validatePayload validate and get the payload from the request.
func validatePostPayload(r *http.Request, w http.ResponseWriter) bool {
	if r.ContentLength == 0 && r.Method == http.MethodPost { // empty payload should not be accepted for POST request
		http.Error(w, "Empty payload", http.StatusBadRequest)

		return false
	}

	return true
}

func handleIntrospectRequest(w http.ResponseWriter, reqBody []byte, expectedGnapResp *gnap.IntrospectResponse) error {
	encReq := &gnap.IntrospectRequest{}

	err := json.Unmarshal(reqBody, encReq)
	if err != nil {
		return err
	}

	mResp, err := json.Marshal(expectedGnapResp)
	if err != nil {
		return err
	}

	if expectedGnapResp != nil && len(expectedGnapResp.Flags) > 0 &&
		expectedGnapResp.Flags[0] == "mocking empty response" {
		mResp = []byte{}
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

// CreateMockHTTPServerAndClient creates mock http server and client using tls and returns them.
func CreateMockHTTPServerAndClient(t *testing.T, inHandler http.Handler) (net.Listener, string, *http.Client) {
	t.Helper()

	server := startMockServer(inHandler)
	port := getServerPort(server)
	serverURL := fmt.Sprintf("https://localhost:%d", port)

	// build a mock cert pool
	cp := x509.NewCertPool()
	err := addCertsToCertPool(cp)
	require.NoError(t, err)

	// build a tls.Config instance to be used by the outbound transport
	tlsConfig := &tls.Config{ //nolint:gosec
		RootCAs:      cp,
		Certificates: nil,
	}

	// create an http client to communicate with the server that has our inbound handlers set above
	client := &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return server, serverURL, client
}

func CreateMockHTTPServerAndClientNotOKStatusCode(t *testing.T, httpCode int) (net.Listener, string, *http.Client) {
	t.Helper()

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(httpCode)
	})

	return CreateMockHTTPServerAndClient(t, hf)
}

func startMockServer(handler http.Handler) net.Listener {
	// ":0" will make the listener auto assign a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("HTTP listener failed to start: %s", err))
	}

	go func() {
		err := http.ServeTLS(listener, handler, certPrefix+"ec-pubCert1.pem", certPrefix+"ec-key1.pem")
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			panic(fmt.Sprintf("HTTP server failed to start: %s", err))
		}
	}()

	return listener
}

func getServerPort(server net.Listener) int {
	// read dynamic port assigned to the server to be used by the client
	return server.Addr().(*net.TCPAddr).Port
}

func addCertsToCertPool(pool *x509.CertPool) error {
	var rawCerts []string

	// add contents of ec-pubCert(1, 2 and 3).pem to rawCerts
	for i := 1; i <= 2; i++ {
		certPath := fmt.Sprintf("%sec-pubCert%d.pem", certPrefix, i)
		// Create a pool with server certificates
		cert, e := ioutil.ReadFile(filepath.Clean(certPath))
		if e != nil {
			return fmt.Errorf("reading certificate failed: %w", e)
		}

		rawCerts = append(rawCerts, string(cert))
	}

	certs := decodeCerts(rawCerts)
	for i := range certs {
		pool.AddCert(certs[i])
	}

	return nil
}

// decodeCerts will decode a list of pemCertsList (string) into a list of x509 certificates.
func decodeCerts(pemCertsList []string) []*x509.Certificate {
	var certs []*x509.Certificate

	for _, pemCertsString := range pemCertsList {
		pemCerts := []byte(pemCertsString)
		for len(pemCerts) > 0 {
			var block *pem.Block

			block, pemCerts = pem.Decode(pemCerts)
			if block == nil {
				break
			}

			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}

			certs = append(certs, cert)
		}
	}

	return certs
}

type mockSigner struct {
	SignatureVal []byte
	SignatureErr error
}

func (s *mockSigner) Sign(_ []byte) ([]byte, error) {
	return s.SignatureVal, s.SignatureErr
}
