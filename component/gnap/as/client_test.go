/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package as

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	gnaprest "github.com/trustbloc/auth/pkg/restapi/operation"
	"github.com/trustbloc/auth/spi/gnap"
)

const (
	certPrefix    = "../testdata/crypto/"
	clientTimeout = 5 * time.Second
)

func TestGNAPAuthClient(t *testing.T) {
	c, err := NewClient(nil, nil, "")
	require.EqualError(t, err, "missing signer")
	require.Empty(t, c)

	c, err = NewClient(&mockSigner{}, nil, "")
	require.EqualError(t, err, "missing http client")
	require.Empty(t, c)

	c, err = NewClient(&mockSigner{}, &http.Client{}, "")
	require.EqualError(t, err, "missing Authorization Server URL")
	require.Empty(t, c)

	c, err = NewClient(&mockSigner{}, &http.Client{}, "https://auth/server/url")
	require.NoError(t, err)
	require.NotEmpty(t, c)
}

func TestRequestAccess(t *testing.T) {
	tests := []struct {
		name      string
		signer    gnap.Signer
		privKey   *jwk.JWK
		tokenVal  string
		grantReq  *gnap.AuthRequest
		grantResp *gnap.AuthResponse
		errMsg    string
	}{
		{
			name:     "success requesting gnap access",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			privKey:  privKey(t),
			tokenVal: "test Success Value",
			grantReq: &gnap.AuthRequest{
				AccessToken: []*gnap.TokenRequest{},
				Client: &gnap.RequestClient{
					Key: clientKey(t),
				},
				Interact: &gnap.RequestInteract{},
			},
			grantResp: &gnap.AuthResponse{AccessToken: []gnap.AccessToken{{Value: "test Success Value"}}},
		},
		{
			name:     "error requesting gnap access with invalid server URL",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			privKey:  privKey(t),
			tokenVal: "test Success Value",
			grantReq: &gnap.AuthRequest{
				AccessToken: []*gnap.TokenRequest{},
				Client:      &gnap.RequestClient{},
				Interact:    &gnap.RequestInteract{},
			},
			errMsg: "failed to build http request: parse \"\\u007fbad url/gnap/auth\": net/url: " +
				"invalid control character in URL",
		},
		{
			name:     "error requesting gnap access with empty request",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			privKey:  privKey(t),
			tokenVal: "test Success Value",
			grantReq: nil,
			errMsg:   "empty request",
		},
		{
			name:     "error requesting gnap access with invalid signer",
			signer:   &mockSigner{SignatureErr: fmt.Errorf("signing error")},
			privKey:  privKey(t),
			tokenVal: "test Success Value",
			grantReq: &gnap.AuthRequest{
				AccessToken: []*gnap.TokenRequest{},
				Client:      &gnap.RequestClient{},
				Interact:    &gnap.RequestInteract{},
			},
			errMsg: "signature error: signing error",
		},
		{
			name:    "error requesting gnap access with http server returning 501 error",
			signer:  &mockSigner{SignatureVal: []byte("signature")},
			privKey: privKey(t),
			grantReq: &gnap.AuthRequest{
				AccessToken: []*gnap.TokenRequest{},
				Client:      &gnap.RequestClient{},
				Interact:    &gnap.RequestInteract{},
			},
			errMsg: "auth server replied with invalid status [/gnap/auth]: 501 Not Implemented",
		},
		{
			name:    "error requesting gnap access with bad http client error",
			signer:  &mockSigner{SignatureVal: []byte("signature")},
			privKey: privKey(t),
			grantReq: &gnap.AuthRequest{
				AccessToken: []*gnap.TokenRequest{},
				Client:      &gnap.RequestClient{},
				Interact:    &gnap.RequestInteract{},
			},
			errMsg: "failed to post HTTP request to [/gnap/auth]: Post \"%s\": x509:" +
				" certificate signed by unknown authority",
		},
		{
			name:    "error requesting gnap access with bad response unmarshall",
			signer:  &mockSigner{SignatureVal: []byte("signature")},
			privKey: privKey(t),
			grantReq: &gnap.AuthRequest{
				AccessToken: []*gnap.TokenRequest{},
				Client:      &gnap.RequestClient{},
				Interact:    &gnap.RequestInteract{},
			},
			errMsg: "read response not properly formatted [/gnap/auth, unexpected end of JSON input]",
			grantResp: &gnap.AuthResponse{
				InstanceID: "mocking empty response",
			},
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := processPOSTAuthAccessRequest(w, r, tc.grantResp)
				require.NoError(t, err)
			})

			server, url, httpClient := CreateMockHTTPServerAndClient(t, hf)

			switch tc.name {
			case "error requesting gnap access with http server returning 501 error":
				server, url, httpClient = CreateMockHTTPServerAndClientNotOKStatusCode(t, http.StatusNotImplemented)
			case "error requesting gnap access with bad http client error":
				httpClient = &http.Client{}
			case "error requesting gnap access with invalid server URL":
				url = string(byte(0x7f)) + "bad url"
			}

			defer func() {
				e := server.Close()
				require.NoError(t, e)
			}()

			c, err := NewClient(tc.signer, httpClient, url)
			require.NoError(t, err)

			response, err := c.RequestAccess(tc.grantReq)
			if tc.errMsg != "" {
				if tc.name == "error requesting gnap access with bad http client error" {
					require.Contains(t, err.Error(), fmt.Sprintf(tc.errMsg, url+gnaprest.AuthRequestPath))
				} else {
					require.EqualError(t, err, tc.errMsg)
				}
				require.Empty(t, response)

				return
			}

			require.NoError(t, err)
			require.EqualValues(t, tc.tokenVal, response.AccessToken[0].Value)
		})
	}
}

func TestValidateHash(t *testing.T) {
	clientNonce := "foo"
	serverNonce := "bar"
	interactRef := "abc-xyz-123"
	requestURI := "http://example.com/foo"

	t.Run("success", func(t *testing.T) {
		hash, err := responseHash(clientNonce, serverNonce, interactRef, requestURI)
		require.NoError(t, err)

		err = ValidateInteractHash(hash, clientNonce, serverNonce, interactRef, requestURI)
		require.NoError(t, err)
	})

	t.Run("invalid hash", func(t *testing.T) {
		err := ValidateInteractHash("blah", clientNonce, serverNonce, interactRef, requestURI)
		require.ErrorIs(t, err, ErrInvalidInteractHash)
	})
}

func TestContinue(t *testing.T) {
	tests := []struct {
		name      string
		signer    gnap.Signer
		privKey   *jwk.JWK
		tokenVal  string
		grantReq  *gnap.ContinueRequest
		client    *gnap.RequestClient
		grantResp *gnap.AuthResponse
		errMsg    string
	}{
		{
			name:     "success continuing gnap access",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			privKey:  privKey(t),
			tokenVal: "test Success Value",
			grantReq: &gnap.ContinueRequest{
				InteractRef: "",
			},
			grantResp: &gnap.AuthResponse{AccessToken: []gnap.AccessToken{{Value: "test Success Value"}}},
		},
		{
			name:     "error continuing gnap access with invalid server URL",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			privKey:  privKey(t),
			tokenVal: "test Success Value",
			grantReq: &gnap.ContinueRequest{
				InteractRef: "",
			},
			errMsg: "failed to build http request: parse \"\\u007fbad url/gnap/continue\": net/url: " +
				"invalid control character in URL",
		},
		{
			name:     "error continuing gnap access with empty request",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			privKey:  privKey(t),
			tokenVal: "test Success Value",
			grantReq: nil,
			errMsg:   "empty request",
		},
		{
			name:     "error requesting gnap access with invalid signer",
			signer:   &mockSigner{SignatureErr: fmt.Errorf("signing error")},
			privKey:  privKey(t),
			tokenVal: "test Success Value",
			grantReq: &gnap.ContinueRequest{InteractRef: ""},
			errMsg:   "signature error: signing error",
		},
		{
			name:     "error continuing gnap access with http server returning 501 error",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			privKey:  privKey(t),
			grantReq: &gnap.ContinueRequest{InteractRef: ""},
			errMsg:   "auth server replied with invalid status [/gnap/continue]: 501 Not Implemented",
		},
		{
			name:     "error continuing gnap access with bad http client error",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			privKey:  privKey(t),
			grantReq: &gnap.ContinueRequest{InteractRef: ""},
			errMsg: "failed to post HTTP request to [/gnap/continue]: Post \"%s\": x509:" +
				" certificate signed by unknown authority",
		},
		{
			name:     "error continuing gnap access with bad response unmarshall",
			signer:   &mockSigner{SignatureVal: []byte("signature")},
			privKey:  privKey(t),
			grantReq: &gnap.ContinueRequest{InteractRef: ""},
			errMsg:   "read response not properly formatted [/gnap/continue, unexpected end of JSON input]",
			grantResp: &gnap.AuthResponse{
				InstanceID: "mocking empty response",
			},
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := processPOSTContinueRequest(w, r, tc.grantResp)
				require.NoError(t, err)
			})

			server, url, httpClient := CreateMockHTTPServerAndClient(t, hf)

			switch tc.name {
			case "error continuing gnap access with http server returning 501 error":
				server, url, httpClient = CreateMockHTTPServerAndClientNotOKStatusCode(t, http.StatusNotImplemented)
			case "error continuing gnap access with bad http client error":
				httpClient = &http.Client{}
			case "error continuing gnap access with invalid server URL":
				url = string(byte(0x7f)) + "bad url"
			}

			defer func() {
				e := server.Close()
				require.NoError(t, e)
			}()

			c, err := NewClient(tc.signer, httpClient, url)
			require.NoError(t, err)

			response, err := c.Continue(tc.grantReq, uuid.NewString())
			if tc.errMsg != "" {
				if tc.name == "error continuing gnap access with bad http client error" {
					require.Contains(t, err.Error(), fmt.Sprintf(tc.errMsg, url+gnaprest.AuthContinuePath))
				} else {
					require.EqualError(t, err, tc.errMsg)
				}
				require.Empty(t, response)

				return
			}

			require.NoError(t, err)
			require.EqualValues(t, tc.tokenVal, response.AccessToken[0].Value)
		})
	}
}

func processPOSTAuthAccessRequest(w http.ResponseWriter, r *http.Request, expectedGnapResp *gnap.AuthResponse) error {
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

	if strings.LastIndex(r.URL.Path, gnaprest.AuthRequestPath) == len(r.URL.Path)-len(gnaprest.AuthRequestPath) {
		err = handleAuthRequest(w, reqBody, expectedGnapResp)
		if err != nil {
			return err
		}
	}

	return nil
}

func processPOSTContinueRequest(w http.ResponseWriter, r *http.Request, expectedGnapResp *gnap.AuthResponse) error {
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

	if strings.LastIndex(r.URL.Path, gnaprest.AuthContinuePath) == len(r.URL.Path)-len(gnaprest.AuthContinuePath) {
		err = handleContinueRequest(w, reqBody, expectedGnapResp)
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

func handleAuthRequest(w http.ResponseWriter, reqBody []byte, expectedGnapResp *gnap.AuthResponse) error {
	encReq := &gnap.AuthRequest{}

	err := json.Unmarshal(reqBody, encReq)
	if err != nil {
		return err
	}

	mResp, err := json.Marshal(expectedGnapResp)
	if err != nil {
		return err
	}

	if expectedGnapResp != nil && expectedGnapResp.InstanceID == "mocking empty response" {
		mResp = []byte{}
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func handleContinueRequest(w http.ResponseWriter, reqBody []byte, expectedGnapResp *gnap.AuthResponse) error {
	encReq := &gnap.ContinueRequest{}

	err := json.Unmarshal(reqBody, encReq)
	if err != nil {
		return err
	}

	mResp, err := json.Marshal(expectedGnapResp)
	if err != nil {
		return err
	}

	if expectedGnapResp != nil && expectedGnapResp.InstanceID == "mocking empty response" {
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

func (s *mockSigner) ProofType() string {
	return "mock"
}

func (s *mockSigner) Sign(request *http.Request, requestBody []byte) (*http.Request, error) {
	return request, s.SignatureErr
}

func privKey(t *testing.T) *jwk.JWK {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       priv,
			KeyID:     "key1",
			Algorithm: "ES256",
		},
		Kty: "EC",
		Crv: "P-256",
	}
}

func clientKey(t *testing.T) *gnap.ClientKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &gnap.ClientKey{
		JWK: jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       priv,
				KeyID:     "key1",
				Algorithm: "ES256",
			},
			Kty: "EC",
			Crv: "P-256",
		},
	}
}
