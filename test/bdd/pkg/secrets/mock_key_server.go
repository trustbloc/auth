/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secrets

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/trustbloc/auth/pkg/restapi/operation"
)

func NewMockKeyServer(token string, tlsConfig *tls.Config) *MockKeyServer {
	return &MockKeyServer{
		ApiToken:  token,
		TLSConfig: tlsConfig,
	}
}

type MockKeyServer struct {
	ApiToken   string
	TLSConfig  *tls.Config
	UserSecret string
}

func (m *MockKeyServer) FetchSecretShare(endpoint string) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	m.addToken(request)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: m.TLSConfig,
		},
	}

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("failed to invoke %s: %w", endpoint, err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			fmt.Printf("WARNING - failed to close response body: %s\n", closeErr.Error())
		}
	}()

	if response.StatusCode != http.StatusOK {
		msg, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("WARNING - failed to read response body: %s\n", err.Error())
		}

		return fmt.Errorf(
			"unexpected response: code=%d msg=%s", response.StatusCode, msg,
		)
	}

	result := &operation.GetSecretResponse{}

	err = json.NewDecoder(response.Body).Decode(result)
	if err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(result.Secret)
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	m.UserSecret = string(decoded)

	return nil
}

func (m *MockKeyServer) addToken(r *http.Request) {
	r.Header.Set(
		"authorization",
		fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte(m.ApiToken))),
	)
}
