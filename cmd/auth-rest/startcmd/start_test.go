/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
)

const flag = "--"

type mockServer struct{}

func (s *mockServer) ListenAndServe(host string, handler http.Handler) error {
	return nil
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start auth-rest", startCmd.Short)
	require.Equal(t, "Start auth-rest inside the hub-auth", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) {
	t.Run("test blank host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "host-url value is empty", err.Error())
	})
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither host-url (command line flag) nor AUTH_REST_HOST_URL (environment variable) have been set.",
			err.Error())
	})
}

func TestStartCmdWithBlankEnvVar(t *testing.T) {
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "AUTH_REST_HOST_URL value is empty", err.Error())
	})
}

func TestStartCmdValidArgs(t *testing.T) {
	path, cleanup := newTestOIDCProvider()
	defer cleanup()

	t.Run("start success", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := getValidArgs(log.ParseString(log.ERROR), path)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.ERROR, log.GetLevel(""))
	})
	t.Run("Valid log level", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := getValidArgs(log.ParseString(log.DEBUG), path)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Nil(t, err)
		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})
	t.Run("Invalid log level - default to info", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := getValidArgs(log.ParseString(log.INFO), path)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func TestHealthCheck(t *testing.T) {
	b := &httptest.ResponseRecorder{}
	healthCheckHandler(b, nil)

	require.Equal(t, http.StatusOK, b.Code)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	path, cleanup := newTestOIDCProvider()
	defer cleanup()

	args := getValidArgs(log.ParseString(log.ERROR), path)
	startCmd.SetArgs(args)

	defer unsetEnvVars(t)

	err := startCmd.Execute()
	require.NoError(t, err)
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	path, cleanup := newTestOIDCProvider()
	defer cleanup()
	setEnvVars(t, path)

	defer unsetEnvVars(t)
	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func setEnvVars(t *testing.T, oidcProviderURL string) {
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.Nil(t, err)

	err = os.Setenv(oidcProviderURLEnvKey, oidcProviderURL)
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)
}

func getValidArgs(logLevel, oidcProviderURL string) []string {
	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, oidcClientIDArg()...)
	args = append(args, oidcClientSecretArg()...)

	if logLevel != "" {
		args = append(args, logLevelArg(logLevel)...)
	}

	if oidcProviderURL != "" {
		args = append(args, oidcProviderURLArg(oidcProviderURL)...)
	}

	return args
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}

func hostURLArg() []string {
	return []string{flag + hostURLFlagName, "localhost:8080"}
}

func logLevelArg(logLevel string) []string {
	return []string{flag + logLevelFlagName, logLevel}
}

func oidcProviderURLArg(oidcProviderURL string) []string {
	return []string{flag + oidcProviderURLFlagName, oidcProviderURL}
}

func oidcClientIDArg() []string {
	return []string{flag + oidcClientIDFlagName, uuid.New().String()}
}

func oidcClientSecretArg() []string {
	return []string{flag + oidcClientSecretFlagName, uuid.New().String()}
}

func newTestOIDCProvider() (string, func()) {
	h := &testOIDCProvider{}
	srv := httptest.NewServer(h)
	h.baseURL = srv.URL

	return srv.URL, srv.Close
}

type oidcConfigJSON struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

type testOIDCProvider struct {
	baseURL string
}

func (t *testOIDCProvider) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	response, err := json.Marshal(&oidcConfigJSON{
		Issuer:      t.baseURL,
		AuthURL:     fmt.Sprintf("%s/oauth2/auth", t.baseURL),
		TokenURL:    fmt.Sprintf("%s/oauth2/token", t.baseURL),
		JWKSURL:     fmt.Sprintf("%s/oauth2/certs", t.baseURL),
		UserInfoURL: fmt.Sprintf("%s/oauth2/userinfo", t.baseURL),
		Algorithms:  []string{"RS256"},
	})
	if err != nil {
		panic(err)
	}

	_, err = w.Write(response)
	if err != nil {
		panic(err)
	}
}
