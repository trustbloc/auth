/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
)

type mockServer struct {
	err error
}

func (s *mockServer) ListenAndServeTLS(host, certFile, keyFile string, handler http.Handler) error {
	return s.err
}

func TestOIDCParameters(t *testing.T) {
	t.Run("error on missing callback URL", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + logLevelFlagName, log.ParseString(log.DEBUG),
			"--" + databaseTypeFlagName, "mem",
			"--" + googleProviderFlagName, oidcURL,
			"--" + googleClientIDFlagName, uuid.New().String(),
			"--" + googleClientSecretFlagName, uuid.New().String(),
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
	})

	t.Run("error on missing google provider URL", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + logLevelFlagName, log.ParseString(log.DEBUG),
			"--" + databaseTypeFlagName, "mem",
			"--" + oidcCallbackURLFlagName, "http://example.com/oauth2/callback",
			"--" + googleClientIDFlagName, uuid.New().String(),
			"--" + googleClientSecretFlagName, uuid.New().String(),
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
	})

	t.Run("error on missing google client ID", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + logLevelFlagName, log.ParseString(log.DEBUG),
			"--" + databaseTypeFlagName, "mem",
			"--" + oidcCallbackURLFlagName, "http://example.com/oauth2/callback",
			"--" + googleProviderFlagName, oidcURL,
			"--" + googleClientSecretFlagName, uuid.New().String(),
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
	})

	t.Run("error on missing google client secret", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + logLevelFlagName, log.ParseString(log.DEBUG),
			"--" + databaseTypeFlagName, "mem",
			"--" + oidcCallbackURLFlagName, "http://example.com/oauth2/callback",
			"--" + googleProviderFlagName, oidcURL,
			"--" + googleClientIDFlagName, uuid.New().String(),
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
	})
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

	t.Run("missing docs sds url arg", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(oidcURL), docsSDSURLFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.EqualError(t, err,
			"Neither sds-docs-url (command line flag) nor AUTH_REST_SDS_DOCS_URL (environment variable) have been set.")
	})

	t.Run("missing keys sds url arg", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(oidcURL), opsKeysSDSURLFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.EqualError(t, err,
			"Neither sds-opskeys-url (command line flag) nor AUTH_REST_SDS_OPSKEYS_URL (environment variable) have been set.") // nolint:lll
	})

	t.Run("missing auth keyserver url arg", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(oidcURL), authKeyServerURLFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.EqualError(t, err,
			"Neither ks-auth-url (command line flag) nor AUTH_REST_KEYSERVER_AUTH_URL (environment variable) have been set.") // nolint:lll
	})

	t.Run("missing ops keyserver url arg", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(oidcURL), opsKeyServerURLFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.EqualError(t, err,
			"Neither ks-ops-url (command line flag) nor AUTH_REST_KEYSERVER_OPS_URL (environment variable) have been set.") // nolint:lll
	})

	t.Run("missing secrets token", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(oidcURL), secretsAPITokenFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.EqualError(t, err, "Neither secrets-api-token (command line flag) nor AUTH_REST_API_TOKEN (environment variable) have been set.") // nolint:lll
	})

	t.Run("uses default depTimeout", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(oidcURL), depTimeoutFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.NoError(t, err)
	})

	t.Run("malformed dep timeout value", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(oidcURL), depTimeoutFlagName, "INVALID")
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.EqualError(t, err, `strconv.ParseUint: parsing "INVALID": invalid syntax`)
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

func TestUIHandler(t *testing.T) {
	t.Run("handle base path", func(t *testing.T) {
		handled := false
		uiHandler(uiEndpoint, func(_ http.ResponseWriter, _ *http.Request, path string) {
			handled = true
			require.Equal(t, uiEndpoint+"/index.html", path)
		})(nil, &http.Request{URL: &url.URL{Path: uiEndpoint}})
		require.True(t, handled)
	})
	t.Run("handle subpaths", func(t *testing.T) {
		const expected = uiEndpoint + "/css/abc123.css"
		handled := false
		uiHandler(uiEndpoint, func(_ http.ResponseWriter, _ *http.Request, path string) {
			handled = true
			require.Equal(t, expected, path)
		})(nil, &http.Request{URL: &url.URL{Path: expected}})
		require.True(t, handled)
	})
}

func TestStartCmdValidArgs(t *testing.T) {
	t.Run("In-memory storage, valid log level", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := allArgs(oidcURL)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.NoError(t, err)
		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})
	t.Run("Invalid log level - default to info", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(oidcURL), logLevelFlagName, "INVALID")
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
	})

	t.Run("server failure", func(t *testing.T) {
		expected := errors.New("test")
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{err: expected})

		args := allArgs(oidcURL)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestInvalidArgs(t *testing.T) {
	t.Run("missing hydra URL param", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(oidcURL), hydraURLFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.EqualError(t, err,
			"Neither hydra-url (command line flag) nor AUTH_REST_HYDRA_URL (environment variable) have been set.")
	})

	t.Run("malformed hydra URL param", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(oidcURL), hydraURLFlagName, ":malformed_url")

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.EqualError(t, err, `failed to parse hydra url: parse ":malformed_url": missing protocol scheme`)
	})

	t.Run("non-bool bool variable", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(oidcURL), deviceSystemCertPoolFlagName, "non-bool-value")
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid syntax")
	})
}

func TestStartCmdFailToCreateController(t *testing.T) {
	t.Run("CouchDB storage", func(t *testing.T) {
		oidcURL := mockOIDCProvider(t)
		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(oidcURL), databaseURLFlagName, "INVALID")
		args = overrideArg(args, databaseTypeFlagName, "couchdb")
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)

		containsLookupFailureErrMsg := strings.Contains(err.Error(), "Temporary failure in name resolution") ||
			strings.Contains(err.Error(), "no such host")

		require.True(t, containsLookupFailureErrMsg)
	})
}

func TestStartCmdInvalidDatabaseType(t *testing.T) {
	oidcURL := mockOIDCProvider(t)
	startCmd := GetStartCmd(&mockServer{})

	args := overrideArg(allArgs(oidcURL), databaseTypeFlagName, "ChesterfieldDB")

	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.EqualError(t, err,
		"ChesterfieldDB is not a valid database type. Run start --help to see the available options")
}

func TestHealthCheck(t *testing.T) {
	b := &httptest.ResponseRecorder{}
	healthCheckHandler(b, nil)

	require.Equal(t, http.StatusOK, b.Code)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t)

	defer unsetEnvVars(t)

	err := startCmd.Execute()
	require.NoError(t, err)
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t)

	defer unsetEnvVars(t)
	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func Test_createProvider(t *testing.T) {
	t.Run("Valid CouchDB URL", func(t *testing.T) {
		provider, err := createProvider(&authRestParameters{
			databaseType: databaseTypeCouchDBOption,
			databaseURL:  "localhost:5984",
		})

		require.NoError(t, err)
		require.NotNil(t, provider)
	})
	t.Run("Empty CouchDB URL", func(t *testing.T) {
		provider, err := createProvider(&authRestParameters{
			databaseType:   databaseTypeCouchDBOption,
			databaseURL:    "",
			startupTimeout: 1,
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "hostURL for new CouchDB provider can't be blank")
		require.Nil(t, provider)
	})
}

func setEnvVars(t *testing.T) {
	oidcURL := mockOIDCProvider(t)

	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)
	err = os.Setenv(databaseTypeEnvKey, "mem")
	require.Nil(t, err)
	err = os.Setenv(oidcCallbackURLEnvKey, "http://example.com/oauth2/callback")
	require.NoError(t, err)
	err = os.Setenv(googleProviderEnvKey, oidcURL)
	require.NoError(t, err)
	err = os.Setenv(googleClientIDEnvKey, uuid.New().String())
	require.NoError(t, err)
	err = os.Setenv(googleClientSecretEnvKey, uuid.New().String())
	require.NoError(t, err)
	err = os.Setenv(docsSDSURLEnvKey, "http://docs.sds.example.com")
	require.NoError(t, err)
	err = os.Setenv(opsKeysSDSURLEnvKey, "https://keys.sds.example.com")
	require.NoError(t, err)
	err = os.Setenv(authKeyServerURLEnvKey, "http://auth.keyserver.example.com")
	require.NoError(t, err)
	err = os.Setenv(opsKeyServerURLEnvKey, "http://ops.keyserver.example.com")
	require.NoError(t, err)
	err = os.Setenv(hydraURLEnvKey, "http://hydra.example.com")
	require.NoError(t, err)
	err = os.Setenv(secretsAPITokenEnvKey, uuid.New().String())
	require.NoError(t, err)
	err = os.Setenv(depTimeoutEnvKey, "1")
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	vars := []string{
		hostURLEnvKey,
		databaseTypeEnvKey,
		oidcCallbackURLEnvKey,
		googleProviderEnvKey,
		googleClientIDEnvKey,
		googleClientSecretEnvKey,
		docsSDSURLEnvKey,
		opsKeysSDSURLEnvKey,
		authKeyServerURLEnvKey,
		opsKeyServerURLEnvKey,
		hydraURLEnvKey,
	}

	for _, envVar := range vars {
		err := os.Unsetenv(envVar)
		require.NoError(t, err)
	}
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

func mockOIDCProvider(t *testing.T) string {
	h := &testOIDCProvider{}
	srv := httptest.NewServer(h)
	h.baseURL = srv.URL

	t.Cleanup(srv.Close)

	return srv.URL
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

func allArgs(oidcURL string) []string {
	return []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + logLevelFlagName, log.ParseString(log.DEBUG),
		"--" + databaseTypeFlagName, "mem",
		"--" + databaseURLFlagName, "test",
		"--" + oidcCallbackURLFlagName, "http://example.com/oauth2/callback",
		"--" + googleProviderFlagName, oidcURL,
		"--" + googleClientIDFlagName, uuid.New().String(),
		"--" + googleClientSecretFlagName, uuid.New().String(),
		"--" + docsSDSURLFlagName, "http://docs.sds.example.com",
		"--" + opsKeysSDSURLFlagName, "https://keys.sds.example.com",
		"--" + authKeyServerURLFlagName, "https://auth.keyserver.example.com",
		"--" + opsKeyServerURLFlagName, "http://ops.keyserver.example.com",
		"--" + hydraURLFlagName, "http://hydra.example.com",
		"--" + secretsAPITokenFlagName, uuid.New().String(),
		"--" + deviceSystemCertPoolFlagName, "true",
		"--" + depTimeoutFlagName, "1",
	}
}

func excludeArg(args []string, arg string) []string {
	filtered := make([]string, 0)

	i := 0

	for i < len(args) {
		if args[i] == "--"+arg {
			i += 2

			continue
		}

		filtered = append(filtered, args[i])
		i++
	}

	return filtered
}

func overrideArg(args []string, name, value string) []string {
	overridden := make([]string, len(args))

	i := 0

	for i < len(args) {
		if args[i] == "--"+name {
			args[i+1] = value
		}

		overridden[i] = args[i]
		i++
	}

	return overridden
}
