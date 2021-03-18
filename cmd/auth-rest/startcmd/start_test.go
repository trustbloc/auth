/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
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

func (s *mockServer) ListenAndServe(host, certFile, keyFile string, handler http.Handler) error {
	return s.err
}

func TestOIDCParameters(t *testing.T) {
	t.Run("error on missing callback URL", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(t), oidcCallbackURLFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
	})

	t.Run("error on missing oidc providers config file", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(t), oidcProvidersConfigFileFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.EqualError(t, err,
			"Neither oidcProviderConfigFile (command line flag) nor AUTH_REST_OIDC_PROVIDERS_CONFIG (environment variable) have been set.") // nolint:lll
	})

	t.Run("error on invalid oidc providers config file name", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(t), oidcProvidersConfigFileFlagName, "INVALID")
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.EqualError(t, err,
			"failed to read oidc providers config file INVALID: open INVALID: no such file or directory")
	})

	t.Run("error on invalid oidc providers config file format", func(t *testing.T) {
		file, err := ioutil.TempFile("", "")
		require.NoError(t, err)
		err = ioutil.WriteFile(file.Name(), []byte("}INVALID"), os.ModeAppend)
		require.NoError(t, err)

		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(t), oidcProvidersConfigFileFlagName, file.Name())
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse contents")
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
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(t), docsSDSURLFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.EqualError(t, err,
			"Neither sds-docs-url (command line flag) nor AUTH_REST_SDS_DOCS_URL (environment variable) have been set.")
	})

	t.Run("missing keys sds url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(t), opsKeysSDSURLFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.EqualError(t, err,
			"Neither sds-opskeys-url (command line flag) nor AUTH_REST_SDS_OPSKEYS_URL (environment variable) have been set.") // nolint:lll
	})

	t.Run("missing auth keyserver url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(t), authKeyServerURLFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.EqualError(t, err,
			"Neither ks-auth-url (command line flag) nor AUTH_REST_KEYSERVER_AUTH_URL (environment variable) have been set.") // nolint:lll
	})

	t.Run("missing ops keyserver url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(t), opsKeyServerURLFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.EqualError(t, err,
			"Neither ks-ops-url (command line flag) nor AUTH_REST_KEYSERVER_OPS_URL (environment variable) have been set.") // nolint:lll
	})

	t.Run("missing secrets token", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(t), secretsAPITokenFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.EqualError(t, err, "Neither secrets-api-token (command line flag) nor AUTH_REST_API_TOKEN (environment variable) have been set.") // nolint:lll
	})

	t.Run("uses default depTimeout", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(t), depTimeoutFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.NoError(t, err)
	})

	t.Run("malformed dep timeout value", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(t), depTimeoutFlagName, "INVALID")
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
		startCmd := GetStartCmd(&mockServer{})

		args := allArgs(t)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.NoError(t, err)
		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})
	t.Run("Invalid log level - default to info", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(t), logLevelFlagName, "INVALID")
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
	})

	t.Run("server failure", func(t *testing.T) {
		expected := errors.New("test")
		startCmd := GetStartCmd(&mockServer{err: expected})

		args := allArgs(t)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestInvalidArgs(t *testing.T) {
	t.Run("missing hydra URL param", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := excludeArg(allArgs(t), hydraURLFlagName)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.EqualError(t, err,
			"Neither hydra-url (command line flag) nor AUTH_REST_HYDRA_URL (environment variable) have been set.")
	})

	t.Run("malformed hydra URL param", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(t), hydraURLFlagName, ":malformed_url")

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.EqualError(t, err, `failed to parse hydra url: parse ":malformed_url": missing protocol scheme`)
	})

	t.Run("non-bool bool variable", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(t), deviceSystemCertPoolFlagName, "non-bool-value")
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid syntax")
	})

	t.Run("session cookie auth key", func(t *testing.T) {
		t.Run("missing config", func(t *testing.T) {
			startCmd := GetStartCmd(&mockServer{})

			args := excludeArg(allArgs(t), sessionCookieAuthKeyFlagName)
			startCmd.SetArgs(args)

			err := startCmd.Execute()

			require.Error(t, err)
			require.Contains(t, err.Error(),
				"Neither cookie-auth-key (command line flag) nor AUTH_REST_COOKIE_AUTH_KEY (environment variable) have been set.") // nolint:lll
		})

		t.Run("non-existent file path", func(t *testing.T) {
			startCmd := GetStartCmd(&mockServer{})

			args := overrideArg(allArgs(t), sessionCookieAuthKeyFlagName, "NON-EXISTENT")
			startCmd.SetArgs(args)

			err := startCmd.Execute()

			require.Error(t, err)
			require.Contains(t, err.Error(),
				"failed to read file NON-EXISTENT: open NON-EXISTENT: no such file or directory")
		})

		t.Run("invalid key", func(t *testing.T) {
			startCmd := GetStartCmd(&mockServer{})

			args := overrideArg(allArgs(t), sessionCookieAuthKeyFlagName, invalidKey(t))
			startCmd.SetArgs(args)

			err := startCmd.Execute()

			require.Error(t, err)
			require.Contains(t, err.Error(), "need key of 256 bits but got")
		})
	})

	t.Run("session cookie enc key", func(t *testing.T) {
		t.Run("missing config", func(t *testing.T) {
			startCmd := GetStartCmd(&mockServer{})

			args := excludeArg(allArgs(t), sessionCookieEncKeyFlagName)
			startCmd.SetArgs(args)

			err := startCmd.Execute()

			require.Error(t, err)
			require.Contains(t, err.Error(),
				"Neither cookie-enc-key (command line flag) nor AUTH_REST_COOKIE_ENC_KEY (environment variable) have been set.") // nolint:lll
		})

		t.Run("non-existent file path", func(t *testing.T) {
			startCmd := GetStartCmd(&mockServer{})

			args := overrideArg(allArgs(t), sessionCookieEncKeyFlagName, "NON-EXISTENT")
			startCmd.SetArgs(args)

			err := startCmd.Execute()

			require.Error(t, err)
			require.Contains(t, err.Error(),
				"failed to read file NON-EXISTENT: open NON-EXISTENT: no such file or directory")
		})

		t.Run("invalid key", func(t *testing.T) {
			startCmd := GetStartCmd(&mockServer{})

			args := overrideArg(allArgs(t), sessionCookieEncKeyFlagName, invalidKey(t))
			startCmd.SetArgs(args)

			err := startCmd.Execute()

			require.Error(t, err)
			require.Contains(t, err.Error(), "need key of 256 bits but got")
		})
	})
}

func TestStartCmdFailToCreateController(t *testing.T) {
	t.Run("CouchDB storage", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := overrideArg(allArgs(t), databaseURLFlagName, "INVALID")
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
	startCmd := GetStartCmd(&mockServer{})

	args := overrideArg(allArgs(t), databaseTypeFlagName, "ChesterfieldDB")

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
	t.Run("Empty CouchDB URL", func(t *testing.T) {
		provider, err := createProvider(&authRestParameters{
			databaseType:   databaseTypeCouchDBOption,
			databaseURL:    "",
			startupTimeout: 1,
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to ping couchDB: url can't be blank")
		require.Nil(t, provider)
	})
}

func setEnvVars(t *testing.T) {
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)
	err = os.Setenv(databaseTypeEnvKey, "mem")
	require.Nil(t, err)
	err = os.Setenv(oidcCallbackURLEnvKey, "http://example.com/oauth2/callback")
	require.NoError(t, err)
	err = os.Setenv(oidcProvidersConfigFileEnvKey, oidcProvConfig(t))
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
	err = os.Setenv(sessionCookieAuthKeyEnvKey, key(t))
	require.NoError(t, err)
	err = os.Setenv(sessionCookieEncKeyEnvKey, key(t))
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	vars := []string{
		hostURLEnvKey,
		databaseTypeEnvKey,
		oidcCallbackURLEnvKey,
		oidcProvidersConfigFileEnvKey,
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

func allArgs(t *testing.T) []string {
	return []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + logLevelFlagName, log.ParseString(log.DEBUG),
		"--" + databaseTypeFlagName, "mem",
		"--" + databaseURLFlagName, "test",
		"--" + oidcCallbackURLFlagName, "http://example.com/oauth2/callback",
		"--" + oidcProvidersConfigFileFlagName, oidcProvConfig(t),
		"--" + docsSDSURLFlagName, "http://docs.sds.example.com",
		"--" + opsKeysSDSURLFlagName, "https://keys.sds.example.com",
		"--" + authKeyServerURLFlagName, "https://auth.keyserver.example.com",
		"--" + opsKeyServerURLFlagName, "http://ops.keyserver.example.com",
		"--" + hydraURLFlagName, "http://hydra.example.com",
		"--" + secretsAPITokenFlagName, uuid.New().String(),
		"--" + deviceSystemCertPoolFlagName, "true",
		"--" + depTimeoutFlagName, "1",
		"--" + sessionCookieAuthKeyFlagName, key(t),
		"--" + sessionCookieEncKeyFlagName, key(t),
	}
}

func oidcProvConfig(t *testing.T) string {
	config, err := json.Marshal(&oidcProvidersConfig{
		Providers: map[string]*oidcProviderConfig{
			"provider1": {
				URL:          mockOIDCProvider(t),
				ClientID:     uuid.New().String(),
				ClientSecret: uuid.New().String(),
			},
			"provider2": {
				URL:          mockOIDCProvider(t),
				ClientID:     uuid.New().String(),
				ClientSecret: uuid.New().String(),
			},
		},
	})
	require.NoError(t, err)

	file, err := ioutil.TempFile("", "*.yaml")
	require.NoError(t, err)

	t.Cleanup(func() {
		closeErr := file.Close()
		require.NoError(t, closeErr)
	})

	err = ioutil.WriteFile(file.Name(), config, os.ModeAppend)
	require.NoError(t, err)

	return file.Name()
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

func key(t *testing.T) string {
	t.Helper()

	key := make([]byte, 32)

	n, err := rand.Reader.Read(key)
	require.NoError(t, err)
	require.Equal(t, 32, n)

	file, err := ioutil.TempFile("", "test_*.key")
	require.NoError(t, err)

	t.Cleanup(func() {
		delErr := os.Remove(file.Name())
		require.NoError(t, delErr)
	})

	err = ioutil.WriteFile(file.Name(), key, os.ModeAppend)
	require.NoError(t, err)

	return file.Name()
}

func invalidKey(t *testing.T) string {
	t.Helper()

	key := make([]byte, 18)

	n, err := rand.Reader.Read(key)
	require.NoError(t, err)
	require.Equal(t, 18, n)

	file, err := ioutil.TempFile("", "test_*.key")
	require.NoError(t, err)

	t.Cleanup(func() {
		delErr := os.Remove(file.Name())
		require.NoError(t, delErr)
	})

	err = ioutil.WriteFile(file.Name(), key, os.ModeAppend)
	require.NoError(t, err)

	return file.Name()
}
