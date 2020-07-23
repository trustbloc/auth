/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
)

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
	t.Run("In-memory storage, valid log level", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + logLevelFlagName, log.ParseString(log.DEBUG),
			"--" + databaseTypeFlagName, "mem"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Nil(t, err)
		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})
	t.Run("Invalid log level - default to info", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + logLevelFlagName, "cherry",
			"--" + databaseTypeFlagName, "mem"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func TestStartCmdFailToCreateController(t *testing.T) {
	t.Run("CouchDB storage", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "couchdb",
			"--" + databaseURLFlagName, "BadURL"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.NotNil(t, err)

		containsLookupFailureErrMsg := strings.Contains(err.Error(), "Temporary failure in name resolution") ||
			strings.Contains(err.Error(), "no such host")

		require.True(t, containsLookupFailureErrMsg)
	})
}

func TestStartCmdInvalidDatabaseType(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + logLevelFlagName, log.ParseString(log.DEBUG),
		"--" + databaseTypeFlagName, "ChesterfieldDB"}
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
			databaseType: databaseTypeCouchDBOption,
			databaseURL:  "",
		})

		require.EqualError(t, err, "hostURL for new CouchDB provider can't be blank")
		require.Nil(t, provider)
	})
}

func setEnvVars(t *testing.T) {
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)
	err = os.Setenv(databaseTypeEnvKey, "mem")
	require.Nil(t, err)
}

func unsetEnvVars(t *testing.T) {
	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)
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
