/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/spf13/cobra"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the auth-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "AUTH_REST_HOST_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "AUTH_REST_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "AUTH_REST_TLS_CACERTS"

	logLevelFlagName        = "log-level"
	logLevelEnvKey          = "LOG_LEVEL"
	logLevelFlagShorthand   = "l"
	logLevelPrefixFlagUsage = "Default logging level to set. Supported options: CRITICAL, ERROR, WARNING, INFO, DEBUG." +
		`Defaults to info if not set. Setting to debug may adversely impact performance. Alternatively, this can be ` +
		"set with the following environment variable: " + logLevelEnvKey

	// OIDC flags
	oidcProviderURLFlagName  = "oidc-opurl"
	oidcProviderURLFlagUsage = "URL for the OIDC provider." +
		" Alternatively, this can be set with the following environment variable: " + oidcProviderURLEnvKey
	oidcProviderURLEnvKey = "HUB_AUTH_OIDC_OPURL"

	oidcClientIDFlagName  = "oidc-clientid"
	oidcClientIDFlagUsage = "OAuth2 client_id for OIDC." +
		" Alternatively, this can be set with the following environment variable: " + oidcProviderURLEnvKey
	oidcClientIDEnvKey = "HUB_AUTH_OIDC_CLIENTID"

	oidcClientSecretFlagName  = "oidc-clientsecret" //nolint:gosec
	oidcClientSecretFlagUsage = "OAuth2 client secret for OIDC." +
		" Alternatively, this can be set with the following environment variable: " + oidcClientSecretEnvKey
	oidcClientSecretEnvKey = "HUB_AUTH_OIDC_CLIENTSECRET" //nolint:gosec

	oidcCallbackURLFlagName  = "oidc-callback"
	oidcCallbackURLFlagUsage = "Base URL for the OAuth2 callback endpoints." +
		" Alternatively, this can be set with the following environment variable: " + oidcCallbackURLEnvKey
	oidcCallbackURLEnvKey = "HUB_AUTH_OIDC_CALLBACK"
)

const (
	// api
	healthCheckEndpoint = "/healthcheck"
)

var logger = log.New("auth-rest")

type authRestParameters struct {
	srv               server
	hostURL           string
	tlsSystemCertPool bool
	tlsCACerts        []string
	logLevel          string
	oidcParameters    *oidcParameters
}

type healthCheckResp struct {
	Status      string    `json:"status"`
	CurrentTime time.Time `json:"currentTime"`
}

type oidcParameters struct {
	oidcProviderURL  string
	oidcClientID     string
	oidcClientSecret string
	oidcCallbackURL  string
}

type server interface {
	ListenAndServe(host string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler) error {
	return http.ListenAndServe(host, router)
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start auth-rest",
		Long:  "Start auth-rest inside the hub-auth",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getAuthRestParameters(cmd, srv)
			if err != nil {
				return err
			}

			return startAuthService(parameters)
		},
	}
}

func getOIDCParameters(cmd *cobra.Command) (*oidcParameters, error) {
	oidcProviderURL, err := cmdutils.GetUserSetVarFromString(cmd, oidcProviderURLFlagName, oidcProviderURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	oidcClientID, err := cmdutils.GetUserSetVarFromString(cmd, oidcClientIDFlagName, oidcClientIDEnvKey, true)
	if err != nil {
		return nil, err
	}

	oidcClientSecret, err := cmdutils.GetUserSetVarFromString(
		cmd, oidcClientSecretFlagName, oidcClientSecretEnvKey, true)
	if err != nil {
		return nil, err
	}

	oidcCallbackURL, err := cmdutils.GetUserSetVarFromString(cmd, oidcCallbackURLFlagName, oidcCallbackURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &oidcParameters{
		oidcProviderURL:  oidcProviderURL,
		oidcClientID:     oidcClientID,
		oidcClientSecret: oidcClientSecret,
		oidcCallbackURL:  oidcCallbackURL,
	}, nil
}

func getAuthRestParameters(cmd *cobra.Command, srv server) (*authRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPool, tlsCACerts, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	oidcParams, err := getOIDCParameters(cmd)
	if err != nil {
		return nil, err
	}

	loggingLevel, err := cmdutils.GetUserSetVarFromString(cmd, logLevelFlagName, logLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &authRestParameters{
		srv:               srv,
		hostURL:           strings.TrimSpace(hostURL),
		tlsSystemCertPool: tlsSystemCertPool,
		tlsCACerts:        tlsCACerts,
		logLevel:          loggingLevel,
		oidcParameters:    oidcParams,
	}, nil
}

func getTLS(cmd *cobra.Command) (bool, []string, error) {
	tlsSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey, true)
	if err != nil {
		return false, nil, err
	}

	tlsSystemCertPool := false
	if tlsSystemCertPoolString != "" {
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return false, nil, err
		}
	}

	tlsCACerts, err := cmdutils.GetUserSetVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey, true)
	if err != nil {
		return false, nil, err
	}

	return tlsSystemCertPool, tlsCACerts, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(logLevelFlagName, logLevelFlagShorthand, "", logLevelPrefixFlagUsage)
	startCmd.Flags().StringP(oidcProviderURLFlagName, "", "", oidcProviderURLFlagUsage)
	startCmd.Flags().StringP(oidcClientIDFlagName, "", "", oidcClientIDFlagUsage)
	startCmd.Flags().StringP(oidcClientSecretFlagName, "", "", oidcClientSecretFlagUsage)
	startCmd.Flags().StringP(oidcCallbackURLFlagName, "", "", oidcCallbackURLFlagUsage)
}

func startAuthService(parameters *authRestParameters) error {
	if parameters.logLevel != "" {
		setDefaultLogLevel(parameters.logLevel)
	}

	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	logger.Infof("root ca's %v", rootCAs)

	router := mux.NewRouter()

	// health check
	router.HandleFunc(healthCheckEndpoint, healthCheckHandler).Methods(http.MethodGet)

	for _, handler := range logspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("starting auth rest server on host %s", parameters.hostURL)

	return parameters.srv.ListenAndServe(parameters.hostURL, constructCORSHandler(router))
}

func setDefaultLogLevel(userLogLevel string) {
	logLevel, err := log.ParseLevel(userLogLevel)
	if err != nil {
		logger.Warnf(`%s is not a valid logging level. It must be one of the following: `+
			log.ParseString(log.CRITICAL)+", "+
			log.ParseString(log.ERROR)+", "+
			log.ParseString(log.WARNING)+", "+
			log.ParseString(log.INFO)+", "+
			log.ParseString(log.DEBUG)+". Defaulting to info.", userLogLevel)

		logLevel = log.INFO
	} else if logLevel == log.DEBUG {
		logger.Infof(`Log level set to "debug". Performance may be adversely impacted.`)
	}

	log.SetLevel("", logLevel)
}

func constructCORSHandler(handler http.Handler) http.Handler {
	return cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost},
			AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization"},
		},
	).Handler(handler)
}

func healthCheckHandler(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusOK)

	err := json.NewEncoder(rw).Encode(&healthCheckResp{
		Status:      "success",
		CurrentTime: time.Now(),
	})
	if err != nil {
		logger.Errorf("healthcheck response failure, %s", err)
	}
}
