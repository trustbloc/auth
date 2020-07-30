/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	"github.com/trustbloc/edge-core/pkg/storage"
	couchdbstore "github.com/trustbloc/edge-core/pkg/storage/couchdb"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/hub-auth/pkg/restapi"
	"github.com/trustbloc/hub-auth/pkg/restapi/operation"
)

// General parameters.
const (
	databaseTypeMemOption     = "mem"
	databaseTypeCouchDBOption = "couchdb"

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

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = "AUTH_REST_TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = "AUTH_REST_TLS_SERVE_KEY"

	logLevelFlagName        = "log-level"
	logLevelEnvKey          = "AUTH_REST_LOG_LEVEL"
	logLevelFlagShorthand   = "l"
	logLevelPrefixFlagUsage = "Default logging level to set. Supported options: CRITICAL, ERROR, WARNING, INFO, DEBUG." +
		`Defaults to info if not set. Setting to debug may adversely impact performance. Alternatively, this can be ` +
		"set with the following environment variable: " + logLevelEnvKey

	databaseTypeFlagName      = "database-type"
	databaseTypeEnvKey        = "AUTH_REST_DATABASE_TYPE"
	databaseTypeFlagShorthand = "d"
	databaseTypeFlagUsage     = "The type of database to use for storage. Supported options: mem, couchdb. " +
		" Alternatively, this can be set with the following environment variable: " + databaseTypeEnvKey

	databaseURLFlagName      = "database-url"
	databaseURLEnvKey        = "AUTH_REST_DATABASE_URL"
	databaseURLFlagShorthand = "r"
	databaseURLFlagUsage     = "The URL of the database. Not needed if using memstore." +
		" For CouchDB, include the username:password@ text if required." +
		" Alternatively, this can be set with the following environment variable: " + databaseURLEnvKey

	databasePrefixFlagName      = "database-prefix"
	databasePrefixEnvKey        = "AUTH_REST_DATABASE_PREFIX"
	databasePrefixFlagShorthand = "p"
	databasePrefixFlagUsage     = "An optional prefix to be used when creating and retrieving databases." +
		" This followed by an underscore will be prepended to any databases created by hub-auth. " +
		" Alternatively, this can be set with the following environment variable: " + databasePrefixEnvKey

	invalidDatabaseTypeErrMsg = "%s is not a valid database type. Run start --help to see the available options"
)

// OIDC parameters.
const (
	// assumed to be the same landing page for all callbacks from all OIDC providers
	oidcCallbackURLFlagName  = "oidcCallbackURL"
	oidcCallbackURLFlagUsage = "Base URL for the OIDC callback endpoint." +
		" Alternatively, this can be set with the following environment variable: " + oidcCallbackURLEnvKey
	oidcCallbackURLEnvKey = "AUTH_REST_OIDC_CALLBACK"

	googleProviderFlagName  = "googleURL"
	googleProviderFlagUsage = "URL for Google's OIDC provider (should be 'https://accounts.google.com')." +
		" Alternatively, this can be set with the following environment variable: " + googleProviderEnvKey
	googleProviderEnvKey = "AUTH_REST_GOOGLE_URL"

	googleClientIDFlagName  = "googleClientID"
	googleClientIDFlagUsage = "ClientID issued by Google for use with hub-auth." +
		" For info on how to set it up: https://developers.google.com/identity/protocols/oauth2/openid-connect." +
		" Alternatively, this can be set with the following environment variable: " + googleClientIDEnvKey
	googleClientIDEnvKey = "AUTH_REST_GOOGLE_CLIENTID"

	googleClientSecretFlagName  = "googleClientSecret"
	googleClientSecretFlagUsage = "ClientSecret issued by Google for use with hub-auth." +
		" Alternatively, this can be set with the following environment variable: " + googleClientSecretEnvKey
	googleClientSecretEnvKey = "AUTH_REST_GOOGLE_CLIENTSECRET" // nolint:gosec
)

// Bootstrap parameters.
const (
	sdsURLFlagName  = "sds-url"
	sdsURLFlagUsage = "URL for the Secure Data Storage service." +
		" Alternatively, this can be set with the following environment variable: " + sdsURLEnvKey
	sdsURLEnvKey = "AUTH_REST_SDS_URL"

	keyServerURLFlagName  = "ks-url"
	keyServerURLFlagUsage = "URL for the Key Server." +
		" Alternatively, this can be set with the following environment variable: " + keyServerURLEnvKey
	keyServerURLEnvKey = "AUTH_REST_KEYSERVER_URL"
)

const (
	// api
	healthCheckEndpoint = "/healthcheck"
)

var logger = log.New("auth-rest")

type authRestParameters struct {
	hostURL         string
	logLevel        string
	databaseType    string
	databaseURL     string
	databasePrefix  string
	tlsParams       *tlsParams
	oidcParams      *oidcParams
	bootstrapParams *bootstrapParams
}

type tlsParams struct {
	useSystemCertPool bool
	caCerts           []string
	serveCertPath     string
	serveKeyPath      string
}

type oidcParams struct {
	baseCallbackURL string
	google          *oidcProviderParams
}

type oidcProviderParams struct {
	providerURL  string
	clientID     string
	clientSecret string
}

type bootstrapParams struct {
	sdsURL       string
	keyServerURL string
}

type healthCheckResp struct {
	Status      string    `json:"status"`
	CurrentTime time.Time `json:"currentTime"`
}

type server interface {
	ListenAndServeTLS(host, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServeTLS starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServeTLS(host, certFile, keyFile string, router http.Handler) error {
	return http.ListenAndServeTLS(host, certFile, keyFile, router)
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
			parameters, err := getAuthRestParameters(cmd)
			if err != nil {
				return err
			}

			return startAuthService(parameters, srv)
		},
	}
}

func getAuthRestParameters(cmd *cobra.Command) (*authRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	loggingLevel, err := cmdutils.GetUserSetVarFromString(cmd, logLevelFlagName, logLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	databaseType, err := cmdutils.GetUserSetVarFromString(cmd, databaseTypeFlagName, databaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	var databaseURL string
	if databaseType == databaseTypeMemOption {
		databaseURL = "N/A"
	} else {
		var errGetUserSetVar error
		databaseURL, errGetUserSetVar = cmdutils.GetUserSetVarFromString(cmd, databaseURLFlagName, databaseURLEnvKey, true)
		if errGetUserSetVar != nil {
			return nil, errGetUserSetVar
		}
	}

	databasePrefix, err := cmdutils.GetUserSetVarFromString(cmd, databasePrefixFlagName, databasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	oidcParams, err := getOIDCParams(cmd)
	if err != nil {
		return nil, err
	}

	bootstrapParams, err := getBootstrapParams(cmd)
	if err != nil {
		return nil, err
	}

	return &authRestParameters{
		hostURL:         hostURL,
		tlsParams:       tlsParams,
		logLevel:        loggingLevel,
		databaseType:    databaseType,
		databaseURL:     databaseURL,
		databasePrefix:  databasePrefix,
		oidcParams:      oidcParams,
		bootstrapParams: bootstrapParams,
	}, nil
}

func getTLS(cmd *cobra.Command) (*tlsParams, error) {
	params := &tlsParams{
		useSystemCertPool: false,
	}

	useSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey, true)
	if err != nil {
		return nil, err
	}

	if useSystemCertPoolString != "" {
		params.useSystemCertPool, err = strconv.ParseBool(useSystemCertPoolString)
		if err != nil {
			return nil, err
		}
	}

	params.caCerts, err = cmdutils.GetUserSetVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey, true)
	if err != nil {
		return nil, err
	}

	params.serveCertPath, err = cmdutils.GetUserSetVarFromString(cmd,
		tlsServeCertPathFlagName, tlsServeCertPathEnvKey, true)
	if err != nil {
		return nil, err
	}

	params.serveKeyPath, err = cmdutils.GetUserSetVarFromString(cmd,
		tlsServeKeyPathFlagName, tlsServeKeyPathFlagEnvKey, true)

	return params, err
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	startCmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)
	startCmd.Flags().StringP(logLevelFlagName, logLevelFlagShorthand, "", logLevelPrefixFlagUsage)
	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, databaseURLFlagShorthand, "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, databasePrefixFlagShorthand, "", databasePrefixFlagUsage)
	startCmd.Flags().StringP(oidcCallbackURLFlagName, "", "", oidcCallbackURLFlagUsage)
	startCmd.Flags().StringP(googleProviderFlagName, "", "", googleProviderFlagUsage)
	startCmd.Flags().StringP(googleClientIDFlagName, "", "", googleClientIDFlagUsage)
	startCmd.Flags().StringP(googleClientSecretFlagName, "", "", googleClientSecretFlagUsage)
	startCmd.Flags().StringP(sdsURLFlagName, "", "", sdsURLFlagUsage)
	startCmd.Flags().StringP(keyServerURLFlagName, "", "", keyServerURLFlagUsage)
}

func startAuthService(parameters *authRestParameters, srv server) error {
	if parameters.logLevel != "" {
		setDefaultLogLevel(parameters.logLevel)
	}

	provider, err := createProvider(parameters)
	if err != nil {
		return err
	}

	rootCAs, err := tlsutils.GetCertPool(parameters.tlsParams.useSystemCertPool, parameters.tlsParams.caCerts)
	if err != nil {
		return err
	}

	logger.Debugf("root ca's %v", rootCAs)

	router := mux.NewRouter()

	// health check
	router.HandleFunc(healthCheckEndpoint, healthCheckHandler).Methods(http.MethodGet)

	for _, handler := range logspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	svc, err := restapi.New(&operation.Config{
		TransientStoreProvider: memstore.NewProvider(),
		StoreProvider:          provider,
		OIDCCallbackURL:        parameters.oidcParams.baseCallbackURL,
		OIDCProviderURL:        parameters.oidcParams.google.providerURL,
		OIDCClientID:           parameters.oidcParams.google.clientID,
		OIDCClientSecret:       parameters.oidcParams.google.clientSecret,
		BootstrapConfig: &operation.BootstrapConfig{
			SDSURL:       parameters.bootstrapParams.sdsURL,
			KeyServerURL: parameters.bootstrapParams.keyServerURL,
		},
	})
	if err != nil {
		return err
	}

	for _, handler := range svc.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof(`Starting hub-auth REST server with the following parameters: 
Host URL: %s
Database type: %s
Database URL: %s
Database prefix: %s`, parameters.hostURL, parameters.databaseType, parameters.databaseURL, parameters.databasePrefix)

	return srv.ListenAndServeTLS(
		parameters.hostURL,
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
		constructCORSHandler(router),
	)
}

func getOIDCParams(cmd *cobra.Command) (*oidcParams, error) {
	params := &oidcParams{}

	var err error

	params.baseCallbackURL, err = cmdutils.GetUserSetVarFromString(cmd,
		oidcCallbackURLFlagName, oidcCallbackURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	params.google, err = getGoogleOIDCParams(cmd)
	if err != nil {
		return nil, fmt.Errorf("misconfigured Google OIDC params: %w", err)
	}

	return params, nil
}

func getGoogleOIDCParams(cmd *cobra.Command) (*oidcProviderParams, error) {
	params := &oidcProviderParams{}

	var err error

	params.providerURL, err = cmdutils.GetUserSetVarFromString(cmd, googleProviderFlagName, googleProviderEnvKey, false)
	if err != nil {
		return nil, err
	}

	params.clientID, err = cmdutils.GetUserSetVarFromString(cmd, googleClientIDFlagName, googleClientIDEnvKey, false)
	if err != nil {
		return nil, err
	}

	params.clientSecret, err = cmdutils.GetUserSetVarFromString(cmd,
		googleClientSecretFlagName, googleClientSecretEnvKey, false)

	return params, err
}

func getBootstrapParams(cmd *cobra.Command) (*bootstrapParams, error) {
	params := &bootstrapParams{}

	var err error

	params.sdsURL, err = cmdutils.GetUserSetVarFromString(cmd, sdsURLFlagName, sdsURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	params.keyServerURL, err = cmdutils.GetUserSetVarFromString(cmd, keyServerURLFlagName, keyServerURLEnvKey, false)

	return params, err
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

func createProvider(parameters *authRestParameters) (storage.Provider, error) {
	var provider storage.Provider

	switch {
	case strings.EqualFold(parameters.databaseType, databaseTypeMemOption):
		provider = memstore.NewProvider()
	case strings.EqualFold(parameters.databaseType, databaseTypeCouchDBOption):
		couchDBProvider, err := couchdbstore.NewProvider(parameters.databaseURL)
		if err != nil {
			return nil, err
		}

		provider = couchDBProvider
	default:
		return nil, fmt.Errorf(invalidDatabaseTypeErrMsg, parameters.databaseType)
	}

	return provider, nil
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
