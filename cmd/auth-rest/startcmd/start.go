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

	logLevelFlagName        = "log-level"
	logLevelEnvKey          = "LOG_LEVEL"
	logLevelFlagShorthand   = "l"
	logLevelPrefixFlagUsage = "Default logging level to set. Supported options: CRITICAL, ERROR, WARNING, INFO, DEBUG." +
		`Defaults to info if not set. Setting to debug may adversely impact performance. Alternatively, this can be ` +
		"set with the following environment variable: " + logLevelEnvKey

	databaseTypeFlagName      = "database-type"
	databaseTypeEnvKey        = "DATABASE_TYPE"
	databaseTypeFlagShorthand = "d"
	databaseTypeFlagUsage     = "The type of database to use for storage. Supported options: mem, couchdb. " +
		" Alternatively, this can be set with the following environment variable: " + databaseTypeEnvKey

	databaseURLFlagName      = "database-url"
	databaseURLEnvKey        = "DATABASE_URL"
	databaseURLFlagShorthand = "r"
	databaseURLFlagUsage     = "The URL of the database. Not needed if using memstore." +
		" For CouchDB, include the username:password@ text if required." +
		" Alternatively, this can be set with the following environment variable: " + databaseURLEnvKey

	databasePrefixFlagName      = "database-prefix"
	databasePrefixEnvKey        = "DATABASE_PREFIX"
	databasePrefixFlagShorthand = "p"
	databasePrefixFlagUsage     = "An optional prefix to be used when creating and retrieving databases." +
		" This followed by an underscore will be prepended to any databases created by hub-auth. " +
		" Alternatively, this can be set with the following environment variable: " + databasePrefixEnvKey

	invalidDatabaseTypeErrMsg = "%s is not a valid database type. Run start --help to see the available options"
)

const (
	// api
	healthCheckEndpoint = "/healthcheck"
)

var logger = log.New("auth-rest")

type authRestParameters struct {
	hostURL           string
	tlsSystemCertPool bool
	tlsCACerts        []string
	logLevel          string
	databaseType      string
	databaseURL       string
	databasePrefix    string
}

type healthCheckResp struct {
	Status      string    `json:"status"`
	CurrentTime time.Time `json:"currentTime"`
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

	tlsSystemCertPool, tlsCACerts, err := getTLS(cmd)
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

	return &authRestParameters{
		hostURL:           hostURL,
		tlsSystemCertPool: tlsSystemCertPool,
		tlsCACerts:        tlsCACerts,
		logLevel:          loggingLevel,
		databaseType:      databaseType,
		databaseURL:       databaseURL,
		databasePrefix:    databasePrefix,
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

	tlsCACerts, err := cmdutils.GetUserSetVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey, true)
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
	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, databaseURLFlagShorthand, "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, databasePrefixFlagShorthand, "", databasePrefixFlagUsage)
}

func startAuthService(parameters *authRestParameters, srv server) error {
	if parameters.logLevel != "" {
		setDefaultLogLevel(parameters.logLevel)
	}

	provider, err := createProvider(parameters)
	if err != nil {
		return err
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

	// TODO #34 add the handlers from this controller to the router so that the endpoints are reachable
	_, err = restapi.New(&operation.Config{Provider: provider})
	if err != nil {
		return err
	}

	logger.Infof(`Starting hub-auth REST server with the following parameters: 
Host URL: %s
Database type: %s
Database URL: %s
Database prefix: %s`, parameters.hostURL, parameters.databaseType, parameters.databaseURL, parameters.databasePrefix)

	return srv.ListenAndServe(parameters.hostURL, constructCORSHandler(router))
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
