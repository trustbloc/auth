/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
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
	"gopkg.in/yaml.v2"

	"github.com/trustbloc/auth/pkg/gnap/accesspolicy"
	"github.com/trustbloc/auth/pkg/gnap/interact/redirect"
	"github.com/trustbloc/auth/pkg/restapi"
	"github.com/trustbloc/auth/pkg/restapi/common/hydra"
	"github.com/trustbloc/auth/pkg/restapi/gnap"
	"github.com/trustbloc/auth/pkg/restapi/operation"
)

// General parameters.
const (
	databaseTypeMemOption     = "mem"
	databaseTypeCouchDBOption = "couchdb"
	databaseTypeMySQLOption   = "mysql"
	databaseTypeMongoDBOption = "mongodb"

	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the auth-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "AUTH_REST_HOST_URL"

	externalURLFlagName  = "external-url"
	externalURLEnvKey    = "AUTH_REST_EXTERNAL_URL"
	externalURLFlagUsage = "URL that the auth-rest instance is exposed on. " +
		" Alternatively, this can be set with the following environment variable: " + externalURLEnvKey

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
	databaseTypeFlagUsage     = "The type of database to use for storage. Supported options: mem, couchdb, mysql, " +
		"mongodb. Alternatively, this can be set with the following environment variable: " + databaseTypeEnvKey

	databaseURLFlagName      = "database-url"
	databaseURLEnvKey        = "AUTH_REST_DATABASE_URL"
	databaseURLFlagShorthand = "r"
	databaseURLFlagUsage     = "The URL (or connection string) of the database. Not needed if using memstore." +
		" For CouchDB, include the username:password@ text if required." +
		" Alternatively, this can be set with the following environment variable: " + databaseURLEnvKey

	staticFilesPathFlagName  = "static-path"
	staticFilesPathFlagUsage = "Path to the folder where the static files are to be hosted under " + uiEndpoint + "." +
		"Alternatively, this can be set with the following environment variable: " + staticFilesPathEnvKey
	staticFilesPathEnvKey = "AUTH_REST_STATIC_FILES"

	databasePrefixFlagName      = "database-prefix"
	databasePrefixEnvKey        = "AUTH_REST_DATABASE_PREFIX"
	databasePrefixFlagShorthand = "p"
	databasePrefixFlagUsage     = "An optional prefix to be used when creating and retrieving databases." +
		" Alternatively, this can be set with the following environment variable: " + databasePrefixEnvKey

	invalidDatabaseTypeErrMsg = "%s is not a valid database type. Run start --help to see the available options"

	defaultDepTimeout   = 120
	depTimeoutFlagName  = "startup-timeout"
	depTimeoutFlagUsage = "Optional. Number of seconds to wait for external dependencies to become available." +
		" Only used at startup. Default value is 120s." +
		" Alternatively, this can be set with the following environment variable: " + depTimeoutEnvKey
	depTimeoutEnvKey = "AUTH_REST_DEP_TIMEOUT"
)

// OIDC parameters.
const (
	hydraURLFlagName  = "hydra-url"
	hydraURLFlagUsage = "Base URL to the hydra service." +
		"Alternatively, this can be set with the following environment variable: " + hydraURLEnvKey
	hydraURLEnvKey = "AUTH_REST_HYDRA_URL"

	// assumed to be the same landing page for all callbacks from all OIDC providers.
	oidcCallbackURLFlagName  = "oidcCallbackURL"
	oidcCallbackURLFlagUsage = "Base URL for the OIDC callback endpoint." +
		" Alternatively, this can be set with the following environment variable: " + oidcCallbackURLEnvKey
	oidcCallbackURLEnvKey = "AUTH_REST_OIDC_CALLBACK"

	oidcProvidersConfigFileFlagName  = "oidcProviderConfigFile"
	oidcProvidersConfigFileFlagUsage = "Path to the yaml file with the configured OIDC providers." +
		" Alternatively, this can be set with the following environment variable: " + oidcProvidersConfigFileEnvKey
	oidcProvidersConfigFileEnvKey = "AUTH_REST_OIDC_PROVIDERS_CONFIG"

	oidcStaticImageFolderFlagName  = "oidcStaticImageFolder"
	oidcStaticImageFolderFlagUsage = "Path to static logo images for the oidc providers." +
		" Alternatively, this can be set with the following environment variable: " + oidcStaticImageFolderEnvKey
	oidcStaticImageFolderEnvKey = "AUTH_REST_STATIC_IMAGES"
)

// Device certificate validation parameters.
const (
	deviceSystemCertPoolFlagName  = "device-systemcertpool"
	deviceSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + deviceSystemCertPoolEnvKey
	deviceSystemCertPoolEnvKey = "AUTH_REST_DEVICE_SYSTEMCERTPOOL"

	deviceCACertsFlagName  = "device-cacerts"
	deviceCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + deviceCACertsEnvKey
	deviceCACertsEnvKey = "AUTH_REST_DEVICE_CACERTS"
)

// Bootstrap parameters.
const (
	docsSDSURLFlagName  = "sds-docs-url"
	docsSDSURLFlagUsage = "URL for the Secure Data Storage service for end-user documents." +
		" Alternatively, this can be set with the following environment variable: " + docsSDSURLEnvKey
	docsSDSURLEnvKey = "AUTH_REST_SDS_DOCS_URL"

	opsKeysSDSURLFlagName  = "sds-opskeys-url"
	opsKeysSDSURLFlagUsage = "URL for the Secure Data Storage service for end-user operational keys." +
		" Alternatively, this can be set with the following environment variable: " + opsKeysSDSURLEnvKey
	opsKeysSDSURLEnvKey = "AUTH_REST_SDS_OPSKEYS_URL"

	authKeyServerURLFlagName  = "ks-auth-url"
	authKeyServerURLFlagUsage = "URL for the Auth Key Server." +
		" Alternatively, this can be set with the following environment variable: " + authKeyServerURLEnvKey
	authKeyServerURLEnvKey = "AUTH_REST_KEYSERVER_AUTH_URL"

	opsKeyServerURLFlagName  = "ks-ops-url"
	opsKeyServerURLFlagUsage = "URL for the Ops Key Server." +
		" Alternatively, this can be set with the following environment variable: " + opsKeyServerURLEnvKey
	opsKeyServerURLEnvKey = "AUTH_REST_KEYSERVER_OPS_URL"
)

const (
	// TODO temporary.
	secretsAPITokenFlagName  = "secrets-api-token"
	secretsAPITokenFlagUsage = "Static token used to protect the GET /secrets API." +
		" Alternatively, this can be set with the following environment variable: " + secretsAPITokenEnvKey
	secretsAPITokenEnvKey = "AUTH_REST_API_TOKEN" // nolint:gosec // this is not a hard-coded secret
)

// Keys.
const (
	sessionCookieAuthKeyFlagName  = "cookie-auth-key"
	sessionCookieAuthKeyFlagUsage = "Path to the pem-encoded 32-byte key to use to authenticate session cookies." +
		" Alternatively, this can be set with the following environment variable: " + sessionCookieAuthKeyEnvKey
	sessionCookieAuthKeyEnvKey = "AUTH_REST_COOKIE_AUTH_KEY"

	sessionCookieEncKeyFlagName  = "cookie-enc-key"
	sessionCookieEncKeyFlagUsage = "Path to the pem-encoded 32-byte key to use to encrypt session cookies." +
		" Alternatively, this can be set with the following environment variable: " + sessionCookieEncKeyEnvKey
	sessionCookieEncKeyEnvKey = "AUTH_REST_COOKIE_ENC_KEY"
)

const (
	// api.
	uiEndpoint          = "/ui"
	healthCheckEndpoint = "/healthcheck"
)

var logger = log.New("auth-rest") //nolint:gochecknoglobals

type healthCheckResp struct {
	Status      string    `json:"status"`
	CurrentTime time.Time `json:"currentTime"`
}

type server interface {
	ListenAndServe(host string, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	if certFile == "" || keyFile == "" {
		return http.ListenAndServe(host, router)
	}

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
		Long:  "Start auth-rest inside the auth",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getAuthRestParameters(cmd)
			if err != nil {
				return err
			}

			return startAuthService(parameters, srv)
		},
	}
}

func getAuthRestParameters(cmd *cobra.Command) (*authRestParameters, error) { //nolint:funlen,gocyclo
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	externalURL, err := cmdutils.GetUserSetVarFromString(cmd, externalURLFlagName, externalURLEnvKey, true)
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

	staticFiles, err := cmdutils.GetUserSetVarFromString(cmd, staticFilesPathFlagName, staticFilesPathEnvKey, true)
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

	oidcStaticImages, err := cmdutils.GetUserSetVarFromString(cmd,
		oidcStaticImageFolderFlagName, oidcStaticImageFolderEnvKey, false)
	if err != nil {
		return nil, err
	}

	bootstrapParams, err := getBootstrapParams(cmd)
	if err != nil {
		return nil, err
	}

	deviceCertParams, err := getDeviceCertParams(cmd)
	if err != nil {
		return nil, err
	}

	secretsToken, err := cmdutils.GetUserSetVarFromString(cmd, secretsAPITokenFlagName, secretsAPITokenEnvKey, false)
	if err != nil {
		return nil, err
	}

	timeout, err := getDepTimeout(cmd)
	if err != nil {
		return nil, err
	}

	keys, err := getKeyParams(cmd)
	if err != nil {
		return nil, err
	}

	return &authRestParameters{
		hostURL:          hostURL,
		externalURL:      externalURL,
		tlsParams:        tlsParams,
		logLevel:         loggingLevel,
		databaseType:     databaseType,
		databaseURL:      databaseURL,
		databasePrefix:   databasePrefix,
		oidcParams:       oidcParams,
		bootstrapParams:  bootstrapParams,
		staticFiles:      staticFiles,
		devicecertParams: deviceCertParams,
		startupTimeout:   timeout,
		secretsAPIToken:  secretsToken,
		keys:             keys,
		staticImages:     oidcStaticImages,
	}, nil
}

func getDepTimeout(cmd *cobra.Command) (uint64, error) {
	timeout, err := cmdutils.GetUserSetVarFromString(cmd, depTimeoutFlagName, depTimeoutEnvKey, true)
	if err != nil {
		return 0, fmt.Errorf("failed to read depTimeout config: %w", err)
	}

	if timeout == "" {
		return defaultDepTimeout, nil
	}

	return strconv.ParseUint(timeout, 10, 64)
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
	startCmd.Flags().StringP(externalURLFlagName, "", "", externalURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	startCmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)
	startCmd.Flags().StringP(logLevelFlagName, logLevelFlagShorthand, "", logLevelPrefixFlagUsage)
	startCmd.Flags().StringP(staticFilesPathFlagName, "", "", staticFilesPathFlagUsage)
	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, databaseURLFlagShorthand, "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, databasePrefixFlagShorthand, "", databasePrefixFlagUsage)
	startCmd.Flags().StringP(hydraURLFlagName, "", "", hydraURLFlagUsage)
	startCmd.Flags().StringP(oidcCallbackURLFlagName, "", "", oidcCallbackURLFlagUsage)
	startCmd.Flags().StringP(oidcProvidersConfigFileFlagName, "", "", oidcProvidersConfigFileFlagUsage)
	startCmd.Flags().StringP(oidcStaticImageFolderFlagName, "", "", oidcStaticImageFolderFlagUsage)
	startCmd.Flags().StringP(docsSDSURLFlagName, "", "", docsSDSURLFlagUsage)
	startCmd.Flags().StringP(opsKeysSDSURLFlagName, "", "", opsKeysSDSURLFlagUsage)
	startCmd.Flags().StringP(authKeyServerURLFlagName, "", "", authKeyServerURLFlagUsage)
	startCmd.Flags().StringP(opsKeyServerURLFlagName, "", "", opsKeyServerURLFlagUsage)
	startCmd.Flags().StringP(deviceSystemCertPoolFlagName, "", "", deviceSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(deviceCACertsFlagName, "", []string{}, deviceCACertsFlagUsage)
	startCmd.Flags().StringP(secretsAPITokenFlagName, "", "", secretsAPITokenFlagUsage)
	startCmd.Flags().StringP(depTimeoutFlagName, "", "", depTimeoutFlagUsage)
	startCmd.Flags().StringP(sessionCookieAuthKeyFlagName, "", "", sessionCookieAuthKeyFlagUsage)
	startCmd.Flags().StringP(sessionCookieEncKeyFlagName, "", "", sessionCookieEncKeyFlagUsage)
}

// nolint:funlen
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

	router := mux.NewRouter()

	fs := http.FileServer(http.Dir(parameters.staticImages))
	router.PathPrefix("/static/images/").Handler(http.StripPrefix("/static/images/", fs))

	// health check
	router.HandleFunc(healthCheckEndpoint, healthCheckHandler).Methods(http.MethodGet)

	for _, handler := range logspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// TODO: support creating multiple GNAP user interaction handlers
	interact, err := redirect.New(parameters.externalURL + gnap.InteractPath)
	if err != nil {
		return fmt.Errorf("initializing GNAP interaction handler: %w", err)
	}

	svc, err := restapi.New(&operation.Config{
		TransientStoreProvider: provider,
		StoreProvider:          provider,
		Hydra:                  hydra.NewClient(parameters.oidcParams.hydraURL, rootCAs),
		OIDC: &operation.OIDCConfig{
			CallbackURL: parameters.oidcParams.callbackURL,
			Providers:   parameters.oidcParams.providers,
		},
		BootstrapConfig: &operation.BootstrapConfig{
			DocumentSDSVaultURL: parameters.bootstrapParams.documentSDSVaultURL,
			KeySDSVaultURL:      parameters.bootstrapParams.keySDSVaultURL,
			AuthZKeyServerURL:   parameters.bootstrapParams.authZKeyServerURL,
			OpsKeyServerURL:     parameters.bootstrapParams.opsKeyServerURL,
		},
		DeviceRootCerts: parameters.devicecertParams.caCerts,
		TLSConfig:       &tls.Config{RootCAs: rootCAs}, //nolint:gosec
		UIEndpoint:      uiEndpoint,
		Cookies: &operation.CookieConfig{
			AuthKey: parameters.keys.sessionCookieAuthKey,
			EncKey:  parameters.keys.sessionCookieEncKey,
		},
		StartupTimeout: parameters.startupTimeout,
		SecretsToken:   parameters.secretsAPIToken,
	}, &gnap.Config{
		BaseURL:            parameters.hostURL,
		AccessPolicy:       &accesspolicy.AccessPolicy{},
		InteractionHandler: interact,
		UIEndpoint:         uiEndpoint,
	})
	if err != nil {
		return err
	}

	for _, handler := range svc.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof(`Starting auth REST server with the following parameters:Host URL: %s Database type: %s
Database URL: %s
Database prefix: %s`, parameters.hostURL, parameters.databaseType, parameters.databaseURL, parameters.databasePrefix)

	// static frontend
	router.PathPrefix(uiEndpoint).
		Subrouter().
		Methods(http.MethodGet).
		HandlerFunc(uiHandler(parameters.staticFiles, http.ServeFile))

	return srv.ListenAndServe(
		parameters.hostURL,
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
		constructCORSHandler(router),
	)
}

func uiHandler(
	basePath string,
	fileServer func(http.ResponseWriter, *http.Request, string)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == uiEndpoint {
			fileServer(w, r, strings.ReplaceAll(basePath+"/index.html", "//", "/"))

			return
		}

		fileServer(w, r, strings.ReplaceAll(basePath+"/"+r.URL.Path[len(uiEndpoint):], "//", "/"))
	}
}

func getOIDCParams(cmd *cobra.Command) (*oidcParams, error) {
	params := &oidcParams{}

	var err error

	params.callbackURL, err = cmdutils.GetUserSetVarFromString(cmd,
		oidcCallbackURLFlagName, oidcCallbackURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	hydraURLString, err := cmdutils.GetUserSetVarFromString(cmd, hydraURLFlagName, hydraURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	params.hydraURL, err = url.Parse(hydraURLString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hydra url: %w", err)
	}

	oidcProvFile, err := cmdutils.GetUserSetVarFromString(cmd,
		oidcProvidersConfigFileFlagName, oidcProvidersConfigFileEnvKey, false)
	if err != nil {
		return nil, err
	}

	config, err := ioutil.ReadFile(filepath.Clean(oidcProvFile))
	if err != nil {
		return nil, fmt.Errorf("failed to read oidc providers config file %s: %w", oidcProvFile, err)
	}

	data := &oidcProvidersConfig{}

	err = yaml.Unmarshal(config, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse contents of %s: %w", oidcProvFile, err)
	}

	params.providers = make(map[string]*operation.OIDCProviderConfig, len(data.Providers))

	for k, v := range data.Providers {
		params.providers[k] = &operation.OIDCProviderConfig{
			URL:             v.URL,
			ClientID:        v.ClientID,
			ClientSecret:    v.ClientSecret,
			Name:            v.Name,
			SignUpLogoURL:   v.SignUpLogoURL,
			SignInLogoURL:   v.SignInLogoURL,
			Order:           v.Order,
			SkipIssuerCheck: v.SkipIssuerCheck,
			Scopes:          v.Scopes,
		}
	}

	return params, nil
}

func getBootstrapParams(cmd *cobra.Command) (*bootstrapParams, error) {
	params := &bootstrapParams{}

	var err error

	params.documentSDSVaultURL, err = cmdutils.GetUserSetVarFromString(cmd, docsSDSURLFlagName, docsSDSURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	params.keySDSVaultURL, err = cmdutils.GetUserSetVarFromString(cmd,
		opsKeysSDSURLFlagName, opsKeysSDSURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	params.authZKeyServerURL, err = cmdutils.GetUserSetVarFromString(cmd,
		authKeyServerURLFlagName, authKeyServerURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	params.opsKeyServerURL, err = cmdutils.GetUserSetVarFromString(cmd,
		opsKeyServerURLFlagName, opsKeyServerURLEnvKey, false)

	return params, err
}

func getDeviceCertParams(cmd *cobra.Command) (*deviceCertParams, error) {
	params := &deviceCertParams{}

	var err error

	useSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, deviceSystemCertPoolFlagName,
		deviceSystemCertPoolEnvKey, true)
	if err != nil {
		return nil, err
	}

	if useSystemCertPoolString != "" {
		params.useSystemCertPool, err = strconv.ParseBool(useSystemCertPoolString)
		if err != nil {
			return nil, err
		}
	}

	params.caCerts, err = cmdutils.GetUserSetVarFromArrayString(cmd, deviceCACertsFlagName, deviceCACertsEnvKey, true)
	if err != nil {
		return nil, err
	}

	return params, err
}

func getKeyParams(cmd *cobra.Command) (*keyParameters, error) {
	params := &keyParameters{}

	sessionCookieAuthKeyPath, err := cmdutils.GetUserSetVarFromString(cmd,
		sessionCookieAuthKeyFlagName, sessionCookieAuthKeyEnvKey, false)
	if err != nil {
		return nil, fmt.Errorf("failed to configure session cookie auth key: %w", err)
	}

	params.sessionCookieAuthKey, err = parseKey(sessionCookieAuthKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to configure session cookie auth key: %w", err)
	}

	sessionCookieEncKeyPath, err := cmdutils.GetUserSetVarFromString(cmd,
		sessionCookieEncKeyFlagName, sessionCookieEncKeyEnvKey, false)
	if err != nil {
		return nil, fmt.Errorf("failed to configure session cookie enc key: %w", err)
	}

	params.sessionCookieEncKey, err = parseKey(sessionCookieEncKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to configure session cooie enc key: %w", err)
	}

	return params, nil
}

func parseKey(file string) ([]byte, error) {
	const (
		keyLen = 32
		bitNum = 8
	)

	bits, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", file, err)
	}

	if len(bits) != keyLen {
		return nil, fmt.Errorf("%s: need key of %d bits but got %d", file, keyLen*bitNum, len(bits)*bitNum)
	}

	return bits, nil
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
