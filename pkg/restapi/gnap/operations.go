/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/auth/pkg/gnap/accesspolicy"
	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/pkg/gnap/authhandler"
	"github.com/trustbloc/auth/pkg/internal/common/support"
	"github.com/trustbloc/auth/pkg/restapi/common"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/auth/spi/gnap/clientverifier/httpsig"
)

var logger = log.New("auth-restapi") //nolint:gochecknoglobals

const (
	gnapBasePath = "/gnap"
	// AuthRequestPath endpoint for GNAP authorization request.
	AuthRequestPath = gnapBasePath + "/auth"
	// AuthContinuePath endpoint for GNAP authorization continuation.
	AuthContinuePath = gnapBasePath + "/continue"
	// AuthIntrospectPath endpoint for GNAP token introspection.
	AuthIntrospectPath = gnapBasePath + "/introspect"
	// InteractPath endpoint for GNAP interact.
	InteractPath = gnapBasePath + "/interact"

	// GNAP error response codes.
	errInvalidRequest = "invalid_request"
	errRequestDenied  = "request_denied"
)

// TODO: figure out what logic should go in the access policy vs operation handlers.

// Operation defines Auth Server GNAP handlers.
type Operation struct {
	authHandler *authhandler.AuthHandler
	uiEndpoint  string
}

// Config defines configuration for GNAP operations.
type Config struct {
	StoreProvider      storage.Provider
	AccessPolicy       *accesspolicy.AccessPolicy
	BaseURL            string
	InteractionHandler api.InteractionHandler
	UIEndpoint         string
}

// New creates GNAP operation handler.
func New(config *Config) (*Operation, error) {
	auth, err := authhandler.New(&authhandler.Config{
		StoreProvider:      config.StoreProvider,
		AccessPolicy:       config.AccessPolicy,
		ContinuePath:       config.BaseURL + AuthContinuePath,
		InteractionHandler: config.InteractionHandler,
	})
	if err != nil {
		return nil, err
	}

	return &Operation{
		authHandler: auth,
		uiEndpoint:  config.UIEndpoint,
	}, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []common.Handler {
	return []common.Handler{
		support.NewHTTPHandler(AuthRequestPath, http.MethodPost, o.authRequestHandler),
		// TODO add txn_id to url path
		support.NewHTTPHandler(InteractPath, http.MethodGet, o.interactHandler),
		support.NewHTTPHandler(AuthContinuePath, http.MethodPost, o.authContinueHandler),
		support.NewHTTPHandler(AuthIntrospectPath, http.MethodPost, o.introspectHandler),
	}
}

func (o *Operation) authRequestHandler(w http.ResponseWriter, req *http.Request) {
	authRequest := &gnap.AuthRequest{}

	if err := json.NewDecoder(req.Body).Decode(authRequest); err != nil {
		logger.Errorf("failed to parse gnap auth request: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errInvalidRequest,
		})

		return
	}

	v := httpsig.NewVerifier(req)

	resp, err := o.authHandler.HandleAccessRequest(authRequest, v)
	if err != nil {
		logger.Errorf("access policy failed to handle access request: %s", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errRequestDenied,
		})

		return
	}

	o.writeResponse(w, resp)
}

func (o *Operation) interactHandler(w http.ResponseWriter, req *http.Request) {
	// TODO validate txn_id
	// redirect to UI
	http.Redirect(w, req, o.uiEndpoint+"/sign-up", http.StatusFound)
}

func (o *Operation) authContinueHandler(w http.ResponseWriter, req *http.Request) {
	tokHeader := strings.Split(strings.Trim(req.Header.Get("Authorization"), " "), " ")

	if len(tokHeader) < 2 || tokHeader[0] != "GNAP" {
		logger.Errorf("GNAP continuation endpoint requires GNAP token")
		w.WriteHeader(http.StatusUnauthorized)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errRequestDenied,
		})

		return
	}

	token := tokHeader[1]

	continueRequest := &gnap.ContinueRequest{}

	if err := json.NewDecoder(req.Body).Decode(continueRequest); err != nil {
		logger.Errorf("failed to parse gnap continue request: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errInvalidRequest,
		})

		return
	}

	v := httpsig.NewVerifier(req)

	resp, err := o.authHandler.HandleContinueRequest(continueRequest, token, v)
	if err != nil {
		logger.Errorf("access policy failed to handle continue request: %s", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errRequestDenied,
		})

		return
	}

	o.writeResponse(w, resp)
}

func (o *Operation) introspectHandler(w http.ResponseWriter, req *http.Request) {
	o.writeResponse(w, nil)
}

// WriteResponse writes interface value to response.
func (o *Operation) writeResponse(rw http.ResponseWriter, v interface{}) {
	rw.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		logger.Errorf("Unable to send response: %s", err.Error())
	}
}
