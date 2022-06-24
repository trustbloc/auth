/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authhandler

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/auth/pkg/gnap/accesspolicy"
	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/pkg/gnap/session"
	"github.com/trustbloc/auth/spi/gnap"
)

var logger = log.New("gnap/auth-handler") // nolint:gochecknoglobals

/*
AuthHandler handles GNAP access requests and decides what access to grant.

TODO:
 - figure out how auth handler should work with login & consent handling

Input:
- The request handler passes the entire request object, since AuthHandler needs all parts of it:
  - The descriptors of requested access tokens and subject info are used to decide what access to give, and whether
    a login&consent interaction is necessary.
  - The client instance ID allows AuthHandler to check whether any requested
    tokens/data are already granted
  - The interact parameters allow the AuthHandler to decide which login&consent
    provider to use
- The request handler creates a request Verifier that will validate the client key bound to the request,
  and passes the Verifier into the AuthHandler.

TODO what AuthHandler needs to do:
 - Process request, use configured policy to:
   - deny forbidden requests
   - decide which requests can be granted based on access already saved in the session
   - decide which requests to collate into a login & consent interaction for user approval
 - If login & consent is necessary:
   - Decide which login & consent handler to use, invoke the handler to get the interact
     response, and respond to the client with the interact response
   - Handle the continue request, by fetching the login&consent result found under the given interact_ref,
     apply access policy to construct the tokens and subject data to return.
*/
type AuthHandler struct {
	continuePath   string
	accessPolicy   *accesspolicy.AccessPolicy
	sessionStore   *session.Manager
	loginConsent   api.InteractionHandler
	disableHTTPSig bool
}

// Config holds AuthHandler constructor configuration.
type Config struct {
	AccessPolicyConfig *accesspolicy.Config
	ContinuePath       string
	InteractionHandler api.InteractionHandler
	StoreProvider      storage.Provider
	DisableHTTPSig     bool
}

// New returns new AuthHandler.
func New(config *Config) (*AuthHandler, error) {
	accessPolicy, err := accesspolicy.New(config.AccessPolicyConfig)
	if err != nil {
		return nil, err
	}

	sessionHandler, err := session.New(&session.Config{StoreProvider: config.StoreProvider})
	if err != nil {
		return nil, err
	}

	return &AuthHandler{
		continuePath:   config.ContinuePath,
		accessPolicy:   accessPolicy,
		sessionStore:   sessionHandler,
		loginConsent:   config.InteractionHandler,
		disableHTTPSig: config.DisableHTTPSig,
	}, nil
}

// HandleAccessRequest handles GNAP access requests.
func (h *AuthHandler) HandleAccessRequest( // nolint: funlen,gocyclo
	req *gnap.AuthRequest,
	reqVerifier api.Verifier,
	reqURL string,
) (*gnap.AuthResponse, error) {
	var (
		s   *session.Session
		err error
	)

	if req.Client == nil {
		// client can never be omitted entirely
		return nil, errors.New("missing client")
	}

	if req.Client.IsReference {
		s, err = h.sessionStore.GetByID(req.Client.Ref)
		if err != nil {
			return nil, fmt.Errorf("getting client session by client ID: %w", err)
		}
	} else {
		s, err = h.sessionStore.GetOrCreateByKey(req.Client.Key)
		if err != nil {
			return nil, fmt.Errorf("getting client session by key: %w", err)
		}
	}

	if h.disableHTTPSig {
		logger.Warnf("server running in dev mode: http signature verification disabled")
	} else {
		verifyErr := reqVerifier.Verify(s.ClientKey)
		if verifyErr != nil {
			return nil, fmt.Errorf("client request verification failure: %w", verifyErr)
		}
	}

	permissions, err := h.accessPolicy.DeterminePermissions(req.AccessToken, s)
	if err != nil {
		return nil, fmt.Errorf("failed to determine permissions for access request: %w", err)
	}

	// TODO: smarter access policy logic, to recognize if a token is being re-requested, and send that token instead of
	//   creating fresh access tokens every time.
	if permissions.NeedsConsent.IsEmpty() && !permissions.Allowed.IsEmpty() {
		// nothing needs consent, but something is allowed, so create tokens for all allowed, and return
		var resp *gnap.AuthResponse

		resp, s, err = h.tokensGranted(permissions.Allowed.Tokens, s)
		if err != nil {
			return nil, err
		}

		err = h.sessionStore.Save(s)
		if err != nil {
			return nil, err
		}

		return resp, nil
	}

	continueToken := gnap.AccessToken{
		Value: uuid.New().String(),
	}

	s.ContinueToken = &api.ExpiringToken{AccessToken: continueToken}

	s.NeedsConsent = permissions.NeedsConsent

	s.AllowedRequest = permissions.Allowed

	// TODO: support selecting one of multiple interaction handlers
	interact, err := h.loginConsent.PrepareInteraction(req.Interact, reqURL, permissions.NeedsConsent.Tokens)
	if err != nil {
		return nil, fmt.Errorf("creating response interaction parameters: %w", err)
	}

	err = h.sessionStore.Save(s)
	if err != nil {
		return nil, err
	}

	resp := &gnap.AuthResponse{
		Continue: gnap.ResponseContinue{
			URI:         h.continuePath,
			AccessToken: continueToken,
		},
		Interact:   *interact,
		InstanceID: s.ClientID,
	}

	return resp, nil
}

// HandleContinueRequest handles GNAP continue requests.
func (h *AuthHandler) HandleContinueRequest(
	req *gnap.ContinueRequest,
	continueToken string,
	reqVerifier api.Verifier,
) (*gnap.AuthResponse, error) {
	s, err := h.sessionStore.GetByContinueToken(continueToken)
	if err != nil {
		return nil, fmt.Errorf("getting session for continue token: %w", err)
	}

	if h.disableHTTPSig {
		logger.Warnf("server running in dev mode: http signature verification disabled")
	} else {
		verifyErr := reqVerifier.Verify(s.ClientKey)
		if verifyErr != nil {
			return nil, fmt.Errorf("client request verification failure: %w", verifyErr)
		}
	}

	consent, err := h.loginConsent.QueryInteraction(req.InteractRef)
	if err != nil {
		return nil, err
	}

	s.AddSubjectData(consent.SubjectData)

	var tokReqs []*api.ExpiringTokenRequest

	tokReqs = append(tokReqs, consent.Tokens...)

	// create fresh tokens for all requested tokens that were already permitted before this consent interaction
	if s.AllowedRequest != nil {
		tokReqs = append(tokReqs, s.AllowedRequest.Tokens...)
	}

	var resp *gnap.AuthResponse

	resp, s, err = h.tokensGranted(tokReqs, s)
	if err != nil {
		return nil, err
	}

	// clear request metadata, since these are now granted
	s.AllowedRequest = nil
	s.NeedsConsent = nil

	err = h.sessionStore.Save(s)
	if err != nil {
		return nil, err
	}

	err = h.loginConsent.DeleteInteraction(req.InteractRef)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (h *AuthHandler) tokensGranted(
	tokReqs []*api.ExpiringTokenRequest,
	s *session.Session,
) (
	*gnap.AuthResponse,
	*session.Session,
	error,
) {
	var newTokens []gnap.AccessToken

	newTokens, s = h.createTokens(tokReqs, s)

	resp := &gnap.AuthResponse{
		AccessToken: newTokens,
	}

	subjectData, err := h.getSubjectData(newTokens, s)
	if err != nil {
		return nil, nil, err
	}

	if sub, ok := subjectData["sub"]; ok {
		resp.Subject.SubIDs = []gnap.SubjectID{
			{
				Format: "opaque",
				ID:     sub,
			},
		}
	}

	return resp, s, nil
}

func (h *AuthHandler) createTokens(
	tokRequests []*api.ExpiringTokenRequest,
	clientSession *session.Session,
) ([]gnap.AccessToken, *session.Session) {
	newTokens := []gnap.AccessToken{}

	now := time.Now()

	for _, tokenRequest := range tokRequests {
		tok := gnap.AccessToken{
			Value:  uuid.New().String(),
			Label:  tokenRequest.Label,
			Access: tokenRequest.Access,
			Flags:  tokenRequest.Flags,
		}

		tokenExpires := tokenRequest.Expires

		lifetime := tokenExpires.Sub(now)

		tok.Expires = int64(lifetime / time.Second)

		newTokens = append(newTokens, tok)

		clientSession.Tokens = append(clientSession.Tokens, &api.ExpiringToken{
			AccessToken: tok,
			Expires:     tokenExpires,
		})

		if tokenExpires.After(clientSession.Expires) {
			clientSession.Expires = tokenExpires
		}
	}

	return newTokens, clientSession
}

func (h *AuthHandler) getSubjectData(
	tokens []gnap.AccessToken,
	clientSession *session.Session,
) (map[string]string, error) {
	mergedAccess := []gnap.TokenAccess{}

	for _, token := range tokens {
		mergedAccess = append(mergedAccess, token.Access...)
	}

	subjectKeys, err := h.accessPolicy.AllowedSubjectKeys(mergedAccess)
	if err != nil {
		return nil, fmt.Errorf("error fetching subject-data keys: %w", err)
	}

	subjectData := map[string]string{}

	for k := range subjectKeys {
		if v, ok := clientSession.SubjectData[k]; ok {
			subjectData[k] = v
		}
	}

	return subjectData, nil
}

// HandleIntrospection handles GNAP resource-server requests for access token introspection.
func (h *AuthHandler) HandleIntrospection( // nolint:gocyclo
	req *gnap.IntrospectRequest,
	reqVerifier api.Verifier,
) (*gnap.IntrospectResponse, error) {
	var (
		serverSession *session.Session
		clientSession *session.Session
		err           error
	)

	if req.ResourceServer == nil {
		return nil, errors.New("missing rs")
	}

	if req.ResourceServer.IsReference {
		serverSession, err = h.sessionStore.GetByID(req.ResourceServer.Ref)
		if err != nil {
			return nil, fmt.Errorf("getting rs session by rs ID: %w", err)
		}
	} else {
		// TODO: if we create a new session for an unfamiliar resource server, we're implicitly using a TOFU policy.
		serverSession, err = h.sessionStore.GetOrCreateByKey(req.ResourceServer.Key)
		if err != nil {
			return nil, fmt.Errorf("getting rs session by key: %w", err)
		}
	}

	if h.disableHTTPSig {
		logger.Warnf("server running in dev mode: http signature verification disabled")
	} else {
		verifyErr := reqVerifier.Verify(serverSession.ClientKey)
		if verifyErr != nil {
			return nil, fmt.Errorf("rs request verification failure: %w", verifyErr)
		}
	}

	clientSession, clientToken, err := h.sessionStore.GetByAccessToken(req.AccessToken)
	if err != nil || clientToken == nil || (!clientToken.Expires.IsZero() && clientToken.Expires.Before(time.Now())) {
		return &gnap.IntrospectResponse{Active: false}, nil // nolint:nilerr
	}

	if req.Proof != "" && req.Proof != clientSession.ClientKey.Proof {
		return &gnap.IntrospectResponse{Active: false}, nil
	}

	subjectData, err := h.getSubjectData([]gnap.AccessToken{clientToken.AccessToken}, clientSession)
	if err != nil {
		return nil, fmt.Errorf("get subject data: %w", err)
	}

	resp := &gnap.IntrospectResponse{
		Active:      true,
		Access:      clientToken.Access,
		Key:         clientSession.ClientKey,
		Flags:       clientToken.Flags,
		SubjectData: subjectData,
	}

	return resp, err
}
