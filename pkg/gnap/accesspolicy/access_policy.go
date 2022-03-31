/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package accesspolicy

import (
	"errors"

	"github.com/trustbloc/hub-auth/pkg/gnap/api"
	"github.com/trustbloc/hub-auth/pkg/gnap/session"
	"github.com/trustbloc/hub-auth/spi/gnap"
)

/*
AccessPolicy handles GNAP access requests and decides what access to grant.

TODO:
 - figure out how access policy should work with login & consent handling
 - make access policy configurable

Input:
- The request handler passes the entire request object, since AccessPolicy needs all parts of it:
  - The descriptors of requested access tokens and subject info are used to decide what access to give, and whether
    a login&consent interaction is necessary.
  - The client instance ID allows AccessPolicy to check whether any requested
    tokens/data are already granted
  - The interact parameters allow the AccessPolicy to decide which login&consent
    provider to use
- The request handler creates a request Verifier that will validate the client key bound to the request,
  and passes the Verifier into the AccessPolicy.

TODO what AccessPolicy needs to do:
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
type AccessPolicy struct {
	config       interface{}            // nolint:structcheck,unused
	sessionStore *session.Manager       // nolint:structcheck,unused
	loginConsent api.InteractionHandler // nolint:structcheck,unused
}

// HandleAccessRequest handles GNAP access requests.
func (ap *AccessPolicy) HandleAccessRequest(
	req *gnap.AuthRequest,
	reqVerifier api.Verifier,
) (*gnap.AuthResponse, error) {
	return nil, errors.New("not implemented")
}

// HandleContinueRequest handles GNAP continue requests.
func (ap *AccessPolicy) HandleContinueRequest(
	req *gnap.ContinueRequest,
	continueToken string,
	reqVerifier api.Verifier,
) (*gnap.AuthResponse, error) {
	return nil, errors.New("not implemented")
}

// HandleIntrospection handles GNAP resource-server requests for access token introspection.
func (ap *AccessPolicy) HandleIntrospection(
	req *gnap.IntrospectRequest,
	reqVerifier api.Verifier,
) (*gnap.IntrospectResponse, error) {
	return nil, errors.New("not implemented")
}
