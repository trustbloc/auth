/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redirect

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	_ "golang.org/x/crypto/sha3" // nolint:gci // init sha3 hash.

	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/spi/gnap"
)

// InteractHandler handles GNAP redirect-based user login and consent.
type InteractHandler struct {
	interactBasePath string
	txnStore         storage.Store
}

// Config startup configuration for InteractHandler.
type Config struct {
	StoreProvider    storage.Provider
	InteractBasePath string
}

const (
	txnDBName         = "gnap_interact_redirect_store"
	txnIDPrefix       = "t."
	interactRefPrefix = "i."

	txnIDURLQueryPrefix = "?txnID="
)

type txnData struct {
	api.ConsentResult
	Interact    *gnap.RequestInteract `json:"interact,omitempty"`
	RequestURL  string                `json:"req-url,omitempty"`
	ServerNonce string                `json:"server-nonce,omitempty"`
}

// New creates a GNAP redirect-based user login&consent interaction handler.
func New(config *Config) (*InteractHandler, error) {
	store, err := config.StoreProvider.OpenStore(txnDBName)
	if err != nil {
		return nil, err
	}

	return &InteractHandler{
		txnStore:         store,
		interactBasePath: config.InteractBasePath,
	}, nil
}

// TODO consider: split out the interaction hash stuff into a general handler for both redirect & push finish methods.

// PrepareInteraction initializes a redirect-based login&consent interaction,
// returning the redirect parameters to be sent to the client.
func (h InteractHandler) PrepareInteraction(
	clientInteract *gnap.RequestInteract,
	requestURI string,
	requestedTokens []*api.ExpiringTokenRequest,
) (*gnap.ResponseInteract, error) {
	txnID, err := nonce()
	if err != nil {
		return nil, err
	}

	serverNonce, err := nonce()
	if err != nil {
		return nil, err
	}

	txn := &txnData{
		ConsentResult: api.ConsentResult{
			Tokens: requestedTokens,
		},
		Interact:    clientInteract,
		ServerNonce: serverNonce,
		RequestURL:  requestURI,
	}

	txnBytes, err := json.Marshal(txn)
	if err != nil {
		return nil, fmt.Errorf("marshaling txn data: %w", err)
	}

	err = h.txnStore.Put(txnIDPrefix+txnID, txnBytes)
	if err != nil {
		return nil, fmt.Errorf("saving txn data: %w", err)
	}

	return &gnap.ResponseInteract{
		Redirect: h.interactBasePath + txnIDURLQueryPrefix + txnID,
		Finish:   serverNonce,
	}, nil
}

// CompleteInteraction saves an interaction with the given consent data for
// the given login&consent interaction, returning the interact_ref.
func (h InteractHandler) CompleteInteraction(
	txnID string,
	consentSet *api.ConsentResult,
) (string, string, *gnap.RequestInteract, error) {
	txnBytes, err := h.txnStore.Get(txnIDPrefix + txnID)
	if err != nil {
		return "", "", nil, fmt.Errorf("loading txn data: %w", err)
	}

	txn := &txnData{}

	err = json.Unmarshal(txnBytes, txn)
	if err != nil {
		return "", "", nil, fmt.Errorf("parsing txn data: %w", err)
	}

	txn.ConsentResult.SubjectData = consentSet.SubjectData

	interactRef, err := nonce()
	if err != nil {
		return "", "", nil, err
	}

	hashValue, err := responseHash(txn.Interact.Finish.Nonce, txn.ServerNonce, interactRef, txn.RequestURL)
	if err != nil {
		return "", "", nil, fmt.Errorf("creating response hash: %w", err)
	}

	txnBytes, err = json.Marshal(txn.ConsentResult)
	if err != nil {
		return "", "", nil, fmt.Errorf("marshaling txn data: %w", err)
	}

	err = h.txnStore.Put(interactRefPrefix+interactRef, txnBytes)
	if err != nil {
		return "", "", nil, fmt.Errorf("saving txn data: %w", err)
	}

	err = h.txnStore.Delete(txnIDPrefix + txnID)
	if err != nil {
		return "", "", nil, fmt.Errorf("deleting old txn data: %w", err)
	}

	return interactRef, hashValue, txn.Interact, nil
}

func responseHash(clientNonce, serverNonce, interactRef, requestURI string) (string, error) {
	hashBase := clientNonce + "\n" + serverNonce + "\n" + interactRef + "\n" + requestURI

	hasher := crypto.SHA3_512.New()

	_, err := hasher.Write([]byte(hashBase))
	if err != nil {
		return "", fmt.Errorf("failed to hash: %w", err)
	}

	hash := hasher.Sum(nil)

	hashB64 := base64.RawURLEncoding.EncodeToString(hash)

	return hashB64, nil
}

// QueryInteraction fetches the interaction under the given interact_ref.
func (h InteractHandler) QueryInteraction(interactRef string) (*api.ConsentResult, error) {
	txnBytes, err := h.txnStore.Get(interactRefPrefix + interactRef)
	if err != nil {
		return nil, fmt.Errorf("loading interaction data: %w", err)
	}

	txn := &api.ConsentResult{}

	err = json.Unmarshal(txnBytes, txn)
	if err != nil {
		return nil, fmt.Errorf("parsing interaction data: %w", err)
	}

	return txn, nil
}

// DeleteInteraction deletes the interaction under the given interact_ref.
func (h InteractHandler) DeleteInteraction(interactRef string) error {
	err := h.txnStore.Delete(interactRefPrefix + interactRef)
	if err != nil {
		return fmt.Errorf("deleting interaction data: %w", err)
	}

	return nil
}

const nonceLength = 15

func nonce() (string, error) {
	nonceBytes := make([]byte, nonceLength)

	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("creating nonce: %w", err)
	}

	nonceStr := base64.RawURLEncoding.EncodeToString(nonceBytes)

	return nonceStr, nil
}
