/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mockverifier

import (
	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/spi/gnap"
)

// MockVerifier mocks api.Verifier.
type MockVerifier struct {
	ErrVerify error
}

var _ api.Verifier = &MockVerifier{}

// Verify mock api.Verifier.Verify.
func (m *MockVerifier) Verify(*gnap.ClientKey) error {
	return m.ErrVerify
}
