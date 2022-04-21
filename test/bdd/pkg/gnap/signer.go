/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

type Signer struct {
	PrivateKey []byte
}

func (m *Signer) Sign(msg []byte) ([]byte, error) {
	// TODO add signature
	return msg, nil
}
