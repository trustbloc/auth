#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@secrets
Feature: Bootstrap data
  Background: Wallet login
    Given a user logged in with their wallet

  Scenario: Put secret
    When the wallet stores the secret in hub-auth
     And the key server queries hub-auth for the secret
    Then the key server receives the secret

  Scenario: User attempts to store secret twice
    When the wallet executes an HTTP POST on the bootstrap endpoint
    And the wallet executes an HTTP GET on the bootstrap endpoint
    Then hub-auth returns the updated bootstrap data
