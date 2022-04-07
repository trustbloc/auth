#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@secrets
Feature: Secrets
  Background: Wallet login
    Given a user logged in with their wallet

  Scenario: Put secret
    When the wallet stores the secret in auth
     And the key server queries auth for the secret
    Then the key server receives the secret

  Scenario: User attempts to store secret twice
    When the wallet stores the secret in auth
     And the wallet attempts to store the secret again
    Then auth returns an error
