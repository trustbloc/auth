#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@login
Feature: Wallet login
  Background: Register wallet as OIDC client
    Given the wallet is registered as an OIDC client

  Scenario: User authentication
    When the wallet redirects the user to authenticate at hub-auth
    And the user picks their third party OIDC provider
    And the user authenticates with the third party OIDC provider
    Then the user is redirected back to the wallet
    And the user has authenticated to the wallet
