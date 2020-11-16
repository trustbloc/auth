#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@bootstrap
Feature: Bootstrap data
  Background: Wallet login
    Given a wallet that has logged in

  Scenario: Fetch bootstrap data
    When the wallet executes an HTTP GET on the bootstrap endpoint
    Then hub-auth returns the SDS and KeyServer URLs

  Scenario: Update bootstrap data
    When the wallet executes an HTTP POST on the bootstrap endpoint
     And the wallet executes an HTTP GET on the bootstrap endpoint
    Then hub-auth returns the updated bootstrap data
