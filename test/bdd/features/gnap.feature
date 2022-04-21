#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@gnap
Feature: Grant Negotiation and Authorization Protocol(GNAP) flow (https://www.ietf.org/archive/id/draft-ietf-gnap-core-protocol-09.html)

  Scenario: Redirect-Based User Interaction (https://www.ietf.org/archive/id/draft-ietf-gnap-core-protocol-09.html#appendix-D.1)
    When the client creates a gnap go-client
    Then the client calls the tx request with httpsign and gets back a redirect interaction
    Then client redirects to the interaction URL, user logs into the external oidc provider and the client receives a redirect back
    And client calls continue API and gets back the access token
