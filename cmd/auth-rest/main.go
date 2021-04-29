/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/hub-auth/cmd/auth-rest/startcmd"
)

var logger = log.New("auth-rest") //nolint:gochecknoglobals

func main() {
	rootCmd := &cobra.Command{
		Use: "auth-rest",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(startcmd.GetStartCmd(&startcmd.HTTPServer{}))

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("failed to run auth-rest: %s", err.Error())
	}
}
