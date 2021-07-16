// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"log/syslog"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf/migrate"
)

// bpfMigrateCmd represents the migrate command
var (
	bpfMigrateCmd = &cobra.Command{
		Use:   "migrate",
		Short: "Migrate map",
		Run: func(cmd *cobra.Command, args []string) {
			if len(startPath) > 0 && len(endPath) > 0 {
				log.Fatalf("s (%q) and e (%q) cannot be both set", startPath, endPath)
			}
			var (
				pathName string
				finalize bool
			)
			if len(startPath) > 0 {
				pathName = startPath
			} else if len(endPath) > 0 {
				pathName = endPath
				finalize = true
			} else {
				log.Fatalf("either s or e must be a valid filepath")
			}
			sysLogger, err := syslog.New(syslog.LOG_WARNING, "cilium-map-migrate")
			if err != nil {
				log.Printf("Could not open syslog: %v", err)
			} else {
				defer sysLogger.Close()
			}
			if !finalize {
				_, err = migrate.Start(pathName, sysLogger)
			} else {
				err = migrate.Finish(pathName, returnCode != 0, sysLogger)
			}
			if err != nil {
				log.Fatalf("error migrating state for %q: %v", pathName, err)
			}
		},
	}
	startPath  string
	endPath    string
	returnCode int
)

func init() {
	bpfMapCmd.AddCommand(bpfMigrateCmd)
	bpfMigrateCmd.Flags().StringVarP(&startPath, "start", "s", "", "start file")
	bpfMigrateCmd.Flags().StringVarP(&endPath, "end", "e", "", "end file")
	bpfMigrateCmd.Flags().IntVarP(&returnCode, "return", "r", 0, "return code")
}
