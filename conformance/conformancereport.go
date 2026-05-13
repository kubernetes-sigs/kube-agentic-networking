/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package conformance

import (
	"fmt"
	"os"
	"path/filepath"

	confapis "sigs.k8s.io/gateway-api/conformance/apis/v1"
	"sigs.k8s.io/yaml"
)

// AgenticNetworkingConformanceReport is a report of conformance testing results of
// kube-agentic-networking including the specific conformance profiles that were tested
// and the results of the tests with summaries and statistics.
type AgenticNetworkingConformanceReport struct {
	// GatewayLayerVersion is the version of the kube-agentic-networking the tests run against.
	GatewayLayerVersion string
	// ConformanceReport is the fields reused from the gateway-api conformance reports.
	confapis.ConformanceReport
}

// WriteReport writes the generated conformance report to the specified output file or logs it.
func (report *AgenticNetworkingConformanceReport) WriteReport(logf func(string, ...any), output string) error {
	rawReport, err := yaml.Marshal(*report)
	if err != nil {
		return fmt.Errorf("error marshaling report: %w", err)
	}

	if output != "" {
		if err = os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			return fmt.Errorf("error creating report output directory: %w", err)
		}
		if err = os.WriteFile(output, rawReport, 0o600); err != nil {
			return fmt.Errorf("error writing report file %s: %w", output, err)
		}
		logf("Conformance report written to %s", output)
	} else {
		// Log the report YAML to stdout if no output file is specified.
		logf("Conformance report:\n%s", string(rawReport))
	}
	return nil
}
