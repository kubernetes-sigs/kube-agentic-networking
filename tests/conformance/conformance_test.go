//go:build conformance

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
	"flag"
	"os"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/tests"
	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/flags"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func TestGatewayAPIConformance(t *testing.T) {
	flag.Parse()
	log.SetLogger(zap.New(zap.WriteTo(os.Stderr), zap.UseDevMode(true)))

	if flags.RunTest != nil && *flags.RunTest != "" {
		tlog.Logf(t, "Running Conformance test %s with %s GatewayClass\n cleanup: %t\n debug: %t",
			*flags.RunTest, *flags.GatewayClassName, *flags.CleanupBaseResources, *flags.ShowDebug)
	} else {
		tlog.Logf(t, "Running Conformance tests with %s GatewayClass\n cleanup: %t\n debug: %t",
			*flags.GatewayClassName, *flags.CleanupBaseResources, *flags.ShowDebug)
	}

	opts := conformanceOpts(t)
	opts.RunTest = *flags.RunTest

	// If focusing on a single test, clear the skip list to ensure it runs.
	if opts.RunTest != "" {
		opts.SkipTests = nil
	}

	cSuite, err := suite.NewConformanceTestSuite(opts)
	if err != nil {
		t.Fatalf("Error creating conformance test suite: %v", err)
	}

	cSuite.Setup(t, tests.ConformanceTests)
	if err := cSuite.Run(t, tests.ConformanceTests); err != nil {
		t.Fatalf("Error running conformance tests: %v", err)
	}
}

func conformanceOpts(t *testing.T) suite.ConformanceOptions {
	opts := conformance.DefaultOptions(t)
	opts.SkipTests = skipTestsShortNames(SkipTests)
	opts.SupportedFeatures = sets.New(
			features.SupportGateway,
			features.SupportReferenceGrant,
			features.SupportHTTPRoute,
		)

	opts.TimeoutConfig = config.DefaultTimeoutConfig()
	opts.FailFast = true
	return opts
}

// SkipTests is a list of tests that are skipped in the conformance suite.
var SkipTests = []suite.ConformanceTest{
	// https://github.com/kubernetes-sigs/kube-agentic-networking/issues/256
	tests.HTTPRouteHTTPSListener,
	// Requires EDS to handle headless services without selector.
	tests.HTTPRouteServiceTypes,
}

func skipTestsShortNames(skipTests []suite.ConformanceTest) []string {
	shortNames := make([]string, len(skipTests))
	for i, test := range skipTests {
		shortNames[i] = test.ShortName
	}
	return shortNames
}
