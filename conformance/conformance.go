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
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	clientset "k8s.io/client-go/kubernetes"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8sconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	confflags "sigs.k8s.io/gateway-api/conformance/utils/flags"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"

	"sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/conformance/tests"
	"sigs.k8s.io/kube-agentic-networking/conformance/utils/features"
)

const GatewayLayerProfileName confsuite.ConformanceProfileName = "GatewayLayer"

var GatewayLayerProfile = confsuite.ConformanceProfile{
	Name:         GatewayLayerProfileName,
	CoreFeatures: features.AgenticCoreFeatures,
}

func DefaultOptions(t *testing.T) confsuite.ConformanceOptions {
	t.Helper()

	cfg, err := k8sconfig.GetConfig()
	require.NoError(t, err, "error loading Kubernetes config")

	scheme := runtime.NewScheme()
	require.NoError(t, clientsetscheme.AddToScheme(scheme), "failed to add core Kubernetes types to scheme")
	require.NoError(t, gatewayv1.Install(scheme), "failed to install gatewayv1 types into scheme")
	require.NoError(t, apiextensionsv1.AddToScheme(scheme), "failed to add apiextensionsv1 types to scheme")
	require.NoError(t, v0alpha0.AddToScheme(scheme), "failed to install v0alpha0 types into scheme")

	clientOptions := client.Options{Scheme: scheme}
	c, err := client.New(cfg, clientOptions)
	require.NoError(t, err, "error initializing Kubernetes client")
	cs, err := clientset.NewForConfig(cfg)
	require.NoError(t, err, "error initializing Kubernetes clientset")

	opts := confsuite.ConformanceOptions{
		Client:               c,
		ClientOptions:        clientOptions,
		Clientset:            cs,
		RestConfig:           cfg,
		GatewayClassName:     *confflags.GatewayClassName,
		BaseManifests:        "resources/base.yaml",
		Debug:                *confflags.ShowDebug,
		CleanupBaseResources: *confflags.CleanupBaseResources,
		SupportedFeatures:    sets.New(features.AgenticCoreFeatures.UnsortedList()...),
		ManifestFS:           []fs.FS{&Manifests},
		AllowCRDsMismatch:    true,
	}

	return opts
}

func RunConformance(t *testing.T) {
	opts := DefaultOptions(t)
	confsuite.RegisterConformanceProfile(GatewayLayerProfile)

	cSuite, err := confsuite.NewConformanceTestSuite(opts)
	require.NoError(t, err, "error initializing conformance suite")

	cSuite.Applier.ManifestFS = cSuite.ManifestFS

	// Apply base manifests
	cSuite.Applier.GatewayClass = opts.GatewayClassName
	cSuite.Applier.MustApplyWithCleanup(t, opts.Client, cSuite.TimeoutConfig, opts.BaseManifests, cSuite.Cleanup)

	t.Log("Waiting for agentic-conformance-infra namespace to be ready")
	kubernetes.NamespacesMustBeReady(t, opts.Client, cSuite.TimeoutConfig, []string{"agentic-conformance-infra"})

	err = cSuite.Run(t, tests.ConformanceTests)
	require.NoError(t, err, "error running conformance tests")
}
