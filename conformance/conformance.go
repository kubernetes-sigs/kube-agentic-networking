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
	"context"
	"errors"
	"io/fs"
	"strings"
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
	gatewayfeatures "sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
	"sigs.k8s.io/kube-agentic-networking/conformance/tests"
	"sigs.k8s.io/kube-agentic-networking/conformance/utils/features"
	"sigs.k8s.io/kube-agentic-networking/version"
)

const GatewayLayerProfileName confsuite.ConformanceProfileName = "Gateway"

var GatewayLayerProfile = confsuite.ConformanceProfile{
	Name:             GatewayLayerProfileName,
	CoreFeatures:     features.AgenticCoreFeatures,
	ExtendedFeatures: sets.New(features.SupportAccessPolicySPIFFESource, features.SupportAccessPolicyExternalAuth),
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
	require.NoError(t, v1alpha1.AddToScheme(scheme), "failed to install v1alpha1 types into scheme")

	clientOptions := client.Options{Scheme: scheme}
	c, err := client.New(cfg, clientOptions)
	require.NoError(t, err, "error initializing Kubernetes client")
	cs, err := clientset.NewForConfig(cfg)
	require.NoError(t, err, "error initializing Kubernetes clientset")

	exemptFeatures := confsuite.ParseSupportedFeatures(*confflags.ExemptFeatures)
	skipTests := confsuite.ParseSkipTests(*confflags.SkipTests)
	namespaceLabels := confsuite.ParseKeyValuePairs(*confflags.NamespaceLabels)
	namespaceAnnotations := confsuite.ParseKeyValuePairs(*confflags.NamespaceAnnotations)

	conformanceProfiles := sets.New(GatewayLayerProfileName)

	implementation := confsuite.ParseImplementation(
		*confflags.ImplementationOrganization,
		*confflags.ImplementationProject,
		*confflags.ImplementationURL,
		*confflags.ImplementationVersion,
		*confflags.ImplementationContact,
	)

	supportedFeaturesSet := sets.New(features.AgenticCoreFeatures.UnsortedList()...)
	if *confflags.SupportedFeatures != "" {
		for _, f := range strings.Split(*confflags.SupportedFeatures, ",") {
			supportedFeaturesSet.Insert(gatewayfeatures.FeatureName(strings.TrimSpace(f)))
		}
	}

	opts := confsuite.ConformanceOptions{
		Client:               c,
		ClientOptions:        clientOptions,
		Clientset:            cs,
		RestConfig:           cfg,
		GatewayClassName:     *confflags.GatewayClassName,
		BaseManifests:        "resources/base.yaml.tmpl",
		Debug:                *confflags.ShowDebug,
		CleanupBaseResources: *confflags.CleanupBaseResources,
		SupportedFeatures:    supportedFeaturesSet,
		SkipTests:            skipTests,
		ExemptFeatures:       exemptFeatures,
		RunTest:              *confflags.RunTest,
		Mode:                 *confflags.Mode,
		Implementation:       implementation,
		ConformanceProfiles:  conformanceProfiles,
		ManifestFS:           []fs.FS{&Manifests},
		ReportOutputPath:     *confflags.ReportOutput,
		SkipProvisionalTests: *confflags.SkipProvisionalTests,
		AllowCRDsMismatch:    true,
		NamespaceLabels:      namespaceLabels,
		NamespaceAnnotations: namespaceAnnotations,
	}

	// Remove any features explicitly exempted via flags.
	if opts.ExemptFeatures.Len() > 0 {
		var toDelete []gatewayfeatures.FeatureName
		for _, f := range opts.ExemptFeatures.UnsortedList() {
			toDelete = append(toDelete, f)
		}
		opts.SupportedFeatures = opts.SupportedFeatures.Delete(toDelete...)
	}

	return opts
}

func RunConformance(t *testing.T) {
	RunConformanceWithOptions(t, DefaultOptions(t))
}

func RunConformanceWithOptions(t *testing.T, opts confsuite.ConformanceOptions) {
	t.Helper()
	ctx := context.Background()

	confsuite.RegisterConformanceProfile(GatewayLayerProfile)

	cSuite, err := confsuite.NewConformanceTestSuite(opts)
	require.NoError(t, err, "error initializing conformance suite")

	installedCRDs := &apiextensionsv1.CustomResourceDefinitionList{}
	err = opts.Client.List(ctx, installedCRDs)
	require.NoError(t, err, "error getting installedCRDs")

	apiVersion, err := getKubeAgenticNetworkingVersion(installedCRDs.Items)
	if err != nil {
		if opts.AllowCRDsMismatch {
			apiVersion = "UNDEFINED"
		} else {
			require.NoError(t, err, "error getting the kube-agentic-networking version")
		}
	}

	cSuite.Applier.ManifestFS = cSuite.ManifestFS
	// Setup conformance suite (Ensures GatewayClass is accepted, applies BaseManifests and certs)
	cSuite.Setup(t, tests.ConformanceTests)

	t.Log("Preparing TLS resources for Gateway")
	err = PrepareTLSResources(ctx, opts.Clientset, "agentic-conformance-infra")
	require.NoError(t, err, "error preparing TLS resources")

	t.Log("Touching Gateway to force reconciliation")
	gw := &gatewayv1.Gateway{}
	err = opts.Client.Get(ctx, client.ObjectKey{Namespace: "agentic-conformance-infra", Name: "conformance-primary"}, gw)
	require.NoError(t, err, "error getting Gateway to touch")
	if gw.Annotations == nil {
		gw.Annotations = make(map[string]string)
	}
	err = opts.Client.Update(ctx, gw)
	require.NoError(t, err, "error touching Gateway for reconciliation")

	t.Log("Waiting for agentic-conformance-infra namespace to be ready")
	kubernetes.NamespacesMustBeReady(t, opts.Client, cSuite.TimeoutConfig, []string{"agentic-conformance-infra"})

	err = cSuite.Run(t, tests.ConformanceTests)
	require.NoError(t, err, "error running conformance tests")

	if opts.ReportOutputPath != "" {
		t.Log("Generating Kube Agentic Networking conformance report")
		report, err := cSuite.Report()
		require.NoError(t, err, "error generating conformance report")

		agenticReport := AgenticNetworkingConformanceReport{
			GatewayLayerVersion: apiVersion,
			ConformanceReport:   *report,
		}
		err = agenticReport.WriteReport(t.Logf, opts.ReportOutputPath)
		require.NoError(t, err, "error writing conformance report")
	}
}

func getKubeAgenticNetworkingVersion(crds []apiextensionsv1.CustomResourceDefinition) (string, error) {
	var bundleVersion string
	for _, crd := range crds {
		// Only scan the xaccesspolicies CRD to extract the bundle version, allowing xbackends to remain unannotated.
		if crd.Name != "xaccesspolicies.agentic.networking.x-k8s.io" {
			continue
		}
		v, okv := crd.Annotations[version.BundleVersionAnnotation]
		if !okv {
			return "", errors.New("xaccesspolicies CRD found but missing the bundle version annotation")
		}
		bundleVersion = v
		break
	}
	if bundleVersion == "" {
		return "", errors.New("xaccesspolicies CRD not found in the cluster")
	}
	return bundleVersion, nil
}
