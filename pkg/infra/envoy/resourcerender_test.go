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

package envoy

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/agenticidentitysigner"
)

func TestRenderConfigMap(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
		},
	}
	rm := NewResourceManager(nil, gw, "envoy-image", "cluster.local")

	cm, err := rm.renderConfigMap()
	if err != nil {
		t.Fatalf("failed to render ConfigMap: %v", err)
	}

	// Verify entries exist
	requiredKeys := []string{
		constants.EnvoyBootstrapCfgFileName,
		constants.SpiffeIdentitySdsFileName,
		constants.SpiffeTrustSdsFileName,
	}

	for _, key := range requiredKeys {
		if _, ok := cm.Data[key]; !ok {
			t.Errorf("ConfigMap missing key: %s", key)
		}
	}

	// Verify SDS content
	identitySds := cm.Data[constants.SpiffeIdentitySdsFileName]
	if !strings.Contains(identitySds, "/run/gateway-identity-mtls/credential-bundle.pem") {
		t.Errorf("identity SDS does not point to the correct bundle path")
	}

	trustSds := cm.Data[constants.SpiffeTrustSdsFileName]
	expectedTrustPath := "/run/gateway-identity-mtls/cluster.local.trust-bundle.pem"
	if !strings.Contains(trustSds, expectedTrustPath) {
		t.Errorf("trust SDS does not point to the correct bundle path: got %s, want %s", trustSds, expectedTrustPath)
	}
}

func TestRenderDeployment(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
		},
	}
	trustDomain := "test.cluster"
	rm := NewResourceManager(nil, gw, "envoy-image", trustDomain)

	dep := rm.renderDeployment()

	// Verify Identification Labels
	if dep.Labels[constants.GatewayNameLabel] != gw.Name {
		t.Errorf("Deployment missing gateway name label: got %s, want %s", dep.Labels[constants.GatewayNameLabel], gw.Name)
	}
	if dep.Spec.Selector.MatchLabels[constants.GatewayNameLabel] != gw.Name {
		t.Errorf("Deployment selector missing gateway name label: got %s, want %s", dep.Spec.Selector.MatchLabels[constants.GatewayNameLabel], gw.Name)
	}
	if dep.Spec.Template.Labels[constants.GatewayNameLabel] != gw.Name {
		t.Errorf("Pod template missing gateway name label: got %s, want %s", dep.Spec.Template.Labels[constants.GatewayNameLabel], gw.Name)
	}

	// Verify Volume Mounts are ReadOnly
	for _, m := range dep.Spec.Template.Spec.Containers[0].VolumeMounts {
		if !m.ReadOnly {
			t.Errorf("Volume mount %s should be ReadOnly", m.Name)
		}
	}

	// Verify Projected Volumes
	var tlsConfigVol *corev1.Volume
	for _, v := range dep.Spec.Template.Spec.Volumes {
		if v.Name == envoyIdentityMtlsVolumeName {
			tlsConfigVol = &v
			break
		}
	}

	if tlsConfigVol == nil {
		t.Fatal("envoy-identity-mtls volume not found in deployment")
	}

	sources := tlsConfigVol.Projected.Sources
	foundCTB := false
	foundPC := false

	for _, s := range sources {
		if s.ClusterTrustBundle != nil {
			foundCTB = true
			if *s.ClusterTrustBundle.SignerName != agenticidentitysigner.Name {
				t.Errorf("CTB signer mismatch: got %s, want %s", *s.ClusterTrustBundle.SignerName, agenticidentitysigner.Name)
			}
			labels := agenticidentitysigner.CTBLabels(trustDomain)
			for k, v := range labels {
				if s.ClusterTrustBundle.LabelSelector.MatchLabels[k] != v {
					t.Errorf("CTB label mismatch for key %s: got %s, want %s", k, s.ClusterTrustBundle.LabelSelector.MatchLabels[k], v)
				}
			}
			expectedPath := constants.SpiffeTrustBundleFileName(trustDomain)
			if s.ClusterTrustBundle.Path != expectedPath {
				t.Errorf("CTB path mismatch: got %s, want %s", s.ClusterTrustBundle.Path, expectedPath)
			}
		}
		if s.PodCertificate != nil {
			foundPC = true
			if s.PodCertificate.SignerName != agenticidentitysigner.Name {
				t.Errorf("PC signer mismatch: got %s, want %s", s.PodCertificate.SignerName, agenticidentitysigner.Name)
			}
			if s.PodCertificate.CredentialBundlePath != constants.SpiffeCredentialBundleFileName {
				t.Errorf("PC bundle path mismatch: got %s, want %s", s.PodCertificate.CredentialBundlePath, constants.SpiffeCredentialBundleFileName)
			}
		}
	}

	if !foundCTB || !foundPC {
		t.Errorf("Deployment projected volume missing sources: CTB=%v, PC=%v", foundCTB, foundPC)
	}
}

func TestRenderService(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
		},
	}
	rm := NewResourceManager(nil, gw, "envoy-image", "cluster.local")

	svc := rm.renderService()

	if svc.Labels[constants.GatewayNameLabel] != gw.Name {
		t.Errorf("Service missing gateway name label: got %s, want %s", svc.Labels[constants.GatewayNameLabel], gw.Name)
	}
}

func TestRenderServiceAccount(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
		},
	}
	rm := NewResourceManager(nil, gw, "envoy-image", "cluster.local")

	sa := rm.renderServiceAccount()

	if sa.Labels[constants.GatewayNameLabel] != gw.Name {
		t.Errorf("ServiceAccount missing gateway name label: got %s, want %s", sa.Labels[constants.GatewayNameLabel], gw.Name)
	}
}
