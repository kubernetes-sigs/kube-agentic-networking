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

package translator

import (
	"reflect"
	"testing"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	apiv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

type mockAccessPolicyLister struct {
	agenticlisters.XAccessPolicyLister
}

func (m *mockAccessPolicyLister) List(_ labels.Selector) ([]*apiv0alpha0.XAccessPolicy, error) {
	return nil, nil
}

func TestBuildDownstreamTLSContext(t *testing.T) {
	anyContext, err := buildDownstreamTLSContext()
	if err != nil {
		t.Fatalf("failed to build downstream TLS context: %v", err)
	}

	if anyContext == nil {
		t.Fatal("expected non-nil TLS context")
	}

	tlsContext := &tlsv3.DownstreamTlsContext{}
	if err := anyContext.UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("failed to unmarshal any to DownstreamTlsContext: %v", err)
	}

	// Verify mTLS requirement
	if tlsContext.GetRequireClientCertificate() == nil || !tlsContext.GetRequireClientCertificate().GetValue() {
		t.Errorf("RequireClientCertificate should be true for mTLS")
	}

	// Verify SDS Config Names
	common := tlsContext.GetCommonTlsContext()
	if len(common.GetTlsCertificateSdsSecretConfigs()) != 1 || common.GetTlsCertificateSdsSecretConfigs()[0].GetName() != constants.SpiffeIdentitySdsConfigName {
		t.Errorf("Identity SDS secret config name mismatch")
	}

	validation := common.GetValidationContextSdsSecretConfig()
	if validation == nil || validation.GetName() != constants.SpiffeTrustSdsConfigName {
		t.Errorf("Trust SDS secret config name mismatch")
	}
}

func TestTranslateListenerToFilterChain(t *testing.T) {
	mockLister := &mockAccessPolicyLister{}
	translator := &Translator{}

	testCases := []struct {
		name                string
		listener            gatewayv1.Listener
		expectedServerNames []string
	}{
		{
			name: "HTTPS with hostname",
			listener: gatewayv1.Listener{
				Name:     "https",
				Port:     443,
				Protocol: gatewayv1.HTTPSProtocolType,
				Hostname: ptr.To(gatewayv1.Hostname("example.com")),
			},
			expectedServerNames: []string{"example.com"},
		},
		{
			name: "HTTPS with wildcard hostname",
			listener: gatewayv1.Listener{
				Name:     "https-wildcard",
				Port:     443,
				Protocol: gatewayv1.HTTPSProtocolType,
				Hostname: ptr.To(gatewayv1.Hostname("*.example.com")),
			},
			expectedServerNames: []string{"*.example.com"},
		},
		{
			name: "HTTP without hostname",
			listener: gatewayv1.Listener{
				Name:     "http",
				Port:     80,
				Protocol: gatewayv1.HTTPProtocolType,
			},
			expectedServerNames: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fc, err := translator.translateListenerToFilterChain(tc.listener, "route-config", mockLister)
			if err != nil {
				t.Fatalf("failed to translate listener: %v", err)
			}

			if len(tc.expectedServerNames) > 0 {
				if fc.GetFilterChainMatch() == nil {
					t.Fatal("expected FilterChainMatch to be set")
				}
				if !reflect.DeepEqual(fc.GetFilterChainMatch().GetServerNames(), tc.expectedServerNames) {
					t.Errorf("expected ServerNames %v, got %v", tc.expectedServerNames, fc.GetFilterChainMatch().GetServerNames())
				}
			} else if fc.GetFilterChainMatch() != nil && len(fc.GetFilterChainMatch().GetServerNames()) > 0 {
				t.Errorf("expected no ServerNames in FilterChainMatch, got %v", fc.GetFilterChainMatch().GetServerNames())
			}
		})
	}
}
