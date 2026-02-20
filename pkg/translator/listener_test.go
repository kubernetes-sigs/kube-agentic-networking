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
	"testing"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

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
	if tlsContext.RequireClientCertificate == nil || !tlsContext.RequireClientCertificate.Value {
		t.Errorf("RequireClientCertificate should be true for mTLS")
	}

	// Verify SDS Config Names
	common := tlsContext.CommonTlsContext
	if len(common.TlsCertificateSdsSecretConfigs) != 1 || common.TlsCertificateSdsSecretConfigs[0].Name != constants.SpiffeIdentitySdsConfigName {
		t.Errorf("Identity SDS secret config name mismatch")
	}

	validation := common.GetValidationContextSdsSecretConfig()
	if validation == nil || validation.Name != constants.SpiffeTrustSdsConfigName {
		t.Errorf("Trust SDS secret config name mismatch")
	}
}
