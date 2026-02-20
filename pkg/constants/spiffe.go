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

package constants

import "fmt"

const (
	// SpiffeMountPath is the base path where SPIFFE certificates (credential-bundle.pem, trust-bundle.pem) are mounted in the Envoy pod.
	// This is the Projected Volume that interacts with the Kubernetes Pod Certificate Signer
	SpiffeMountPath = "/run/gateway-identity-mtls"
	// SpiffeCredentialBundleFileName is the name of the file containing both the SPIFFE certificate chain and the private key.
	SpiffeCredentialBundleFileName = "credential-bundle.pem"
	// spiffeTrustBundleFileSuffix is the suffix of the file containing the SPIFFE trust bundle.
	// The full filename is <trust_domain>.<spiffeTrustBundleFileSuffix>
	spiffeTrustBundleFileSuffix = "trust-bundle.pem"

	// EnvoySdsMountPath is the path where Envoy SDS configurations are mounted.
	EnvoySdsMountPath = "/etc/envoy/sds"
	// SpiffeIdentitySdsFileName is the filename for the SDS configuration that defines the Envoy TLS certificate and private key secret.
	// This file is referenced in Envoy's DownstreamTlsContext common_tls_context.tls_certificate_sds_secret_configs.
	SpiffeIdentitySdsFileName = "spiffe_identity.yaml"
	// SpiffeTrustSdsFileName is the filename for the SDS configuration that defines the Envoy TLS trust bundle (CA) secret.
	// This file is referenced in Envoy's DownstreamTlsContext common_tls_context.validation_context_sds_secret_config.
	SpiffeTrustSdsFileName = "spiffe_trust.yaml"

	// SDS config names used in Envoy configuration
	SpiffeIdentitySdsConfigName = "spiffe_identity"
	SpiffeTrustSdsConfigName    = "spiffe_trust"

	// DefaultKeyType is the key type used for SPIFFE identity certificates.
	DefaultKeyType = "ECDSAP256"
)

// SpiffeTrustBundleFileName returns the full trust bundle filename for a given trust domain.
func SpiffeTrustBundleFileName(trustDomain string) string {
	return fmt.Sprintf("%s.%s", trustDomain, spiffeTrustBundleFileSuffix)
}
