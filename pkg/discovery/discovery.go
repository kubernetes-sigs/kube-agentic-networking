/*
Copyright 2025 The Kubernetes Authors.

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

package discovery

import (
	"encoding/json"
	"fmt"
	"net/http"

	"k8s.io/client-go/rest"
)

// JWTIssuer automatically discovers the JWT issuer from the Kubernetes API server
// by querying the OIDC discovery endpoint.
func JWTIssuer(config *rest.Config) (string, error) {
	// Use the REST config to create a transport that trusts the cluster's CA.
	transport, err := rest.TransportFor(config)
	if err != nil {
		return "", fmt.Errorf("failed to create transport from kubeconfig: %w", err)
	}
	client := &http.Client{Transport: transport}

	// Make a request to the standard OIDC discovery endpoint.
	wellKnownURL := config.Host + "/.well-known/openid-configuration"
	resp, err := client.Get(wellKnownURL)
	if err != nil {
		return "", fmt.Errorf("failed to get OIDC discovery endpoint %s: %w", wellKnownURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery endpoint %s returned status %d", wellKnownURL, resp.StatusCode)
	}

	// Parse the JSON response and extract the issuer.
	var oidcDiscovery struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&oidcDiscovery); err != nil {
		return "", fmt.Errorf("failed to decode OIDC discovery response: %w", err)
	}

	if oidcDiscovery.Issuer == "" {
		return "", fmt.Errorf("issuer field not found in OIDC discovery response from %s", wellKnownURL)
	}

	return oidcDiscovery.Issuer, nil
}
