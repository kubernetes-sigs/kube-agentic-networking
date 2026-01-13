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

package translator

import (
	"fmt"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1listers "k8s.io/client-go/listers/core/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

const (
	// The timeout for new network connections to hosts in the cluster.
	defaultConnectTimeout = 5 * time.Second
)

func fetchBackend(namespace string, backendRef gatewayv1.BackendRef, backendLister agenticlisters.XBackendLister, serviceLister corev1listers.ServiceLister) (*agenticv0alpha0.XBackend, error) {
	// 1. Validate that the Kind is Backend.
	if backendRef.Kind != nil && *backendRef.Kind != "XBackend" {
		return nil, &ControllerError{
			Reason:  string(gatewayv1.RouteReasonInvalidKind),
			Message: fmt.Sprintf("unsupported backend kind: %s", *backendRef.Kind),
		}
	}

	ns := namespace
	if backendRef.Namespace != nil {
		ns = string(*backendRef.Namespace)
	}

	// 2. Fetch the Backend resource.
	backend, err := backendLister.XBackends(ns).Get(string(backendRef.Name))
	if err != nil {
		return nil, &ControllerError{
			Reason:  string(gatewayv1.RouteReasonBackendNotFound),
			Message: fmt.Sprintf("failed to get Backend %s/%s: %v", ns, backendRef.Name, err),
		}
	}

	// 3. Check if the referenced Service exists.
	if svcName := backend.Spec.MCP.ServiceName; svcName != nil {
		if _, err := serviceLister.Services(ns).Get(*svcName); err != nil {
			fmt.Printf("Service lookup error for backend %s/%s, error: %v\n", ns, backendRef.Name, err)
			return nil, &ControllerError{
				Reason:  string(gatewayv1.RouteReasonBackendNotFound),
				Message: fmt.Sprintf("failed to get Backend service %s/%s: %v", ns, *svcName, err),
			}
		}
	}

	// TODO: Do we need to check hostname resolution for external MCP backends?
	return backend, nil
}

func convertBackendToCluster(backend *agenticv0alpha0.XBackend) (*clusterv3.Cluster, error) {
	clusterName := fmt.Sprintf(constants.ClusterNameFormat, backend.Namespace, backend.Name)

	// Create the base cluster configuration.
	cluster := &clusterv3.Cluster{
		Name:           clusterName,
		ConnectTimeout: durationpb.New(defaultConnectTimeout),
	}

	if backend.Spec.MCP.ServiceName != nil {
		// For in-cluster services, use the FQDN.
		serviceFQDN := fmt.Sprintf("%s.%s.svc.cluster.local", *backend.Spec.MCP.ServiceName, backend.Namespace)
		cluster.ClusterDiscoveryType = &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS}
		cluster.LoadAssignment = createClusterLoadAssignment(clusterName, serviceFQDN, uint32(backend.Spec.MCP.Port))
		return cluster, nil
	}

	// External MCP backend specified via backend.Spec.MCP.Hostname
	cluster.ClusterDiscoveryType = &clusterv3.Cluster_Type{Type: clusterv3.Cluster_LOGICAL_DNS}
	cluster.LoadAssignment = createClusterLoadAssignment(clusterName, *backend.Spec.MCP.Hostname, uint32(backend.Spec.MCP.Port))
	// TODO: A new field will probably be added to Backend to allow configuring TLS for external MCP backends.
	// For now, we always enable TLS for external MCP backends.
	if true {
		tlsContext := &tlsv3.UpstreamTlsContext{
			Sni: *backend.Spec.MCP.Hostname,
		}
		any, err := anypb.New(tlsContext)
		if err != nil {
			return nil, err
		}
		cluster.TransportSocket = &corev3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &corev3.TransportSocket_TypedConfig{
				TypedConfig: any,
			},
		}
	}

	return cluster, nil
}

func buildClustersFromBackends(backends []*agenticv0alpha0.XBackend) ([]*clusterv3.Cluster, error) {
	var clusters []*clusterv3.Cluster
	for _, backend := range backends {
		cluster, err := convertBackendToCluster(backend)
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, cluster)
	}
	return clusters, nil
}

func buildK8sApiCluster() (*clusterv3.Cluster, error) {
	tlsContext := &tlsv3.UpstreamTlsContext{
		Sni: "kubernetes.default.svc",
		CommonTlsContext: &tlsv3.CommonTlsContext{
			ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
				ValidationContext: &tlsv3.CertificateValidationContext{
					TrustedCa: &corev3.DataSource{
						Specifier: &corev3.DataSource_Filename{
							// This tells Envoy to trust the K8s API server's cert
							Filename: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
						},
					},
				},
			},
		},
	}
	anyTlsContext, err := anypb.New(tlsContext)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UpstreamTlsContext: %w", err)
	}

	cluster := &clusterv3.Cluster{
		Name:                 constants.K8sAPIClusterName,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_LOGICAL_DNS},
		LoadAssignment:       createClusterLoadAssignment(constants.K8sAPIClusterName, "kubernetes.default.svc", 443), // Use port 443 for HTTPS
		TransportSocket: &corev3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &corev3.TransportSocket_TypedConfig{
				TypedConfig: anyTlsContext,
			},
		},
	}
	return cluster, nil
}
