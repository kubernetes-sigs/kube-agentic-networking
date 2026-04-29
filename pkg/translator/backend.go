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

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// routeBackend represents either an XBackend or a direct Service reference for HTTPRoute backendRefs.
// Used so we can build clusters and route action from both without duplicating caller logic.
type routeBackend struct {
	clusterName string
	xbackend    *agenticv0alpha0.XBackend // nil if this is a direct Service ref
	svcNS       string
	svcName     string
	svcPort     int32
}

func (rb *routeBackend) ClusterName() string { return rb.clusterName }

// Hostname returns the host rewrite for external backends; empty for Service or in-cluster XBackend.
func (rb *routeBackend) Hostname() string {
	if rb.xbackend != nil && rb.xbackend.Spec.MCP.Hostname != nil {
		return *rb.xbackend.Spec.MCP.Hostname
	}
	return ""
}

// XBackend returns the XBackend when this is an XBackend ref; nil for direct Service refs (no RBAC from XAccessPolicy).
func (rb *routeBackend) XBackend() *agenticv0alpha0.XBackend { return rb.xbackend }

// isServiceRef returns true if the BackendRef refers to a core Service (Kind nil or "Service", Group nil or "").
func isServiceRef(backendRef gatewayv1.BackendRef) bool {
	kind := "Service"
	if backendRef.Kind != nil {
		kind = string(*backendRef.Kind)
	}
	group := ""
	if backendRef.Group != nil {
		group = string(*backendRef.Group)
	}
	return (kind == "Service" || kind == "") && (group == "" || group == "core")
}

func (t *Translator) fetchBackend(namespace string, backendRef gatewayv1.BackendRef) (*routeBackend, error) {
	if isServiceRef(backendRef) {
		return t.fetchServiceBackend(namespace, backendRef)
	}
	// XBackend path
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

	backend, err := t.backendLister.XBackends(ns).Get(string(backendRef.Name))
	if err != nil {
		return nil, &ControllerError{
			Reason:  string(gatewayv1.RouteReasonBackendNotFound),
			Message: fmt.Sprintf("failed to get Backend %s/%s: %v", ns, backendRef.Name, err),
		}
	}

	if svcName := backend.Spec.MCP.ServiceName; svcName != nil {
		if _, err := t.serviceLister.Services(ns).Get(*svcName); err != nil {
			return nil, &ControllerError{
				Reason:  string(gatewayv1.RouteReasonBackendNotFound),
				Message: fmt.Sprintf("failed to get Backend service %s/%s: %v", ns, *svcName, err),
			}
		}
	}

	return &routeBackend{
		clusterName: fmt.Sprintf(constants.ClusterNameFormat, backend.Namespace, backend.Name),
		xbackend:    backend,
	}, nil
}

// fetchServiceBackend resolves a direct Service backendRef (Kind Service or nil).
func (t *Translator) fetchServiceBackend(routeNamespace string, backendRef gatewayv1.BackendRef) (*routeBackend, error) {
	ns := routeNamespace
	if backendRef.Namespace != nil {
		ns = string(*backendRef.Namespace)
	}
	if t.referenceGrantLister != nil && ns != routeNamespace {
		if !AllowedByReferenceGrant(routeNamespace, gatewayv1.GroupName, "HTTPRoute", ns, "", "Service", string(backendRef.Name), t.referenceGrantLister) {
			return nil, &ControllerError{
				Reason:  string(gatewayv1.RouteReasonRefNotPermitted),
				Message: fmt.Sprintf("cross-namespace reference to Service %s/%s not permitted by ReferenceGrant", ns, backendRef.Name),
			}
		}
	}
	svc, err := t.serviceLister.Services(ns).Get(string(backendRef.Name))
	if err != nil {
		return nil, &ControllerError{
			Reason:  string(gatewayv1.RouteReasonBackendNotFound),
			Message: fmt.Sprintf("failed to get Service %s/%s: %v", ns, backendRef.Name, err),
		}
	}
	port := resolveServicePort(svc, backendRef.Port)
	return &routeBackend{
		clusterName: fmt.Sprintf(constants.ClusterNameFormat, ns, string(backendRef.Name)),
		svcNS:       ns,
		svcName:     string(backendRef.Name),
		svcPort:     port,
	}, nil
}

func resolveServicePort(svc *corev1.Service, backendPort *gatewayv1.PortNumber) int32 {
	if backendPort != nil {
		for _, p := range svc.Spec.Ports {
			if p.Port == *backendPort {
				return p.Port
			}
		}
		return *backendPort
	}
	if len(svc.Spec.Ports) > 0 {
		return svc.Spec.Ports[0].Port
	}
	return constants.DefaultServicePort
}

func convertBackendToCluster(backend *agenticv0alpha0.XBackend) (*clusterv3.Cluster, error) {
	clusterName := fmt.Sprintf(constants.ClusterNameFormat, backend.Namespace, backend.Name)

	// Create the base cluster configuration.
	cluster := &clusterv3.Cluster{
		Name:           clusterName,
		ConnectTimeout: durationpb.New(constants.DefaultConnectTimeout),
	}

	if backend.Spec.MCP.ServiceName != nil {
		// For in-cluster services, use the FQDN.
		serviceFQDN := fmt.Sprintf("%s.%s.svc.cluster.local", *backend.Spec.MCP.ServiceName, backend.Namespace)
		cluster.ClusterDiscoveryType = &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS}
		//nolint:gosec // G115: port values are within valid uint32 bounds
		cluster.LoadAssignment = createClusterLoadAssignment(clusterName, serviceFQDN, uint32(backend.Spec.MCP.Port))
		return cluster, nil
	}

	// External MCP backend specified via backend.Spec.MCP.Hostname
	cluster.ClusterDiscoveryType = &clusterv3.Cluster_Type{Type: clusterv3.Cluster_LOGICAL_DNS}
	cluster.DnsLookupFamily = clusterv3.Cluster_ALL
	//nolint:gosec // G115: port values are within valid uint32 bounds
	cluster.LoadAssignment = createClusterLoadAssignment(clusterName, *backend.Spec.MCP.Hostname, uint32(backend.Spec.MCP.Port))
	// TODO: A new field will probably be added to Backend to allow configuring TLS for external MCP backends.
	// For now, we always enable TLS for external MCP backends.
	if true {
		tlsContext := &tlsv3.UpstreamTlsContext{
			Sni: *backend.Spec.MCP.Hostname,
		}
		tlsAny, err := anypb.New(tlsContext)
		if err != nil {
			return nil, err
		}
		cluster.TransportSocket = &corev3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &corev3.TransportSocket_TypedConfig{
				TypedConfig: tlsAny,
			},
		}
	}

	return cluster, nil
}

// buildClustersFromRouteBackends builds Envoy clusters from a mix of XBackend and direct Service refs.
func buildClustersFromRouteBackends(backends []*routeBackend) ([]*clusterv3.Cluster, error) {
	var clusters []*clusterv3.Cluster
	for _, rb := range backends {
		var cluster *clusterv3.Cluster
		var err error
		if rb.xbackend != nil {
			cluster, err = convertBackendToCluster(rb.xbackend)
		} else {
			cluster = convertServiceRefToCluster(rb.svcNS, rb.svcName, rb.svcPort)
		}
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, cluster)
	}
	return clusters, nil
}
