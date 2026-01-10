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
	mutationv3 "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	credential_injectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/credential_injector/v3"
	headermutationv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	upstream_codecv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/upstream_codec/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	genericv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/http/injected_credentials/generic/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	http_protocol_options "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
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
							Filename: constants.ServiceAccountCACertPath,
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

	anyHttpProtocolOptions, err := buildK8sApiHttpProtocolOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal http protocol options: %w", err)
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
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": anyHttpProtocolOptions,
		},
	}
	return cluster, nil
}

// buildK8sApiHttpProtocolOptions configures the HTTP protocol options for upstream
// requests to the Kubernetes API server. It sets up a chain of HTTP filters to
// handle credential injection, header manipulation, and finally routing the request.
// This is necessary for the Envoy proxy to securely communicate with the Kubernetes API.
func buildK8sApiHttpProtocolOptions() (*anypb.Any, error) {
	credentialInjectorFilter, err := buildK8sApiCredentialInjector()
	if err != nil {
		return nil, fmt.Errorf("failed to build credential injector filter: %w", err)
	}

	headerMutationFilter, err := buildHeaderMutationFilter()
	if err != nil {
		return nil, fmt.Errorf("failed to build header mutation filter: %w", err)
	}

	upstreamCodecFilter, err := buildUpstreamCodecFilter()
	if err != nil {
		return nil, fmt.Errorf("failed to build upstream codec filter: %w", err)
	}

	httpProtocolOptions := &http_protocol_options.HttpProtocolOptions{
		// upstream_protocol_options is a required field. Missing it will get "Proto constraint validation failed" error.
		UpstreamProtocolOptions: &http_protocol_options.HttpProtocolOptions_ExplicitHttpConfig_{
			ExplicitHttpConfig: &http_protocol_options.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &http_protocol_options.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
					Http2ProtocolOptions: &corev3.Http2ProtocolOptions{
						ConnectionKeepalive: &corev3.KeepaliveSettings{
							// TODO: make these values configurable
							Interval: durationpb.New(30 * time.Second),
							Timeout:  durationpb.New(5 * time.Second),
						},
					},
				},
			},
		},
		HttpFilters: []*hcmv3.HttpFilter{
			credentialInjectorFilter,
			headerMutationFilter,
			upstreamCodecFilter,
		},
	}

	anyHttpProtocolOptions, err := anypb.New(httpProtocolOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal http protocol options: %w", err)
	}
	return anyHttpProtocolOptions, nil
}

// buildK8sApiCredentialInjector configures the `envoy.filters.http.credential_injector` filter.
// This filter is responsible for injecting a Kubernetes service account token
// into the Authorization header in the upstream requests.
func buildK8sApiCredentialInjector() (*hcmv3.HttpFilter, error) {
	genericCredential := &genericv3.Generic{
		Credential: &tlsv3.SdsSecretConfig{
			// Since only name is specified, secret will be loaded from static resources.
			Name: constants.CredentialBearerSecretName,
		},
	}
	genericCredentialAny, err := anypb.New(genericCredential)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal generic provider config: %w", err)
	}

	credentialInjector := &credential_injectorv3.CredentialInjector{
		Credential: &corev3.TypedExtensionConfig{
			Name:        "envoy.http.injected_credentials.generic",
			TypedConfig: genericCredentialAny,
		},
		Overwrite: true,
	}
	anyCredentialInjector, err := anypb.New(credentialInjector)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential injector: %w", err)
	}

	return &hcmv3.HttpFilter{
		Name: "envoy.filters.http.credential_injector",
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: anyCredentialInjector,
		},
	}, nil
}

// buildHeaderMutationFilter configures the `envoy.filters.http.header_mutation` filter.
// This filter modifies the Authorization header in upstream requests by prepending
// the "Bearer " prefix to the token value from the incoming request.
// The header will be `Authorization: Bearer <token>`.
func buildHeaderMutationFilter() (*hcmv3.HttpFilter, error) {
	headerMutation := &headermutationv3.HeaderMutation{
		Mutations: &headermutationv3.Mutations{
			RequestMutations: []*mutationv3.HeaderMutation{
				{
					Action: &mutationv3.HeaderMutation_Append{
						Append: &corev3.HeaderValueOption{
							Header: &corev3.HeaderValue{
								Key:   "Authorization",
								Value: "Bearer %REQ(Authorization)%",
							},
							AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS,
						},
					},
				},
			},
		},
	}
	anyHeaderMutation, err := anypb.New(headerMutation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header mutation: %w", err)
	}
	return &hcmv3.HttpFilter{
		Name: "envoy.filters.http.header_mutation",
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: anyHeaderMutation,
		},
	}, nil
}

// buildUpstreamCodecFilter configures the `envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec` filter.
// This filter is used to explicitly specify the codec for the upstream connection.
func buildUpstreamCodecFilter() (*hcmv3.HttpFilter, error) {
	upstreamCodec := &upstream_codecv3.UpstreamCodec{}
	anyUpstreamCodec, err := anypb.New(upstreamCodec)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal upstream codec: %w", err)
	}

	return &hcmv3.HttpFilter{
		Name: "envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec",
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: anyUpstreamCodec,
		},
	}, nil
}
