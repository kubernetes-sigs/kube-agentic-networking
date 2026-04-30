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
	"fmt"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	mcpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/mcp/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	tlsinspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// newTLSCertificateSecret creates a new Envoy TLS certificate secret.
func newTLSCertificateSecret(name string, certBytes, keyBytes []byte) *tlsv3.Secret {
	return &tlsv3.Secret{
		Name: name,
		Type: &tlsv3.Secret_TlsCertificate{
			TlsCertificate: &tlsv3.TlsCertificate{
				CertificateChain: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineBytes{InlineBytes: certBytes},
				},
				PrivateKey: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineBytes{InlineBytes: keyBytes},
				},
			},
		},
	}
}

// newValidationContextSecret creates a new Envoy validation context secret.
func newValidationContextSecret(name string, caBytes []byte) *tlsv3.Secret {
	return &tlsv3.Secret{
		Name: name,
		Type: &tlsv3.Secret_ValidationContext{
			ValidationContext: &tlsv3.CertificateValidationContext{
				TrustedCa: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineBytes{InlineBytes: caBytes},
				},
			},
		},
	}
}

// createClusterLoadAssignment constructs a ClusterLoadAssignment for a given service.
func createClusterLoadAssignment(clusterName, serviceHost string, servicePort uint32) *endpointv3.ClusterLoadAssignment {
	return &endpointv3.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpointv3.LocalityLbEndpoints{
			{
				LbEndpoints: []*endpointv3.LbEndpoint{
					{
						HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
							Endpoint: &endpointv3.Endpoint{
								Address: &corev3.Address{
									Address: &corev3.Address_SocketAddress{
										SocketAddress: &corev3.SocketAddress{
											Address: serviceHost,
											PortSpecifier: &corev3.SocketAddress_PortValue{
												PortValue: servicePort,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// convertServiceRefToCluster creates an Envoy cluster from a direct Service reference.
func convertServiceRefToCluster(ns, name string, port int32) *clusterv3.Cluster {
	clusterName := fmt.Sprintf(constants.ClusterNameFormat, ns, name)
	serviceFQDN := fmt.Sprintf("%s.%s.svc.cluster.local", name, ns)
	cluster := &clusterv3.Cluster{
		Name:                 clusterName,
		ConnectTimeout:       durationpb.New(constants.DefaultConnectTimeout),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS},
		//nolint:gosec // G115: port values are within valid uint32 bounds
		LoadAssignment: createClusterLoadAssignment(clusterName, serviceFQDN, uint32(port)),
	}
	return cluster
}

// createEnvoyAddress creates an Envoy Address for a given port.
func createEnvoyAddress(port uint32) *corev3.Address {
	return &corev3.Address{
		Address: &corev3.Address_SocketAddress{
			SocketAddress: &corev3.SocketAddress{
				Protocol: corev3.SocketAddress_TCP,
				Address:  "0.0.0.0",
				PortSpecifier: &corev3.SocketAddress_PortValue{
					PortValue: port,
				},
			},
		},
	}
}

// createListenerFilters returns the default listener filters.
func createListenerFilters() []*listener.ListenerFilter {
	tlsInspectorConfig, _ := anypb.New(&tlsinspector.TlsInspector{})
	return []*listener.ListenerFilter{
		{
			Name: wellknown.TlsInspector,
			ConfigType: &listener.ListenerFilter_TypedConfig{
				TypedConfig: tlsInspectorConfig,
			},
		},
	}
}

// toEnvoyExactStringMatchers converts a slice of strings to Exact StringMatchers.
func toEnvoyExactStringMatchers(s []string) []*matcherv3.StringMatcher {
	var matchers []*matcherv3.StringMatcher
	for _, str := range s {
		matchers = append(matchers, &matcherv3.StringMatcher{
			MatchPattern: &matcherv3.StringMatcher_Exact{
				Exact: str,
			},
		})
	}
	return matchers
}

// newAdsSdsSecretConfig creates an SdsSecretConfig using ADS.
func newAdsSdsSecretConfig(secretName string) *tlsv3.SdsSecretConfig {
	return &tlsv3.SdsSecretConfig{
		Name: secretName,
		SdsConfig: &corev3.ConfigSource{
			ResourceApiVersion: corev3.ApiVersion_V3,
			ConfigSourceSpecifier: &corev3.ConfigSource_Ads{
				Ads: &corev3.AggregatedConfigSource{},
			},
		},
	}
}

// newPathSdsSecretConfig creates an SdsSecretConfig using a local path.
func newPathSdsSecretConfig(name, filename string) *tlsv3.SdsSecretConfig {
	return &tlsv3.SdsSecretConfig{
		Name: name,
		SdsConfig: &corev3.ConfigSource{
			ResourceApiVersion: corev3.ApiVersion_V3,
			ConfigSourceSpecifier: &corev3.ConfigSource_PathConfigSource{
				PathConfigSource: &corev3.PathConfigSource{
					Path: fmt.Sprintf("%s/%s", constants.EnvoySdsMountPath, filename),
				},
			},
		},
	}
}

// buildMCPFilter constructs the MCP filter.
func buildMCPFilter() (*hcm.HttpFilter, error) {
	mcpProto := &mcpv3.Mcp{}
	mcpAny, err := anypb.New(mcpProto)
	if err != nil {
		klog.Errorf("Failed to marshal mcp config: %v", err)
		return nil, err
	}

	return &hcm.HttpFilter{
		Name: "envoy.filters.http.mcp",
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: mcpAny,
		},
	}, nil
}

// buildRouterFilter constructs the router filter.
func buildRouterFilter() (*hcm.HttpFilter, error) {
	routerProto := &routerv3.Router{}
	routerAny, err := anypb.New(routerProto)
	if err != nil {
		klog.Errorf("Failed to marshal router config: %v", err)
		return nil, err
	}

	return &hcm.HttpFilter{
		Name: wellknown.Router,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: routerAny,
		},
	}, nil
}

// buildLocalReplyConfig constructs the local reply configuration for 403 responses
func buildLocalReplyConfig() *hcm.LocalReplyConfig {
	return &hcm.LocalReplyConfig{
		Mappers: []*hcm.ResponseMapper{
			{
				Filter: &accesslogv3.AccessLogFilter{
					FilterSpecifier: &accesslogv3.AccessLogFilter_AndFilter{
						AndFilter: &accesslogv3.AndFilter{
							Filters: []*accesslogv3.AccessLogFilter{
								{
									FilterSpecifier: &accesslogv3.AccessLogFilter_StatusCodeFilter{
										StatusCodeFilter: &accesslogv3.StatusCodeFilter{
											Comparison: &accesslogv3.ComparisonFilter{
												Op: accesslogv3.ComparisonFilter_EQ,
												Value: &corev3.RuntimeUInt32{
													DefaultValue: 403,
												},
											},
										},
									},
								},
								{
									FilterSpecifier: &accesslogv3.AccessLogFilter_HeaderFilter{
										HeaderFilter: &accesslogv3.HeaderFilter{
											Header: &routev3.HeaderMatcher{
												Name:                 "WWW-Authenticate",
												HeaderMatchSpecifier: &routev3.HeaderMatcher_PresentMatch{PresentMatch: false},
											},
										},
									},
								},
							},
						},
					},
				},
				StatusCode: wrapperspb.UInt32(200),
				BodyFormatOverride: &corev3.SubstitutionFormatString{
					Format: &corev3.SubstitutionFormatString_JsonFormat{
						JsonFormat: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"jsonrpc": structpb.NewStringValue("2.0"),
								"id":      structpb.NewStringValue("%DYNAMIC_METADATA(mcp_proxy:id)%"),
								"error": structpb.NewStructValue(&structpb.Struct{
									Fields: map[string]*structpb.Value{
										"code":    structpb.NewNumberValue(403),
										"message": structpb.NewStringValue("Access to this tool is forbidden."),
									},
								}),
							},
						},
					},
					ContentType: "application/json",
				},
			},
		},
	}
}
