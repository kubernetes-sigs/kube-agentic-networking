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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	ext_authzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	mcpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/mcp/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	tlsinspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	udpproxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/udp/udp_proxy/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

const (
	uriTimeout = 5 * time.Second

	wellknownJWTAuthnFilter = "envoy.filters.http.jwt_authn"
)

type listenerConditions map[gatewayv1.SectionName][]metav1.Condition

func (lc listenerConditions) setCondition(listenerName gatewayv1.SectionName, condition metav1.Condition) {
	conditions := lc[listenerName]
	if conditions == nil {
		conditions = []metav1.Condition{}
	}
	meta.SetStatusCondition(&conditions, condition)
	lc[listenerName] = conditions
}

func (lc listenerConditions) isConditionTrue(listenerName gatewayv1.SectionName, conditionType string) bool {
	return meta.IsStatusConditionTrue(lc[listenerName], conditionType)
}

// validateListeners checks for conflicts among all listeners on a Gateway as per the spec.
// It returns a map of conflicted listener conditions and a Gateway-level condition if any conflicts exist.
func (t *Translator) validateListeners(gateway *gatewayv1.Gateway) listenerConditions {
	conds := make(listenerConditions)
	for _, listener := range gateway.Spec.Listeners {
		// Initialize with a fresh slice.
		conds[listener.Name] = []metav1.Condition{}
	}

	// Check for Port and Hostname Conflicts
	listenersByPort := make(map[gatewayv1.PortNumber][]gatewayv1.Listener)
	for _, listener := range gateway.Spec.Listeners {
		listenersByPort[listener.Port] = append(listenersByPort[listener.Port], listener)
	}

	for _, listenersOnPort := range listenersByPort {
		// Rule: A TCP listener cannot share a port with HTTP/HTTPS/TLS listeners.
		hasTCP := false
		hasHTTPTLS := false
		for _, listener := range listenersOnPort {
			if listener.Protocol == gatewayv1.TCPProtocolType || listener.Protocol == gatewayv1.UDPProtocolType {
				hasTCP = true
			}
			if listener.Protocol == gatewayv1.HTTPProtocolType || listener.Protocol == gatewayv1.HTTPSProtocolType || listener.Protocol == gatewayv1.TLSProtocolType {
				hasHTTPTLS = true
			}
		}

		if hasTCP && hasHTTPTLS {
			for _, listener := range listenersOnPort {
				conds.setCondition(listener.Name, metav1.Condition{
					Type:    string(gatewayv1.ListenerConditionConflicted),
					Status:  metav1.ConditionTrue,
					Reason:  string(gatewayv1.ListenerReasonProtocolConflict),
					Message: "Protocol conflict: TCP/UDP listeners cannot share a port with HTTP/HTTPS/TLS listeners.",
				})
			}
			continue // Skip further checks for this port
		}

		// Rule: HTTP/HTTPS/TLS listeners on the same port must have unique hostnames.
		seenHostnames := make(map[gatewayv1.Hostname]gatewayv1.SectionName)
		for _, listener := range listenersOnPort {
			// This check only applies to protocols that use hostnames for distinction.
			if listener.Protocol == gatewayv1.HTTPProtocolType || listener.Protocol == gatewayv1.HTTPSProtocolType || listener.Protocol == gatewayv1.TLSProtocolType {
				hostname := gatewayv1.Hostname("")
				if listener.Hostname != nil {
					hostname = *listener.Hostname
				}

				if conflictingListenerName, exists := seenHostnames[hostname]; exists {
					conflictedCondition := metav1.Condition{
						Type:    string(gatewayv1.ListenerConditionConflicted),
						Status:  metav1.ConditionTrue,
						Reason:  string(gatewayv1.ListenerReasonHostnameConflict),
						Message: fmt.Sprintf("Hostname '%s' conflicts with another listener on the same port.", hostname),
					}
					conds.setCondition(listener.Name, conflictedCondition)
					conds.setCondition(conflictingListenerName, conflictedCondition)
				} else {
					seenHostnames[hostname] = listener.Name
				}
			}
		}
	}

	for _, listener := range gateway.Spec.Listeners {
		// If a listener is already conflicted, we don't need to check its secrets.
		if conds.isConditionTrue(listener.Name, string(gatewayv1.ListenerConditionConflicted)) {
			continue
		}

		if condition := t.validateCertificateRefs(gateway, listener); condition != nil {
			conds.setCondition(listener.Name, *condition)
		} else {
			conds.setCondition(listener.Name, metav1.Condition{
				Type:               string(gatewayv1.ListenerConditionResolvedRefs),
				Status:             metav1.ConditionTrue,
				Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
				Message:            "All references resolved",
				ObservedGeneration: gateway.Generation,
			})
		}
	}

	return conds
}

func (t *Translator) validateCertificateRefs(gateway *gatewayv1.Gateway, listener gatewayv1.Listener) *metav1.Condition {
	if listener.TLS == nil {
		return nil
	}

	for _, ref := range listener.TLS.CertificateRefs {
		group := ""
		if ref.Group != nil {
			group = string(*ref.Group)
		}
		kind := "Secret"
		if ref.Kind != nil {
			kind = string(*ref.Kind)
		}

		if (group != "" && group != "core") || kind != "Secret" {
			return &metav1.Condition{
				Type:               string(gatewayv1.ListenerConditionResolvedRefs),
				Status:             metav1.ConditionFalse,
				Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
				Message:            fmt.Sprintf("Unsupported certificate reference group %q kind %q. Only core/Secret is supported.", group, kind),
				ObservedGeneration: gateway.Generation,
			}
		}

		ns := gateway.Namespace
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}

		// Check if secret exists
		_, err := t.secretLister.Secrets(ns).Get(string(ref.Name))
		if err != nil {
			reason := string(gatewayv1.ListenerReasonInvalidCertificateRef)
			message := fmt.Sprintf("Failed to get Secret %s/%s: %v", ns, ref.Name, err)
			if apierrors.IsNotFound(err) {
				message = fmt.Sprintf("Secret %s/%s not found", ns, ref.Name)
			}
			return &metav1.Condition{
				Type:               string(gatewayv1.ListenerConditionResolvedRefs),
				Status:             metav1.ConditionFalse,
				Reason:             reason,
				Message:            message,
				ObservedGeneration: gateway.Generation,
			}
		}

		// Check if cross-namespace reference is allowed by ReferenceGrant
		if ns == gateway.Namespace {
			continue
		}

		if !AllowedByReferenceGrant(
			gateway.Namespace, "gateway.networking.k8s.io", "Gateway",
			ns, "", "Secret", string(ref.Name),
			t.referenceGrantLister,
		) {
			return &metav1.Condition{
				Type:               string(gatewayv1.ListenerConditionResolvedRefs),
				Status:             metav1.ConditionFalse,
				Reason:             string(gatewayv1.ListenerReasonRefNotPermitted),
				Message:            fmt.Sprintf("Reference to Secret %s/%s not permitted by ReferenceGrant", ns, ref.Name),
				ObservedGeneration: gateway.Generation,
			}
		}
	}

	return nil
}

func (t *Translator) translateListenerToFilterChain(lis gatewayv1.Listener, routeName string, gateway *gatewayv1.Gateway) (*listener.FilterChain, error) {
	var filterChain *listener.FilterChain
	var err error

	switch lis.Protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		filterChain, err = t.buildHTTPFilterChain(lis, routeName, gateway)
	case gatewayv1.TCPProtocolType, gatewayv1.TLSProtocolType:
		filterChain, err = buildTCPFilterChain(lis)
	case gatewayv1.UDPProtocolType:
		filterChain, err = buildUDPFilterChain(lis)
	}
	if err != nil {
		return nil, err
	}

	// Add TLS transport socket config if the listener uses HTTPS or TLS protocol.
	// https://github.com/kubernetes-sigs/kube-agentic-networking/issues/95
	if lis.Protocol == gatewayv1.HTTPSProtocolType || lis.Protocol == gatewayv1.TLSProtocolType {
		if lis.Hostname != nil && *lis.Hostname != "" {
			if filterChain.GetFilterChainMatch() == nil {
				filterChain.FilterChainMatch = &listener.FilterChainMatch{}
			}
			filterChain.FilterChainMatch.ServerNames = []string{string(*lis.Hostname)}
		}

		tlsContext, err := buildDownstreamTLSContext()
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS context for listener %s: %w", lis.Name, err)
		}
		if tlsContext != nil {
			filterChain.TransportSocket = &corev3.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &corev3.TransportSocket_TypedConfig{
					TypedConfig: tlsContext,
				},
			}
		}
	}

	return filterChain, nil
}

// buildLocalReplyConfig constructs the local reply configuration for 403 responses
func buildLocalReplyConfig() *hcm.LocalReplyConfig {
	return &hcm.LocalReplyConfig{
		Mappers: []*hcm.ResponseMapper{
			{
				// Use an access-log style filter to identify the responses we want to remap.
				// The AND filter ensures both conditions must hold:
				// 1) Status code equals the runtime-configurable value (default 403).
				// 2) The "WWW-Authenticate" header is NOT present so we don't catch
				//    upstream authentication failures (which include that header).
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
								// MCP servers typically return 403 with a "WWW-Authenticate" header when
								// the client fails to authenticate. We only want to remap our custom 403s,
								// so require that header to be absent.
								// https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#protected-resource-metadata-discovery-requirements
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
				// TODO: https://github.com/kubernetes-sigs/kube-agentic-networking/issues/169
				// NOTE: Temporary workaround: Agent SDKs incorrectly treat a 403 in a way that
				// prevents proper client-side error handling. To remain compatible until all SDKs
				// are fixed, set the HTTP status code to 200 and encode a JSON-RPC error body.
				// See the linked SDK improvement below for context.
				// https://github.com/modelcontextprotocol/python-sdk/commit/2fe56e56de2aff8fcb964ff7e26e7c6df4d14653
				// Change the HTTP status code back to 403 when the commit above is released in all Agent SDKs.
				StatusCode: wrapperspb.UInt32(200),
				// Override the body format to JSON-RPC 2.0.
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

func (t *Translator) buildHTTPFilterChain(lis gatewayv1.Listener, routeName string, gateway *gatewayv1.Gateway) (*listener.FilterChain, error) {
	httpFilters, err := t.buildHTTPFilters(gateway)
	if err != nil {
		return nil, err
	}

	hcmConfig := &hcm.HttpConnectionManager{
		StatPrefix:       string(lis.Name),
		LocalReplyConfig: buildLocalReplyConfig(),
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource: &corev3.ConfigSource{
					ResourceApiVersion:    corev3.ApiVersion_V3,
					ConfigSourceSpecifier: &corev3.ConfigSource_Ads{Ads: &corev3.AggregatedConfigSource{}},
				},
				RouteConfigName: routeName,
			},
		},
		HttpFilters: httpFilters,
	}
	hcmAny, err := anypb.New(hcmConfig)
	if err != nil {
		return nil, err
	}

	return &listener.FilterChain{
		Filters: []*listener.Filter{{
			Name: wellknown.HTTPConnectionManager,
			ConfigType: &listener.Filter_TypedConfig{
				TypedConfig: hcmAny,
			},
		}},
	}, nil
}

func buildTCPFilterChain(lis gatewayv1.Listener) (*listener.FilterChain, error) {
	// TCP and TLS listeners require a TCP proxy filter.
	// We'll assume for now that routes for these are not supported and it's a direct pass-through.
	tcpProxy := &tcpproxyv3.TcpProxy{
		StatPrefix: string(lis.Name),
		ClusterSpecifier: &tcpproxyv3.TcpProxy_Cluster{
			Cluster: "some_static_cluster", // This needs to be determined from a TCPRoute/TLSRoute
		},
	}
	tcpProxyAny, err := anypb.New(tcpProxy)
	if err != nil {
		return nil, err
	}
	return &listener.FilterChain{
		Filters: []*listener.Filter{{
			Name: wellknown.TCPProxy,
			ConfigType: &listener.Filter_TypedConfig{
				TypedConfig: tcpProxyAny,
			},
		}},
	}, nil
}

func buildUDPFilterChain(lis gatewayv1.Listener) (*listener.FilterChain, error) {
	udpProxy := &udpproxy.UdpProxyConfig{
		StatPrefix: string(lis.Name),
		RouteSpecifier: &udpproxy.UdpProxyConfig_Cluster{
			Cluster: "some_udp_cluster", // This needs to be determined from a UDPRoute
		},
	}
	udpProxyAny, err := anypb.New(udpProxy)
	if err != nil {
		return nil, err
	}
	return &listener.FilterChain{
		Filters: []*listener.Filter{{
			Name: "envoy.filters.udp_listener.udp_proxy",
			ConfigType: &listener.Filter_TypedConfig{
				TypedConfig: udpProxyAny,
			},
		}},
	}, nil
}

func (t *Translator) buildHTTPFilters(gateway *gatewayv1.Gateway) ([]*hcm.HttpFilter, error) {
	// 1. Add MCP filter.
	mcpFilter, err := buildMCPFilter()
	if err != nil {
		return nil, err
	}

	// 2. Add Gateway-level RBAC filters.
	gatewayRBACFilters, err := t.buildGatewayLevelRBACFilters(gateway)
	if err != nil {
		return nil, err
	}

	// 3. Add Backend-level RBAC filters.
	// We build only placeholder filters for backends that have policies at this stage.
	// These will be overridden at the cluster/route level.
	backendRBACFiltersCount := t.calculateMaxBackendRBACFilters(gateway)
	backendRBACFilters, err := t.buildBackendLevelRBACFilters(backendRBACFiltersCount)
	if err != nil {
		return nil, err
	}

	// 4. Add ext_authz filters.
	extAuthzFilters, err := t.buildExtAuthzFilters(gateway)
	if err != nil {
		return nil, err
	}

	// 5. Add router filter.
	routerFilter, err := buildRouterFilter()
	if err != nil {
		return nil, err
	}

	// Compose the list at the end to ensure the correct order.
	// IMPORTANT: Order matters here!
	// 1. The MCP filter must come first to populate metadata for RBAC.
	// 2. Gateway-level RBAC filters must come before backend-level RBAC filters.
	// 3. Backend-level RBAC filters must come before the ext_authz filter to ensure evaluation of RBAC shadow rules that trigger ext_authz.
	// 4. Ext_authz filter must come before router filter to enforce access control before routing.
	// 5. Router filter must come last to handle routing after all other filters have processed the request.
	var filters []*hcm.HttpFilter
	filters = append(filters, mcpFilter)
	filters = append(filters, gatewayRBACFilters...)
	filters = append(filters, backendRBACFilters...)
	filters = append(filters, extAuthzFilters...)
	filters = append(filters, routerFilter)

	return filters, nil
}

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

func (t *Translator) buildExtAuthzFilters(gateway *gatewayv1.Gateway) ([]*hcm.HttpFilter, error) {
	accessPolicies, err := t.accessPolicyLister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list AccessPolicies: %w", err)
	}

	var filters []*hcm.HttpFilter
	uniqueExtAuthzConfigs := make(map[string]struct{}) // To track unique externalAuth configs and avoid duplicate filters
	for _, ap := range accessPolicies {
		// We only care about AccessPolicies that are directly or indirectly attached to this Gateway.
		if !t.isAccessPolicyAttachedToGateway(ap, gateway) {
			continue
		}
		for _, rule := range ap.Spec.Rules {
			if rule.Authorization == nil || rule.Authorization.ExternalAuth == nil {
				continue
			}
			extAuthz := rule.Authorization.ExternalAuth
			uniqueID, err := externalAuthUniqueID(extAuthz)
			if err != nil {
				klog.Error(err)
				continue
			}
			if _, exists := uniqueExtAuthzConfigs[uniqueID]; exists {
				continue // Skip if we've already built an ext_authz filter for this config
			}
			uniqueExtAuthzConfigs[uniqueID] = struct{}{}

			// Build the ext_authz filter for this RBAC filter and ext_authz config combination
			extAuthzFilter, err := buildExtAuthzFilterForRBACFilter(extAuthz, uniqueID, ap.GetNamespace())
			if err != nil {
				klog.Error(err)
				continue
			}
			filters = append(filters, extAuthzFilter)
		}
	}

	return filters, nil
}

func buildExtAuthzFilterForRBACFilter(extAuthz *gatewayv1.HTTPExternalAuthFilter, extAuthzUniqueID, namespace string) (*hcm.HttpFilter, error) {
	extAuthzProto := &ext_authzv3.ExtAuthz{
		FailureModeAllow: false,
		FilterEnabledMetadata: &matcherv3.MetadataMatcher{
			Filter: wellknown.HTTPRoleBasedAccessControl,
			Path: []*matcherv3.MetadataMatcher_PathSegment{
				{
					Segment: &matcherv3.MetadataMatcher_PathSegment_Key{
						Key: fmt.Sprintf("%s_%s_shadow_effective_policy_id", externalAuthzShadowRulePrefix, extAuthzUniqueID),
					},
				},
			},
			Value: &matcherv3.ValueMatcher{
				MatchPattern: &matcherv3.ValueMatcher_PresentMatch{PresentMatch: true},
			},
		},
		MetadataContextNamespaces: []string{
			mcpProxyFilterName,
			wellknownJWTAuthnFilter, // Although we don't directly depend on the JWT authn filter, we propagate metadata that it generates for use in ext_authz, in case the filter is set by the user.
		},
	}
	backendRef := extAuthz.BackendRef
	clusterName := clusterNameForBackendRefAndProtocol(backendRef, namespace, string(extAuthz.ExternalAuthProtocol))
	switch extAuthz.ExternalAuthProtocol {
	case gatewayv1.HTTPRouteExternalAuthGRPCProtocol: // grpc protocol
		extAuthzProto.Services = &ext_authzv3.ExtAuthz_GrpcService{
			GrpcService: &corev3.GrpcService{
				TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
						ClusterName: clusterName,
						Authority:   fqdnFromBackendRef(backendRef, namespace),
					},
				},
			},
		}
		if extAuthz.GRPCAuthConfig != nil && len(extAuthz.GRPCAuthConfig.AllowedRequestHeaders) > 0 {
			extAuthzProto.AllowedHeaders = &matcherv3.ListStringMatcher{
				Patterns: toEnvoyExactStringMatchers(extAuthz.GRPCAuthConfig.AllowedRequestHeaders),
			}
		}
	case gatewayv1.HTTPRouteExternalAuthHTTPProtocol: // http protocol
		if config := extAuthz.HTTPAuthConfig; config != nil {
			if backendRef.Kind != nil && *backendRef.Kind != "Service" {
				return nil, fmt.Errorf("Unsupported backend ref kind for ext_authz HTTP protocol: %s", *backendRef.Kind)
			}
			uri := fmt.Sprintf("http://%s", backendRef.Name)
			if namespace := backendRef.Namespace; namespace != nil {
				uri = fmt.Sprintf("%s.%s.svc.cluster.local", uri, *namespace)
			}
			if port := backendRef.Port; port != nil {
				uri = fmt.Sprintf("%s:%d", uri, *port)
			}
			httpService := &ext_authzv3.ExtAuthz_HttpService{
				HttpService: &ext_authzv3.HttpService{
					ServerUri: &corev3.HttpUri{
						Uri: uri,
						HttpUpstreamType: &corev3.HttpUri_Cluster{
							Cluster: clusterName,
						},
						Timeout: durationpb.New(uriTimeout),
					},
					PathPrefix: config.Path,
				},
			}
			if len(config.AllowedResponseHeaders) > 0 {
				httpService.HttpService.AuthorizationResponse = &ext_authzv3.AuthorizationResponse{
					AllowedUpstreamHeaders: &matcherv3.ListStringMatcher{
						Patterns: toEnvoyExactStringMatchers(config.AllowedResponseHeaders),
					},
				}
			}
			extAuthzProto.Services = httpService
			if len(config.AllowedRequestHeaders) > 0 {
				extAuthzProto.AllowedHeaders = &matcherv3.ListStringMatcher{
					Patterns: toEnvoyExactStringMatchers(config.AllowedRequestHeaders),
				}
			}
			// We don't support AllowedResponseHeaders yet
		}
	}
	if forwardRequestBody := extAuthz.ForwardBody; forwardRequestBody != nil {
		extAuthzProto.WithRequestBody = &ext_authzv3.BufferSettings{
			MaxRequestBytes:     uint32(forwardRequestBody.MaxSize),
			AllowPartialMessage: true,
		}
	}
	extAuthzAny, err := anypb.New(extAuthzProto)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal ext_authz config: %v", err)
	}
	return &hcm.HttpFilter{
		Name: wellknown.HTTPExternalAuthorization,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: extAuthzAny,
		},
	}, nil
}

func (t *Translator) isAccessPolicyAttachedToGateway(ap *v0alpha0.XAccessPolicy, gateway *gatewayv1.Gateway) bool {
	for _, targetRef := range ap.Spec.TargetRefs {
		if (targetRef.Group == "" || targetRef.Group == gatewayv1.GroupName) && targetRef.Kind == "Gateway" && string(targetRef.Name) == gateway.Name {
			return true
		}
	}
	routes := t.getHTTPRoutesForGateway(gateway)
	for _, targetRef := range ap.Spec.TargetRefs {
		if targetRef.Group == v0alpha0.GroupName && targetRef.Kind == "XBackend" {
			for _, route := range routes {
				for _, rule := range route.Spec.Rules {
					for _, beRef := range rule.BackendRefs {
						if beRef.Group != nil && *beRef.Group == v0alpha0.GroupName && beRef.Kind != nil && *beRef.Kind == "XBackend" {
							ns := route.Namespace
							if beRef.Namespace != nil {
								ns = string(*beRef.Namespace)
							}
							if ns == ap.Namespace && string(beRef.Name) == string(targetRef.Name) {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

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

// TODO: We may want to optimize this in the future by supporting both listener's TLS config and the shared TLS context.
// https://github.com/kubernetes-sigs/kube-agentic-networking/issues/94
func buildDownstreamTLSContext() (*anypb.Any, error) {
	tlsContext := &tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{
				{
					Name: constants.SpiffeIdentitySdsConfigName,
					SdsConfig: &corev3.ConfigSource{
						ResourceApiVersion: corev3.ApiVersion_V3,
						ConfigSourceSpecifier: &corev3.ConfigSource_PathConfigSource{
							PathConfigSource: &corev3.PathConfigSource{
								Path: fmt.Sprintf("%s/%s", constants.EnvoySdsMountPath, constants.SpiffeIdentitySdsFileName),
							},
						},
					},
				},
			},
			ValidationContextType: &tlsv3.CommonTlsContext_ValidationContextSdsSecretConfig{
				ValidationContextSdsSecretConfig: &tlsv3.SdsSecretConfig{
					Name: constants.SpiffeTrustSdsConfigName,
					SdsConfig: &corev3.ConfigSource{
						ResourceApiVersion: corev3.ApiVersion_V3,
						ConfigSourceSpecifier: &corev3.ConfigSource_PathConfigSource{
							PathConfigSource: &corev3.PathConfigSource{
								Path: fmt.Sprintf("%s/%s", constants.EnvoySdsMountPath, constants.SpiffeTrustSdsFileName),
							},
						},
					},
				},
			},
		},
		RequireClientCertificate: wrapperspb.Bool(true),
	}

	anyObj, err := anypb.New(tlsContext)
	if err != nil {
		return nil, err
	}
	return anyObj, nil
}

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

func externalAuthUniqueID(externalAuth *gatewayv1.HTTPExternalAuthFilter) (string, error) {
	j, err := json.Marshal(externalAuth)
	if err != nil {
		return "", fmt.Errorf("Failed to marshal externalAuth config for unique ID generation: %v", err)
	}
	sha256sum := sha256.Sum256(j)
	return fmt.Sprintf("%x", sha256sum), nil
}
