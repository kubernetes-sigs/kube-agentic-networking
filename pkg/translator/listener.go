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
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	ext_authzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	jwt_authnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	mcpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/mcp/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

const (
	standardK8sOIDCJWKSURI = "https://kubernetes.default.svc/openid/v1/jwks"
	// Cache the keys for 1 hour to avoid spamming the API server
	jwksCacheDuration = 1 * time.Hour
	uriTimeout        = 5 * time.Second

	wellknownJWTAuthnFilter = "envoy.filters.http.jwt_authn"
)

// setListenerCondition is a helper to safely set a condition on a listener's status
// in a map of conditions.
func setListenerCondition(
	conditionsMap map[gatewayv1.SectionName][]metav1.Condition,
	listenerName gatewayv1.SectionName,
	condition metav1.Condition,
) {
	// This "get, modify, set" pattern is the standard way to
	// work around the Go constraint that map values are not addressable.
	conditions := conditionsMap[listenerName]
	if conditions == nil {
		conditions = []metav1.Condition{}
	}
	meta.SetStatusCondition(&conditions, condition)
	conditionsMap[listenerName] = conditions
}

// validateListeners checks for conflicts among all listeners on a Gateway as per the spec.
// It returns a map of conflicted listener conditions and a Gateway-level condition if any conflicts exist.
func (t *Translator) validateListeners(gateway *gatewayv1.Gateway) map[gatewayv1.SectionName][]metav1.Condition {
	listenerConditions := make(map[gatewayv1.SectionName][]metav1.Condition)
	for _, listener := range gateway.Spec.Listeners {
		// Initialize with a fresh slice.
		listenerConditions[listener.Name] = []metav1.Condition{}
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
				setListenerCondition(listenerConditions, listener.Name, metav1.Condition{
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
					setListenerCondition(listenerConditions, listener.Name, conflictedCondition)
					setListenerCondition(listenerConditions, conflictingListenerName, conflictedCondition)
				} else {
					seenHostnames[hostname] = listener.Name
				}
			}
		}
	}

	for _, listener := range gateway.Spec.Listeners {
		// If a listener is already conflicted, we don't need to check its secrets.
		if meta.IsStatusConditionTrue(listenerConditions[listener.Name], string(gatewayv1.ListenerConditionConflicted)) {
			continue
		}

		if listener.TLS == nil {
			// No TLS config, so no secrets to resolve. This listener is considered resolved.
			setListenerCondition(listenerConditions, listener.Name, metav1.Condition{
				Type:    string(gatewayv1.ListenerConditionResolvedRefs),
				Status:  metav1.ConditionTrue,
				Reason:  string(gatewayv1.ListenerReasonResolvedRefs),
				Message: "All references resolved",
			})
			continue
		}

		for _, certRef := range listener.TLS.CertificateRefs {
			if certRef.Group != nil && *certRef.Group != "" {
				setListenerCondition(listenerConditions, listener.Name, metav1.Condition{
					Type:    string(gatewayv1.ListenerConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
					Message: fmt.Sprintf("unsupported certificate ref grup: %s", *certRef.Group),
				})
				break
			}

			if certRef.Kind != nil && *certRef.Kind != "Secret" {
				setListenerCondition(listenerConditions, listener.Name, metav1.Condition{
					Type:    string(gatewayv1.ListenerConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
					Message: fmt.Sprintf("unsupported certificate ref kind: %s", *certRef.Kind),
				})
				break
			}

			secretNamespace := gateway.Namespace
			if certRef.Namespace != nil {
				secretNamespace = string(*certRef.Namespace)
			}

			secret, err := t.secretLister.Secrets(secretNamespace).Get(string(certRef.Name))
			if err != nil {
				setListenerCondition(listenerConditions, listener.Name, metav1.Condition{
					Type:    string(gatewayv1.ListenerConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
					Message: fmt.Sprintf("reference to Secret %s/%s not found", secretNamespace, certRef.Name),
				})
				break
			}
			if err := validateSecretCertificate(secret); err != nil {
				setListenerCondition(listenerConditions, listener.Name, metav1.Condition{
					Type:    string(gatewayv1.ListenerConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
					Message: fmt.Sprintf("malformed Secret %s/%s : %v", secretNamespace, certRef.Name, err.Error()),
				})
				break
			}
		}

		// Set the ResolvedRefs condition based on the outcome of the secret validation.
		if !meta.IsStatusConditionFalse(listenerConditions[listener.Name], string(gatewayv1.ListenerConditionResolvedRefs)) {
			setListenerCondition(listenerConditions, listener.Name, metav1.Condition{
				Type:    string(gatewayv1.ListenerConditionResolvedRefs),
				Status:  metav1.ConditionTrue,
				Reason:  string(gatewayv1.ListenerReasonResolvedRefs),
				Message: "All references resolved",
			})
		}
	}

	return listenerConditions
}

func (t *Translator) translateListenerToFilterChain(gateway *gatewayv1.Gateway, lis gatewayv1.Listener, routeName string, accessPolicyLister agenticlisters.XAccessPolicyLister) (*listener.FilterChain, error) {
	var filterChain *listener.FilterChain
	var err error

	switch lis.Protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		filterChain, err = buildHTTPFilterChain(lis, routeName, t.jwtIssuer, accessPolicyLister)
	case gatewayv1.TCPProtocolType, gatewayv1.TLSProtocolType:
		filterChain, err = buildTCPFilterChain(lis)
	case gatewayv1.UDPProtocolType:
		filterChain, err = buildUDPFilterChain(lis)
	}
	if err != nil {
		return nil, err
	}

	// Add SNI matching for applicable protocols
	if lis.Protocol == gatewayv1.HTTPSProtocolType || lis.Protocol == gatewayv1.TLSProtocolType {
		if lis.Hostname != nil && *lis.Hostname != "" {
			filterChain.FilterChainMatch = &listener.FilterChainMatch{
				ServerNames: []string{string(*lis.Hostname)},
			}
		}
		// Configure TLS context
		tlsContext, err := t.buildDownstreamTLSContext(context.Background(), gateway, lis)
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

func buildHTTPFilterChain(lis gatewayv1.Listener, routeName, jwtIssuer string, accessPolicyLister agenticlisters.XAccessPolicyLister) (*listener.FilterChain, error) {
	httpFilters, err := buildHTTPFilters(jwtIssuer, accessPolicyLister)
	if err != nil {
		return nil, err
	}

	hcmConfig := &hcm.HttpConnectionManager{
		StatPrefix: string(lis.Name),
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

func buildHTTPFilters(issuer string, accessPolicyLister agenticlisters.XAccessPolicyLister) ([]*hcm.HttpFilter, error) {
	// Configure JWT filter globally as it's needed for all routes to establish identity.
	jwtAuthnFilter, err := buildJwtAuthnFilter(issuer)
	if err != nil {
		return nil, err
	}

	mcpFilter, err := buildMCPFilter()
	if err != nil {
		return nil, err
	}

	rbacFilter, err := buildRBACFilter()
	if err != nil {
		return nil, err
	}

	extAuthzFilters, err := buildExtAuthzFilters(accessPolicyLister)
	if err != nil {
		return nil, err
	}

	routerFilter, err := buildRouterFilter()
	if err != nil {
		return nil, err
	}

	filters := []*hcm.HttpFilter{
		// IMPORTANT: Order matters here!
		// JWT filter must come before RBAC to populate claims for evaluation.
		// RBAC filter must come before the ext_authz filter to ensure evaluation of RBAC shadow rules that trigger ext_authz.
		// Ext_authz filter must come before router filter to enforce access control before routing.
		// Router filter must come last to handle routing after all other filters have processed the request.
		jwtAuthnFilter,
		mcpFilter,
		rbacFilter,
	}
	filters = append(filters, extAuthzFilters...)
	return append(filters, routerFilter), nil
}

func buildJwtAuthnFilter(issuer string) (*hcm.HttpFilter, error) {
	jwtProto := &jwt_authnv3.JwtAuthentication{
		Providers: map[string]*jwt_authnv3.JwtProvider{
			"kubernetes_provider": {
				Issuer: issuer, // Dynamically set issuer
				JwksSourceSpecifier: &jwt_authnv3.JwtProvider_RemoteJwks{
					RemoteJwks: &jwt_authnv3.RemoteJwks{
						HttpUri: &corev3.HttpUri{
							Uri: standardK8sOIDCJWKSURI,
							HttpUpstreamType: &corev3.HttpUri_Cluster{
								Cluster: constants.K8sAPIClusterName,
							},
							Timeout: durationpb.New(uriTimeout),
						},
						CacheDuration: durationpb.New(jwksCacheDuration),
					},
				},
				FromHeaders: []*jwt_authnv3.JwtHeader{
					{
						Name: constants.SAAuthTokenHeader,
					},
				},
				ClaimToHeaders: []*jwt_authnv3.JwtClaimToHeader{
					{
						ClaimName:  "sub",
						HeaderName: constants.UserRoleHeader,
					},
				},
				PayloadInMetadata: "sa_token",
			},
		},
		Rules: []*jwt_authnv3.RequirementRule{
			{
				Match: &routev3.RouteMatch{
					PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"},
				},
				RequirementType: &jwt_authnv3.RequirementRule_Requires{
					Requires: &jwt_authnv3.JwtRequirement{
						RequiresType: &jwt_authnv3.JwtRequirement_ProviderName{
							ProviderName: "kubernetes_provider",
						},
					},
				},
			},
		},
	}
	jwtAny, err := anypb.New(jwtProto)
	if err != nil {
		klog.Errorf("Failed to marshal jwt_authn config: %v", err)
		return nil, err
	}

	return &hcm.HttpFilter{
		Name: wellknownJWTAuthnFilter,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: jwtAny,
		},
	}, nil
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

func buildRBACFilter() (*hcm.HttpFilter, error) {
	rbacProto := &rbacv3.RBAC{}
	rbacAny, err := anypb.New(rbacProto)
	if err != nil {
		klog.Errorf("Failed to marshal rbac config: %v", err)
		return nil, err
	}

	return &hcm.HttpFilter{
		Name: wellknown.HTTPRoleBasedAccessControl,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: rbacAny,
		},
	}, nil
}

func buildExtAuthzFilters(accessPolicyLister agenticlisters.XAccessPolicyLister) ([]*hcm.HttpFilter, error) {
	accessPolicies, err := accessPolicyLister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list AccessPolicies: %w", err)
	}

	var filters []*hcm.HttpFilter
	hashes := make(map[string]struct{}) // To track unique externalAuth configs and avoid duplicate filters
	for _, ap := range accessPolicies {
		for _, rule := range ap.Spec.Rules {
			if rule.Authorization == nil || rule.Authorization.ExternalAuth == nil {
				continue
			}
			extAuthz := rule.Authorization.ExternalAuth
			hash, err := externalAuthUniqueID(extAuthz)
			if err != nil {
				klog.Error(err)
				continue
			}
			if _, exists := hashes[hash]; exists {
				continue // Skip if we've already created a filter for this config
			}
			hashes[hash] = struct{}{}
			extAuthzProto := &ext_authzv3.ExtAuthz{
				FailureModeAllow: false,
				FilterEnabledMetadata: &matcherv3.MetadataMatcher{
					Filter: wellknown.HTTPRoleBasedAccessControl,
					Path: []*matcherv3.MetadataMatcher_PathSegment{
						{
							Segment: &matcherv3.MetadataMatcher_PathSegment_Key{
								Key: fmt.Sprintf("%s_%s_shadow_effective_policy_id", externalAuthzShadowRulePrefix, hash),
							},
						},
					},
					Value: &matcherv3.ValueMatcher{
						MatchPattern: &matcherv3.ValueMatcher_PresentMatch{PresentMatch: true},
					},
				},
				MetadataContextNamespaces: []string{
					wellknownJWTAuthnFilter,
				},
			}
			backendRef := extAuthz.BackendRef
			clusterName := clusterNameForBackendRefAndProtocol(backendRef, ap.GetNamespace(), string(extAuthz.ExternalAuthProtocol))
			switch extAuthz.ExternalAuthProtocol {
			case gatewayv1.HTTPRouteExternalAuthGRPCProtocol:
				extAuthzProto.Services = &ext_authzv3.ExtAuthz_GrpcService{
					GrpcService: &corev3.GrpcService{
						TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
							EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
								ClusterName: clusterName,
								Authority:   fqdnFromBackendRef(backendRef, ap.GetNamespace()),
							},
						},
					},
				}
				if extAuthz.GRPCAuthConfig != nil && len(extAuthz.GRPCAuthConfig.AllowedRequestHeaders) > 0 {
					extAuthzProto.AllowedHeaders = &matcherv3.ListStringMatcher{
						Patterns: toEnvoyExactStringMatchers(extAuthz.GRPCAuthConfig.AllowedRequestHeaders),
					}
				}
			case gatewayv1.HTTPRouteExternalAuthHTTPProtocol:
				if config := extAuthz.HTTPAuthConfig; config != nil {
					if backendRef.Kind != nil && *backendRef.Kind != "Service" {
						klog.Errorf("Unsupported backend ref kind for ext_authz HTTP protocol: %s", *backendRef.Kind)
						continue
					}
					uri := fmt.Sprintf("http://%s", backendRef.Name)
					if namespace := backendRef.Namespace; namespace != nil {
						uri = fmt.Sprintf("%s.%s.svc.cluster.local", uri, *namespace)
					}
					if port := backendRef.Port; port != nil {
						uri = fmt.Sprintf("%s:%d", uri, *port)
					}
					extAuthzProto.Services = &ext_authzv3.ExtAuthz_HttpService{
						HttpService: &ext_authzv3.HttpService{
							ServerUri: &corev3.HttpUri{
								Uri:     uri,
								Timeout: durationpb.New(uriTimeout),
							},
							PathPrefix: config.Path,
						},
					}
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
				klog.Errorf("Failed to marshal ext_authz config: %v", err)
				return nil, err
			}
			extAuthzFilter := &hcm.HttpFilter{
				Name: wellknown.HTTPExternalAuthorization,
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: extAuthzAny,
				},
			}
			filters = append(filters, extAuthzFilter)
		}
	}

	return filters, nil
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

func (t *Translator) buildDownstreamTLSContext(ctx context.Context, gateway *gatewayv1.Gateway, lis gatewayv1.Listener) (*anypb.Any, error) {
	if lis.TLS == nil {
		return nil, nil
	}
	if len(lis.TLS.CertificateRefs) == 0 {
		return nil, fmt.Errorf("TLS is configured, but no certificate refs are provided")
	}

	tlsContext := &tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			TlsCertificates: []*tlsv3.TlsCertificate{},
		},
	}

	for _, certRef := range lis.TLS.CertificateRefs {
		if certRef.Group != nil && *certRef.Group != "" {
			return nil, fmt.Errorf("unsupported certificate ref group: %s", *certRef.Group)
		}
		if certRef.Kind != nil && *certRef.Kind != "Secret" {
			return nil, fmt.Errorf("unsupported certificate ref kind: %s", *certRef.Kind)
		}

		secretNamespace := gateway.Namespace
		if certRef.Namespace != nil {
			secretNamespace = string(*certRef.Namespace)
		}

		secretName := string(certRef.Name)
		secret, err := t.secretLister.Secrets(secretNamespace).Get(secretName)
		if err != nil {
			// Per the spec, if the grant was missing, we must not reveal that the secret doesn't exist.
			// The error from the grant check above takes precedence.
			return nil, fmt.Errorf("failed to get secret %s/%s: %w", secretNamespace, secretName, err)
		}

		tlsCert, err := toEnvoyTlsCertificate(secret)
		if err != nil {
			return nil, fmt.Errorf("failed to convert secret to tls certificate: %v", err)
		}
		tlsContext.CommonTlsContext.TlsCertificates = append(tlsContext.CommonTlsContext.TlsCertificates, tlsCert)
	}

	any, err := anypb.New(tlsContext)
	if err != nil {
		return nil, err
	}
	return any, nil
}

func validateSecretCertificate(secret *corev1.Secret) error {
	privateKey, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return fmt.Errorf("secret %s/%s does not contain key %s", secret.Namespace, secret.Name, corev1.TLSPrivateKeyKey)
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return fmt.Errorf("secret %s/%s key %s does not contain a valid PEM-encoded private key", secret.Namespace, secret.Name, corev1.TLSPrivateKeyKey)
	}

	certChain, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return fmt.Errorf("secret %s/%s does not contain key %s", secret.Namespace, secret.Name, corev1.TLSCertKey)
	}
	block, _ = pem.Decode(certChain)
	if block == nil {
		return fmt.Errorf("secret %s/%s key %s does not contain a valid PEM-encoded certificate chain", secret.Namespace, secret.Name, corev1.TLSCertKey)
	}
	return nil
}

func toEnvoyTlsCertificate(secret *corev1.Secret) (*tlsv3.TlsCertificate, error) {
	privateKey, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s does not contain key %s", secret.Namespace, secret.Name, corev1.TLSPrivateKeyKey)
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, fmt.Errorf("secret %s/%s key %s does not contain a valid PEM-encoded private key", secret.Namespace, secret.Name, corev1.TLSPrivateKeyKey)
	}

	certChain, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s does not contain key %s", secret.Namespace, secret.Name, corev1.TLSCertKey)
	}
	block, _ = pem.Decode(certChain)
	if block == nil {
		return nil, fmt.Errorf("secret %s/%s key %s does not contain a valid PEM-encoded certificate chain", secret.Namespace, secret.Name, corev1.TLSCertKey)
	}

	return &tlsv3.TlsCertificate{
		CertificateChain: &corev3.DataSource{
			Specifier: &corev3.DataSource_InlineBytes{
				InlineBytes: certChain,
			},
		},
		PrivateKey: &corev3.DataSource{
			Specifier: &corev3.DataSource_InlineBytes{
				InlineBytes: privateKey,
			},
		},
	}, nil
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
