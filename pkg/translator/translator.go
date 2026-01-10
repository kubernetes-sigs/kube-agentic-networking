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
	"fmt"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoyproxytypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

type ControllerError struct {
	Reason  string
	Message string
}

// Error implements the error interface.
func (e *ControllerError) Error() string {
	return e.Message
}

// Translator holds the xDS cache and version for generating snapshots.
type Translator struct {
	jwtIssuer          string
	client             kubernetes.Interface
	gwClient           gatewayclient.Interface
	namespaceLister    corev1listers.NamespaceLister
	serviceLister      corev1listers.ServiceLister
	secretLister       corev1listers.SecretLister
	gatewayLister      gatewaylisters.GatewayLister
	httprouteLister    gatewaylisters.HTTPRouteLister
	accessPolicyLister agenticlisters.XAccessPolicyLister
	backendLister      agenticlisters.XBackendLister
}

func New(
	jwtIssuer string,
	client kubernetes.Interface,
	gwClient gatewayclient.Interface,
	namespaceLister corev1listers.NamespaceLister,
	serviceLister corev1listers.ServiceLister,
	secretLister corev1listers.SecretLister,
	gatewayLister gatewaylisters.GatewayLister,
	httpRouteLister gatewaylisters.HTTPRouteLister,
	accessPolicyLister agenticlisters.XAccessPolicyLister,
	backendLister agenticlisters.XBackendLister,
) *Translator {
	return &Translator{
		jwtIssuer,
		client,
		gwClient,
		namespaceLister,
		serviceLister,
		secretLister,
		gatewayLister,
		httpRouteLister,
		accessPolicyLister,
		backendLister,
	}
}

// TranslateGatewayToXDS translates Gateway and HTTPRoute resources into Envoy xDS resources.
func (t *Translator) TranslateGatewayToXDS(ctx context.Context, gw *gatewayv1.Gateway) (map[resourcev3.Type][]envoyproxytypes.Resource, error) {
	// Get the desired state
	envoyResources, _, _, err := t.buildEnvoyResourcesForGateway(gw)
	if err != nil {
		return nil, err
	}

	return envoyResources, nil
}

var (
	SupportedKinds = sets.New[gatewayv1.Kind](
		"HTTPRoute",
	)
)

// Main State Calculation Function
func (t *Translator) buildEnvoyResourcesForGateway(gateway *gatewayv1.Gateway) (
	map[resourcev3.Type][]envoyproxytypes.Resource,
	[]gatewayv1.ListenerStatus,
	map[types.NamespacedName][]gatewayv1.RouteParentStatus, // HTTPRoutes
	error,
) {

	httpRouteStatuses := make(map[types.NamespacedName][]gatewayv1.RouteParentStatus)
	routesByListener := make(map[gatewayv1.SectionName][]*gatewayv1.HTTPRoute)

	// 1. List HTTPRoutes referencing this Gateway
	allHTTPRoutesForGateway := t.getHTTPRoutesForGateway(gateway)
	// 2. Validate each HTTPRoute and group accepted ones by listener
	for _, httpRoute := range allHTTPRoutesForGateway {
		key := types.NamespacedName{Name: httpRoute.Name, Namespace: httpRoute.Namespace}
		parentStatuses, acceptingListeners := t.validateHTTPRoute(gateway, httpRoute)

		// Store the definitive status for the route.
		if len(parentStatuses) > 0 {
			httpRouteStatuses[key] = parentStatuses
		}
		// If the route was accepted, associate it with the listeners that accepted it.
		if len(acceptingListeners) > 0 {
			// Associate the accepted route with the listeners that will handle it.
			// Use a set to prevent adding a route multiple times to the same listener.
			processedListeners := make(map[gatewayv1.SectionName]bool)
			for _, listener := range acceptingListeners {
				if _, ok := processedListeners[listener.Name]; !ok {
					routesByListener[listener.Name] = append(routesByListener[listener.Name], httpRoute)
					processedListeners[listener.Name] = true
				}
			}
		}
	}

	// Start building Envoy config using only the pre-validated and accepted routes
	envoyRoutes := []envoyproxytypes.Resource{}
	envoyClusters := make(map[string]envoyproxytypes.Resource)
	allListenerStatuses := make(map[gatewayv1.SectionName]gatewayv1.ListenerStatus)

	// 3. Group Gateway listeners by port
	listenersByPort := make(map[gatewayv1.PortNumber][]gatewayv1.Listener)
	for _, listener := range gateway.Spec.Listeners {
		listenersByPort[listener.Port] = append(listenersByPort[listener.Port], listener)
	}

	// validate listeners that may reuse the same port
	listenerValidationConditions := t.validateListeners(gateway)

	finalEnvoyListeners := []envoyproxytypes.Resource{}
	// 4. For each port group, process Listeners (build routes & filter chains)
	for port, listeners := range listenersByPort {
		// This slice will hold the filter chains.
		var filterChains []*listenerv3.FilterChain
		// Prepare to collect ALL virtual hosts for this port into a single list.
		virtualHostsForPort := make(map[string]*routev3.VirtualHost)
		routeName := fmt.Sprintf(constants.RouteNameFormat, port)

		// All these listeners have the same port
		for _, listener := range listeners {
			var attachedRoutes int32
			listenerStatus := gatewayv1.ListenerStatus{
				Name:           gatewayv1.SectionName(listener.Name),
				SupportedKinds: []gatewayv1.RouteGroupKind{},
				Conditions:     listenerValidationConditions[listener.Name],
				AttachedRoutes: 0,
			}
			supportedKinds, allKindsValid := getSupportedKinds(listener)
			listenerStatus.SupportedKinds = supportedKinds

			if !allKindsValid {
				meta.SetStatusCondition(&listenerStatus.Conditions, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonInvalidRouteKinds),
					Message:            "Invalid route kinds specified in allowedRoutes",
					ObservedGeneration: gateway.Generation,
				})
				allListenerStatuses[listener.Name] = listenerStatus
				continue // Stop processing this invalid listener
			}

			isConflicted := meta.IsStatusConditionTrue(listenerStatus.Conditions, string(gatewayv1.ListenerConditionConflicted))
			// If the listener is conflicted set its status and skip Envoy config generation.
			if isConflicted {
				allListenerStatuses[listener.Name] = listenerStatus
				continue
			}

			// If there are not references issues then set condition to true
			if !meta.IsStatusConditionFalse(listenerStatus.Conditions, string(gatewayv1.ListenerConditionResolvedRefs)) {
				meta.SetStatusCondition(&listenerStatus.Conditions, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
					Message:            "All references resolved",
					ObservedGeneration: gateway.Generation,
				})
			}

			switch listener.Protocol {
			case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
				// 5. For each accepted HTTPRoute for this listener -> translate to Envoy routes
				for _, httpRoute := range routesByListener[listener.Name] {
					routes, allValidBackends, resolvedRefsCondition := translateHTTPRouteToEnvoyRoutes(httpRoute, t.serviceLister, t.accessPolicyLister, t.backendLister)

					key := types.NamespacedName{Name: httpRoute.Name, Namespace: httpRoute.Namespace}
					currentParentStatuses := httpRouteStatuses[key]
					for i := range currentParentStatuses {
						// Only add the ResolvedRefs condition if the parent was Accepted.
						if meta.IsStatusConditionTrue(currentParentStatuses[i].Conditions, string(gatewayv1.RouteConditionAccepted)) {
							meta.SetStatusCondition(&currentParentStatuses[i].Conditions, resolvedRefsCondition)
						}
					}
					httpRouteStatuses[key] = currentParentStatuses

					clusters, err := buildClustersFromBackends(allValidBackends)
					if err != nil {
						return nil, nil, nil, fmt.Errorf("failed to build clusters from HTTPRoute %s/%s: %w", httpRoute.Namespace, httpRoute.Name, err)
					}
					for _, cluster := range clusters {
						envoyClusters[cluster.Name] = cluster
					}

					// Aggregate Envoy routes into VirtualHosts.
					if routes != nil {
						attachedRoutes++
						// 7. Put routes into virtual hosts for each intersecting hostname
						// Get the domain for this listener's VirtualHost.
						vhostDomains := getIntersectingHostnames(listener, httpRoute.Spec.Hostnames)
						for _, domain := range vhostDomains {
							vh, ok := virtualHostsForPort[domain]
							if !ok {
								vh = &routev3.VirtualHost{
									Name:    fmt.Sprintf(constants.VHostNameFormat, gateway.Name, port, domain),
									Domains: []string{domain},
								}
								virtualHostsForPort[domain] = vh
							}
							vh.Routes = append(vh.Routes, routes...)
							klog.V(4).Infof("created VirtualHost %s for listener %s with domain %s", vh.Name, listener.
								Name, domain)
							if klog.V(4).Enabled() {
								for _, route := range routes {
									klog.Infof("adding route %s to VirtualHost %s", route.Name, vh.Name)
								}
							}
						}
					}
				}

				// TODO: Process GRPCRoutes

			default:
				klog.Warningf("Unsupported listener protocol for route processing: %s", listener.Protocol)
			}

			// 8. translate listener into a filter chain (HTTP connection manager that references route config 'route-<port>')
			filterChain, err := t.translateListenerToFilterChain(gateway, listener, routeName)
			if err != nil {
				meta.SetStatusCondition(&listenerStatus.Conditions, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionProgrammed),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonInvalid),
					Message:            fmt.Sprintf("Failed to program listener: %v", err),
					ObservedGeneration: gateway.Generation,
				})
			} else {
				meta.SetStatusCondition(&listenerStatus.Conditions, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionProgrammed),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonProgrammed),
					Message:            "Listener is programmed",
					ObservedGeneration: gateway.Generation,
				})

				filterChains = append(filterChains, filterChain)
			}

			listenerStatus.AttachedRoutes = attachedRoutes
			meta.SetStatusCondition(&listenerStatus.Conditions, metav1.Condition{
				Type:               string(gatewayv1.ListenerConditionAccepted),
				Status:             metav1.ConditionTrue,
				Reason:             string(gatewayv1.ListenerReasonAccepted),
				Message:            "Listener is valid",
				ObservedGeneration: gateway.Generation,
			})
			allListenerStatuses[listener.Name] = listenerStatus
		}

		// 9. Create RouteConfiguration (one per port group) with virtual hosts
		allVirtualHosts := make([]*routev3.VirtualHost, 0, len(virtualHostsForPort))
		for _, vh := range virtualHostsForPort {
			sortRoutes(vh.Routes)
			allVirtualHosts = append(allVirtualHosts, vh)
		}

		// now aggregate all the listeners on the same port
		routeConfig := &routev3.RouteConfiguration{
			Name:                     routeName,
			VirtualHosts:             allVirtualHosts,
			IgnorePortInHostMatching: true, // tricky to figure out thanks to howardjohn
		}
		envoyRoutes = append(envoyRoutes, routeConfig)

		// 10. If there are any filterChains -> create an Envoy Listener for port with those filterChains
		if len(filterChains) > 0 {
			envoyListener := &listenerv3.Listener{
				Name:            fmt.Sprintf(constants.ListenerNameFormat, port),
				Address:         createEnvoyAddress(uint32(port)),
				FilterChains:    filterChains,
				ListenerFilters: createListenerFilters(),
			}
			// If this is plain HTTP, we must now create exactly ONE default filter chain.
			// Use first listener as a template
			// For HTTPS, we create one filter chain per listener because they have unique
			// SNI matches and TLS settings.
			if listeners[0].Protocol == gatewayv1.HTTPProtocolType {
				filterChain, _ := t.translateListenerToFilterChain(gateway, listeners[0], routeName)
				envoyListener.FilterChains = []*listenerv3.FilterChain{filterChain}
			}
			finalEnvoyListeners = append(finalEnvoyListeners, envoyListener)
		}
	}

	// 11. Convert clusters map to slice
	clustersSlice := make([]envoyproxytypes.Resource, 0, len(envoyClusters))
	for _, cluster := range envoyClusters {
		clustersSlice = append(clustersSlice, cluster)
	}

	k8sApiCluster, err := buildK8sApiCluster()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to build kubernetes_api_cluster: %w", err)
	}
	clustersSlice = append(clustersSlice, k8sApiCluster)

	orderedStatuses := make([]gatewayv1.ListenerStatus, len(gateway.Spec.Listeners))
	for i, listener := range gateway.Spec.Listeners {
		orderedStatuses[i] = allListenerStatuses[listener.Name]
	}

	// 12. Return resource map and status objects
	return map[resourcev3.Type][]envoyproxytypes.Resource{
			resourcev3.ListenerType: finalEnvoyListeners,
			resourcev3.RouteType:    envoyRoutes,
			resourcev3.ClusterType:  clustersSlice,
		}, orderedStatuses,
		httpRouteStatuses, nil
}

func getSupportedKinds(listener gatewayv1.Listener) ([]gatewayv1.RouteGroupKind, bool) {
	supportedKinds := []gatewayv1.RouteGroupKind{}
	allKindsValid := true
	groupName := gatewayv1.Group(gatewayv1.GroupName)

	if listener.AllowedRoutes != nil && len(listener.AllowedRoutes.Kinds) > 0 {
		for _, kind := range listener.AllowedRoutes.Kinds {
			if (kind.Group == nil || *kind.Group == groupName) && SupportedKinds.Has(kind.Kind) {
				supportedKinds = append(supportedKinds, gatewayv1.RouteGroupKind{
					Group: &groupName,
					Kind:  kind.Kind,
				})
			} else {
				allKindsValid = false
			}
		}
	} else if listener.Protocol == gatewayv1.HTTPProtocolType || listener.Protocol == gatewayv1.HTTPSProtocolType {
		for _, kind := range SupportedKinds.UnsortedList() {
			supportedKinds = append(supportedKinds,
				gatewayv1.RouteGroupKind{
					Group: &groupName,
					Kind:  kind,
				},
			)
		}
	}

	return supportedKinds, allKindsValid
}

// getHTTPRoutesForGateway returns all HTTPRoutes that have a ParentRef pointing to the specified Gateway.
func (t *Translator) getHTTPRoutesForGateway(gw *gatewayv1.Gateway) []*gatewayv1.HTTPRoute {
	var matchingRoutes []*gatewayv1.HTTPRoute
	allRoutes, err := t.httprouteLister.List(labels.Everything())
	if err != nil {
		klog.Errorf("failed to list HTTPRoutes: %v", err)
		return matchingRoutes
	}

	for _, route := range allRoutes {
		for _, parentRef := range route.Spec.ParentRefs {
			// Check if the ParentRef targets the Gateway, defaulting to the route's namespace.
			refNamespace := route.Namespace
			if parentRef.Namespace != nil {
				refNamespace = string(*parentRef.Namespace)
			}
			if parentRef.Name == gatewayv1.ObjectName(gw.Name) && refNamespace == gw.Namespace {
				matchingRoutes = append(matchingRoutes, route)
				break // Found a matching ref for this gateway, no need to check others.
			}
		}
	}
	return matchingRoutes
}

// validateHTTPRoute is the definitive validation function. It iterates through all
// parentRefs of an HTTPRoute and generates a complete RouteParentStatus for each one
// that targets the specified Gateway. It also returns a slice of all listeners
// that ended up accepting the route.
func (t *Translator) validateHTTPRoute(
	gateway *gatewayv1.Gateway,
	httpRoute *gatewayv1.HTTPRoute,
) ([]gatewayv1.RouteParentStatus, []gatewayv1.Listener) {

	var parentStatuses []gatewayv1.RouteParentStatus
	// Use a map to collect a unique set of listeners that accepted the route.
	acceptedListenerSet := make(map[gatewayv1.SectionName]gatewayv1.Listener)

	// --- Determine the ResolvedRefs status for the entire Route first. ---
	// This is a property of the route itself, independent of any parent.
	resolvedRefsCondition := metav1.Condition{
		Type:               string(gatewayv1.RouteConditionResolvedRefs),
		ObservedGeneration: httpRoute.Generation,
		LastTransitionTime: metav1.Now(),
	}

	// --- Iterate over EACH ParentRef in the HTTPRoute ---
	for _, parentRef := range httpRoute.Spec.ParentRefs {
		// We only care about refs that target our current Gateway.
		refNamespace := httpRoute.Namespace
		if parentRef.Namespace != nil {
			refNamespace = string(*parentRef.Namespace)
		}
		if parentRef.Name != gatewayv1.ObjectName(gateway.Name) || refNamespace != gateway.Namespace {
			continue // This ref is for another Gateway.
		}

		// This ref targets our Gateway. We MUST generate a status for it.
		var listenersForThisRef []gatewayv1.Listener
		rejectionReason := gatewayv1.RouteReasonNoMatchingParent

		// --- Find all listeners on the Gateway that match this specific parentRef ---
		for _, listener := range gateway.Spec.Listeners {
			sectionNameMatches := (parentRef.SectionName == nil) || (*parentRef.SectionName == listener.Name)
			portMatches := (parentRef.Port == nil) || (*parentRef.Port == listener.Port)

			if sectionNameMatches && portMatches {
				// The listener matches the ref. Now check if the listener's policy (e.g., hostname) allows it.
				if !isAllowedByListener(gateway, listener, httpRoute, t.namespaceLister) {
					rejectionReason = gatewayv1.RouteReasonNotAllowedByListeners
					continue
				}
				if !isAllowedByHostname(listener, httpRoute) {
					rejectionReason = gatewayv1.RouteReasonNoMatchingListenerHostname
					continue
				}
				listenersForThisRef = append(listenersForThisRef, listener)
			}
		}

		// --- Build the final status for this ParentRef ---
		status := gatewayv1.RouteParentStatus{
			ParentRef:      parentRef,
			ControllerName: "test",
			Conditions:     []metav1.Condition{},
		}

		// Create the 'Accepted' condition based on the listener validation.
		acceptedCondition := metav1.Condition{
			Type:               string(gatewayv1.RouteConditionAccepted),
			ObservedGeneration: httpRoute.Generation,
			LastTransitionTime: metav1.Now(),
		}

		if len(listenersForThisRef) == 0 {
			acceptedCondition.Status = metav1.ConditionFalse
			acceptedCondition.Reason = string(rejectionReason)
			acceptedCondition.Message = "No listener matched the parentRef."
			if rejectionReason == gatewayv1.RouteReasonNotAllowedByListeners {
				acceptedCondition.Message = "Route is not allowed by a listener's policy."
			} else {
				acceptedCondition.Message = "The route's hostnames do not match any listener hostnames."
			}
		} else {
			acceptedCondition.Status = metav1.ConditionTrue
			acceptedCondition.Reason = string(gatewayv1.RouteReasonAccepted)
			acceptedCondition.Message = "Route is accepted."
			for _, l := range listenersForThisRef {
				acceptedListenerSet[l.Name] = l
			}
		}

		// --- 4. Combine the two independent conditions into the final status. ---
		status.Conditions = append(status.Conditions, acceptedCondition, resolvedRefsCondition)
		parentStatuses = append(parentStatuses, status)
	}

	var allAcceptingListeners []gatewayv1.Listener
	for _, l := range acceptedListenerSet {
		allAcceptingListeners = append(allAcceptingListeners, l)
	}

	return parentStatuses, allAcceptingListeners
}

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
