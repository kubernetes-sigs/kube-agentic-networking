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
	"errors"
	"fmt"
	"sort"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// translateHTTPRouteToEnvoyRoutes translates a full HTTPRoute into a slice of Envoy Routes.
// It now correctly handles RequestHeaderModifier filters.
func translateHTTPRouteToEnvoyRoutes(
	httpRoute *gatewayv1.HTTPRoute,
	serviceLister corev1listers.ServiceLister,
	accessPolicyLister agenticlisters.XAccessPolicyLister,
	backendLister agenticlisters.XBackendLister,
) ([]*routev3.Route, []*agenticv0alpha0.XBackend, metav1.Condition) {

	var envoyRoutes []*routev3.Route
	var allValidBackends []*agenticv0alpha0.XBackend
	overallCondition := createSuccessCondition(httpRoute.Generation)

	for ruleIndex, rule := range httpRoute.Spec.Rules {
		var redirectAction *routev3.RedirectAction
		var headersToAdd []*corev3.HeaderValueOption
		var headersToRemove []string
		var urlRewriteAction *routev3.RouteAction

		// Process filters using a switch and delegate logic to helpers.
	FilterLoop:
		for _, filter := range rule.Filters {
			switch filter.Type {
			case gatewayv1.HTTPRouteFilterRequestRedirect:
				redirectAction = processRequestRedirectFilter(filter.RequestRedirect)
				if redirectAction != nil {
					// Only one redirect filter is allowed per rule: stop processing further filters.
					break FilterLoop
				}
			case gatewayv1.HTTPRouteFilterRequestHeaderModifier:
				adds, removes := processRequestHeaderModifierFilter(filter.RequestHeaderModifier)
				headersToAdd = append(headersToAdd, adds...)
				headersToRemove = append(headersToRemove, removes...)
			case gatewayv1.HTTPRouteFilterURLRewrite:
				urlRewriteAction = processURLRewriteFilter(filter.URLRewrite)
			default:
				// Unsupported/ignored filter types are skipped here.
				klog.Warningf("Unsupported HTTPRoute filter type: %s", filter.Type)
			}
		}

		buildRoutesForRule := func(match gatewayv1.HTTPRouteMatch, matchIndex int) {
			routeMatch, matchCondition := translateHTTPRouteMatch(match, httpRoute.Generation)
			if matchCondition.Status == metav1.ConditionFalse {
				overallCondition = matchCondition
				return
			}

			envoyRoute := &routev3.Route{
				Name:                   fmt.Sprintf(constants.EnvoyRouteNameFormat, httpRoute.Namespace, httpRoute.Name, ruleIndex, matchIndex),
				Match:                  routeMatch,
				RequestHeadersToAdd:    headersToAdd,
				RequestHeadersToRemove: headersToRemove,
			}

			if redirectAction != nil {
				// If this is a redirect, set the Redirect action. No backends are needed.
				envoyRoute.Action = &routev3.Route_Redirect{
					Redirect: redirectAction,
				}
			} else {
				// Build the forwarding action with backend clusters and per-cluster security policies.
				routeAction, validBackends, err := buildHTTPRouteAction(
					httpRoute.Namespace,
					rule.BackendRefs,
					serviceLister,
					accessPolicyLister,
					backendLister,
				)
				var controllerErr *ControllerError
				if errors.As(err, &controllerErr) {
					overallCondition = createFailureCondition(gatewayv1.RouteConditionReason(controllerErr.Reason), controllerErr.Message, httpRoute.Generation)
					envoyRoute.Action = &routev3.Route_DirectResponse{
						DirectResponse: &routev3.DirectResponseAction{Status: 500},
					}
					// Skip further processing for this route if backends are invalid.
					envoyRoutes = append(envoyRoutes, envoyRoute)
					return
				}
				allValidBackends = append(allValidBackends, validBackends...)

				// If a URLRewrite filter was present, merge its properties into the RouteAction.
				if urlRewriteAction != nil {
					routeAction.HostRewriteSpecifier = urlRewriteAction.HostRewriteSpecifier
					routeAction.RegexRewrite = urlRewriteAction.RegexRewrite
					routeAction.PrefixRewrite = urlRewriteAction.PrefixRewrite
				}

				envoyRoute.Action = &routev3.Route_Route{
					Route: routeAction,
				}
			}
			envoyRoutes = append(envoyRoutes, envoyRoute)
		}

		if len(rule.Matches) == 0 {
			buildRoutesForRule(gatewayv1.HTTPRouteMatch{}, 0)
		} else {
			for matchIndex, match := range rule.Matches {
				buildRoutesForRule(match, matchIndex)
			}
		}
	}
	return envoyRoutes, allValidBackends, overallCondition
}

// processURLRewriteFilter translates a gatewayv1.HTTPURLRewriteFilter into an
// Envoy routev3.RouteAction with the appropriate rewrite actions.
func processURLRewriteFilter(f *gatewayv1.HTTPURLRewriteFilter) *routev3.RouteAction {
	if f == nil {
		return nil
	}

	routeAction := &routev3.RouteAction{}
	// The flag prevents the function from returning an empty &routev3.RouteAction{}
	// struct when no actual rewrite is needed.
	rewriteActionSet := false

	// Handle hostname rewrite.
	if f.Hostname != nil {
		routeAction.HostRewriteSpecifier = &routev3.RouteAction_HostRewriteLiteral{
			HostRewriteLiteral: string(*f.Hostname),
		}
		rewriteActionSet = true

	}

	// Handle path rewrite.
	if f.Path != nil {
		switch f.Path.Type {
		case gatewayv1.FullPathHTTPPathModifier:
			if f.Path.ReplaceFullPath != nil {
				routeAction.RegexRewrite = &matcherv3.RegexMatchAndSubstitute{
					Pattern:      &matcherv3.RegexMatcher{EngineType: &matcherv3.RegexMatcher_GoogleRe2{}, Regex: ".*"},
					Substitution: *f.Path.ReplaceFullPath,
				}
				rewriteActionSet = true
			}
		case gatewayv1.PrefixMatchHTTPPathModifier:
			if f.Path.ReplacePrefixMatch != nil {
				routeAction.PrefixRewrite = *f.Path.ReplacePrefixMatch
				rewriteActionSet = true
			}
		}
	}

	// If no rewrite actions were set, return nil.
	if !rewriteActionSet {
		return nil
	}

	return routeAction
}

// processRequestRedirectFilter converts a Gateway API HTTPRequestRedirectFilter into an Envoy RedirectAction.
func processRequestRedirectFilter(f *gatewayv1.HTTPRequestRedirectFilter) *routev3.RedirectAction {
	if f == nil {
		return nil
	}

	action := &routev3.RedirectAction{}

	if f.Hostname != nil {
		action.HostRedirect = string(*f.Hostname)
	}

	if f.StatusCode != nil {
		switch *f.StatusCode {
		case 301:
			action.ResponseCode = routev3.RedirectAction_MOVED_PERMANENTLY
		case 302:
			action.ResponseCode = routev3.RedirectAction_FOUND
		case 303:
			action.ResponseCode = routev3.RedirectAction_SEE_OTHER
		case 307:
			action.ResponseCode = routev3.RedirectAction_TEMPORARY_REDIRECT
		case 308:
			action.ResponseCode = routev3.RedirectAction_PERMANENT_REDIRECT
		default:
			action.ResponseCode = routev3.RedirectAction_MOVED_PERMANENTLY
		}
	} else {
		// The Gateway API spec defaults to a 302 redirect (Envoy: FOUND).
		action.ResponseCode = routev3.RedirectAction_FOUND
	}

	return action
}

// processRequestHeaderModifierFilter converts a Gateway API HTTPHeaderFilter into Envoy header mutations.
func processRequestHeaderModifierFilter(f *gatewayv1.HTTPHeaderFilter) ([]*corev3.HeaderValueOption, []string) {
	var headersToAdd []*corev3.HeaderValueOption
	var headersToRemove []string

	if f == nil {
		return headersToAdd, headersToRemove
	}

	// Handle "set" actions (overwrite)
	for _, header := range f.Set {
		headersToAdd = append(headersToAdd, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   string(header.Name),
				Value: header.Value,
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	// Handle "add" actions (append)
	for _, header := range f.Add {
		headersToAdd = append(headersToAdd, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   string(header.Name),
				Value: header.Value,
			},
			AppendAction: corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
		})
	}

	// Handle "remove" actions
	headersToRemove = append(headersToRemove, f.Remove...)

	return headersToAdd, headersToRemove
}

// buildHTTPRouteAction returns an action, a list of *valid* BackendRefs, and a structured error.
func buildHTTPRouteAction(namespace string,
	backendRefs []gatewayv1.HTTPBackendRef,
	serviceLister corev1listers.ServiceLister,
	accessPolicyLister agenticlisters.XAccessPolicyLister,
	backendLister agenticlisters.XBackendLister) (*routev3.RouteAction, []*agenticv0alpha0.XBackend, error) {

	weightedClusters := &routev3.WeightedCluster{}
	var validBackends []*agenticv0alpha0.XBackend

	for _, httpBackendRef := range backendRefs {
		backend, err := fetchBackend(namespace, httpBackendRef.BackendRef, backendLister, serviceLister)
		if err != nil {
			return nil, nil, err
		}
		validBackends = append(validBackends, backend)
		weight := int32(1)
		if httpBackendRef.Weight != nil {
			weight = *httpBackendRef.Weight
		}
		if weight == 0 {
			continue
		}

		clusterWeight := &routev3.WeightedCluster_ClusterWeight{
			Name:   fmt.Sprintf(constants.ClusterNameFormat, backend.Namespace, backend.Name),
			Weight: &wrapperspb.UInt32Value{Value: uint32(weight)},
		}

		// The HostRewriteLiteral is set on the individual clusterWeight within the WeightedCluster.
		// This ensures that for external backends with a specified hostname, Envoy rewrites
		// the Host header to the correct external hostname before forwarding the request.
		if backend.Spec.MCP.Hostname != nil {
			clusterWeight.HostRewriteSpecifier = &routev3.WeightedCluster_ClusterWeight_HostRewriteLiteral{
				HostRewriteLiteral: *backend.Spec.MCP.Hostname,
			}
		}

		clusterWeight.TypedPerFilterConfig, err = buildPerClusterRBACFilterConfig(accessPolicyLister, backend)
		if err != nil {
			klog.Errorf("Failed to build per-cluster RBAC config for backend %s/%s: %v", backend.Namespace, backend.Name, err)
			// Continue without RBAC config for this cluster if it fails to build.
		}
		weightedClusters.Clusters = append(weightedClusters.Clusters, clusterWeight)
	}

	if len(weightedClusters.Clusters) == 0 {
		return nil, nil, &ControllerError{Reason: string(gatewayv1.RouteReasonUnsupportedValue), Message: "no valid backends provided with a weight > 0"}
	}

	action := &routev3.RouteAction{ClusterSpecifier: &routev3.RouteAction_WeightedClusters{WeightedClusters: weightedClusters}}

	return action, validBackends, nil
}

// buildPerClusterRBACFilterConfig creates the TypedPerFilterConfig for a cluster, specifically for the RBAC filter.
func buildPerClusterRBACFilterConfig(accessPolicyLister agenticlisters.XAccessPolicyLister, backend *agenticv0alpha0.XBackend) (map[string]*anypb.Any, error) {
	perFilterConfig := make(map[string]*anypb.Any)

	// Envoy's per-cluster configuration requires an RBACPerRoute message containing
	// RBAC rules derived from AuthPolicy resources targeting this backend.
	rbacConfig, err := rbacConfigFromAccessPolicy(accessPolicyLister, backend)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RBAC policies: %w", err)
	}
	rbacPerRouteProto := &rbacv3.RBACPerRoute{
		Rbac: rbacConfig,
	}

	// Marshal the RBAC config into an Any proto.
	rbacAny, err := anypb.New(rbacPerRouteProto)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RBACPerRoute proto: %w", err)
	}

	perFilterConfig[wellknown.HTTPRoleBasedAccessControl] = rbacAny

	return perFilterConfig, nil
}

// translateHTTPRouteMatch translates a Gateway API HTTPRouteMatch into an Envoy RouteMatch.
// It returns the result and a condition indicating success or failure.
func translateHTTPRouteMatch(match gatewayv1.HTTPRouteMatch, generation int64) (*routev3.RouteMatch, metav1.Condition) {
	routeMatch := &routev3.RouteMatch{}

	if match.Path != nil {
		pathType := gatewayv1.PathMatchPathPrefix
		if match.Path.Type != nil {
			pathType = *match.Path.Type
		}
		if match.Path.Value == nil {
			msg := "path match value cannot be nil"
			return nil, createFailureCondition(gatewayv1.RouteReasonUnsupportedValue, msg, generation)
		}
		pathValue := *match.Path.Value

		switch pathType {
		case gatewayv1.PathMatchExact:
			routeMatch.PathSpecifier = &routev3.RouteMatch_Path{Path: pathValue}
		case gatewayv1.PathMatchPathPrefix:
			if pathValue == "/" {
				routeMatch.PathSpecifier = &routev3.RouteMatch_Prefix{Prefix: "/"}
			} else {
				path := strings.TrimSuffix(pathValue, "/")
				routeMatch.PathSpecifier = &routev3.RouteMatch_PathSeparatedPrefix{PathSeparatedPrefix: path}
			}
		case gatewayv1.PathMatchRegularExpression:
			routeMatch.PathSpecifier = &routev3.RouteMatch_SafeRegex{
				SafeRegex: &matcherv3.RegexMatcher{
					EngineType: &matcherv3.RegexMatcher_GoogleRe2{GoogleRe2: &matcherv3.RegexMatcher_GoogleRE2{}},
					Regex:      pathValue,
				},
			}
		default:
			msg := fmt.Sprintf("unsupported path match type: %s", pathType)
			return nil, createFailureCondition(gatewayv1.RouteReasonUnsupportedValue, msg, generation)
		}
	} else {
		// As per Gateway API spec, a nil path match defaults to matching everything.
		routeMatch.PathSpecifier = &routev3.RouteMatch_Prefix{Prefix: "/"}
	}

	// Translate Header Matches
	for _, headerMatch := range match.Headers {
		headerMatcher := &routev3.HeaderMatcher{
			Name: string(headerMatch.Name),
		}
		matchType := gatewayv1.HeaderMatchExact
		if headerMatch.Type != nil {
			matchType = *headerMatch.Type
		}

		switch matchType {
		case gatewayv1.HeaderMatchExact:
			headerMatcher.HeaderMatchSpecifier = &routev3.HeaderMatcher_StringMatch{
				StringMatch: &matcherv3.StringMatcher{
					MatchPattern: &matcherv3.StringMatcher_Exact{Exact: headerMatch.Value},
				},
			}
		case gatewayv1.HeaderMatchRegularExpression:
			headerMatcher.HeaderMatchSpecifier = &routev3.HeaderMatcher_SafeRegexMatch{
				SafeRegexMatch: &matcherv3.RegexMatcher{
					EngineType: &matcherv3.RegexMatcher_GoogleRe2{GoogleRe2: &matcherv3.RegexMatcher_GoogleRE2{}},
					Regex:      headerMatch.Value,
				},
			}
		default:
			msg := fmt.Sprintf("unsupported header match type: %s", matchType)
			return nil, createFailureCondition(gatewayv1.RouteReasonUnsupportedValue, msg, generation)
		}
		routeMatch.Headers = append(routeMatch.Headers, headerMatcher)
	}

	// Translate Query Parameter Matches
	for _, queryMatch := range match.QueryParams {
		// Gateway API only supports "Exact" match for query parameters.
		queryMatcher := &routev3.QueryParameterMatcher{
			Name: string(queryMatch.Name),
			QueryParameterMatchSpecifier: &routev3.QueryParameterMatcher_StringMatch{
				StringMatch: &matcherv3.StringMatcher{
					MatchPattern: &matcherv3.StringMatcher_Exact{Exact: queryMatch.Value},
				},
			},
		}
		routeMatch.QueryParameters = append(routeMatch.QueryParameters, queryMatcher)
	}

	// If all translations were successful, return the final object and a success condition.
	return routeMatch, createSuccessCondition(generation)
}

func createSuccessCondition(generation int64) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.RouteConditionResolvedRefs),
		Status:             metav1.ConditionTrue,
		Reason:             string(gatewayv1.RouteReasonResolvedRefs),
		Message:            "All references resolved",
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	}
}

func createFailureCondition(reason gatewayv1.RouteConditionReason, message string, generation int64) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.RouteConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	}
}

// sortRoutes is the definitive sorter for Envoy routes based on Gateway API precedence.
func sortRoutes(routes []*routev3.Route) {
	sort.Slice(routes, func(i, j int) bool {
		matchI := routes[i].GetMatch()
		matchJ := routes[j].GetMatch()

		// De-prioritize the catch-all route, ensuring it's always last.
		isCatchAllI := isCatchAll(matchI)
		isCatchAllJ := isCatchAll(matchJ)

		if isCatchAllI != isCatchAllJ {
			// If I is the catch-all, it should come after J (return false).
			// If J is the catch-all, it should come after I (return true).
			return isCatchAllJ
		}

		// Precedence Rule 1: Exact Path Match vs. Other Path Matches
		isExactPathI := matchI.GetPath() != ""
		isExactPathJ := matchJ.GetPath() != ""
		if isExactPathI != isExactPathJ {
			return isExactPathI // Exact path is higher precedence
		}

		// Precedence Rule 2: Longest Prefix Match
		prefixI := getPathMatchValue(matchI)
		prefixJ := getPathMatchValue(matchJ)

		if len(prefixI) != len(prefixJ) {
			return len(prefixI) > len(prefixJ) // Longer prefix is higher precedence
		}

		// Precedence Rule 3: Number of Header Matches
		headerCountI := len(matchI.GetHeaders())
		headerCountJ := len(matchJ.GetHeaders())
		if headerCountI != headerCountJ {
			return headerCountI > headerCountJ // More headers is higher precedence
		}

		// Precedence Rule 4: Number of Query Param Matches
		queryCountI := len(matchI.GetQueryParameters())
		queryCountJ := len(matchJ.GetQueryParameters())
		if queryCountI != queryCountJ {
			return queryCountI > queryCountJ // More query params is higher precedence
		}

		// If all else is equal, maintain original order (stable sort)
		return false
	})
}

// getPathMatchValue is a helper to extract the path string for comparison.
func getPathMatchValue(match *routev3.RouteMatch) string {
	if match.GetPath() != "" {
		return match.GetPath()
	}
	if match.GetPrefix() != "" {
		return match.GetPrefix()
	}
	if match.GetPathSeparatedPrefix() != "" {
		return match.GetPathSeparatedPrefix()
	}
	if sr := match.GetSafeRegex(); sr != nil { // Regex Match (used for other PathPrefix)
		// This correctly handles the output of translateHTTPRouteMatch.
		regex := sr.GetRegex()
		// Remove the trailing regex that matches subpaths.
		path := strings.TrimSuffix(regex, "(/.*)?")
		// Remove the quoting added by regexp.QuoteMeta.
		path = strings.ReplaceAll(path, `\`, "")
		return path
	}
	return ""
}

// isCatchAll determines if a route match is a generic "catch-all" rule.
// A catch-all matches all paths ("/") and has no other specific conditions.
func isCatchAll(match *routev3.RouteMatch) bool {
	if match == nil {
		return false
	}
	// It's a catch-all if the path match is for "/" AND there are no other constraints.
	isRootPrefix := match.GetPrefix() == "/"
	hasNoHeaders := len(match.GetHeaders()) == 0
	hasNoParams := len(match.GetQueryParameters()) == 0

	return isRootPrefix && hasNoHeaders && hasNoParams
}
