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

const (
	// listenerNameFormat is the format string for Envoy listener names, becoming `listener-<port>`.
	listenerNameFormat = "listener-%d"
	// routeNameFormat is the format string for Envoy route configuration names, becoming `route-<port>`.
	routeNameFormat = "route-%d"
	// envoyRouteNameFormat is the format string for individual Envoy route names within a RouteConfiguration,
	// becoming `<namespace>-<httproute-name>-rule<rule-index>-match<match-index>`.
	envoyRouteNameFormat = "%s-%s-rule%d-match%d"
	// vHostNameFormat is the format string for Envoy virtual host names, becoming `<gateway-name>-vh-<port>-<domain>`.
	vHostNameFormat = "%s-vh-%d-%s"
	// clusterNameFormat is the format string for Envoy cluster names, becoming `<namespace>-<backend-name>`.
	clusterNameFormat = "%s-%s"
	// rbacPolicyNameFormat is the format string for Envoy RBAC policies, becoming `<namespace>-<backend-name>-rule-<rule-index>`.
	rbacPolicyNameFormat = "%s-%s-rule-%d"
)

const (
	// k8sAPIClusterName is the name of the cluster that points to the Kubernetes API server.
	k8sAPIClusterName = "kubernetes_api_cluster"
	// saAuthTokenHeader is the header used to carry the Kubernetes service account token.
	saAuthTokenHeader = "x-k8s-sa-token"
	// userRoleHeader is the header populated with the subject claim from the JWT.
	userRoleHeader = "x-user-role"
)
