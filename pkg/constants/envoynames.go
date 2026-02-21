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

package constants

const (
	// Envoy proxy name format
	ProxyNameFormat = "envoy-proxy-%s"
	// EnvoyBootstrapCfgFileName is the name of the Envoy bootstrap configuration file.
	EnvoyBootstrapCfgFileName = "envoy.yaml"

	// ListenerNameFormat is the format string for Envoy listener names, becoming `listener-<port>`.
	ListenerNameFormat = "listener-%d"
	// RouteNameFormat is the format string for Envoy route configuration names, becoming `route-<port>`.
	RouteNameFormat = "route-%d"
	// EnvoyRouteNameFormat is the format string for individual Envoy route names within a RouteConfiguration,
	// becoming `<namespace>-<httproute-name>-rule<rule-index>-match<match-index>`.
	EnvoyRouteNameFormat = "%s-%s-rule%d-match%d"
	// VHostNameFormat is the format string for Envoy virtual host names, becoming `<gateway-name>-vh-<port>-<domain>`.
	VHostNameFormat = "%s-vh-%d-%s"
	// ClusterNameFormat is the format string for Envoy cluster names, becoming `<namespace>-<backend-name>`.
	ClusterNameFormat = "%s-%s"
	// K8sAPIClusterName is the name of the cluster that points to the Kubernetes API server.
	K8sAPIClusterName = "kubernetes_api_cluster"

	// EnvoyBootstrapMountPath is the path where the Envoy bootstrap configuration is mounted.
	EnvoyBootstrapMountPath = "/etc/envoy/bootstrap"

	// GatewayNameLabel is the label key used to identify resources associated with a specific Gateway.
	GatewayNameLabel = "kube-agentic-networking.sigs.k8s.io/gateway-name"
)
