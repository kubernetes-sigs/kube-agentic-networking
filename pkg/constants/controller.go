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

package constants

const (
	// ProjectName is the name of the project.
	ProjectName = "kube-agentic-networking.sigs.k8s.io"

	// ControllerName is the name of the controller used in GatewayClass resources.
	ControllerName = "sigs.k8s.io/kube-agentic-networking-controller"

	// AgenticNetSystemNamespace is the namespace where agentic-networking system components are deployed.
	AgenticNetSystemNamespace = "agentic-net-system"

	// XDSServerServiceName is the name of the Service that exposes the xDS server.
	XDSServerServiceName = "agentic-net-xds-server"

	// Finalizers: block deletion until no dependents reference the resource.

	// GatewayClassFinalizer is set on GatewayClass; removed when no Gateways use this class.
	GatewayClassFinalizer = ProjectName + "/gatewayclass-finalizer"
	// GatewayFinalizer is set on Gateway; removed when no HTTPRoutes reference it and proxy is cleaned up.
	GatewayFinalizer = ProjectName + "/gateway-finalizer"
	// XBackendFinalizer is set on XBackend; removed when no XAccessPolicy targets it.
	XBackendFinalizer = ProjectName + "/xbackend-finalizer"
)
