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
	"net"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// convertServiceRefToCluster builds an Envoy cluster for a Service backendRef using
// EndpointSlice endpoints when available, falling back to STRICT_DNS otherwise.
func (t *Translator) convertServiceRefToCluster(svc *corev1.Service, servicePort int32) *clusterv3.Cluster {
	clusterName := fmt.Sprintf(constants.ClusterNameFormat, svc.Namespace, svc.Name)
	cluster := &clusterv3.Cluster{
		Name:           clusterName,
		ConnectTimeout: durationpb.New(constants.DefaultConnectTimeout),
		LbPolicy:       clusterv3.Cluster_ROUND_ROBIN,
	}

	if assignment := t.clusterLoadAssignmentForService(svc, servicePort); assignment != nil {
		endpoints := assignment.GetEndpoints()
		if len(endpoints) > 0 && len(endpoints[0].GetLbEndpoints()) > 0 {
			cluster.ClusterDiscoveryType = &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC}
			cluster.LoadAssignment = assignment
			return cluster
		}
	}

	// No EndpointSlice endpoints yet; use STRICT_DNS so ClusterIP services can resolve.
	serviceFQDN := fmt.Sprintf("%s.%s.svc.cluster.local", svc.Name, svc.Namespace)
	cluster.ClusterDiscoveryType = &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS}
	//nolint:gosec // G115: port values are within valid uint32 bounds
	cluster.LoadAssignment = createClusterLoadAssignment(clusterName, serviceFQDN, uint32(servicePort))
	return cluster
}

func (t *Translator) clusterLoadAssignmentForService(svc *corev1.Service, servicePort int32) *endpointv3.ClusterLoadAssignment {
	if t.endpointSliceLister == nil {
		return nil
	}

	svcPort, ok := servicePortDef(svc, servicePort)
	if !ok {
		return nil
	}

	clusterName := fmt.Sprintf(constants.ClusterNameFormat, svc.Namespace, svc.Name)
	selector := labels.Set{discoveryv1.LabelServiceName: svc.Name}.AsSelector()
	slices, err := t.endpointSliceLister.EndpointSlices(svc.Namespace).List(selector)
	if err != nil {
		return nil
	}

	var lbEndpoints []*endpointv3.LbEndpoint
	for _, slice := range slices {
		epPort, ok := endpointSlicePortNumber(svcPort, slice.Ports)
		if !ok {
			continue
		}
		for i := range slice.Endpoints {
			ep := &slice.Endpoints[i]
			if !endpointIsReady(ep) {
				continue
			}
			for _, addr := range ep.Addresses {
				if net.ParseIP(addr) == nil {
					continue
				}
				lbEndpoints = append(lbEndpoints, lbEndpointForAddress(addr, epPort))
			}
		}
	}

	if len(lbEndpoints) == 0 {
		return nil
	}

	return &endpointv3.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpointv3.LocalityLbEndpoints{
			{LbEndpoints: lbEndpoints},
		},
	}
}

func servicePortDef(svc *corev1.Service, port int32) (corev1.ServicePort, bool) {
	for _, p := range svc.Spec.Ports {
		if p.Port == port {
			return p, true
		}
	}
	if len(svc.Spec.Ports) > 0 {
		return svc.Spec.Ports[0], true
	}
	return corev1.ServicePort{}, false
}

func endpointSlicePortNumber(svcPort corev1.ServicePort, slicePorts []discoveryv1.EndpointPort) (int32, bool) {
	targetPort := svcPort.TargetPort
	if targetPort.Type == intstr.Int && targetPort.IntVal != 0 {
		for _, p := range slicePorts {
			if p.Port != nil && *p.Port == targetPort.IntVal {
				return *p.Port, true
			}
		}
	}
	if svcPort.Name != "" {
		for _, p := range slicePorts {
			if p.Name != nil && *p.Name == svcPort.Name && p.Port != nil {
				return *p.Port, true
			}
		}
	}
	for _, p := range slicePorts {
		if p.Port != nil && *p.Port == svcPort.Port {
			return *p.Port, true
		}
	}
	return 0, false
}

func endpointIsReady(ep *discoveryv1.Endpoint) bool {
	if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
		return false
	}
	if ep.Conditions.Serving != nil && !*ep.Conditions.Serving {
		return false
	}
	return len(ep.Addresses) > 0
}

func lbEndpointForAddress(address string, port int32) *endpointv3.LbEndpoint {
	//nolint:gosec // G115: port values are within valid uint32 bounds
	portU32 := uint32(port)
	return &endpointv3.LbEndpoint{
		HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
			Endpoint: &endpointv3.Endpoint{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Protocol: corev3.SocketAddress_TCP,
							Address:  address,
							PortSpecifier: &corev3.SocketAddress_PortValue{
								PortValue: portU32,
							},
						},
					},
				},
			},
		},
	}
}
