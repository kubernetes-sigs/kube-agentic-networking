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
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/utils/ptr"
)

func TestEndpointSlicePortNumber(t *testing.T) {
	svcPort := corev1.ServicePort{
		Name:       "first-port",
		Port:       8080,
		TargetPort: intstr.FromInt32(3000),
	}
	slicePorts := []discoveryv1.EndpointPort{{
		Name: ptr.To("first-port"),
		Port: ptr.To(int32(3000)),
	}}

	got, ok := endpointSlicePortNumber(svcPort, slicePorts)
	if !ok || got != 3000 {
		t.Fatalf("endpointSlicePortNumber() = (%d, %v), want (3000, true)", got, ok)
	}
}

func TestClusterLoadAssignmentForService(t *testing.T) {
	ns := "gateway-conformance-infra"
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "manual-endpointslices", Namespace: ns},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{
				Name:       "first-port",
				Port:       8080,
				TargetPort: intstr.FromInt32(3000),
			}},
		},
	}
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "manual-endpointslices-ip4",
			Namespace: ns,
			Labels:    map[string]string{discoveryv1.LabelServiceName: svc.Name},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports: []discoveryv1.EndpointPort{{
			Name: ptr.To("first-port"),
			Port: ptr.To(int32(3000)),
		}},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"10.0.0.1"},
			Conditions: discoveryv1.EndpointConditions{
				Ready: ptr.To(true),
			},
		}},
	}

	factory := informers.NewSharedInformerFactoryWithOptions(nil, 0)
	_ = factory.Discovery().V1().EndpointSlices().Informer().GetIndexer().Add(slice)

	tr := &Translator{endpointSliceLister: factory.Discovery().V1().EndpointSlices().Lister()}
	assignment := tr.clusterLoadAssignmentForService(svc, 8080)
	if assignment == nil {
		t.Fatal("expected cluster load assignment")
	}
	endpoints := assignment.GetEndpoints()
	if len(endpoints) != 1 || len(endpoints[0].GetLbEndpoints()) != 1 {
		t.Fatalf("expected one lb endpoint, got %#v", assignment)
	}

	addr := endpoints[0].GetLbEndpoints()[0].GetEndpoint().GetAddress().GetSocketAddress()
	if addr.GetAddress() != "10.0.0.1" || addr.GetPortValue() != 3000 {
		t.Fatalf("unexpected endpoint address: %#v", addr)
	}
}

func TestEndpointIsReady(t *testing.T) {
	if !endpointIsReady(&discoveryv1.Endpoint{
		Addresses:  []string{"10.0.0.1"},
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
	}) {
		t.Fatal("expected ready endpoint")
	}
	if endpointIsReady(&discoveryv1.Endpoint{
		Addresses:  []string{"10.0.0.1"},
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)},
	}) {
		t.Fatal("expected not-ready endpoint")
	}
}

func TestClusterLoadAssignmentSelector(t *testing.T) {
	selector := labels.Set{discoveryv1.LabelServiceName: "svc"}.AsSelector()
	requirements, _ := selector.Requirements()
	if len(requirements) != 1 || requirements[0].Key() != discoveryv1.LabelServiceName {
		t.Fatalf("unexpected selector: %v", selector)
	}
}
