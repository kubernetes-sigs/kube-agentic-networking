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

package controller

import (
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestSetGatewayConditions(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Generation: 1,
		},
	}

	t.Run("error setting conditions", func(t *testing.T) {
		newGw := gw.DeepCopy()
		setGatewayConditions(newGw, nil, fmt.Errorf("test error"))

		if len(newGw.Status.Conditions) != 2 {
			t.Fatalf("expected 2 conditions, got %d", len(newGw.Status.Conditions))
		}

		var programmedCondition *metav1.Condition
		for i, c := range newGw.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
				programmedCondition = &newGw.Status.Conditions[i]
				break
			}
		}
		if programmedCondition == nil || programmedCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected programmed condition to be false")
		}
	})

	t.Run("success all listeners programmed", func(t *testing.T) {
		newGw := gw.DeepCopy()
		listenerStatuses := []gatewayv1.ListenerStatus{
			{
				Name: "http",
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.ListenerConditionProgrammed),
						Status: metav1.ConditionTrue,
					},
				},
			},
		}
		setGatewayConditions(newGw, listenerStatuses, nil)

		var programmedCondition *metav1.Condition
		for i, c := range newGw.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
				programmedCondition = &newGw.Status.Conditions[i]
				break
			}
		}
		if programmedCondition == nil || programmedCondition.Status != metav1.ConditionTrue {
			t.Errorf("expected programmed condition to be true")
		}
	})

	t.Run("success some listeners not programmed", func(t *testing.T) {
		newGw := gw.DeepCopy()
		listenerStatuses := []gatewayv1.ListenerStatus{
			{
				Name: "http",
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.ListenerConditionProgrammed),
						Status: metav1.ConditionTrue,
					},
				},
			},
			{
				Name: "https",
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.ListenerConditionProgrammed),
						Status: metav1.ConditionFalse,
					},
				},
			},
		}
		setGatewayConditions(newGw, listenerStatuses, nil)

		var programmedCondition *metav1.Condition
		for i, c := range newGw.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
				programmedCondition = &newGw.Status.Conditions[i]
				break
			}
		}
		if programmedCondition == nil || programmedCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected programmed condition to be false")
		}
	})
}

func TestGatewaySecretRefNamespaceIndexFunc(t *testing.T) {
	ns1 := "ns1"
	ns2 := "ns2"
	gwNS := "gw-ns"

	tests := []struct {
		name     string
		obj      interface{}
		expected []string
	}{
		{
			name:     "not a Gateway",
			obj:      "not a gateway",
			expected: nil,
		},
		{
			name: "gateway with no listeners",
			obj: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Namespace: gwNS},
				Spec:       gatewayv1.GatewaySpec{},
			},
			expected: []string{},
		},
		{
			name: "gateway with listeners but no TLS",
			obj: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Namespace: gwNS},
				Spec: gatewayv1.GatewaySpec{
					Listeners: []gatewayv1.Listener{{}},
				},
			},
			expected: []string{},
		},
		{
			name: "gateway with certificateRefs (same and cross namespace)",
			obj: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Namespace: gwNS},
				Spec: gatewayv1.GatewaySpec{
					Listeners: []gatewayv1.Listener{
						{
							TLS: &gatewayv1.ListenerTLSConfig{
								CertificateRefs: []gatewayv1.SecretObjectReference{
									{
										Name: "secret1",
									},
									{
										Name:      "secret2",
										Namespace: ptr.To(gatewayv1.Namespace(ns1)),
									},
								},
							},
						},
						{
							TLS: &gatewayv1.ListenerTLSConfig{
								CertificateRefs: []gatewayv1.SecretObjectReference{
									{
										Name:      "secret3",
										Namespace: ptr.To(gatewayv1.Namespace(ns2)),
									},
									{
										Name:      "secret4",
										Namespace: ptr.To(gatewayv1.Namespace(ns1)), // Duplicate ns1
									},
								},
							},
						},
					},
				},
			},
			expected: []string{gwNS, ns1, ns2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := GatewaySecretRefNamespaceIndexFunc(tt.obj)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(keys) != len(tt.expected) {
				t.Fatalf("expected len %d, got %d. keys: %v", len(tt.expected), len(keys), keys)
			}
			for i, v := range keys {
				if v != tt.expected[i] {
					t.Errorf("expected key at index %d to be %q, got %q", i, tt.expected[i], v)
				}
			}
		})
	}
}
