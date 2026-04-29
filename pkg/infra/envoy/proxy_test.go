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

package envoy

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestEnsureDeployment(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
		},
	}
	nodeID := proxyName(gw.Namespace, gw.Name)

	t.Run("deployment not found, creates and returns error (not ready)", func(t *testing.T) {
		client := fake.NewClientset()
		rm := NewResourceManager(client, gw, "envoy-image", "cluster.local")

		err := rm.ensureDeployment(context.Background())
		if err == nil {
			t.Fatal("expected error as deployment is not available yet")
		}

		// Verify deployment was created
		_, err = client.AppsV1().Deployments("test-ns").Get(context.Background(), nodeID, metav1.GetOptions{})
		if err != nil {
			t.Errorf("failed to get created deployment: %v", err)
		}
	})

	t.Run("deployment exists but not available, returns error", func(t *testing.T) {
		dep := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeID,
				Namespace: "test-ns",
			},
			Status: appsv1.DeploymentStatus{
				Conditions: []appsv1.DeploymentCondition{
					{
						Type:   appsv1.DeploymentAvailable,
						Status: corev1.ConditionFalse,
					},
				},
			},
		}
		client := fake.NewClientset(dep)
		rm := NewResourceManager(client, gw, "envoy-image", "cluster.local")

		err := rm.ensureDeployment(context.Background())
		if err == nil {
			t.Fatal("expected error as deployment is not available")
		}
	})

	t.Run("deployment exists and available, returns nil", func(t *testing.T) {
		dep := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeID,
				Namespace: "test-ns",
			},
			Status: appsv1.DeploymentStatus{
				Conditions: []appsv1.DeploymentCondition{
					{
						Type:   appsv1.DeploymentAvailable,
						Status: corev1.ConditionTrue,
					},
				},
			},
		}
		client := fake.NewClientset(dep)
		rm := NewResourceManager(client, gw, "envoy-image", "cluster.local")

		err := rm.ensureDeployment(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestEnsureService(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
		},
	}
	nodeID := proxyName(gw.Namespace, gw.Name)

	t.Run("service not found, creates and returns error (no LoadBalancer address)", func(t *testing.T) {
		client := fake.NewClientset()
		rm := NewResourceManager(client, gw, "envoy-image", "cluster.local")

		_, err := rm.ensureService(context.Background())
		if err == nil {
			t.Fatal("expected error as service has no LoadBalancer address")
		}

		// Verify service was created
		_, err = client.CoreV1().Services("test-ns").Get(context.Background(), nodeID, metav1.GetOptions{})
		if err != nil {
			t.Errorf("failed to get created service: %v", err)
		}
	})

	t.Run("service exists but no LoadBalancer address, returns error", func(t *testing.T) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeID,
				Namespace: "test-ns",
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
			},
		}
		client := fake.NewClientset(svc)
		rm := NewResourceManager(client, gw, "envoy-image", "cluster.local")

		_, err := rm.ensureService(context.Background())
		if err == nil {
			t.Fatal("expected error as service has no LoadBalancer address")
		}
	})

	t.Run("service exists and has LoadBalancer IP, returns IP", func(t *testing.T) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeID,
				Namespace: "test-ns",
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
			},
			Status: corev1.ServiceStatus{
				LoadBalancer: corev1.LoadBalancerStatus{
					Ingress: []corev1.LoadBalancerIngress{
						{IP: "10.0.0.1"},
					},
				},
			},
		}
		client := fake.NewClientset(svc)
		rm := NewResourceManager(client, gw, "envoy-image", "cluster.local")

		ip, err := rm.ensureService(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ip != "10.0.0.1" {
			t.Errorf("ensureService() = %s, want %s", ip, "10.0.0.1")
		}
	})

	t.Run("service exists and has LoadBalancer Hostname, returns Hostname", func(t *testing.T) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeID,
				Namespace: "test-ns",
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
			},
			Status: corev1.ServiceStatus{
				LoadBalancer: corev1.LoadBalancerStatus{
					Ingress: []corev1.LoadBalancerIngress{
						{Hostname: "envoy.example.com"},
					},
				},
			},
		}
		client := fake.NewClientset(svc)
		rm := NewResourceManager(client, gw, "envoy-image", "cluster.local")

		address, err := rm.ensureService(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if address != "envoy.example.com" {
			t.Errorf("ensureService() = %s, want %s", address, "envoy.example.com")
		}
	})
}
