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

package envoy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// ResourceManager manages the Envoy proxy resources for a given Gateway.
type ResourceManager struct {
	client                     kubernetes.Interface
	gw                         *gatewayv1.Gateway
	nodeID                     string
	envoyImage                 string
	namespace                  string
	agenticIdentityTrustDomain string
}

// NewResourceManager creates a new ResourceManager.
// The nodeID is generated based on the Gateway's namespace and name and is not exposed to the controller.
func NewResourceManager(client kubernetes.Interface, gw *gatewayv1.Gateway, envoyImage string, agenticIdentityTrustDomain string) *ResourceManager {
	return &ResourceManager{
		client:                     client,
		gw:                         gw,
		nodeID:                     proxyName(gw.Namespace, gw.Name),
		envoyImage:                 envoyImage,
		namespace:                  gw.Namespace,
		agenticIdentityTrustDomain: agenticIdentityTrustDomain,
	}
}

// proxyName generates a deterministic name for the Envoy proxy resources.
func proxyName(namespace, name string) string {
	namespacedName := types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}
	hash := sha256.Sum256([]byte(namespacedName.String()))
	return fmt.Sprintf(constants.ProxyNameFormat, hex.EncodeToString(hash[:6]))
}

// EnsureProxyExist ensures that the Envoy proxy deployment, service, and other resources exist and are ready.
// It returns the LoadBalancer address (IP or Hostname) of the proxy service.
func (r *ResourceManager) EnsureProxyExist(ctx context.Context) (string, error) {
	logger := klog.FromContext(ctx).WithValues("resourceName", klog.KRef(r.namespace, r.nodeID))
	ctx = klog.NewContext(ctx, logger)

	if err := r.ensureSA(ctx); err != nil {
		return "", err
	}

	if err := r.ensureConfigMap(ctx); err != nil {
		return "", err
	}

	// Create the Service first to trigger LoadBalancer allocation early.
	// The LoadBalancer allocation may take 3-5 minutes in e2e/conformance tests.
	// The Deployment can take about 1-2 minutes to be ready, so we want to start
	// LoadBalancer allocation as early as possible.
	if _, err := r.ensureServiceExists(ctx); err != nil {
		return "", err
	}

	if err := r.ensureDeployment(ctx); err != nil {
		return "", err
	}

	return r.ensureService(ctx)
}

func (r *ResourceManager) NodeID() string {
	return r.nodeID
}

// ensureSA ensures that the ServiceAccount for the Envoy proxy exists.
func (r *ResourceManager) ensureSA(ctx context.Context) error {
	logger := klog.FromContext(ctx)

	sa := r.renderServiceAccount()
	_, err := r.client.CoreV1().ServiceAccounts(sa.Namespace).Get(ctx, sa.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Creating Envoy proxy serviceaccount", "name", sa.Name, "namespace", sa.Namespace)
			_, err = r.client.CoreV1().ServiceAccounts(sa.Namespace).Create(ctx, sa, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create envoy serviceaccount: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get envoy serviceaccount: %w", err)
		}
	}
	logger.Info("Envoy proxy serviceaccount is ready!")
	return nil
}

// ensureConfigMap ensures that the ConfigMap for the Envoy proxy exists.
func (r *ResourceManager) ensureConfigMap(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	cm, err := r.renderConfigMap()
	if err != nil {
		return err
	}

	_, err = r.client.CoreV1().ConfigMaps(cm.Namespace).Get(ctx, cm.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Creating Envoy bootstrap configmap", "name", cm.Name, "namespace", cm.Namespace)
			_, err = r.client.CoreV1().ConfigMaps(cm.Namespace).Create(ctx, cm, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create envoy configmap: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get envoy configmap: %w", err)
		}
	}

	logger.Info("Envoy bootstrap configmap is ready!")
	return nil
}

// ensureDeployment ensures that the Envoy deployment exists and is available.
func (r *ResourceManager) ensureDeployment(ctx context.Context) error {
	logger := klog.FromContext(ctx)

	deployment := r.renderDeployment()
	dep, err := r.client.AppsV1().Deployments(deployment.Namespace).Get(ctx, deployment.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Creating Envoy proxy deployment", "name", deployment.Name, "namespace", deployment.Namespace)
			dep, err = r.client.AppsV1().Deployments(deployment.Namespace).Create(ctx, deployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create envoy deployment: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get envoy deployment: %w", err)
		}
	}

	// If the Deployment was just created, we will highly likely immediately fail
	// here and return.
	for _, cond := range dep.Status.Conditions {
		if cond.Type == appsv1.DeploymentAvailable && cond.Status == corev1.ConditionTrue {
			logger.Info("Envoy proxy deployment is ready!")
			return nil
		}
	}

	return fmt.Errorf("envoy deployment %s is not available yet", deployment.Name)
}

// ensureServiceExists ensures that the Service for the Envoy proxy exists.
func (r *ResourceManager) ensureServiceExists(ctx context.Context) (*corev1.Service, error) {
	logger := klog.FromContext(ctx)
	service := r.renderService()

	svc, err := r.client.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Creating Envoy proxy service", "name", service.Name, "namespace", service.Namespace)
			svc, err = r.client.CoreV1().Services(service.Namespace).Create(ctx, service, metav1.CreateOptions{})
			if err != nil {
				return nil, fmt.Errorf("failed to create envoy service: %w", err)
			}
			return svc, nil
		}
		return nil, fmt.Errorf("failed to get envoy service: %w", err)
	}
	return svc, nil
}

// ensureService ensures that the Service for the Envoy proxy exists and has a LoadBalancer address (IP or Hostname) assigned.
func (r *ResourceManager) ensureService(ctx context.Context) (string, error) {
	logger := klog.FromContext(ctx)
	svc, err := r.ensureServiceExists(ctx)
	if err != nil {
		return "", err
	}

	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return "", fmt.Errorf("envoy service %s type is %s, expected %s", svc.Name, svc.Spec.Type, corev1.ServiceTypeLoadBalancer)
	}

	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		return "", fmt.Errorf("loadbalancer address is not assigned yet for service %s", svc.Name)
	}

	ingress := svc.Status.LoadBalancer.Ingress[0]
	address := ingress.IP
	if address == "" {
		address = ingress.Hostname
	}
	if address == "" {
		return "", fmt.Errorf("loadbalancer IP or Hostname is not assigned yet for service %s", svc.Name)
	}

	logger.Info("Envoy proxy service is ready with LoadBalancer address!", "address", address)
	return address, nil
}

func DeleteProxy(ctx context.Context, client kubernetes.Interface, namespace, name string) error {
	nodeID := proxyName(namespace, name)
	logger := klog.FromContext(ctx).WithValues("resourceName", klog.KRef(namespace, nodeID))

	// Delete Deployment
	err := client.AppsV1().Deployments(namespace).Delete(ctx, nodeID, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete envoy deployment: %w", err)
	}
	logger.Info("Envoy deployment deleted")

	// Delete Service
	err = client.CoreV1().Services(namespace).Delete(ctx, nodeID, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete envoy service: %w", err)
	}
	logger.Info("Envoy service deleted")

	// Delete ConfigMap
	err = client.CoreV1().ConfigMaps(namespace).Delete(ctx, nodeID, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete envoy configmap: %w", err)
	}
	logger.Info("Envoy configmap deleted")

	// Delete ServiceAccount
	err = client.CoreV1().ServiceAccounts(namespace).Delete(ctx, nodeID, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete envoy serviceaccount: %w", err)
	}
	logger.Info("Envoy serviceaccount deleted")

	// TODO: Clean up xds cache, though it should be ok if we don't.
	return nil
}
